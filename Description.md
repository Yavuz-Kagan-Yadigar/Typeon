# P2P Mesajlaşma Protokolü — Taslak v0.2

## 1. Kimlik (Identity)

**v0.2 kararı: iki katmanlı kimlik modeli.**

```
Identity (kişi)  →  1..N Device (cihaz)
```

- **Identity**: kullanıcının "kim olduğu" — kişiler ve gruplar bir Identity'ye
  güvenir, bir cihaza değil.
- **Device**: her fiziksel cihaz kendi anahtar çiftini üretir (bkz. 1.2),
  kendi fingerprint'ine sahiptir. Bir Identity'ye bağlı birden fazla Device
  olabilir (telefon + laptop + masaüstü).

```
Identity {
  identity_id: bytes[32],          // ilk cihazın fingerprint'i, DEĞİŞMEZ
  devices: [
    {
      device_fingerprint: bytes[32],
      device_name: string,          // "Ahmet'in telefonu"
      added_at: timestamp,
      status: Active | Revoked,
    }
  ],                                 // max 5 Active cihaz (bkz. not aşağıda)
  primary_device: bytes[32] | null, // bkz. 1.6, cihaz ekleme/çıkarma yetkisi
}
```

**Karar: bir Identity'ye en fazla 5 Active cihaz.** Sebep: pairwise
çoklu-cihaz mesajlaşmasının maliyeti (bölüm 1.7.1) cihaz sayısıyla
çarpımsal artıyor (N_A × N_B şifreleme/gönderim) — 5 cihaz makul bir
gerçek kullanım tavanı (telefon, laptop, masaüstü, tablet, yedek telefon
gibi) sağlarken, maliyeti de öngörülebilir tutuyor. `Revoked` cihazlar
sayıya dahil değil; 5. Active cihaz eklenmek istendiğinde en eski/istenen
bir cihazın önce iptal edilmesi istenir.

- `identity_id`, o kişinin ilk kurduğu cihazın fingerprint'i olarak sabitlenir
  ve bir daha değişmez — dışarıdan biri bu kişiyle konuşurken hep aynı
  `identity_id`'ye güvenir, hangi cihazın o an aktif olduğuna bakmaz.
- Kişiler (Contact) ve gruplar artık **device_fingerprint değil, identity_id**
  bazlı tutulur (bkz. bölüm 2 ve 5 güncellemeleri).

### 1.1 Anahtar çiftleri

Her **cihaz** (Device) iki ayrı amaç için iki anahtar çifti tutar:

| Amaç | Algoritma | Kullanım |
|---|---|---|
| İmzalama (kimlik doğrulama) | Ed25519 + ML-DSA-65 (hibrit) | Mesaj/paket imzalama, fingerprint temeli |
| Anahtar değişimi (KEM) | X25519 + ML-KEM-768 (hibrit) | Oturum anahtarı türetme, forward secrecy |

**Neden hibrit (klasik + PQ birlikte)?**
- Saf PQ algoritmalar (ML-DSA, ML-KEM) nispeten yeni; olası bir kriptanaliz
  kırılmasına karşı klasik algoritma (Ed25519/X25519) yedek katman sağlar.
- Güvenlik = klasik VE post-kuantum güvenliğin ikisinin de kırılması gerekir
  (birleşik anahtar, her iki algoritmanın çıktısının hash'lenmesiyle türetilir).
- Bu, Signal'ın PQXDH yaklaşımı ve genel endüstri pratiğiyle uyumlu.

### 1.2 Fingerprint (Cihaz Kimliği)

```
fingerprint = SHA3-256( sign_pubkey_ed25519 || sign_pubkey_mldsa || kem_pubkey_x25519 || kem_pubkey_mlkem )
```

- Ham fingerprint: 32 byte.
- Kullanıcıya gösterilen biçim: **Base32, 5'li gruplar halinde, büyük harf**
  Örnek: `XJ4K2-9QWRT-7YHBM-3ZPLC-VN8DF-...` (tamamı ~52 karakter, 8 grup)
- Kısa doğrulama kodu (sesli okuma için): fingerprint'in ilk 8 baytından türetilen
  **5 haneli sayı grupları x 4** (Signal'ın "safety number" formatına benzer,
  insan gözüyle karşılaştırmayı kolaylaştırır).
- **Identity kodu** (kullanıcıya gösterilen "benim kişi kodum"): `identity_id`
  aynı formatta gösterilir — TOFU eşleşmesinde artık bu kod paylaşılır,
  tek bir cihazın fingerprint'i değil.

### 1.3 QR içeriği (ilk eşleşme paketi)

QR kod, aşağıdaki alanları içeren CBOR (compact binary) kodlanmış bir yapı taşır:

```
EshlesmePaketi {
  version: u8,
  device_name: string,           // kullanıcı dostu isim, örn "Ahmet'in telefonu"
  sign_pubkey_ed25519: bytes[32],
  sign_pubkey_mldsa: bytes[~1952],
  kem_pubkey_x25519: bytes[32],
  kem_pubkey_mlkem: bytes[~1184],
  fingerprint: bytes[32],        // yukarıdakilerden türetilmiş, doğrulama için
  known_nodes: [Multiaddr],      // bu cihazın bildiği node listesi (max ~10)
  timestamp: u64,
}
```

QR kapasitesi gerçek bir kısıt — ML-DSA/ML-KEM public key'leri klasik anahtarlardan
çok daha büyük (Kyber-768 ~1184 byte, Dilithium ~1952 byte). Ham haliyle bu tek
QR'a sığmayabilir.

**Karar (v0.1): fingerprint-only QR.**
```
QRPaketi {
  version: u8,
  device_name: string,
  identity_id: bytes[32],        // v0.2: artık kişi kimliği taşınır
  device_fingerprint: bytes[32], // bu cihazın kendi fingerprint'i
  rendezvous_node: Multiaddr,    // tek bir bilinen adres, bağlanmak için yeterli
}
```
- QR küçük kalır, tarama anlık ve hatasız (çoklu-QR/galeri yöntemi denendi,
  sıra karışma riski ve tarama sürtünmesi nedeniyle ertelendi — ihtiyaç
  olursa "çevrimdışı tam aktarım modu" olarak ileride eklenebilir).
- Tam public key'ler bağlantı kurulunca karşı taraftan indirilir, indirilen
  anahtarların hash'i QR'daki `fingerprint` ile karşılaştırılır; eşleşmezse
  bağlantı reddedilir. Bu ekstra bir round-trip getirir ama güvenliği
  bozmaz (fingerprint zaten TOFU'nun temel doğrulama noktası).

### 1.4 Manuel giriş formatı

```
node-adresi:  /ip4/1.2.3.4/tcp/4001/p2p/<peer_id>
kisi-kodu:    XJ4K2-9QWRT-7YHBM-3ZPLC-VN8DF  (identity_id, kısaltılmış gösterim)
```

Node kendi ayarlar ekranında hem QR hem bu iki metni gösterir (kopyalanabilir).

### 1.5 Cihaz ekleme (yeni Device, var olan Identity'ye)

Bir kullanıcı ikinci cihazını (örn. laptop) eklemek istediğinde:

```
1. Yeni cihaz kendi anahtar çiftini üretir → kendi device_fingerprint'i olur.
2. Yeni cihaz bir "cihaz ekleme QR'ı" gösterir:
   DeviceLinkRequest {
     device_fingerprint: bytes[32],
     device_name: string,
     kem_pubkey_x25519, kem_pubkey_mlkem,  // geçici bağlantı kurmak için
   }
3. Var olan (onaylı) cihaz bu QR'ı OKUR (yani onay, var olan cihazdan verilir,
   ters yönde değil — bu, saldırganın "sahte cihaz ekle" isteği göndermesini
   anlamsız kılar, çünkü onay her zaman zaten güvenilen cihazdan çıkar).
4. Var olan cihaz, DeviceAdd paketini imzalar:
   DeviceAdd {
     identity_id: bytes[32],
     new_device_fingerprint: bytes[32],
     added_by: bytes[32],            // onaylayan cihazın fingerprint'i
     signature: bytes,
   }
5. DeviceAdd, doğrudan bağlantı üzerinden yeni cihaza gönderilir VE
   identity_id'ye güvenen tüm kişilere/gruplara yayılır (bkz. 1.7 senkron).
6. Yeni cihaz artık identity_id'nin parçası; kişiler onu da mesaj alıcısı
   olarak tanır.
```

### 1.6 Cihaz çıkarma / iptal (Revoke)

- Herhangi bir **Active** cihaz, aynı Identity'deki başka bir cihazı iptal
  edebilir (`status: Revoked`) — bu, "birincil cihaz" tekelini önler: telefon
  kaybolursa laptop üzerinden iptal edilebilir, tersi de geçerli.
  **Bu, bölüm 6'daki "kurucu cihaz kaybı" sorununu da kişisel kimlik
  düzeyinde çözer** (bkz. bölüm 5.5, grup bağlamına aktarımı).
- İptal, imzalı bir `DeviceRevoke` paketiyle diğer tüm Active cihazlara ve
  bilinen kişilere/gruplara yayılır.
- İptal edilen cihaz artık geçerli imza/şifreleme üretemez sayılır — karşı
  taraflar bu cihazdan gelen yeni mesajları reddeder (geçmiş mesajlar
  etkilenmez, bkz. bölüm 2.2 fingerprint değişikliği mantığıyla tutarlı).
- **Son cihaz iptali engellenir**: bir Identity'nin en az bir Active cihazı
  kalmalı (aksi halde kimlik kurtarılamaz hale gelir) — istisna: 1.8'deki
  kurtarma dosyası ile yeni cihaz eklenmesi.

### 1.7 Cihazlar arası senkronizasyon

Yeni bir Device eklendiğinde veya var olan cihazlar arasında durum
tutarlılığı sağlanırken şu veriler senkronize edilir:

```
SyncPayload {
  contacts: [Contact],           // bkz. bölüm 2.1
  groups: [Group],               // bkz. bölüm 5.2
  ratchet_states: [RatchetState],// bkz. 1.7.1 — özel ele alınır
  message_history: [Message]?,   // opsiyonel, kullanıcı tercih eder
}
```

- Senkron, cihazlar arasında kurulan kendi 1:1 ratchet oturumu üzerinden
  taşınır (yani cihaz-cihaz iletişimi de kullanıcı-kullanıcı iletişimiyle
  aynı şifreleme/imza mekanizmasını kullanır, ayrı bir kanal icat edilmez).
- İlk senkron tam kopya; sonrasında sadece **delta** (değişiklikler)
  gönderilir (yeni kişi, yeni grup, ratchet ilerlemesi).
- Mesaj geçmişi senkronu **opsiyonel** — bant genişliği/depolama maliyeti
  yüksek olabileceğinden kullanıcı bunu açık/kapalı seçebilir. Kapalıysa
  yeni cihaz sadece o andan sonraki mesajları görür.

#### 1.7.1 Ratchet state senkronu ve çakışma çözümü

Bu, tam senkronizasyonun **en riskli** kısmı — iki cihaz aynı anda aynı
kişiyle konuşursa ratchet zinciri çakışabilir. Çözüm (Signal'ın Sesame
yaklaşımına benzer):

```
Her (Identity_A ↔ Identity_B) çifti için TEK BİR mantıksal ratchet yerine,
Identity_A'nın HER cihazı, Identity_B'nin HER cihazıyla AYRI bir ratchet
oturumu tutar:

  (device_A1 ↔ device_B1), (device_A1 ↔ device_B2),
  (device_A2 ↔ device_B1), (device_A2 ↔ device_B2), ...
```

- Yani "kişiler arası mesajlaşma" aslında **cihaz çiftleri arası pairwise
  ratchet oturumlarının toplamı** olarak modellenir — bölüm 5'teki grup
  mesajlaşma mantığıyla birebir aynı prensip (pairwise), sadece "grup
  üyeleri" yerine "aynı kişinin cihazları" için uygulanıyor.
- Mesaj gönderilirken: gönderen cihaz, alıcı Identity'nin **tüm Active
  cihazlarına** kendi ratchet oturumuyla ayrı ayrı şifreli kopya gönderir.
- Çakışma riski **yok** çünkü her cihaz çifti kendi bağımsız ratchet
  zincirini yürütüyor — "iki cihaz aynı anda yazdı" durumu, günlük
  kullanımda "aynı mesaj iki farklı cihaz-çiftinde iki kez şifrelenip
  gönderildi" haline geliyor, ratchet matematiği bozulmuyor.
- Bedeli: N_A cihaz × N_B cihaz kadar şifreleme/gönderim (küçük N'lerde,
  örn. 2x2, ihmal edilebilir maliyet).
- Okundu bilgisi / "diğer cihazım da bu mesajı gördü" senkronu **v0.2
  kapsamına alındı** (aşağıda tasarlandı) — yeni bir mimari katman değil,
  var olan iki mekanizmaya (normal mesajlaşma + SyncPayload) küçük birer
  ek yeterli.

**Karşı tarafa okundu bildirimi** (normal mesaj trafiğinin parçası):
```
ReadReceipt {
  message_id: bytes,
  read_by_identity: bytes[32],   // hangi kişi okudu
  read_at: timestamp,
}
```
Bu, diğer `MessagePacket`'ler gibi şifrelenip imzalanarak gönderilir —
ayrı bir kanal icat edilmiyor. **Hangi cihazdan okunduğu taşınmaz/gösterilmez**
— kişinin Active cihazlarından **herhangi biri** mesajı okuduğu an, o kişi
için tek bir "görüldü" durumu tetiklenir.

**Görüntüleme biçimi**: basit, kişi bazlı tek satır.

```
{display_name}  görüldü  {read_at}

örnek:
Ahmet  görüldü  14:32
```

- 1:1 sohbette: karşı taraf **herhangi bir cihazından** okuduğu an tek
  "görüldü" işareti belirir (hangi cihaz olduğu önemsiz, gösterilmez).
- Grup sohbette: "tamamı görüldü" özeti, gruptaki **her üyenin en az bir
  cihazının** okumasıyla tamamlanır; kişi bazlı liste istenirse görülebilir
  ama cihaz detayı yine gösterilmez.
- `display_name`, alıcı tarafın o kişiye verdiği takma addır (bölüm 2.1
  `Contact.display_name`).

**Kendi cihazların arasında "okundu" senkronu**
(bölüm 1.7'deki `SyncPayload`'a küçük bir ek):
```
SyncPayload {
  ...
  read_states: [{ message_id, read_at }],
}
```
Bir cihaz mesajı ilk okuyan cihaz olduğunda: `ReadReceipt` karşı tarafa
gönderilir, aynı zamanda "bu mesaj okundu" bilgisi kendi `SyncPayload`
delta'sına eklenir. Diğer cihazların (laptop gibi) senkronda öğreneceği
tek şey "bu mesaj zaten okundu" — hangi cihazın okuduğu bilgisi taşınmaz,
sadece durum (okundu/okunmadı) senkronize edilir.

### 1.8 Kimlik kurtarma dosyası (kişisel bazda)

Kullanıcının **son cihazını** kaybetmesi durumuna karşı (bölüm 1.6'nın
"en az bir Active cihaz kalmalı" kuralının istisnası):

```
RecoveryFile (kullanıcı tarafından .txt olarak indirilip güvenli saklanır) {
  identity_id: bytes[32],
  master_seed: bytes[32],        // tüm cihaz anahtarlarının türetildiği kök
                                   // (ilk cihaz kurulumunda üretilir)
  created_at: timestamp,
}
```

- Bu dosya, tüm cihazların anahtarlarının türetilebileceği bir **kök seed**
  içerir (HKDF ile her cihaz için ayrı anahtar türetilir, ama hepsi bu
  köke bağlıdır).
- Kullanıcı bu dosyayı ilk kurulumda indirip (parola ile şifreli, AES-256-GCM)
  offline bir yerde saklar (USB, kağıda yazılan kurtarma cümlesi, vs.).
- Kaybolma durumunda: yeni cihaza bu dosya + parola girilir → `identity_id`
  ile aynı kimlik altında yeni bir Device olarak devam edilir → tüm eski
  Active cihazlara (varsa) otomatik `DeviceAdd` bildirimi gider.
- **Not**: bu dosya ele geçirilirse saldırgan o kimliği taklit edebilir —
  bu nedenle "sadece son çare" olarak tanıtılmalı, günlük kullanımda
  cihaz-cihaz onayı (1.5) tercih edilen yol olmalı.

---

## 2. Güven Modeli (TOFU + Güvenlik Numarası Değişikliği)

### 2.1 Yerel kayıt (her cihazda tutulan tablo)

**v0.2 güncellemesi**: Contact artık tek bir fingerprint değil, bir
`identity_id` ve o kimliğe ait **bilinen (Active) cihazlar listesini** tutar:

```
Contact {
  contact_id: uuid,                    // yerel, kullanıcıya özel
  display_name: string,                // kullanıcının verdiği takma ad
  trusted_identity_id: bytes[32],      // TOFU anında kaydedilen kişi kimliği
  known_devices: [
    {
      device_fingerprint: bytes[32],
      verified: bool,                  // bu spesifik cihaz doğrulandı mı
      first_seen: timestamp,
      status: Active | Revoked,
    }
  ],
  last_device_change: timestamp | null,
  ratchet_states: [DeviceRatchetState],// bkz. bölüm 3, cihaz çifti başına ayrı
}
```

### 2.2 Cihaz değişikliği akışı (fingerprint bazında, identity_id sabit)

`identity_id` sabit kaldığı sürece (yani karşı taraf hep aynı "kişi" olarak
tanınıyorsa), cihaz ekleme/çıkarma **beklenen ve imzalı** bir olaydır —
bölüm 1.5/1.6'daki `DeviceAdd`/`DeviceRevoke` paketleri bunu taşır ve bu
paketler zaten var olan güvenilir bir cihaz tarafından imzalanmıştır. Bu
durumda **kullanıcıya alarm gösterilmez** — sadece bilgilendirme:
"[Kişi] yeni bir cihaz ekledi: [device_name]".

**Gerçek alarm durumu**, imzasız veya beklenmeyen bir değişiklik:

```
Bağlantı kurulurken gelen (identity_id, device_fingerprint) çifti kontrol edilir:

  identity_id hiç bilinmiyor (ilk kez görülüyor)
    → TOFU: kaydet, verified = false, normal devam et

  identity_id biliniyor, device_fingerprint known_devices içinde VE Active
    → normal, sessiz devam

  identity_id biliniyor, device_fingerprint YENİ ama geçerli imzalı
  DeviceAdd paketiyle geldi (mevcut Active cihazdan onaylanmış)
    → sessizce known_devices'a eklenir, sadece bilgi bildirimi gösterilir

  identity_id biliniyor, device_fingerprint YENİ ve imzalı DeviceAdd YOK
  (yani biri doğrudan yeni bir anahtarla "ben buyum" diyor, onay zinciri yok)
    → BLOKLA (yeni mesaj gönderme/alma durur)
    → kullanıcıya uyarı ekranı:
        - "[Kişi] için tanınmayan yeni bir cihaz görüldü, onaylı değil"
        - eski/bilinen cihazların kısa kodu vs yeni cihazın kısa kodu
        - "Reddet" (varsayılan) / "Yeniden doğrula ve kabul et"
        - kabul edilirse: known_devices'a eklenir, verified = false,
          last_device_change = now
    → ESKİ mesajlar/ratchet state'ler korunur, sadece yeni cihazla olan
      oturum yeni bir DeviceRatchetState ile başlar
```

Bu ayrım önemli: **imzalı DeviceAdd zinciri**, çoklu cihaz senaryosunda
her yeni cihaz eklemesinin kullanıcıyı gereksiz yere alarma boğmamasını
sağlıyor, ama zincirsiz/beklenmeyen bir anahtar değişikliği hâlâ tam
güçle yakalanıp bloklanıyor — yani MITM/impersonation koruması bölüm
1 öncesindeki tasarımla aynı sıkılıkta korunuyor, sadece "meşru çoklu
cihaz" durumuna sürtünmesiz bir yol açılıyor.

### 2.3 Doğrulama (opsiyonel ama teşvik edilen adım)

Kullanıcı iki kısa kodu (kendi Identity'si + karşı tarafın Identity'si,
bölüm 1.2'de tanımlı `identity_id` kısa kodu) yüz yüze veya güvenilir bir
sesli kanaldan karşılaştırıp doğrulayabilir. Bu adım olmadan da sistem
çalışır (TOFU yeterli güvenlik sağlar, sadece ilk temas anında kim
olduğuna güvenmiş olursun) — ama doğrulama, ilk temasın da sahte
olmadığını garantiler. Doğrulama Identity düzeyinde yapılır; tek tek her
cihazı ayrıca doğrulamaya gerek yoktur (DeviceAdd zinciri zaten Identity
doğrulamasının cihazlara yayılmasını sağlar).

---

## 3. Mesaj Şifreleme ve Forward Secrecy

### 3.1 Oturum kurulumu (hibrit KEM)

İlk bağlantıda çift taraflı bir "hibrit el sıkışma" yapılır:

```
1. X25519 ECDH  → shared_secret_classic
2. ML-KEM-768   → shared_secret_pq (encapsulate/decapsulate)
3. root_key = HKDF( shared_secret_classic || shared_secret_pq, salt="p2pmsg-v0.1" )
```

### 3.2 Double Ratchet (forward secrecy + break-in recovery)

Signal'ın Double Ratchet algoritması, KEM adımı PQ-hibrit olacak şekilde uyarlanır:

- **Simetrik ratchet**: her mesajda mesaj anahtarı ilerletilir (HKDF zinciri),
  bir mesaj anahtarı ele geçirilse bile öncekiler/sonrakiler etkilenmez.
- **DH ratchet → KEM ratchet**: taraflar yeni bir X25519+ML-KEM çifti üretip
  yeniden anahtar değişimi yapar — bu adım "break-in recovery" sağlar (biri
  geçmiş anahtarı ele geçirse bile gelecekteki mesajlara erişemez).

  **Karar (v0.1): 30 dakikada bir** (mesaj sayısından bağımsız, zaman bazlı).
  PQ-KEM adımları klasik DH'den ağır olduğu için her mesajda yenileme
  anlamsız maliyet getirir; 30 dakika, aktif bir sohbette birkaç kez
  tetiklenecek, boşta bekleyen sohbette gereksiz yere çalışmayacak makul
  bir denge. Sabit kodlanmış değil, ileride ayarlanabilir bir parametre
  olarak bırakılabilir.

### 3.3 Her mesaj paketi

```
MessagePacket {
  header: {
    sender_identity_id: bytes[32],   // v0.2: kişi kimliği (kime ait olduğu)
    sender_device_fingerprint: bytes[32], // v0.2: hangi cihazdan gönderildi
    ratchet_pubkey: bytes,           // güncel ratchet adımının public key'i
    message_number: u32,
    prev_chain_length: u32,
  },
  ciphertext: bytes,               // AEAD (ChaCha20-Poly1305) şifreli içerik
  signature: bytes,                // ML-DSA + Ed25519 hibrit imza (header+ciphertext üzerinde)
}
```

- **İmza neden var?** Şifreleme gizliliği sağlar ama tek başına *kimin
  gönderdiğini* kriptografik olarak kanıtlamaz (KEM simetriktir). İmza,
  relay/node'ların ya da bir saldırganın paketi değiştirememesini
  ve gönderenin gerçekten iddia edilen cihaz fingerprint'ine sahip
  olduğunu garanti eder.
- Node/relay bu paketi kör taşır: `ciphertext` içeriğini çözemez, `signature`'ı
  değiştirirse alıcı tarafta doğrulama başarısız olur ve paket reddedilir.
- **v0.2 çoklu cihaz kuralı**: gönderen taraf, alıcı Identity'nin **tüm
  Active cihazlarına** ayrı ayrı `MessagePacket` gönderir (her biri kendi
  cihaz-çifti `DeviceRatchetState`'i ile şifrelenir, bkz. bölüm 1.7.1).
  Alıcı tarafta, aynı mantıksal mesajın Identity'nin diğer cihazlarına da
  gittiğini bilmesi gerekmez — her cihaz kendi kopyasını bağımsız alır.

---

## 4. Keşif ve Adresleme

### 4.1 Node listesi paylaşımı

Her cihaz bildiği node adreslerinin küçük bir alt kümesini (~10, en son
görülen/en güvenilir) QR eşleşme paketinde taşır. Yeni kullanıcı bu listeyi
alıp kendi DHT bootstrap listesine ekler.

### 4.2 DHT kaydı (WAN keşfi)

```
DHT_Entry {
  key: device_fingerprint,       // v0.2: DHT hâlâ cihaz bazlı adreslenir
                                   // (IP:port bir cihaza ait, bir Identity'nin
                                   //  soyut kavramına değil)
  value: {
    multiaddrs: [Multiaddr],     // o an bilinen IP:port'lar
    last_updated: timestamp,
    signature: bytes,             // kaydın gerçekten o cihaz fingerprint'ine
                                   // ait cihaz tarafından imzalandığını kanıtlar
  }
}
```
Bir Identity'nin birden fazla cihazına ulaşmak isteyen taraf, `known_devices`
listesindeki her `device_fingerprint` için ayrı DHT sorgusu yapar.

- Cihaz IP/port değiştirdiğinde DHT kaydını günceller (imzalı, sahte
  güncelleme engellenir).
- Bu kayıt sadece "kim nerede" bilgisi taşır, mesaj içeriği asla DHT'ye
  yazılmaz.

### 4.3 Node modu (opsiyonel)

- **Peer modu** (varsayılan): DHT'yi sorgular, kayıt günceller, çoğunlukla
  arka planda pasif.
- **Node modu** (kullanıcı açar): Kademlia routing tablosuna aktif katkı +
  isteğe bağlı Circuit Relay v2 hizmeti (simetrik NAT arkasındaki iki
  peer arasında şifreli trafiği kör taşır).

---

## 5. Grup Mesajlaşma

### 5.1 Model kararı: Pairwise (çiftler halinde) şifreleme

Hedef ölçek küçük (2-15 kişi), üyelik yönetimi tek yetkili (kurucu) elinde.
Bu ölçekte **Sender Keys** modelinin getirdiği karmaşıklık (üyelik değişiminde
anahtar rotasyonu, "kim ne zaman hangi anahtarı biliyordu" durum takibi)
gereksiz — bunun yerine mevcut 1:1 Double Ratchet altyapısı olduğu gibi
yeniden kullanılır:

```
Grup mesajı gönderilirken:
  gönderen cihaz, mesajı gruptaki her üye için AYRI AYRI
  kendi 1:1 ratchet oturumuyla şifreler ve doğrudan o üyeye gönderir.

  N üyeli grup → her mesaj N-1 kez şifrelenir, N-1 ayrı paket gider.
```

- Avantaj: yeni kripto yok, mevcut güvenlik garantileri (forward secrecy,
  fingerprint doğrulama, güvenlik numarası değişikliği tespiti) hiçbir
  değişiklik olmadan grup bağlamına taşınıyor.
- Maliyet: N ile doğrusal büyüyen bant genişliği/CPU — 15 kişilik grupta
  kabul edilebilir, yüzlerce kişilik grupta sorun olurdu (bu ölçek hedefte yok).
- İleride ölçek büyürse Sender Keys'e geçiş **ayrı bir protokol versiyonu**
  olarak ele alınabilir (v0.1 kapsamı dışı, ama mimari buna kapalı değil —
  grup kimliği/üyelik modeli aşağıda buna izin verecek şekilde tasarlandı).

### 5.2 Grup kimliği ve üyelik

```
Group {
  group_id: uuid,                      // yerel + üyeler arası paylaşılan, rastgele üretilir
  name: string,
  founder_fingerprint: bytes[32],      // kurucu, tek yetkili
  members: [
    {
      identity_id: bytes[32],            // v0.2: kişi bazlı üyelik (cihaz değil)
      added_at: timestamp,
      added_by: bytes[32],               // her zaman founder_identity_id olmalı
    }
  ],
  created_at: timestamp,
  version: u32,                        // üyelik listesi her değiştiğinde artar
}
```

**Kararlar:**
- Sadece `founder_identity_id` üye ekleyebilir/çıkarabilir. Başka hiçbir üyenin
  bu yetkisi yok. **v0.2 güncellemesi**: kurucunun kendisi artık birden
  fazla cihaza sahip olabileceği için (bölüm 1), "kurucu cihazını kaybetti"
  sorunu grup düzeyinde değil **kimlik düzeyinde** çözülüyor — kurucu
  telefonunu kaybederse, kurucunun başka bir Active cihazı (bölüm 1.6)
  ya da son çare olarak kurtarma dosyası (bölüm 1.8) ile aynı
  `founder_identity_id` altında devam eder, grup üyelik yetkisi kesintiye
  uğramaz. Eskiden bağımsız bir "yedek kurucu" mekanizması gerektiren bu
  sorun, artık genel kimlik/cihaz modelinin doğal bir sonucu olarak çözülmüş
  oluyor.
- Üyelik değişikliği kurucu tarafından imzalanmış bir `GroupUpdate` paketi
  olarak tüm mevcut (ve varsa yeni eklenen) üyelere pairwise gönderilir —
  ve her üyenin **tüm Active cihazlarına** ayrı ayrı (bölüm 1.7.1 pairwise
  cihaz-çifti mantığıyla tutarlı):

```
GroupUpdate {
  group_id: uuid,
  new_version: u32,
  change: Add(identity_id) | Remove(identity_id) | Rename(string),
  signed_by: bytes[32],                // founder_identity_id olmalı
  signed_by_device: bytes[32],         // kurucunun hangi cihazı imzaladı
  signature: bytes,
}
```

- Alıcı taraf, `signed_by == founder_identity_id` değilse `GroupUpdate`'i
  reddeder — bu, kurucu olmayan birinin sahte üyelik değişikliği
  göndermesini engeller (imza doğrulaması zaten var olan Dilithium+Ed25519
  imza mekanizmasını kullanır, bölüm 3.3). `signed_by_device`'ın kurucunun
  bilinen/Active bir cihazı olması da ayrıca doğrulanır (bölüm 2.2).

### 5.3 Üye çıkarma ve forward secrecy

Bir üye gruptan çıkarıldığında:
- Kalan üyelerle olan 1:1 ratchet oturumları etkilenmez (zaten ayrı ayrı).
- Çıkarılan üyeyle (üyenin **tüm cihazlarıyla**) olan grup-özel mesajlaşma
  durur (kurucu artık ona `GroupUpdate` veya grup mesajı göndermez).
- **Not**: çıkarılan üye, çıkarılmadan önce aldığı geçmiş mesajları hâlâ
  okuyabilir durumda (yerel kopyası var) — bu p2p/uçtan uca modelde
  kaçınılmaz bir sınırlama (merkezi sunucu olmadığı için "geçmişi sil"
  zorlanamaz). Kullanıcıya bu konuda net olmak gerekir.

### 5.4 Grup keşfi / davet akışı

- Kurucu, grup oluşturduğunda `group_id` + kendi `identity_id`'sini içeren bir
  "grup daveti" üretir (QR veya manuel paylaşım, bölüm 1.3/1.4 ile aynı
  mekanizma kullanılır).
- Davet edilen kişi, kurucuyla zaten var olan (veya o anda kurulan) 1:1
  bağlantı üzerinden `GroupUpdate(Add)` paketini alır, grubu yerel olarak
  oluşturur/günceller.

### 5.5 Çoklu cihazlı üyelerle grup etkileşimi

- Bir grup üyesinin yeni bir cihaz eklemesi (bölüm 1.5), grup üyeliğini
  otomatik olarak genişletir — kurucudan ayrıca onay istenmez, çünkü
  `identity_id` zaten üye olarak kayıtlı; yeni cihaz sadece o Identity'nin
  bir parçası olarak mesaj trafiğine dahil olur.
- Bir üye kendi cihazlarından birini iptal ederse (bölüm 1.6), grup
  otomatik olarak günceli takip eder — o cihaza artık grup mesajı gönderilmez.

---

## 6. Açık Kalan Kararlar

1. **QR içeriği**: tam public key mi, yoksa fingerprint + sonradan çekme mi?
   → **Karar verildi**: fingerprint-only (bkz. bölüm 1.3).
2. **Ratchet yenileme sıklığı**: → **Karar verildi**: 30 dakika (bkz. bölüm 3.2).
3. **Çoklu cihaz desteği**: → **Karar verildi**: tam senkronizasyon,
   Identity/Device iki katmanlı model (bkz. bölüm 1, 2.2, 3.3, 5.5).
4. **Kurucu cihaz kaybı**: → **Karar verildi**: kimlik düzeyinde çözüldü,
   kurtarma dosyası (bölüm 1.8) son çare olarak mevcut (bkz. bölüm 5.2 notu).
5. **Node teşvik modeli — karar: sadece gönüllülük.**
   Kullanım senaryosu küçük ölçekli (arkadaş grubu, tanıdık kişi sayısı),
   node modu proje sahibi tarafından kendi cihazında açık tutulacak.
   Karşılıklılık/teşvik mekanizmasına gerek yok; ölçek büyürse (yabancılar
   arası kullanım) bu karar yeniden değerlendirilebilir.

   **Bunun bootstrap'a etkisi**: Küçük, güvenilir bir grup için tam DHT
   şart değil — v0.1'de tek "bilinen node" (senin her zaman açık cihazın)
   bootstrap noktası olarak yeterli olabilir. DHT (Kademlia) yine de
   koddan çıkarılmaz (ileride büyürse hazır dursun), ama pratik akış
   şöyle basitleşir: yeni kullanıcı → senin node'unun adresini QR/manuel
   alır → ona bağlanır → DHT üzerinden diğerlerini keşfeder. Tek node
   çevrimdışıysa (v0.1'in kabul ettiği kısıt) yeni keşif durur; bu,
   küçük ölçekte kabul edilebilir bir trade-off.
6. **Okundu bilgisi senkronu**: → **Karar verildi**: v0.2 kapsamına alındı,
   ReadReceipt (normal mesaj trafiği) + SyncPayload'a `read_states` eki
   (bkz. bölüm 1.7.1).
7. **Cihaz sayısı sınırı**: → **Karar verildi**: Identity başına en fazla
   5 Active cihaz (bkz. bölüm 1).

---

## 7. Prototip için minimum kapsam (v0.1 hedefi)

Çoklu cihaz/senkron protokol düzeyinde tam tasarlandı (bölüm 1), ama
**prototipte uygulama sırası** hâlâ aşamalı olmalı — aksi halde ilk
çalışan sürüme ulaşmak gereksiz yere gecikir. Protokol tek parça, kod
teslimatı iki aşama:

**Aşama A — temel (tek cihaz varsayımıyla test edilir, ama kod
Identity/Device ayrımına göre yazılır, sadece "1 Identity = 1 Device"
özel durumuyla çalıştırılır):**
- [x] Identity/Device modeli, fingerprint üretimi ve gösterimi
- [ ] QR eşleşme (identity_id + device_fingerprint + tek node adresi)
- [ ] Manuel node/kişi ekleme
- [ ] libp2p + Kademlia DHT üzerinden iki cihazın birbirini bulması
- [ ] Hibrit KEM ile oturum kurulumu
- [ ] Double Ratchet ile 1:1 mesajlaşma (metin, tek satır)
- [ ] Cihaz/kimlik değişikliği tespiti ve uyarı ekranı (bölüm 2.2)
- [ ] Node modu aç/kapa (Linux masaüstünde önce, Android sonra)
- [ ] Grup oluşturma, davet, pairwise grup mesajlaşma (bölüm 5)

**Aşama B — çoklu cihaz (Aşama A'nın üzerine eklenir):**
- [ ] DeviceAdd/DeviceRevoke akışı (bölüm 1.5/1.6)
- [ ] Cihazlar arası SyncPayload (kişiler, gruplar) (bölüm 1.7)
- [ ] Cihaz-çifti bazlı DeviceRatchetState ve pairwise çoklu-cihaz gönderimi (bölüm 1.7.1)
- [ ] Kimlik kurtarma dosyası (.txt, parola korumalı) (bölüm 1.8)
- [ ] Mesaj geçmişi senkronu (opsiyonel, kullanıcı tercihi)
- [ ] Okundu bilgisi (ReadReceipt + SyncPayload read_states) (bölüm 1.7.1)

Dosya transferi, sesli/görüntülü arama v0.1/v0.2 kapsamı DIŞINDA.
