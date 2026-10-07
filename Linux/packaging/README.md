# Paketleme

## Linux — Flatpak

```sh
# Bir kerelik: runtime + SDK + Rust eklentisi + derleyici
flatpak --user install -y flathub org.gnome.Platform//49 org.gnome.Sdk//49 \
        org.freedesktop.Sdk.Extension.rust-stable//25.08 org.flatpak.Builder

# Derle ve yerel bir ostree deposuna yaz
cd Linux/packaging
flatpak run org.flatpak.Builder --user --force-clean --disable-rofiles-fuse \
        --repo=repo build-dir com.p2p.messenger.Typeon.yml

# Tek dosyalık dağıtılabilir paket
flatpak build-bundle repo typeon.flatpak com.p2p.messenger.Typeon

# Kurulum (hedef makinede)
flatpak install --user typeon.flatpak
flatpak run com.p2p.messenger.Typeon
```

`flatpak-builder` bu makinede PATH'te YOK — flatpak uygulaması olarak
(`org.flatpak.Builder`) kurulu, bu yüzden `flatpak run` ile çağrılıyor.

`--disable-rofiles-fuse` gereksiz görünüyor ama grafik oturumu DIŞINDAN
(ör. ssh, otomasyon) çalıştırıldığında şart: aksi halde derleme
`Failed to execute child process "fusermount3" (Permission denied)` →
`Failure spawning rofiles-fuse` ile ölüyor. Kapattığı şey yalnızca bir
yazma-koruma iyileştirmesi; çıktıyı etkilemiyor.

**Tuzak:** `flatpak build-bundle`, kendisinden ÖNCEKİ derleme başarısız olsa
bile 0 ile döner — `repo`'da ne varsa onu paketler, yani TAZE ZAMAN DAMGALI
ESKİ içerik elde edersiniz. Derleyicinin kendi çıkış kodunu kontrol edin ve
paketlemeden önce commit tarihini doğrulayın:

```sh
ostree --repo=repo log app/com.p2p.messenger.Typeon/x86_64/master | head -4
```

### Neden Flatpak (AppImage/RPM değil)

- Uygulama **GTK4 + libadwaita** üzerine kurulu. Bir AppImage'a bunları elle
  paketlemek gdk-pixbuf loader önbelleğini, derlenmiş GSettings şemalarını ve
  ikon temasını da taşımayı gerektirir — kırılgan ve dağıtımlar arası zayıf.
  GNOME runtime bunların hepsini doğru sürümlerle zaten sağlıyor.
- RPM en kolayı olurdu ama **self-contained değil**: sistemdeki
  gtk4/libadwaita sürümlerine bağlı kalırdı.
- Derleme **sandbox içinde** yapılıyor, host'ta değil: host openSUSE'de
  GTK 4.22, runtime'da 4.20 var. Host'ta derleyip runtime'da çalıştırmak
  sembol uyuşmazlığı riski taşırdı.

### İzinler (`finish-args`) ve gerekçeleri

| İzin | Neden |
|---|---|
| `--share=network` | libp2p/gossipsub + Tor. Ağsız uygulamanın işlevi yok. |
| `--talk-name=org.freedesktop.secrets` | **Zorunlu.** Kasa anahtarı sistem anahtarlığında; uygulama anahtarlık olmadan açılmıyor (bkz. `src/keyring.rs`). KDE Wallet ve GNOME Keyring ikisi de bu adı sağlıyor. |
| `--socket=wayland` / `--socket=fallback-x11` / `--device=dri` | GTK4 penceresi. |
| `--socket=pulseaudio` | Sesli mesaj kaydı ve çalınması. |

Geniş dosya sistemi izni **kasıtlı olarak yok**: dosya seçme/kaydetme
`gtk::FileDialog` üzerinden portal ile gidiyor, sandbox dışına erişim
gerekmiyor.

## Android — release APK

```sh
export JAVA_HOME=/usr/lib64/jvm/java-21-openjdk
cd p2p_messenger_android        && ./gradlew :app:assembleRelease   # istemci
cd p2p_messenger_android_server && ./gradlew :app:assembleRelease   # sunucu
```

Çıktılar: `app/build/outputs/apk/release/app-release.apk`

`--offline` KULLANMAYIN: `lintVitalRelease` görevi `lint-gradle` artefaktını
indirmek istiyor ve çevrimdışı modda derleme bu adımda kırılıyor.

### İmzalama — dikkat

Release, **depodaki aynı keystore** ile imzalanıyor (`app/debug.keystore`,
`CN=Typeon Debug`). Bu bilinçli bir tercih: imza anahtarı değişirse Android
uygulamayı farklı bir uygulama sayar, üzerine kurulumu reddeder ve kullanıcı
önce kaldırmak zorunda kalır — bu da kimliği, ratchet oturumlarını, mesaj
arşivini ve sunucu uygulamasında **onion kimliğini** siler. Onion adresi
değişince o sunucuya adresine göre kayıtlı tüm istemciler bir daha ulaşamaz.

Play Store'a çıkılacaksa ayrı bir release keystore gerekir — ama o geçiş
mevcut kurulumların bir kez kaldırılmasını gerektirir.

## Gerçek cihazda bulunan iki tuzak

**1. Anahtarlık izni tek başına yetmiyor.** Sadece
`--talk-name=org.freedesktop.secrets` verildiğinde uygulama şu ekranla
açılmıyordu: *"No system keyring found — Neither KDE Wallet nor GNOME Keyring
is installed."*

Sebep `src/keyring.rs` dosya başı notunda zaten yazıyor: KDE'de
`org.freedesktop.secrets` çoğu zaman kendi başına D-Bus ile başlatılabilir
değil, bu yüzden `ensure_available()` cüzdanı önce GERÇEK adıyla aktive
ediyor. Flatpak'in D-Bus proxy'si izin verilmeyen adları
`ListActivatableNames` sonucundan da gizlediği için uygulama hiç aday
göremiyor ve "kurulu değil" sonucuna varıyor. Bu yüzden dört arka uç adının
hepsine `--talk-name` gerekiyor (`BACKEND_NAMES` listesi).

**2. Manifest'i düzenlemek build önbelleğini ıskalatıyordu.** Kaynak `../..`
olduğu için manifest de kopyalanan ağacın içindeydi; `Linux/packaging` artık
`skip` listesinde.

## Bilinen sınırlar

- **Flatpak AYRI bir cihazdır.** Native derleme `~/.local/share/typeon`
  kullanıyor, Flatpak ise `~/.var/app/com.p2p.messenger.Typeon/data/typeon`.
  Üstelik kasa anahtarı sistem anahtarlığında **veri dizini yoluna göre**
  saklanıyor (`keyring.rs`, `attributes()` içinde `profile` alanı) — profili
  kopyalamak kasayı AÇILAMAZ hale getirir. Doğru yol: Flatpak'i QR ile yeni
  bir ikincil cihaz olarak bağlamak.
- Tema: libadwaita sistem GTK temasını takip etmiyor; sandbox içinde
  Breeze-Dark yerine Adwaita'ya düşüyor. Kozmetik.
- Sesli mesaj `ffmpeg` çağırıyor; GNOME 49 Platform runtime'ı
  `/usr/bin/ffmpeg` (7.1.3) sağladığı için ek modül gerekmiyor.
