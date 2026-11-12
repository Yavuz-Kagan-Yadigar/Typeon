//! Timeouts, limits and protocol ids, with the small types they belong to.

use super::*;


/// Bir zarfın `pending_envelopes`'te ne kadar süre bekleyebileceği — bu
/// süre dolunca kalıcı olarak "Failed" sayılır (bkz. `MessageSendStatus`).
/// Only `Message` envelopes outside `awaiting_confirmation` (Ack, typing
/// and the like) use this limit; a tracked message is retried there until it
/// is confirmed, and Handshake/IdentityExchange have
/// `PENDING_HANDSHAKE_TIMEOUT_MS`.
pub(crate) const PENDING_ENVELOPE_TIMEOUT_MS: u64 = 20_000;

/// One entry of `pending_envelopes`.
pub(crate) struct QueuedEnvelope {
    pub(crate) target: String,
    pub(crate) envelope: NetworkEnvelope,
    /// First publish attempt (ms): the timeout counts from here.
    pub(crate) first_attempt_at: u64,
    /// next retry (ms). The delay grows with the entry's age (1-30 s),
    /// so a Handshake to an offline peer is not sealed and deposited every
    /// second for 5 min. 0 = due now (connection came up).
    pub(crate) next_at: u64,
    /// `deposit_dedup_key`, computed once at enqueue.
    pub(crate) key: Option<String>,
}

impl QueuedEnvelope {
    pub(crate) fn new(target: String, envelope: NetworkEnvelope, first_attempt_at: u64) -> Self {
        let key = ciborium_bytes(&envelope).ok().map(|b| crate::server_client::deposit_dedup_key(&envelope, &b));
        let next_at = pending_retry_at(first_attempt_at, current_time_ms());
        QueuedEnvelope { target, envelope, first_attempt_at, next_at, key }
    }
}

/// retry delay = age / 8, clamped to 1-30 s.
pub(crate) fn pending_retry_at(first_attempt_at: u64, now: u64) -> u64 {
    now + (now.saturating_sub(first_attempt_at) / 8).clamp(1_000, 30_000)
}

/// Spec dışı, teslim garantisi düzeltmesi ("karşı taraf şu an kapalı, 2-24
/// saat sonra açacak"): `Handshake`/`IdentityExchange` için AYRI (ve çok
/// daha uzun) bir kuyruk ömrü.
/// Bu ikisi `MessageContent` DEĞİL, `NetworkEnvelope` — yani
/// `awaiting_confirmation`'ın (onaylanana kadar süresiz yeniden deneme)
/// kapsamına yapısal olarak GİREMİYORLAR ve tek dayanakları bu kuyruk.
/// 20 saniyelik ortak ömür onlar için YANLIŞTI: kapalı bir cihaza ilk kez
/// mesaj yazıldığında `gossipsub.publish` `InsufficientPeers` ile
/// başarısız olur, `HandshakeInit` 20 sn sonra SESSİZCE atılır ve BİR DAHA
/// HİÇ gönderilmez (`initiate_handshake_with` yalnızca ratchet YOKKEN
/// çağrılır, oysa gönderen tarafta ratchet artık VAR). Karşı taraf ise
/// paketleri `early_packets`'e tamponlayıp el sıkışmayı bekler, o hiç
/// gelmez ve tampon dolar/eskir — iki uçta da hiçbir hata görünmeden mesaj
/// asla teslim edilmez.
/// 5 dakika, "az sonra açacak" senaryosunu (ağ birkaç saniye/dakika sonra
/// toparlanıyor) doğrudan çözer. Daha uzun kesintiler için ikinci bir
/// savunma katmanı var: `maybe_redo_handshake` (bkz.) — onaylanmamış bir
/// mesajın tazeleme turunda el sıkışmayı da tazeler, yani el sıkışma
/// pratikte mesajın kendisiyle AYNI (7 günlük) dayanıklılığı kazanır.
pub(crate) const PENDING_HANDSHAKE_TIMEOUT_MS: u64 = 5 * 60 * 1000;

/// İKİ CİHAZLI GERÇEK TESTTE ÖLÇÜLDÜ (2026-09-06): 4 taşıma yolu birden açık
/// (LAN doğrudan + Tor onion + sunucu + gossipsub) olduğunda AYNI zarf her
/// mesaj için 2-4 kez ulaşıyor. İlk kopya işleniyor, sonrakiler ratchet
/// ilerlediği için ÇÖZÜLEMİYOR ve her seferinde `error!("Gelen paket
/// işlenemedi: ...")` logluyor — iki telefonda da dakikada ~3 kez, saatlerce
/// (imza doğrulama + radyo israfı). `process_incoming_envelope` artık BAŞARIYLA
/// işlenmiş her zarfın bir özetini (ham baytların 64-bit hash'i) bu süre
/// boyunca tutar; bayt-aynısı bir tekrar sessizce düşürülür (tekrar eden bir
/// `Message` için gönderene Ack yine de yeniden gönderilir — zaten bunun için
/// tekrar gönderiyor). Bellek: girdi başına 16 bayt, periyodik budama +
/// sert tavan (`INBOUND_DEDUP_MAX_ENTRIES`).
pub(crate) const INBOUND_DEDUP_WINDOW_MS: u64 = 10 * 60 * 1000;
pub(crate) const INBOUND_DEDUP_MAX_ENTRIES: usize = 8192;

/// bkz. `pairing_mailbox_subs` — bir ratchet hiç kurulamazsa (karşı taraf
/// kalıcı olarak erişilemez) eşleşme-dönemi posta kutusu aboneliği sonsuza
/// kadar açık kalmasın.
pub(crate) const PAIRING_MAILBOX_TTL_MS: u64 = 15 * 60 * 1000;

/// İki el sıkışma tazelemesi (bkz. `maybe_redo_handshake`) arasındaki asgari
/// süre. Tazeleme oturumu SIFIRLADIĞI için (taze efemeral anahtarlar, yeni
/// kök anahtar, yeni gossipsub topic'i) bedava değil — ama saatlerce kapalı
/// bir cihaz için 10 dakikada bir yeni bir şans vermek, "el sıkışmam hiç
/// varmadı" durumundan kurtulmanın TEK yolu.
pub(crate) const HANDSHAKE_REDO_MIN_INTERVAL_MS: u64 = 10 * 60 * 1000;

/// stok libp2p `ping::Behaviour` yerine ÖZEL bir keepalive protokolü (request_response
/// tabanlı, bkz. `KeepAliveRequest`/`KeepAliveResponse`/`P2PBehaviour.keepalive`)
/// kullanılıyor. Sebep: stok `ping::Behaviour` TÜM bağlantılara TEK bir sabit
/// aralık uygular (bağlantı ne kadar süredir kanıtlanmış şekilde sağlıklı
/// olursa olsun) — hücresel radyo tipik olarak herhangi bir aktiviteden
/// sonra 5-15sn yüksek güçlü RRC durumunda kalır, yani sabit 2sn'lik bir
/// ping aralığı, bağlı HERHANGİ bir eş varken radyonun neredeyse HİÇ boşta
/// kalamaması demek. Bu özel protokol, bir bağlantı `KEEPALIVE_STABILIZE_MS`
/// boyunca KESİNTİSİZ sağlıklı kaldıktan SONRA gönderim aralığını
/// `KEEPALIVE_IDLE_INTERVAL_MS`'e genişletir — herhangi bir başarısızlık ya
/// da yeni bir bağlantı aralığı ANINDA `KEEPALIVE_FAST_INTERVAL_MS`'e
/// sıfırlar, yani "az önce kurulmuş, henüz kanıtlanmamış" bir bağlantı hâlâ
/// eskisi kadar sık/hızlı test edilir — canlılık tespiti YAVAŞLAMAZ, sadece
/// zaten kanıtlanmış, sessiz bekleyen bir bağlantı için gereksiz sık
/// prob'lama kesilir.
/// How long a revoked own device keeps its connection, so the revoke notice
/// sent to it is delivered first (`revoke_own_linked_device`).
pub(crate) const REVOKE_DISCONNECT_DELAY_MS: u64 = 30_000;
pub(crate) const KEEPALIVE_FAILURES_BEFORE_DISCONNECT: u32 = 3;
/// See `server_rpc_timeouts`. Any answered request resets the count, so a busy
/// but alive connection (parallel blob chunks) is not dropped.
pub(crate) const SERVER_RPC_TIMEOUTS_BEFORE_DISCONNECT: u32 = 3;
/// Yeni kurulmuş/henüz stabilize OLMAMIŞ bir bağlantı için keepalive
/// gönderim aralığı — eski `ping::Behaviour` aralığıyla AYNI (kullanıcı
/// isteği: "2sn aralıklarla 3 kere ping").
pub(crate) const KEEPALIVE_FAST_INTERVAL_MS: u64 = 2_000;
/// Bir bağlantı `KEEPALIVE_STABILIZE_MS` boyunca kesintisiz sağlıklı
/// kaldıktan SONRA kullanılan genişletilmiş gönderim aralığı — pil
/// tasarrufu (bkz. yukarıdaki sabitin dokümantasyonu).
pub(crate) const KEEPALIVE_IDLE_INTERVAL_MS: u64 = 20_000;
/// Ekran kapalı + uygulama arka plandayken kullanılan keepalive aralığı
/// (bkz. `P2PCore.power_save`). Canlılık tespiti KAYBOLMUYOR — yalnızca
/// zaten kanıtlanmış, sessiz bekleyen bir bağlantı için prob sıklığı
/// düşüyor; herhangi bir başarısızlık ya da yeni bağlantı yine ANINDA
/// `KEEPALIVE_FAST_INTERVAL_MS`'e sıfırlıyor.
pub(crate) const KEEPALIVE_POWER_SAVE_INTERVAL_MS: u64 = 60_000;
/// Bir bağlantının "stabilize" (artık daha seyrek test edilebilir)
/// sayılması için gereken, kesintisiz sağlıklı geçen süre.
pub(crate) const KEEPALIVE_STABILIZE_MS: u64 = 120_000;
/// Tek bir keepalive isteğinin yanıt için beklediği azami süre. Eski
/// `PING_TIMEOUT_SECS`'teki AYNI Tor gerekçesiyle (bu uygulamanın
/// varsayılan taşıması Tor, bkz. `tor.rs` — bir onion-service devresi
/// tipik olarak 6 röle atlaması içerir ve sağlıklı bir devrede bile 2sn'yi
/// aşan gecikme sıra dışı değildir) 6sn olarak ayarlı — 2sn olsaydı ARDIŞIK
/// 3 yavaş-ama-sağlıklı yanıt (`KEEPALIVE_FAILURES_BEFORE_DISCONNECT`) Tor
/// üzerinde makul bir olasılıkla gerçekleşir ve bağlantı GEREKSİZ YERE
/// kapatılıp yeniden kurulmaya zorlanırdı.
/// 6 → 4 sn: o 6 sn'nin ~2 sn'si iki uçtaki poll bekleyişiydi (yanıt ancak
/// bir sonraki `poll_events` turunda işleniyordu). Poll artık olay güdümlü
/// (`wait_for_network_activity`) — Tor üzerinde ölçülen gidiş-dönüş <1 sn.
/// 4 → 10 s: a probe to a phone whose LTE radio sleeps waits for the radio to
/// come up before Tor even starts; 4 s declared live links dead and every
/// "reconnect" cost a full onion circuit build (the churn that kept the 9S
/// radio awake).
pub(crate) const KEEPALIVE_TIMEOUT_SECS: u64 = 10;

/// Radio-saver window (metered network + screen off, see `P2PCore.metered`):
/// every periodic network job — keepalive probes, server sweep, reconnect
/// sweep — runs together once per window, so the cellular radio wakes once
/// per window instead of never sleeping (each packet keeps LTE up ~10 s).
/// Incoming data still arrives at once over the open links and server push;
/// a direct link that died in between is covered by the server path, so the
/// window length mostly trades wakeups against dead-link detection time.
pub(crate) const RADIO_WINDOW_MS: u64 = 8 * 60 * 1000;
/// Window on an unmetered network: a Wi-Fi wakeup has no LTE-style radio tail.
pub(crate) const RADIO_WINDOW_WIFI_MS: u64 = 4 * 60 * 1000;
/// How long Tor stays non-dormant after a full wake, see `TOR_FULL_WAKE_MS`.
pub(crate) const RADIO_AWAKE_MS: u64 = 30_000;
/// In radio-saver mode Tor leaves dormant only this often, not at every
/// window. Leaving dormant re-fires arti's periodic tasks: it refills the
/// onion-service circuit pool (12-16 circuits, ~130 KB) and that kept the LTE
/// radio up ~100 s per window (9S 2026-10-02: 32 % radio, 22 mAh/h). The
/// window's own work (keepalive, server poll, redial) runs on existing
/// circuits and builds what it needs on demand. The consensus is valid 3 h,
/// so a refresh every 45 min keeps it fresh.
pub(crate) const TOR_FULL_WAKE_MS: u64 = 45 * 60 * 1000;
/// bkz. `KeepAliveState.suspect` — canlı bağlantıdan bu sürede Ack gelmezse yokla.
pub(crate) const ACK_SUSPECT_MS: u64 = 1_500;
pub(crate) const KEEPALIVE_PROTOCOL: &str = "/p2pmessenger/keepalive/1.0.0";
/// Advertised (never preferred) so identify tells peers we decode
/// `KeepAliveResponse.quiet_ms`. Older builds expect a unit response and
/// fail every probe on anything else, then drop the link every ~20 s.
pub(crate) const KEEPALIVE_QUIET_PROTOCOL: &str = "/p2pmessenger/keepalive/1.1.0";
/// Ack'lerin taşındığı `request_response` protokolü. Eşle canlı bir libp2p
/// bağlantısı varken Ack'ler ratchet-şifreli `MessageContent::Ack` paketi
/// yerine bununla, eş başına TOPLU gider:
/// - Güvenilir: karşı taraf ancak Ack'leri UYGULADIKTAN sonra yanıt verir;
///   yanıt gelmezse (zaman aşımı, bağlantı koptu, eski sürüm protokolü
///   bilmiyor) aynı Ack'ler şifreli pakete düşer — o da sunucuya bırakılır.
///   "Gönderdim ama ulaştı mı bilmiyorum" durumu yalnızca bağlantısız ve
///   sunucusuz yolda kalır; orada da göndericinin yeniden denemesi +
///   `reack_if_already_handled` telafi eder.
/// - Verimli: Ack başına hibrit imza (Ed25519+ML-DSA) + AEAD + ratchet adımı
///   + gossipsub yayını yerine birkaç bayt; grup fan-out'unun onlarca Ack'i
///   tek istek. Hız sınırına da takılmaz (`file_chunks` gibi).
/// - Kimlik: istekçi Noise ile kanıtlanmış `PeerId`; `device_to_peer_id`
///   yalnızca imzası doğrulanmış paketlerden dolar, yani sahte Ack yok.
pub(crate) const ACK_PROTOCOL: &str = "/p2pmessenger/ack/1.0.0";
/// bkz. `start_network` — bir bağlantının kurulması (dial + Noise + Yamux)
/// için azami süre. libp2p builder'ının sabit 10 sn'si Tor'a yetmiyordu.
pub(crate) const SWARM_CONNECTION_TIMEOUT_SECS: u64 = 60;
/// Direct delivery to a connected device. Before this, a connected device was
/// reached only through gossipsub, which delivers only if it currently knows
/// the peer subscribes to the topic. That knowledge is exchanged only when a
/// peer's first connection opens, so connection churn (Tor/relay/direct paths
/// replacing each other, mobile data) left one side with a live connection but
/// a stale topic list. Publishes then failed with InsufficientPeers and went via
/// the server, 5-16 s (device, 2026-09-18). A request/response goes over the
/// Noise-authenticated connection itself, and the response proves the peer got
/// the bytes. Gossipsub and the server stay as the fallback.
pub(crate) const ENVELOPE_PROTOCOL: &str = "/p2pmessenger/envelope/1.0.0";
/// Largest serialized envelope any path carries.
pub(crate) const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;

/// Swarm events one `poll_events` turn handles in its main drain.
pub(crate) const MAX_SWARM_EVENTS_PER_TURN: u32 = 256;
/// Largest sticker part sent to my other devices inside one `SiblingEcho`
/// (well under `MAX_ENVELOPE_BYTES` and the server's deposit limit); a
/// bigger sticker goes in several parts.
pub(crate) const STICKER_SYNC_MAX_BYTES: usize = 768 * 1024;
/// Most parts of one sticker (`MAX_STICKER_BYTES` / `STICKER_SYNC_MAX_BYTES`, rounded up).
pub(crate) const STICKER_SYNC_MAX_PARTS: usize = 8;
/// Stickers being put together from parts at once; the oldest is dropped.
pub(crate) const STICKER_PARTS_MAX_PENDING: usize = 16;
pub(crate) const ACK_BATCH_MAX: usize = 256;
pub(crate) const ACK_REQUEST_TIMEOUT_SECS: u64 = 30;

/// `known_relay_peers` üst sınırı — spec §4.1'in önerdiği "~10, en son
/// görülen/en güvenilir" ölçeğiyle aynı (bkz. o alanın dokümantasyonu).
pub(crate) const MAX_KNOWN_RELAYS: usize = 10;
/// bkz. `ensure_relay_reservations` — kabul edilmemiş (henüz dinleme adresi
/// gelmemiş) bir rezervasyon bu süre sonunda bırakılıp yeniden istenir.
pub(crate) const RELAY_RESERVATION_RETRY_MS: u64 = 2 * 60 * 1000;

/// yamux akış alma penceresi.
/// Varsayılan (yamux spesifikasyonundaki `DEFAULT_CREDIT`) **262.144 bayt**.
/// Bizim dosya parçamız ise `FILE_CHUNK_SIZE + 16` = **262.160 bayt** — AEAD
/// etiketi yüzünden krediyi tam **16 bayt** aşıyor. Sonuç: her parça, son 16
/// baytını gönderebilmek için karşı taraftan pencere güncellemesi bekliyor,
/// yani parça başına FAZLADAN bir gidiş-dönüş. Tor'da gidiş-dönüş 3-18 sn
/// olduğu için bu, aktarım süresini neredeyse ikiye katlayabilecek bir
/// tesadüf.
/// yamux 0.13'ün otomatik pencere büyütmesi (QUIC benzeri BDP tahmini) bunu
/// kurtarmıyor: `request_response` HER İSTEK İÇİN yeni bir alt-akış açıyor,
/// akış tek parça taşıyıp kapanıyor, dolayısıyla otomatik ayar hiç devreye
/// girmiyor — her parça sıfırdan 256 KiB ile başlıyor.
/// Bu yüzden sabit ve bol bir başlangıç penceresi veriyoruz. (Bunu ayarlamak
/// libp2p sarmalayıcısında yamux 0.12 yoluna geçiyor, yani otomatik ayardan
/// vazgeçiyoruz — bizim erişim deseninde zaten hiçbir işe yaramıyordu.)
pub(crate) const YAMUX_RECEIVE_WINDOW: u32 = 4 * 1024 * 1024;
/// Alt-akış başına tampon tavanı — pencereden küçük olmamalı.
pub(crate) const YAMUX_MAX_BUFFER: usize = 8 * 1024 * 1024;

/// bkz. `YAMUX_RECEIVE_WINDOW`.
pub(crate) fn tuned_yamux() -> yamux::Config {
    let mut cfg = yamux::Config::default();
    #[allow(deprecated)]
    {
        cfg.set_receive_window_size(YAMUX_RECEIVE_WINDOW);
        cfg.set_max_buffer_size(YAMUX_MAX_BUFFER);
    }
    cfg
}


/// Bir eşle paralel aktarımın sağlık durumu — bkz. `manage_bulk_connections`
/// ve `note_bulk_timeout`.
#[derive(Default, Debug)]
pub(crate) struct BulkHealth {
    /// Son zaman aşımlarının anları (yalnızca `BULK_STRIKE_WINDOW_MS`
    /// içindekiler tutulur).
    pub(crate) strikes: Vec<u64>,
    /// Bir sonraki fazladan dial'ın en erken zamanı.
    pub(crate) next_dial_at: u64,
    /// Şu anki yeniden deneme beklemesi (her düşürmede ikiye katlanır).
    pub(crate) backoff_ms: u64,
    /// Kaç kez devre düşürüldü.
    pub(crate) drops: u32,
    /// Paralellikten vazgeçildiyse, ne zamana kadar.
    pub(crate) giveup_until: u64,
}

/// Toplu aktarım (dosya parçaları) sürerken bir eşe açık tutulacak libp2p
/// bağlantısı sayısı.
/// Neden: `request_response` giden istekleri açık bağlantılara ZATEN
/// dağıtıyor (`libp2p-request-response`: `ix = request_id % connections.len()`),
/// ve `ArtiDialTransport` artık her bağlantıya ayrı Tor devresi veriyor.
/// İkisi birleşince parça boru hattı birden çok devreye yayılıyor — tek bir
/// Tor devresinin bant genişliği bu uygulamada ölçülen gerçek tavandı.
/// Yalnızca aktarım SÜRERKEN açılır ve bitince kapatılır: onion devresi
/// kurmak pahalı (~5-15 sn) ve boşta duran fazladan devre hem Tor ağına hem
/// pile yük.
/// Sayı ÖLÇÜMLE seçildi. Aynı ~14 MB'lık dosya, aynı çift, dönüşümlü
/// (varyantlar sırayla kurulup çalıştırıldı, böylece ikisi de aynı ağ
/// koşullarını gördü), süre karşı tarafın diskinden okundu:
///   1 bağlantı → medyan  46 KB/s (n=5, aralık 23-182)
///   3 bağlantı → medyan  90 KB/s (n=7, aralık 51-204)
///   6 bağlantı → medyan 150 KB/s (n=3, aralık 64-173)
/// 1 → 3 farkı yönü tutarlı ve mekanizmayla uyumlu: tek devrede hız o
/// devrenin kalitesine rehin (dağılım iki uçlu: ya 169-182 ya 23-46),
/// paralelde kötü devre diğerleriyle seyreliyor.
/// 3 → 6 farkı ise İSTATİSTİKSEL OLARAK GÖSTERİLEMEDİ: 6, dokuz eşleşmenin
/// beşinde önde, aralıklar büyük ölçüde örtüşüyor. Ölçülebilir bir kazanç
/// olmadığı için 3'te kalıyoruz — 6 devre, aynı transfer için Tor ağına ve
/// (hem gönderen hem alan telefonun) piline iki katı yük demek.
/// DÜZELTME: burada bir ara "5 bağlantı çok daha kötü, pencere sürekli 2'ye
/// çöküyor" yazıyordu. O ölçüm ölü-devre kurtarması EKLENMEDEN ÖNCEKİ
/// derlemeye aitti ve dial aralığı 12 sn olduğu için altı devreyi kurmak
/// transferin ilk dakikasını yiyordu; sağlamlaştırılmış derlemede o çöküş
/// tekrarlanmadı. Yanlış gerekçeyi kodda bırakmamak için not düşüldü.
pub(crate) const BULK_PARALLEL_CONNECTIONS: usize = 3;
/// Aynı eşe fazladan bağlantı denemeleri arasındaki TABAN süre — dial
/// havadayken üst üste yenilerini açmamak için. Her başarısızlıkta ikiye
/// katlanır (bkz. `BulkHealth.backoff_ms`).
pub(crate) const BULK_DIAL_MIN_INTERVAL_MS: u64 = 6_000;
/// Yeniden deneme beklemesinin tavanı.
pub(crate) const BULK_DIAL_MAX_BACKOFF_MS: u64 = 120_000;
/// Bu kadar süre içinde bu kadar zaman aşımı görülürse bir devre düşürülür.
/// Tek bir zaman aşımı Tor'da NORMAL — eski kurtarma kodu ilk zaman aşımında
/// üç devrenin üçünü birden atıyordu, yani bir kez öksüren yola ceza olarak
/// sağlam iki devre de gidiyordu. Bir sağlıklı devrenin ölümünü gürültüden
/// ayırt etmenin yolu tek olayda değil, PENCERE içindeki sayıda.
pub(crate) const BULK_STRIKE_WINDOW_MS: u64 = 60_000;
pub(crate) const BULK_STRIKES_TO_DROP: usize = 3;
/// Bu kadar düşürmeden sonra bu aktarım için paralellik tamamen bırakılır:
/// yol kalıcı olarak kötüyse devre açıp kapamak (her biri ~5-15 sn ve
/// kurulum sırasında veri trafiğiyle yarışıyor) durumu İYİLEŞTİRMİYOR,
/// kötüleştiriyor. Tek devreye çekilip sakin ilerlemek daha hızlı bitiriyor.
pub(crate) const BULK_MAX_DROPS_BEFORE_GIVEUP: u32 = 3;
/// Paralellikten vazgeçildikten sonra yeniden denemeden önceki bekleme.
pub(crate) const BULK_GIVEUP_COOLDOWN_MS: u64 = 300_000;

/// `contacts` tablosu üst sınırı.
/// `evaluate_sender_device`'in `NewContactTofu` kolu (bkz. o fonksiyonun
/// dokümantasyonu), spec 2.2'nin gerektirdiği gibi, hem kullanıcının
/// kendi başlattığı QR/manuel eşleşmede HEM DE tek taraflı bir `IdentityExchange`
/// paketinin (mailbox topic'ine, `p2p_msg_<own_fingerprint>`, HER ZAMAN
/// abone olunduğu için) sürpriz bir şekilde gelmesinde aynı şekilde
/// tetiklenir — bu ikincisi, karşı tarafın kullanıcının hiçbir yerel eylemi
/// (QR tarama/manuel giriş) OLMADAN sadece fingerprint'i biliyor olması
/// (ör. ortak bir grup, DHT/Node modu, ya da paylaşılan bir röle listesi
/// yoluyla öğrenilmiş) yeterlidir. Tek taraflı QR akışının çalışması için
/// bu davranış KASITLI olarak korunuyor (bkz. spec 1.3 "tek taraflı taranan
/// QR" notu) — ama sınırsız bırakılırsa, taze kimlik üretmesi bedava olan
/// bir saldırgan bu yolla sınırsız sayıda "kişi" kaydı oluşturup hem
/// bellek/disk (her kayıt SQLite'a da yazılır) hem de kullanıcının kişi
/// listesini kirletebilir (Sybil/flood). Bu üst sınıra ulaşılınca YENİ
/// (daha önce hiç görülmemiş bir identity_id'den gelen) TOFU kayıtları
/// sessizce reddedilir — zaten bilinen kişilerin ek cihazları (spec 2.2
/// "NewDeviceViaSignedAdd"/"UnverifiedNewDeviceAlert" kolları) bundan
/// ETKİLENMEZ, sadece TAMAMEN YENİ kişi eklenmesi durur. 500, gerçekçi
/// hiçbir kullanım biçiminin (arkadaş grubu ölçeğinde, spec §7.1'deki
/// hedef kitle) yaklaşmayacağı ama saldırganın maliyetini anlamlı şekilde
/// sınırlayan cömert bir tavan.
pub(crate) const MAX_CONTACTS: usize = 500;

/// Bir cihaza karşılıklı `IdentityExchange` yanıtı verme sıklığının tavanı —
/// bkz. `P2PCore.last_identity_exchange_reply`.
pub(crate) const IDENTITY_EXCHANGE_REPLY_MIN_INTERVAL_MS: u64 = 60_000;

/// Spec dışı, dış inceleme düzeltmesi ("bilinen/güvenilir bir cihaz saniyede
/// onlarca mesaj göndererek CPU/pil/disk tüketebilir — hiçbir hız sınırı
/// yoktu"): `MAX_CONTACTS`/`MAX_EARLY_PACKETS_PER_PEER`/vb. gibi mevcut
/// sınırların HİÇBİRİ zaten TANIDIK bir cihazın mesaj SIKLIĞINI
/// sınırlamıyordu — sadece bellek büyümesini. Bu, gerçek/imzalı bir
/// bağlantıdan (ör. ele geçirilmiş bir cihaz) gelen sürekli, geçerli
/// görünümlü `Text`/`Handshake`/`IdentityExchange` trafiğinin CPU (ratchet
/// decrypt + hibrit imza doğrulama), disk (arşiv yazımı) ve pil tüketimini
/// zorlamasına karşı SON bir kontrol katmanı. `RATE_LIMIT_MAX_PER_WINDOW`,
/// normal (hızlı yazan biri, art arda ekler, grup fan-out'u) kullanımın
/// rahatça altında kalacak kadar cömert (6 paket/sn sürekliyse bile 10sn'de
/// 60'a ancak değer) ama gerçek bir flood'u anlamlı şekilde kısar.
pub(crate) const RATE_LIMIT_WINDOW_MS: u64 = 10_000;
pub(crate) const RATE_LIMIT_MAX_PER_WINDOW: u32 = 60;
/// all non-established peers together, per `RATE_LIMIT_WINDOW_MS`.
pub(crate) const RATE_LIMIT_MAX_UNKNOWN_TOTAL: u32 = 300;

/// Kurulmuş bir oturumu OLAN eşler için pencere başına tavan.
/// Teslim garantisi düzeltmesi (2026-08-28, kullanıcı isteği "her mesajın
/// alındığından emin ol"): eski hâlde tanıdık/yabancı ayrımı yoktu ve
/// tavanı aşan paket SESSİZCE ATILIYORDU. Bu, P2P modunda gerçek bir kayıp
/// deseni üretiyordu: bir hafta kapalı kalmış bir eş geri döndüğünde
/// birikmiş yüzlerce mesajı arka arkaya yayınlıyor, biz saniyede 6 tanesini
/// alıp gerisini atıyorduk. Kaybolmuyorlardı (gönderenin onay bekleme
/// döngüsü yeniden deniyor) ama 5 sn'den 2 dk'ya çıkan geri çekilmeyle
/// saatlere yayılıyordu. SUNUCU modunda ise aynı paketler `source = None`
/// ile enjekte edildiğinden hız sınırına HİÇ takılmıyordu — yani iki mod
/// arasında, tam da kullanıcının sorduğu asimetri vardı.
/// Artık iki şey birden yapılıyor: kurulmuş oturumu olan eşe çok daha
/// yüksek bir tavan (60/sn) veriliyor VE tavanı aşan paket atılmıyor,
/// ERTELENİYOR (bkz. `deferred_incoming`).
pub(crate) const RATE_LIMIT_MAX_ESTABLISHED: u32 = 600;

/// Ertelenmiş gelen paket kuyruğunun üst sınırı — bellek koruması. Dolarsa
/// EN ESKİ girdi düşer (gönderen onu zaten yeniden deneyecek).
pub(crate) const MAX_DEFERRED_INCOMING: usize = 2000;

/// bkz. `rate_verdict` — hız sınırının üç sonucu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RateVerdict {
    /// Şimdi işle.
    Allow,
    /// Tavan aşıldı ama gönderen KİMLİĞİ DOĞRULANMIŞ bir eş: atma, sıraya
    /// al, bir sonraki turda işle.
    Defer,
    /// Tavan aşıldı ve gönderen tanınmıyor — bu, imza doğrulama maliyetine
    /// karşı asıl korumamız, paket düşer.
    Drop,
}

/// `pending_device_alerts` üst
/// sınırı — `known_relay_peers`/`early_packets` ile aynı desen. Önceden
/// bu `HashMap` sınırsızdı; bilinen bir kişinin identity_id'sini taklit
/// eden (ama imzalı bir DeviceAdd zinciri OLMAYAN) bir saldırgan, farklı
/// taze cihaz anahtarlarıyla tekrar tekrar "yeni cihaz" paketleri
/// göndererek burayı sınırsız büyütebilirdi (bellek/disk tükenmesi —
/// kullanıcı hiçbir uyarıyı kabul/red ETMESE bile). Tavana ulaşılınca
/// yeni uyarılar sessizce düşürülür (kullanıcının zaten onlarca bekleyen
/// uyarısı varsa, bir tane daha göstermemenin güvenlik açısından bir
/// bedeli yok — paket zaten spec 2.2 gereği BLOKLANMIŞ durumda kalır).
pub(crate) const MAX_PENDING_DEVICE_ALERTS: usize = 200;

/// `reconnect_sweep` bu aralıkta bir
/// çalışır (kendini iyileştiren yeniden-bağlanma). `poll_events` zaten
/// düzenli olarak çağrıldığından ayrı bir zamanlayıcıya
/// gerek yok — sadece bu aralık dolduğunda tarama yapılır. 15 sn: kopmuş
/// bir kişiye makul hızda yeniden bağlanır ama gereksiz dial trafiği
/// üretmez.
pub(crate) const RECONNECT_SWEEP_INTERVAL_MS: u64 = 15_000;
/// bkz. `P2PCore.fast_reconnect_until`.
pub(crate) const FAST_RECONNECT_INTERVAL_MS: u64 = 3_000;
pub(crate) const FAST_RECONNECT_WINDOW_MS: u64 = 60_000;
/// network callbacks closer than this are coalesced into one redial
/// round (flapping LTE/Wi-Fi redialed every contact on every callback).
pub(crate) const NETWORK_CHANGE_DEBOUNCE_MS: u64 = 10_000;

/// "aynı hesaba bağlı cihazlar arası
/// aktarım çok sıkıntılı ... mesajlar gitmiyor bazılarında"; gerçek cihaz
/// bulgusu — hem tablet hem Redmi Note 8 Pro'da AYNI 2-3 "hayalet" kardeş
/// cihaz hedefine ait yüzlerce satır birikmiş bulundu, `last_seen` 3+ gün
/// öncesine ait): bir hedef bu kadar süredir HİÇ görülmediyse artık
/// "muhtemelen kalıcı olarak gitmiş" (uygulama kaldırıldı/cihaz sıfırlandı
/// vb.) sayılır. `sibling_active_devices` bundan sonra bu hedefi YENİ
/// senkron trafiğine dahil etmez (bkz. orada) ve
/// `load_pending_durable_retries_from_db` açılışta ona yeniden göndermeyi
/// DENEMEZ (bkz. orada) — ikisi de mevcut `known_remote_devices`/
/// `pending_durable_retries` satırlarını SİLMEZ, sadece boşuna deneme
/// fırtınasını durdurur; cihaz günün birinde gerçekten geri dönüp
/// `last_seen` tazelenirse bir sonraki turda normal şekilde devam eder.
pub(crate) const STALE_PEER_RETRY_HORIZON_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// Çoklu-cihaz (spec 1.7): kardeşlerden geçmiş geri-doldurma isteklerinin
/// asgari aralığı — her kişi/grup için son N mesajı tekrar tekrar istemek
/// (tekrarlar zaten `message_id` ile eleniyor) israf olmasın diye.
pub(crate) const SIBLING_BACKFILL_INTERVAL_MS: u64 = 30 * 60_000;
/// the backfill watermark is the requester's clock, the filter the
/// responder's; this much skew between own devices still loses nothing.
pub(crate) const SIBLING_BACKFILL_SINCE_MARGIN_MS: u64 = 10 * 60_000;
/// Geri-doldurmada kişi/grup başına istenecek/gönderilecek azami mesaj.
pub(crate) const SIBLING_BACKFILL_PER_CONVERSATION: u32 = 30;
/// Çoklu-cihaz kendini-onarma: kardeş cihazlara cihaz listesini (roster)
/// yeniden gönderme aralığı.
/// GEREKÇE (gerçek arıza): `handle_handshake_init` GÖNDERİCİYİ tanımıyorsa
/// paketi reddeder ("Unknown sender device") — yani B cihazı C cihazını hiç
/// öğrenmediyse ikisi ARASINDA hiçbir zaman oturum kurulamaz, dolayısıyla C
/// kendini B'ye tanıtamaz da. Bu asimetriyi ancak İKİSİNİ DE tanıyan üçüncü
/// bir cihaz (ör. bağlamayı yapan birincil) kırabilir. Tek duyuru anı
/// (bağlama sırasındaki `DeviceSync`) kaçırılırsa — ki tam olarak bu
/// oluyordu, bkz. `regen_content` notu — kurtaran HİÇBİR mekanizma yoktu ve
/// 3+ cihazlı kurulum kalıcı olarak yarım kalıyordu. Artık bir kardeşle
/// bağlantı KURULDUĞUNDA roster yeniden gönderiliyor (bu debounce ile
/// seyreltilerek). Yük düşük: `build_sync_payload` avatarları KASITLI olarak
/// dışarıda bırakıyor (bkz. o fonksiyon), geriye anahtarlar/adlar kalıyor.
pub(crate) const SIBLING_ROSTER_SYNC_INTERVAL_MS: u64 = 60 * 60 * 1000;
/// Bir `SiblingHistoryResponse`'ta taşınacak azami toplam kayıt (gossipsub
/// 1MB sınırının çok altında kalmak için — bkz. `start_network`
/// `max_transmit_size`).
pub(crate) const SIBLING_BACKFILL_MAX_ENTRIES: usize = 300;

/// Güvenilirlik düzeltmesi (MessageTooLarge — bkz. `PublishFailure`):
/// bir `HistorySyncResponse`/`SiblingHistoryResponse`'un toplam METİN yükü
/// bu baytı aşamaz — satır sayısı sınırı tek başına yetmiyordu (tek tek
/// mesaj metinleri sınırsız uzunlukta olabilir, 300 uzun mesaj gossipsub'un
/// 1MB `max_transmit_size` sınırını rahatça aşar; zarfın hibrit imza/
/// ratchet ek yükü de üstüne biner). 512KB, 1MB sınırına bol pay bırakır;
/// kırpılan kısım sayfalama ile sonradan çekilir.
pub(crate) const HISTORY_SYNC_MAX_TEXT_BYTES: usize = 512 * 1024;
/// bkz. `HISTORY_SYNC_MAX_TEXT_BYTES` — istekteki `limit` alanı karşı taraf
/// kontrolünde olduğundan satır sayısı da ayrıca sınırlanır.
pub(crate) const HISTORY_SYNC_MAX_MESSAGES: u32 = 200;

/// One "Fetch older history" press asks every source for this span: the
/// window `[cursor - HISTORY_FETCH_WINDOW_MS, cursor)` by send time.
pub(crate) const HISTORY_FETCH_WINDOW_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// Follow-up pages one press may ask for when a source cut its answer
/// (`more`), over all sources of the chat: the rest of the window comes
/// within the same press, and a peer cannot keep us asking for ever.
/// ponytail: shared by all sources; a busy group month with many capped
/// members can run out. Per-source budgets if that ever shows.
pub(crate) const HISTORY_FETCH_MAX_PAGES: u32 = 20;
/// No message is older (2025-01-01 UTC): the first cursor of a chat ignores
/// rows stamped before it (a 1970 device clock, a backdated row).
pub(crate) const HISTORY_FETCH_EPOCH_MS: i64 = 1_735_689_600_000;

/// `reconnect_sweep`, bekleyen bir
/// cihaz bağlama hedefi (`pending_link_target`) için her taramada (≤15sn)
/// dial + `IdentityExchange` yeniden gönderimi yapar — bağlama HİÇ
/// tamamlanmazsa (kullanıcı QR'ı okutup vazgeçti, cihazlar bir daha hiç
/// buluşmadı) bu süresiz bir radyo/trafik sızıntısıydı (süreç yeniden
/// başlayana kadar). Bu ufkun ötesinde otomatik denemeler durur — kullanıcı
/// bağlamayı gerçekten istiyorsa QR'ı yeniden okutur (bu alanı tazeler).
pub(crate) const PENDING_LINK_RETRY_HORIZON_MS: u64 = 60 * 60 * 1000;

/// bkz. `reconnect_backoff` alan dokümantasyonu — ardışık başarısız
/// otomatik-yeniden-bağlanma denemesi başına üstel geri çekilme:
/// 15sn, 30sn, 60sn, ... `RECONNECT_BACKOFF_MAX_MS`'te tavan yapar. İlk
/// birkaç deneme hâlâ hızlı (geçici bir ağ blip'i saniyeler içinde
/// düzelir), ama kalıcı olarak ulaşılamayan bir kişi giderek seyrekleşen
/// denemelere düşer.
pub(crate) const RECONNECT_BACKOFF_BASE_MS: u64 = RECONNECT_SWEEP_INTERVAL_MS;
pub(crate) const RECONNECT_BACKOFF_MAX_MS: u64 = 10 * 60 * 1000;
/// Radio saver cap: every failed onion dial burns hs-pool circuits (HsDir
/// lookups) and the pool refills itself in the background, so a long-gone
/// peer must not be retried every window. It reconnects to us when back.
/// 3 h: at 30 min, four long-offline peers cost 270-410 KB and 40-75 s of
/// LTE radio per round (pcap 2026-10-07).
pub(crate) const RECONNECT_BACKOFF_SAVER_MAX_MS: u64 = 3 * 60 * 60 * 1000;

/// Spec dışı, hata düzeltmesi ("Tor üzerinden bağlı bir cihaz gruba davet
/// edilmesine rağmen grubu hiç görmüyor"): `group_sync_sweep`'in çalışma
/// aralığı — bkz. `pending_group_syncs` dokümantasyonu.
pub(crate) const GROUP_SYNC_SWEEP_INTERVAL_MS: u64 = 20_000;
/// Outside radio saver, a network change force-dials a device heard from
/// within this long (`last_seen` is stamped at most hourly).
pub(crate) const NETWORK_CHANGE_FORCE_SEEN_MS: u64 = 2 * 60 * 60 * 1000;
/// An unchanged own address is announced to contacts again after this long.
pub(crate) const ADDRESS_REANNOUNCE_MS: u64 = 24 * 60 * 60 * 1000;
/// How long a parked per-device copy waits before `group_sync_sweep` resends it.
pub(crate) const DURABLE_PARK_RELOAD_MS: u64 = 60_000;

/// Spec dışı, kullanıcı isteği: `enforce_history_storage_limit`'in periyodik
/// öz-iyileşme taraması aralığı (bkz. `last_storage_sweep_at`) — bu, her
/// dosya tamamlandığında zaten çağrılan anlık kontrole EK bir güvenlik
/// ağıdır (ör. kullanıcı sınırı düşürdüğünde mevcut birikmiş dosyaların da
/// budanması için). Her `poll_events` turunda tam bir SQL
/// SUM sorgusu çalıştırmaktan kaçınmak için makul bir aralıkla sınırlı.
pub(crate) const HISTORY_STORAGE_SWEEP_INTERVAL_MS: u64 = 30_000;

/// gossipsub SIRA GARANTİSİ VERMEZ — bir sohbetin İLK mesajı, onu mümkün kılan
/// `HandshakeInit`'ten ÖNCE varabilir. Önceden bu durumda `receive_message`
/// "No ratchet session for sender" ile hata verip paketi ATIYORDU; DM'de
/// ack-retry eninde sonunda kurtarıyordu ama GRUP mesajlarında retry
/// olmadığı için mesaj KALICI olarak kayboluyordu. Artık böyle paketler
/// burada tamponlanıp el sıkışma tamamlanınca yeniden oynatılıyor.
/// Tampon sınırlıdır (bellek/DoS koruması): peer başına en fazla
/// `MAX_EARLY_PACKETS_PER_PEER`, ve `EARLY_PACKET_TTL_MS`'ten eski girdiler
/// budanır.
/// bu süre önceden sabit 120 sn'ydi
/// ve `EARLY_EDIT_DELETE_TTL_MS`'in (aynı gerekçeyle zaten
/// `MAX_UNCONFIRMED_AGE_MS`'e çekilmiş olan) yanında tutarsız kalıyordu.
/// Tamponun anlamlı olduğu süre, "gönderenin AYNI mesajı hâlâ yeniden
/// denediği" süreyle aynı olmalı: el sıkışma 120 sn'den geç varırsa (yavaş
/// bir Tor devresi, kuyruğa düşmüş bir `HandshakeInit`, ya da sunucudan
/// toplu çekilen bir birikinti) tampon sessizce boşaltılıyor ve o tur
/// için mesajlar düşüyordu. BELLEK TAVANI DEĞİŞMİYOR — sınır zaten
/// süreden değil `MAX_EARLY_PACKETS_PER_PEER` sayısından geliyor.
pub(crate) const EARLY_PACKET_TTL_MS: u64 = MAX_UNCONFIRMED_AGE_MS;
/// bkz. `P2PCore.unknown_group_held`: how long, for how many groups, and how
/// many packets per group content for a group we do not hold is kept.
pub(crate) const UNKNOWN_GROUP_HOLD_TTL_MS: u64 = 30 * 60_000;
pub(crate) const UNKNOWN_GROUP_HOLD_GROUPS: usize = 16;
pub(crate) const UNKNOWN_GROUP_HOLD_PER_GROUP: usize = 64;
/// Teslim garantisi düzeltmesi (2026-08-28): 20'den 200'e çıkarıldı.
/// Bu tampon, el sıkışmadan ÖNCE gelen paketleri tutuyor. 20, tam da en
/// çok gerektiği senaryoda yetersizdi: uzun süre kapalı kalmış bir eş geri
/// döndüğünde birikmiş onlarca mesajını arka arkaya yolluyor ve el sıkışma
/// bunların arasında/sonrasında varabiliyor — 20'yi aşanlar en eskiden
/// başlayarak düşüyordu. Kalıcı kayıp değildi (gönderen yeniden dener) ama
/// tam olarak kaçınmak istediğimiz yavaş, dalgalı teslim deseniydi.
/// `MAX_PENDING_GROUP_MESSAGES_PER_MEMBER` ile aynı büyüklük; sınır zaten
/// SAYIDA, tek tek mesajlar küçük.
pub(crate) const MAX_EARLY_PACKETS_PER_PEER: usize = 200;

/// Spec dışı, hata düzeltmesi ("hızlı arka arkaya gönder-düzenle/sil,
/// düzenleme/silme kayboluyor"): gossipsub mesaj SIRASI garanti etmez
/// (bkz. yukarıdaki KNOWN GAP notu) — bir `Edit`/`Delete` paketi, hedefi
/// olan `Text`'ten ÖNCE karşı tarafa ulaşabilir. Önceden bu durumda hedef
/// satır arşivde bulunamadığından `message_owned_by_sender` `false`
/// dönüyordu ve paket Ack'lenip KALICI olarak "rejected" sayılıyordu —
/// `Text` daha sonra gelse bile düzenleme/silme bir daha asla
/// uygulanmıyordu. Artık bu durumda (satır HİÇ yoksa, sahibi başkasına ait
/// OLDUĞU için değil) paket burada tamponlanır ve hedef `Text` arşivlenince
/// yeniden denenir — bkz. `pending_edits_deletes`/`replay_buffered_edits_deletes`.
/// bu süre önceden `EARLY_PACKET_TTL_MS`
/// ile AYNI, sabit 120sn'ydi — bağımsız bir incelemenin haklı olarak
/// belirttiği gibi, hedef `Text` bundan geç gelirse (aşırı yavaş bir Tor
/// devresi, ya da göndericinin cihazı uykuda) tampon SESSİZCE silinip
/// düzenleme/silme o an için kaybolurdu. Bu KALICI bir kayıp DEĞİL —
/// orijinal göndericinin kendi `awaiting_confirmation` döngüsü Ack
/// gelmediği için AYNI Edit/Delete'i tekrar gönderir (üstel aralıkla,
/// `MAX_UNCONFIRMED_AGE_MS`'e kadar) ve her yeni deneme tamponu SIFIRDAN
/// başlatır — ama süre `MAX_UNCONFIRMED_AGE_MS`'ten KISA olduğu için
/// gereksiz yere erken/sık "sessizce at, bir sonraki denemeyi bekle"
/// döngüsüne giriyordu. Artık `MAX_UNCONFIRMED_AGE_MS` ile AYNI (ratchet
/// rotasyon penceresiyle hizalı) — bu pencereden sonra zaten Text'in
/// KENDİSİ de taze bir ciphertext'le yeniden şifrelenip gönderiliyor
/// (bkz. `regen_content`), yani tampon ile "asıl mesajın hâlâ anlamlı
/// sayıldığı" süre artık TUTARLI.
pub(crate) const EARLY_EDIT_DELETE_TTL_MS: u64 = MAX_UNCONFIRMED_AGE_MS;
pub(crate) const MAX_EARLY_EDITS_DELETES_PER_TARGET: usize = 8;

/// bkz. `pending_group_messages` alanı dokümantasyonu — bir grup üyesi
/// için, o üye çözülene kadar birikebilecek en fazla kuyruklanmış mesaj
/// sayısı (en eskisi atılır) — bellek koruması.
pub(crate) const MAX_PENDING_GROUP_MESSAGES_PER_MEMBER: usize = 200;

/// Spec dışı, kullanıcı isteği (Tor): Tor açıkken libp2p SABİT bir TCP portu
/// dinler — onion service köprüsü (`bridge_incoming_stream`) gelen Tor
/// akışlarını `127.0.0.1:<bu port>`'a yönlendirdiği için sabit ve önceden
/// bilinen bir port gerekir. Tor kapalıyken eskisi gibi rastgele port (0)
/// kullanılır.
pub(crate) const TOR_LIBP2P_PORT: u16 = 42611;

/// bir `HandshakeInit`'in
/// `timestamp`'i, o an ile bu kadar milisaniyeden fazla sapıyorsa (ileri
/// VEYA geri) reddedilir — çok eski yakalanmış el sıkışmaların tekrar
/// oynatılmasını engellerken, cihazlar arası makul saat kaymasına (clock
/// skew) tolerans gösterir. 10 dakika: iki telefonun saatleri arasında
/// gerçek dünyada beklenenden bol bir pencere, ama sınırsız değil.
pub(crate) const HANDSHAKE_MAX_SKEW_MS: u64 = 10 * 60 * 1000;
/// How old an init may be: as long as a message is retried, since the server
/// mailbox holds the init for a peer that is off.
pub(crate) const HANDSHAKE_MAX_AGE_MS: u64 = TEXT_RETRY_GIVE_UP_MS;
/// Two inits created this close together (by their own timestamps, not by when
/// they arrive) are one simultaneous handshake. See `process_handshake_init`.
/// Colliding inits are created seconds apart. A real re-handshake comes much
/// later (redo after 25 min).
pub(crate) const HANDSHAKE_COLLISION_WINDOW_MS: u64 = 90 * 1000;
/// See `note_undecryptable`.
pub(crate) const UNDECRYPTABLE_BEFORE_REHANDSHAKE: u32 = 3;
pub(crate) const UNDECRYPTABLE_WINDOW_MS: u64 = 2 * 60 * 1000;
pub(crate) const UNDECRYPTABLE_REDO_MIN_INTERVAL_MS: u64 = 2 * 60 * 1000;

/// Spec dışı, kullanıcı isteği (bkz. SECURITY.md "Cross-network
/// connectivity" notu): manuel röle adresi girişi hâlâ Ayarlar'da mevcut
/// ve kaldırılmadı, ama sıfırdan hiç ortak röle geçmişi olmayan iki
/// YABANCI'nın (ör. farklı ağlardaki iki yeni kullanıcı) hiçbir elle
/// yapılandırma OLMADAN eşleşebilmesi için burada, uygulamaya GÖMÜLÜ
/// varsayılan bir bootstrap röle listesi tutuluyor — tıpkı IPFS/BitTorrent
/// istemcilerinin gömülü varsayılan bootstrap node'ları gibi. `start_network`
/// içinde, her biri Ayarlar'daki manuel ekleme ile AYNI fonksiyon
/// (`add_known_relay_address`) ile eklenir.
/// KURULUM NOTU: bu liste kasıtlı olarak BOŞ başlıyor — buraya rastgele/
/// var olmayan bir adres koymak sessizce başarısız dial denemelerine yol
/// açar. Kendi (veya güvendiğiniz birinin) Node modu açık, herkese açık bir
/// IP'de çalışan bir Typeon kopyasını kurduktan sonra, o cihazın
/// `getNodeAddress()`'inin döndürdüğü tam onion adresini (ör.
/// "/dns/<host>.onion/tcp/<port>/p2p/12D3Koo...") buraya bir dize olarak ekleyin.
/// Yeniden derleme gerektirir — kullanıcılar yine de Ayarlar'dan kendi
/// bildikleri ek röleleri manuel olarak eklemeye devam edebilir, bu liste
/// onun YERİNE değil, İLK KURULUMDA hiç adres bilmeyen biri için bir
/// başlangıç noktası.
pub(crate) const DEFAULT_BOOTSTRAP_RELAYS: &[&str] = &[
    // "/ip4/1.2.3.4/tcp/4001/p2p/12D3KooWExampleReplaceWithRealAddress",
];

/// Spec dışı, kullanıcı tarafından istenen güvenilir teslim: `Text`
/// (grup DIŞI)/`Edit`/`Delete`/`HistorySyncRequest` içerikli paketler,
/// karşı taraftan bir `Ack` (veya HistorySyncRequest için doğrudan
/// `HistorySyncResponse`) alınana kadar bu aralıklarla tekrar tekrar
/// gönderilir — üstel geri çekilme (exponential backoff), `MAX` ile
/// sınırlı. `gossipsub.publish()`'in yerel başarısı, karşı tarafın
/// GERÇEKTEN aldığının garantisi DEĞİLDİR (bkz. `awaiting_confirmation`
/// alanı dokümantasyonu) — bu yüzden eski `pending_envelopes` kuyruğunun
/// aksine burada bir üst zaman sınırı YOK, kullanıcı açıkça "karşı taraf
/// onaylayana kadar sürekli dene" istedi.
pub(crate) const ACK_RETRY_INITIAL_MS: u64 = 15_000;
pub(crate) const ACK_RETRY_MAX_MS: u64 = 120_000;
/// `recently_acked` üst sınırı. Ack/Seen bir kez gönderilir (önceden koşulsuz
/// 9 kez, ~10.6 dk); kaybolan bir Ack'i göndericinin kendi yeniden denemesi
/// telafi eder — alıcı o kopyayı çözemese bile bu haritada bulup Ack'i
/// yeniden yollar (bkz. `reack_if_already_handled`). Pencere, göndericinin
/// aynı ciphertext'i denediği süreyle (`MAX_UNCONFIRMED_AGE_MS`) aynı;
/// sonrasında gönderen zaten taze şifreleyip yolluyor.
pub(crate) const RECENTLY_ACKED_MAX_ENTRIES: usize = 8192;
/// KRİTİK: bir paket belirli bir ratchet zincir adımına karşı şifrelendi
/// (bkz. `PendingConfirmation.envelope` notu — yeniden şifrelenmeden
/// AYNEN tekrar gönderilir). Karşı taraf o adımı zaten TÜKETTİYSE
/// (normal akış) VE bu peer'le olan oturumda spec 3.2'nin 30 dakikalık
/// DH/KEM rotasyonu bir kez daha gerçekleştiyse (bkz.
/// `ratchet::RATCHET_ROTATION_MS`), alıcının o eski zincire ait
/// skipped-key önbelleği TAMAMEN TEMİZLENİR (`perform_dh_ratchet`/
/// `respond_to_rotation`, forward secrecy'nin istenen/doğru bir sonucu).
/// Bu noktadan sonra o paket ARTIK ASLA çözülemez — "onaylanana kadar
/// sürekli dene" artık kriptografik olarak İMKANSIZ bir şeyi
/// denemektir, sadece alıcıya sonsuza dek "Decryption failed"/
/// "skipped-key cache'te yok" hatası ürettirir (gerçek arıza deseni —
/// uzun bir test oturumunda BİRDEN FAZLA farklı mesajın aynı anda bu
/// duruma düşmesi gözlemlendi). Bu yüzden `awaiting_confirmation`
/// SÜRESİZ değil — rotasyon penceresinin biraz altında (güvenlik payı
/// ile) bir üst yaş sınırı var; aşılırsa paket "Failed" sayılıp
/// bırakılır (kullanıcı isterse manuel olarak yeni bir mesaj olarak
/// tekrar gönderebilir).
pub(crate) const MAX_UNCONFIRMED_AGE_MS: u64 = ratchet::RATCHET_ROTATION_MS - 5 * 60 * 1000;

/// Spec dışı, kullanıcı isteği: sıradan `Text` mesajları (1:1 VE grup fan-out
/// kopyaları) artık `MAX_UNCONFIRMED_AGE_MS` (~25 dk) dolduğunda "Failed"
/// olarak bırakılmıyor — `PendingConfirmation.regen_content` mekanizmasına
/// (bkz. o alanın dokümantasyonu, önceden SADECE Edit/Delete/GroupUpdate
/// için) katılıyor: taze bir ratchet adımıyla yeniden şifrelenip AYNI
/// `message_id` ile (bkz. `send_message_content_inner`'ın `message_id_override`'ı
/// — UI balonunun/`awaiting_confirmation` girdisinin kimliği KORUNUR, "manuel
/// yeniden gönder" gibi yeni bir balon oluşturmaz) süresiz yeniden dener.
/// Bu SÜRESİZ değil — `PendingConfirmation.original_sent_at` (regenerasyonlar
/// arasında SABİT kalan, mesajın İLK kuyruğa girdiği an) bu süreyi aşarsa
/// gerçekten pes edilir (bkz. `retry_unconfirmed_messages`). 2 gün: "karşı
/// taraf günlerce çevrimdışıydı" gerçek dünya senaryosunu kapsayacak kadar
/// cömert, ama süresiz arka plan ağ trafiği üretmeyecek kadar sınırlı —
/// uygulama açılışında (bkz. Kotlin `retryAllPendingNow` çağrısı) bu
/// pencere içindeki HER ŞEY zaten anında yeniden denenir.
/// Kullanıcı kararı (2026-08-27): 2 günden 7 güne çıkarıldı. Sunucudaki
/// posta saklama süresi (14 gün) zaten daha uzun; asıl sınır burasıydı
/// ve bir haftalık tatil/askıya alınmış hat gibi sıradan durumlar 2 günü
/// aşıyordu. `FILE_RETENTION_GRACE_MS` de buna bağlı olduğundan ekler de
/// aynı süre boyunca korunuyor — yani yeniden denenen bir dosya teklifi
/// hâlâ diskte karşılığını buluyor.
pub(crate) const TEXT_RETRY_GIVE_UP_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// bkz. `link_request_open_until`. Grant, birincil cihaz QR'ı taradıktan sonra
/// kalıcı yeniden deneme/sunucu posta kutusuyla gecikmeli gelebilir (ikincil
/// çevrimdışıyken, yeniden başlatma sonrası) — pencere diske yazılır.
/// One hour: while the window is open any paired contact can attach
/// this device to its own identity with a grant it signs itself (the device
/// cannot know who scanned its code). Same as the approver's
/// `PENDING_LINK_RETRY_HORIZON_MS`.
pub(crate) const LINK_REQUEST_WINDOW_MS: u64 = PENDING_LINK_RETRY_HORIZON_MS;
/// How long after this device last produced its own pairing code (QR or
/// typed) a stranger's IdentityExchange may create a contact. Without a
/// window, anyone who knew our fingerprint could fill the contact list at any
/// time, with no action by the user. The UI produces the code each time its
/// screen is shown, which opens the window again.
/// 30 min, not 24 h — a photographed code is a bearer token for the
/// whole window; a delayed (Tor/mailbox) exchange still fits.
pub(crate) const PAIRING_WINDOW_MS: u64 = 30 * 60 * 1000;
/// A pairing code produced again inside this time carries the nonce of the
/// one before (the UI produces the code each time its screen is shown).
pub(crate) const PAIRING_NONCE_REUSE_MS: u64 = 5 * 60 * 1000;
/// Members one GroupUpdate may name (bkz. `process_group_update`).
pub(crate) const MAX_GROUP_MEMBERS: usize = 256;

/// bkz. `DownloadState.last_retry_at` dokümantasyonu — bir indirmenin,
/// hiçbir libp2p-seviyeli olay (ne parça yanıtı, ne `OutboundFailure`)
/// üretmeden bu kadar süre "sessiz" kalabileceği süre; aşılırsa
/// `check_stalled_downloads` AYNI parçayı yeniden ister (bkz.
/// `retry_or_give_up_download` — ESKİDEN burada doğrudan başarısız
/// sayılıyordu, artık sadece `DOWNLOAD_GIVE_UP_TIMEOUT_MS`'ye kadar
/// yeniden deniyor). Aksi hâlde (özellikle iki cihaz da NAT arkasındayken,
/// TCP dial'ın ne başarılı olup ne de temiz bir hatayla sonuçlanmadığı
/// durumlarda) indirme SÜRESİZ "İndiriliyor" durumunda takılı kalabilirdi.
/// (The constant is `DOWNLOAD_STALL_TIMEOUT_MS`, below.)
/// Aynı anda havada olabilecek dosya parçası isteği — UYARLANIR pencere
/// (bkz. `DownloadState.window`).
/// Tek parça havadayken aktarım hızı `parça_boyutu / gidiş-dönüş süresi` ile
/// sınırlıdır — bant genişliğinden BAĞIMSIZ olarak. Gerçek cihazlarda Tor
/// üzerinden ölçüldü: ~70 KB/s indirme, ~12 KB/s yükleme.
/// Ancak SABİT bir derinlik de yanlış: gerçek cihazlarda ölçüldü ki yükleme
/// yolunda derinliği 6'dan 16'ya çıkarmak hızı ~180 KB/s'den ~50 KB/s'ye
/// DÜŞÜRDÜ — çünkü ~200 KB/s'lik bir Tor devresinde 16 × 256 KiB havada
/// tutmak tampon şişmesi (bufferbloat) yaratıp gidiş-dönüşü 24 sn'ye
/// çıkarıyor ve `request_timeout` sınırına (o zaman 30 sn, şimdi `BLOB_REQUEST_TIMEOUT_MS`) dayanıyordu. Bu yüzden
/// pencere AIMD benzeri uyarlanır: her başarılı parçada +1 (gidiş-dönüş
/// hedefin altındaysa), her zaman aşımı/hatada yarıya iner.
pub(crate) const DOWNLOAD_WINDOW_START: usize = 4;
pub(crate) const DOWNLOAD_WINDOW_MIN: usize = 2;
/// Wait before a failed chunk request, or one the server answered with "not
/// here yet", is sent again. Not zero: a request that fails at once was a loop
/// at round-trip rate. Not the 105 s stall timer: too long for the user.
pub(crate) const DOWNLOAD_RETRY_DELAY_MS: u64 = 3_000;
pub(crate) const DOWNLOAD_WINDOW_MAX: usize = 40;
/// Büyüme ölçütü MUTLAK bir eşik DEĞİL, o yolda ölçülen en küçük
/// gidiş-dönüşe göredir (bkz. `DownloadState.rtt_min`) — mutlak bir eşik
/// yavaş bir Tor devresinde pencereyi kalıcı olarak tabana çiviliyordu
/// (gerçek cihazda ölçüldü: 15.6 sn gidiş-dönüş, pencere 2'de takılı),
/// oysa yüksek gecikmeli bir yol tam da BÜYÜK pencere ister. Ölçüt
/// "gidiş-dönüş, o yolun en iyisinin iki katını aştı mı" (Vegas benzeri).
pub(crate) const DOWNLOAD_RTT_GROW_FACTOR: u64 = 2;
/// Bunun üstünde, ölçüt ne derse desin büyütme yok — `file_chunks`
/// `request_timeout`'una (`BLOB_REQUEST_TIMEOUT_MS`) yaklaşıyoruz demektir ve zaman aşımına
/// giren bir parça pencereyi yarıya indirir.
/// bkz. `server_client::BLOB_RTT_CEILING_MS` — aynı gerekçe: gidiş-dönüş
/// parça boyutuyla ölçeklendiği için mutlak eşik yanlış, `request_timeout`un
/// oranı doğru.
pub(crate) const DOWNLOAD_RTT_CEILING_MS: u64 = server_client::BLOB_REQUEST_TIMEOUT_MS * 4 / 5;
/// Bunun altındaki gidiş-dönüşler ölçüm gürültüsü sayılır — `rtt_min` çok
/// küçük çıkıp büyümeyi gereksiz yere durdurmasın.
pub(crate) const DOWNLOAD_RTT_FLOOR_MS: u64 = 750;

/// 105 s: longer than the 90 s chunk request timeout. At the old 45 s a chunk
/// still in flight on a slow Tor path was requested
/// again and counted against its source.
pub(crate) const DOWNLOAD_STALL_TIMEOUT_MS: u64 = server_client::BLOB_REQUEST_TIMEOUT_MS + 15_000;
/// "her şey onaylanana/çok çok uzun -10 dk- bir zaman aşımına kadar denenmeli"):
/// bir indirme, SON GERÇEK ilerlemeden (bkz. `DownloadState.last_progress_at`)
/// bu kadar süre geçene kadar (ara sıra `DOWNLOAD_STALL_TIMEOUT_MS`'de bir
/// aynı parçayı yeniden isteyerek) pes etmez. Önceden TEK bir stall/
/// `OutboundFailure` indirmeyi HEMEN başarısız sayıyordu — geçici bir ağ
/// sıçraması (Tor devresi yeniden kuruluyor, kısa bağlantı kopması vb.)
/// bile kullanıcıyı elle "tekrar dene"ye zorluyordu.
pub(crate) const DOWNLOAD_GIVE_UP_TIMEOUT_MS: u64 = 10 * 60 * 1000;

/// bkz. `enforce_history_storage_limit` dokümantasyonu — bir dosya
/// TAMAMLANDIKTAN sonra en az bu süre boyunca depolama-sınırı
/// tahliyesinden korunur. `TEXT_RETRY_GIVE_UP_MS` (7 gün) ile AYNI
/// tutuluyor — mantık: `FileOffer` metadata'sının kendisi de bu kadar
/// süre teslim edilmeye çalışılır, yani bir alıcının teklifi bu pencere
/// içinde GEÇ almasına rağmen dosyanın diskte hâlâ durması makul.
pub(crate) const FILE_RETENTION_GRACE_MS: u64 = TEXT_RETRY_GIVE_UP_MS;
