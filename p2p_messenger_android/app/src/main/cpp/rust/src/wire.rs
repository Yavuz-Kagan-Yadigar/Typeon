//! libp2p wire types (keepalive, ack, envelope) and the combined `P2PBehaviour`.

use super::*;


/// bkz. `KEEPALIVE_FAST_INTERVAL_MS` dokümantasyonu — bu istek/yanıtın
/// kendisinin içeriği önemsiz, tek amacı bağlantının hâlâ canlı olduğunu
/// doğrulamak. `request_response::cbor`
/// gerektirdiği için boş bir struct bile CBOR ile (de)serialize edilebilir
/// olmalı — `#[derive(Serialize, Deserialize)]` bunu ek alan olmadan sağlar.
/// `bye`: "I am shutting down, do not dial me until I connect again"
/// (desktop Quit). The receiver parks the device (`parked:{fp}` meta) and
/// `try_reconnect_device` skips it until a new connection from it arrives.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeepAliveRequest {
    #[serde(default)]
    pub bye: bool,
}
/// `quiet_ms`: "I am saving radio (metered network, screen off) — do not
/// probe me again for this long". Without it a phone on mobile data could
/// quiet its own timers but every peer's 20-60 s probe still woke its radio.
///
/// Wire: `None` is encoded as CBOR null — byte-identical to the old unit
/// struct, so older peers keep working; the hint is a one-field map, sent
/// only in radio-saver mode. Both forms decode.
#[derive(Debug, Clone, Default)]
pub struct KeepAliveResponse {
    pub quiet_ms: Option<u64>,
}

impl Serialize for KeepAliveResponse {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        match self.quiet_ms {
            None => s.serialize_unit(),
            Some(q) => {
                let mut m = s.serialize_map(Some(1))?;
                m.serialize_entry("quiet_ms", &q)?;
                m.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for KeepAliveResponse {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Hint { quiet_ms: u64 },
            Other(serde::de::IgnoredAny),
        }
        Ok(match Wire::deserialize(d)? {
            Wire::Hint { quiet_ms } => KeepAliveResponse { quiet_ms: Some(quiet_ms) },
            Wire::Other(_) => KeepAliveResponse { quiet_ms: None },
        })
    }
}

/// Toplu teslim onayı — bkz. `ACK_PROTOCOL`/`flush_outbound_acks`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckBatchRequest {
    pub ids: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckBatchResponse;

/// One envelope (the same bytes a gossipsub publish carries), sent straight to
/// a connected device. See `ENVELOPE_PROTOCOL`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeRequest {
    #[serde(with = "serde_bytes")]
    pub bytes: Vec<u8>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeResponse;

/// bkz. `P2PCore.keepalive_state` alan dokümantasyonu.
pub(crate) struct KeepAliveState {
    /// Bağlantı ölmüş olabilir (ağ değişti ya da bir paketimiz hızlıca
    /// onaylanmadı): hemen yoklanır ve TEK başarısızlıkta kapatılır. Önceden
    /// yarı açık bir bağlantı 3 ardışık zaman aşımıyla (~25-60 sn) fark
    /// ediliyordu; o sürede mesajlar ölü sokete yazılıyordu (cihazda ölçüldü:
    /// Wi-Fi→mobil geçişinde karşı taraf 35 sn boyunca fark etmedi).
    pub(crate) suspect: bool,
    /// Bu bağlantının (en son kurulduğu/yeniden kurulduğu) an — sadece
    /// `KEEPALIVE_STABILIZE_MS` eşiğini hesaplamak için, herhangi bir
    /// BAŞARILI keepalive'da SIFIRLANMAZ (yeniden bağlanmada sıfırlanır).
    pub(crate) connected_since: u64,
    /// Bir sonraki keepalive isteğinin gönderileceği an.
    pub(crate) next_due_at: u64,
    /// Ardışık başarısızlık sayısı — bkz. `KEEPALIVE_FAILURES_BEFORE_DISCONNECT`.
    pub(crate) consecutive_failures: u32,
    /// Şu an yanıt bekleyen bir istek varsa kimliği — aynı anda birden
    /// fazla keepalive isteğinin aynı bağlantı için havada kalmasını önler.
    pub(crate) outstanding: Option<request_response::OutboundRequestId>,
    /// Interval chosen at the last successful probe (0 = none yet). An
    /// inbound probe also proves liveness and restarts this interval, so
    /// both sides fall into one schedule — the radio-saver peer's window —
    /// instead of each waking the other's LTE radio on its own clock.
    pub(crate) interval_ms: u64,
    /// Peer advertised `KEEPALIVE_QUIET_PROTOCOL` (can decode `quiet_ms`).
    pub(crate) quiet_capable: bool,
}

// --- libp2p birleşik davranış ---
//
// Spec bölüm 4.2: DHT (Kademlia) keşif için. Identify protokolü, Kademlia'nın
// bağlanan peer'ların dinleme adreslerini öğrenip routing tablosuna
// ekleyebilmesi için ZORUNLUDUR (bkz. docs.rs/libp2p/kad: "the Identify
// protocol must be manually hooked up to Kademlia"). Gossipsub, mesaj/
// handshake paketlerinin taşınması için (bölüm 3.3 son not: "Node/relay bu
// paketi kör taşır").
#[derive(NetworkBehaviour)]
pub(crate) struct P2PBehaviour {
    /// Sunucu (store-and-forward) RPC'si — bkz. `server_client` modülü.
    /// `ProtocolSupport::Full`: sunucunun bize kendiliğinden `Notify`
    /// gönderebilmesi için (yoksa istemcinin sürekli yoklaması gerekirdi,
    /// bir telefonda bu doğrudan pil demek).
    pub(crate) server_rpc: request_response::cbor::Behaviour<server_proto::ServerRequest, server_proto::ServerResponse>,
    pub(crate) kad: kad::Behaviour<MemoryStore>,
    pub(crate) identify: identify::Behaviour,
    /// aktif
    /// bağlantı canlılık testi — bkz. `KeepAliveRequest`/`KeepAliveState`/
    /// `poll_events` Keepalive kolu dokümantasyonu. Bir bağlantının "yarı
    /// açık" (half-open — libp2p hâlâ bağlı sanıyor ama karşı taraf
    /// gerçekte ulaşılamıyor) kalmasını dakikalarca sürebilecek bir
    /// yazma-hatası bekleyerek DEĞİL, düzenli aralıklarla aktif prob'larla
    /// saniyeler içinde tespit eder. Stok `libp2p::ping::Behaviour` YERİNE
    /// özel bir `request_response` protokolü kullanılıyor çünkü stok ping
    /// TÜM bağlantılara tek bir sabit aralık uygular — bu özel sürüm,
    /// bağlantı stabilize olunca (bkz. `KEEPALIVE_STABILIZE_MS`) gönderim
    /// aralığını genişleterek radyo/pil tasarrufu sağlar.
    pub(crate) keepalive: request_response::cbor::Behaviour<KeepAliveRequest, KeepAliveResponse>,
    /// bkz. `ACK_PROTOCOL`.
    pub(crate) acks: request_response::cbor::Behaviour<AckBatchRequest, AckBatchResponse>,
    /// bkz. `ENVELOPE_PROTOCOL`.
    pub(crate) envelopes: request_response::cbor::Behaviour<EnvelopeRequest, EnvelopeResponse>,
    /// Call media streams (`call::MEDIA_PROTOCOL`, and the server relay) —
    /// long-lived streams driven by tokio tasks, see `call` module docs.
    pub(crate) stream: libp2p_stream::Behaviour,
    /// Dosya eki parça transferi — gossipsub'un aksine, bir hedef `PeerId`'ye
    /// doğrudan istek/yanıt (RPC benzeri) gönderir. 4GB'a kadar bir dosyayı
    /// gossipsub üzerinden (küçük/sık mesajlar için tasarlanmış bir pub/sub
    /// ağı) taşımak pratik değil — bkz. attachments.rs modül notu.
    pub(crate) file_chunks: request_response::cbor::Behaviour<FileChunkRequest, FileChunkResponse>,
    /// Spec dışı, güvenlik denetimi devamı (bkz. SECURITY.md "Cross-network
    /// connectivity" notu): bu cihazın kendisini, doğrudan dial
    /// edilemeyen (farklı ağ/NAT arkasındaki) peer'lara ULAŞMAK için bir
    /// röle kullanabilmesini sağlar — her cihazda her zaman açık.
    pub(crate) relay_client: relay::client::Behaviour,
    /// Bu cihazın BAŞKALARI için röle GÖREVİ görüp göremeyeceği. Spec §4.3'ün
    /// "Node modu... isteğe bağlı Circuit Relay v2 hizmeti" ifadesinin gerçek
    /// karşılığı bu alan.
    ///
    /// `Toggle<_>` kullanılıyor (Some/None `start_network`'e geçilen
    /// `node_mode`'a göre `start_network` içinde SEÇİLİYOR, `Toggle`'ın
    /// kendi dokümantasyonu da "state can only be chosen at initialization"
    /// diyor) — bu zaten `set_node_mode`'un var olan sınırlamasıyla (canlı
    /// toggle YOK, bir sonraki `start_network`'e kadar geçerli değil) TAM
    /// örtüşüyor, hiçbir şeyi KISITLAMIYOR.
    ///
    /// ÖNCEDEN bu alan `node_mode` ne olursa olsun HER ZAMAN `Some` inşa
    /// ediliyordu (kapasitesi `max_reservations`/`max_circuits`'i sıfırlayarak
    /// "pratikte" kapatılıyordu) — ama libp2p-relay'in HOP handler'ı
    /// (`behaviour/handler.rs::listen_protocol`) `Config`'e BAKMADAN HER ZAMAN
    /// HOP protokolünü substream olarak advertise ediyor. Sonuç: identify,
    /// `node_mode=false` bir peer'ı da "röle HOP protokolünü konuşuyor" diye
    /// raporluyordu (bkz. `known_relay_peers`/`record_known_relay` filtresi
    /// — `info.protocols.iter().any(|p| *p == relay::HOP_PROTOCOL_NAME)`),
    /// yani AYNI ANDA fleet'teki HER cihaz (node_mode açık olsun olmasın)
    /// sahte bir "röle adayı" gibi kaydediliyor, `dial_with_relay_fallback`
    /// bunlardan bir kısmına dial atıyor ve KESİN OLARAK "Remote reported
    /// resource limit exceeded" ile başarısız oluyordu — gerçek (node_mode
    /// açık) röle adayları `known_relay_peers`'in sabit `MAX_KNOWN_RELAYS`
    /// kapasitesinde bu sahte adaylarla rekabet ediyordu. `Toggle::from(None)`
    /// ile devre dışıyken HOP handler'ı hiç kaydedilmiyor, identify de bu
    /// protokolü hiç raporlamıyor — `known_relay_peers` artık SADECE
    /// gerçekten hizmet verebilecek (`node_mode=true`) cihazları içeriyor.
    pub(crate) relay: Toggle<relay::Behaviour>,
    // mDNS, UPnP and dcutr were removed: onion-only transport, loopback-only
    // listener — mDNS beaconed our PeerId on the LAN and UPnP had nothing to map.
}
