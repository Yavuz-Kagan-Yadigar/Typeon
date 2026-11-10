//! Swarm start, radio/power modes, relays, reconnects and publishing with retry.

use super::*;


/// CM-09: connection slots that peers not known to this device may hold.
pub(crate) const MAX_UNKNOWN_INBOUND: usize = 16;
pub(crate) const UNKNOWN_INBOUND_GRACE_MS: u64 = 2 * 60 * 1000;

/// Of the unknown inbound connections `(id, established ms)`: those older
/// than the grace time, and the newest ones above the slot cap.
pub(crate) fn unknown_inbound_to_close<T>(mut held: Vec<(T, u64)>, now: u64) -> Vec<T> {
    held.sort_by_key(|(_, at)| *at);
    held.into_iter()
        .enumerate()
        .filter(|(i, (_, at))| *i >= MAX_UNKNOWN_INBOUND || now.saturating_sub(*at) > UNKNOWN_INBOUND_GRACE_MS)
        .map(|(_, (id, _))| id)
        .collect()
}
impl P2PCore {

    /// bkz. `P2PCore.device_to_peer_id` alanı dokümantasyonu — herhangi bir
    /// gelen paketin gönderen cihaz fingerprint'i ile o paketin geldiği
    /// gossipsub `PeerId`'sini eşler.
    ///
    /// GÜVENLİK KOŞULU: `device_fingerprint` burada tamamen GÜVENİLİR
    /// olmalı — bu fonksiyon, `process_identity_exchange`/
    /// `process_handshake_init`/`receive_message` içinden, SADECE o
    /// fonksiyonların kendi kriptografik doğrulaması (fingerprint'in
    /// taşınan public key'lerden gerçekten türediği / hibrit imza) BAŞARILI
    /// olduktan SONRA çağrılmalıdır. Spec dışı, güvenlik denetimi düzeltmesi:
    /// önceden `process_incoming_envelope` bunu HER zarf türü için, o
    /// zarfın içeriği doğrulanmadan ÖNCE koşulsuz çağırıyordu — `source`
    /// (gossipsub'ın doğruladığı gerçek gönderen `PeerId`'si) sahtelenemez
    /// olsa da, `device_fingerprint` sadece zarfın İDDİASIYDI. Bir saldırgan,
    /// KENDİ gerçek `PeerId`'sinden, rastgele bir (ör. kurbanın bilinen bir
    /// kişisine ait) `device_fingerprint` iddia eden bir zarf yayınlayarak
    /// bu haritayı (ve kalıcı yeniden-bağlanma ipucu `device_last_addr`'ı)
    /// ZEHİRLEYEBİLİYORDU — paket daha sonra imza/fingerprint uyuşmazlığı
    /// yüzünden reddedilse bile bu yan etki geri alınmıyordu. Sonuç: o
    /// kişiye yönelik dosya indirme istekleri saldırganın `PeerId`'sine
    /// yönlendirilebiliyor, otomatik yeniden bağlanma saldırganın adresini
    /// deniyordu (mesaj gizliliği/bütünlüğü etkilenmiyordu — `known_remote_devices`
    /// ayrıca ve doğru sırayla korunuyordu).
    pub(crate) fn record_peer_id_if_known(&mut self, source: Option<PeerId>, device_fingerprint: &str) {
        if let Some(pid) = source {
            // A device keeps one libp2p key. While its mapped PeerId is still
            // connected, a packet arriving from another PeerId was relayed or
            // replayed by someone else: never let that take over the mapping.
            if let Some(old) = self.device_to_peer_id.get(device_fingerprint) {
                if *old != pid && self.swarm.as_ref().map_or(false, |s| s.is_connected(old)) {
                    return;
                }
            }
            // Nor while an address we hold for the device names another
            // PeerId. The packet is genuine, its carrier need not be: a relay
            // or server that withheld it and delivered the same bytes itself
            // became "the device", got our messages to it, acked them and
            // replaced its onion address. A device that really changed its
            // key says so in its (signed, encrypted) AddressAnnounce, which
            // replaces the stored address.
            let mut unproven = false;
            if self.device_to_peer_id.get(device_fingerprint) != Some(&pid) {
                let known: Vec<PeerId> = [self.device_last_addr.get(device_fingerprint), self.device_onion_addr.get(device_fingerprint)]
                    .into_iter().flatten()
                    .filter_map(|a| a.parse::<Multiaddr>().ok().and_then(|m| extract_peer_id(&m)))
                    .collect();
                if !known.is_empty() && !known.contains(&pid) {
                    return;
                }
                unproven = known.is_empty();
            }
            // Nothing names this PeerId for the device: the carrier is
            // unproven. A gossip author is a key the publisher picks, so a
            // contact could republish the device's packet under its own key
            // and become the device. Bound only over a live connection from
            // that PeerId, never to a server or to another identity's device,
            // and no address is stored from it: the device's own
            // AddressAnnounce supplies that.
            if unproven {
                let my_identity = self.known_remote_devices.get(device_fingerprint).map(|d| d.identity_id.clone());
                let other_identity = self.device_to_peer_id.iter().any(|(f, p)| {
                    *p == pid && f != device_fingerprint
                        && self.known_remote_devices.get(f).map(|d| d.identity_id.clone()) != my_identity
                });
                if self.is_server_peer(&pid)
                    || other_identity
                    || !self.swarm.as_ref().map_or(false, |s| s.is_connected(&pid))
                {
                    return;
                }
            }
            self.device_to_peer_id.insert(device_fingerprint.to_string(), pid);
            if unproven {
                return;
            }
            if let Some(onion) = self.peer_onion_addr.get(&pid).cloned() {
                self.remember_onion_addr(device_fingerprint, &onion);
            }
            // Spec dışı, ağ sağlamlığı düzeltmesi: bu cihazdan GERÇEKTEN
            // paket aldık — o an bağlı olduğumuz somut adresi (varsa,
            // `ConnectionEstablished`'ten doldurulan `peer_id_to_addr`)
            // kalıcı yeniden-bağlanma ipucu olarak sakla. Böylece bir
            // sonraki kopmada `reconnect_sweep` en son ÇALIŞAN adresi
            // kullanır (eşleşme anındaki rendezvous adresi bayatladıysa
            // bile). Adres `/p2p/<peer_id>` son eki içermiyorsa
            // `remember_device_addr` onu zaten yok sayar.
            if let Some(addr) = self.peer_id_to_addr.get(&pid).cloned() {
                // Adres zaten `/p2p/<peer_id>` içeriyorsa (giden dial'de
                // öyle kurmuştuk) tekrar ekleme — yoksa (gelen bağlantının
                // ham `/ip4/.../tcp/...` adresi) ekle.
                let addr_str = if extract_peer_id(&addr).is_some() {
                    addr.to_string()
                } else {
                    addr.with(MultiaddrProtocol::P2p(pid)).to_string()
                };
                self.remember_device_addr(device_fingerprint, &addr_str);
            }
        }
    }
}

impl P2PCore {

    // ---------------------------------------------------------------
    // Bölüm 4: Ağ / Keşif
    // ---------------------------------------------------------------

    pub(crate) fn start_network(&mut self, node_mode: bool, tor_enabled: bool) -> Result<String, String> {
        // A second call in one process (Android restarted the service) started
        // a second arti on the same state dir and a second listener on the
        // same port, with the connection maps of the old swarm still filled.
        if let Some(swarm) = &self.swarm {
            // Node mode / Tor take effect on the next process start only.
            if node_mode != self.node_mode_enabled || tor_enabled != self.tor_enabled {
                warn!("start_network: ağ zaten çalışıyor, yeni ayarlar (node={}, tor={}) yeniden başlatmada geçerli olur", node_mode, tor_enabled);
            }
            return Ok(swarm.local_peer_id().to_string());
        }
        // M-24: the node is onion-only (`tor::DialReject` on TCP). Without Tor
        // the swarm could dial nothing and the app sat offline with no error.
        if !tor_enabled {
            return Err("Tor kapalı: ağ yalnızca Tor üzerinden çalışır".to_string());
        }
        // No network without the storage keys. The gate used to be opened
        // here regardless: after a keystore failure handshakes built sessions
        // that could not be stored, and after the next start both sides were
        // out of step. The caller loads the keys and tries again.
        if !self.storage_keys_ready() {
            return Err("Depolama anahtarları yüklenmedi".to_string());
        }
        // Kalıcı keypair (PeerId) — bkz. `load_or_generate_libp2p_keypair`.
        let app_files_dir = self.app_files_dir.clone().ok_or("initDatabase önce çağrılmalı")?;
        let keypair = load_or_generate_libp2p_keypair(&app_files_dir);

        // Spec dışı, kullanıcı isteği (Tor): Tor açıksa arti onion service'i
        // başlat (arka planda bootstrap eder). Onion service, gelen Tor
        // akışlarını `127.0.0.1:TOR_LIBP2P_PORT`'a köprüler; libp2p bu yüzden
        // SABİT o portu dinlemeli (bkz. TOR_LIBP2P_PORT). Tor kapalıysa hiç
        // arti oluşturulmaz (ağır bağımlılık çalışma-zamanı maliyeti yok).
        let tor_handle: Option<tor::TorHandle> = if tor_enabled {
            let state_dir = format!("{}/arti_state", app_files_dir);
            let cache_dir = format!("{}/arti_cache", app_files_dir);
            match tor::TorHandle::launch(&state_dir, &cache_dir, TOR_LIBP2P_PORT) {
                Ok(h) => Some(h),
                // Not "go on without Tor": the node is onion-only, so that swarm
                // could dial nothing and put a loopback address in the QR code.
                // The caller tries again.
                Err(e) => return Err(format!("Tor başlatılamadı: {}", e)),
            }
        } else {
            None
        };
        // Dial transport için client (Tor kapalıysa None — transport inert).
        let tor_client = tor_handle.as_ref().map(|h| h.client.clone());
        let listen_port: u16 = if tor_handle.is_some() { TOR_LIBP2P_PORT } else { 0 };

        let gs_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(std::time::Duration::from_secs(10))
            .validation_mode(gossipsub::ValidationMode::Strict)
            // Varsayılan 64KB — `FileOffer` artık spec dışı bir 480p/%85
            // JPEG önizleme kapağı taşıyabiliyor (bkz. packet.rs
            // `preview_jpeg` notu); tipik değeri 64KB'ı zorlayabilir (hibrit
            // imza/ratchet_pubkey ek yükü ile birlikte). 1MB, olağan bir
            // önizlemeyi + zarf ek yükünü rahatça karşılıyor, gerçek dosya
            // baytları zaten AYRI bir protokolden (request_response,
            // attachments.rs) gittiği için bu artış büyük dosyaları
            // etkilemiyor.
            .max_transmit_size(1024 * 1024)
            .build()
            .map_err(|e| e.to_string())?;

        // Swarm ELLE kuruluyor, `SwarmBuilder` değil: 0.53'ün `build()`'i
        // bütün bağlantılara SABİT 10 sn zaman aşımı koyuyor (bkz. libp2p
        // builder/phase/build.rs `CONNECTION_TIMEOUT`) ve değiştirmenin yolu
        // yok. Bir Tor onion dial'ı (devre kurulumu + Noise) ya da Tor
        // üzerinden bir röle devresi mobil veride bunu rutin olarak aşıyor —
        // cihazda ölçüldü: sürekli "Timeout has been reached", onion
        // bağlantısı ancak şans eseri kuruluyordu. Transport'lar builder'ın
        // kurduğuyla AYNI (TCP, arti onion dial, röle istemcisi; hepsi
        // Noise + Yamux, V1Lazy).
        let local_peer_id = keypair.public().to_peer_id();
        let (relay_transport, relay_client) = relay::client::new(local_peer_id);
        let transport = {
            use libp2p::core::muxing::StreamMuxerBox;
            use libp2p::core::transport::Transport as _;
            use libp2p::core::upgrade::Version;
            let noise_for = |kp: &libp2p::identity::Keypair| noise::Config::new(kp).map_err(|e| e.to_string());
            // Onion-only (deanon fix, bkz. tor.rs `DialReject`): TCP taşıması
            // yalnızca gelen onion-köprüsü bağlantıları için tutulur; giden
            // her TCP (clearnet) dial'ı reddedilir, böylece hiçbir eşin gerçek
            // IP'sine doğrudan bağlanılmaz. Çıkış tamamen onion/röle üzerinden.
            let tcp_t = tor::DialReject(tcp::tokio::Transport::new(tcp::Config::default().nodelay(true)))
                .upgrade(Version::V1Lazy)
                .authenticate(noise_for(&keypair)?)
                .multiplex(tuned_yamux())
                .map(|(p, m), _| (p, StreamMuxerBox::new(m)));
            // Tor kapalıysa client None → her dial'ı reddeder (bkz. tor.rs).
            let tor_t = tor::ArtiDialTransport::new(tor_client.clone())
                .upgrade(Version::V1Lazy)
                .authenticate(noise_for(&keypair)?)
                .multiplex(tuned_yamux())
                .map(|(p, m), _| (p, StreamMuxerBox::new(m)));
            let relay_t = relay_transport
                .upgrade(Version::V1Lazy)
                .authenticate(noise_for(&keypair)?)
                .multiplex(tuned_yamux())
                .map(|(p, m), _| (p, StreamMuxerBox::new(m)));
            let combined = relay_t
                .or_transport(tor_t)
                .or_transport(tcp_t)
                .map(|out, _| match out {
                    futures::future::Either::Left(futures::future::Either::Left(o)) => o,
                    futures::future::Either::Left(futures::future::Either::Right(o)) => o,
                    futures::future::Either::Right(o) => o,
                });
            libp2p::core::transport::timeout::TransportTimeout::new(
                combined,
                std::time::Duration::from_secs(SWARM_CONNECTION_TIMEOUT_SECS),
            )
            .boxed()
        };
        let keypair_ref = &keypair;
        let behaviour = (|keypair: &libp2p::identity::Keypair, relay_client: relay::client::Behaviour| -> Result<P2PBehaviour, Box<dyn std::error::Error + Send + Sync>> {
                let peer_id = keypair.public().to_peer_id();
                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(keypair.clone()),
                    gs_config,
                )?;
                let store = MemoryStore::new(peer_id);
                let kad = kad::Behaviour::new(peer_id, store);
                // Cache 0: identify's address cache fed every peer's raw listen addresses,
                // 127.0.0.1 included, into each dial. Dials then reached our own node
                // ("Unexpected peer ID <self>", seen on device 2026-09-18). The Identify arm
                // below already records the useful non-loopback addresses itself.
                let identify = identify::Behaviour::new(identify::Config::new(
                    "/p2pmessenger/1.0.0".to_string(),
                    keypair.public(),
                ).with_cache_size(0)
                // Default 5 min per peer: with 3-4 peers the LTE radio woke
                // every ~75 s. Addresses change rarely; push covers changes.
                .with_interval(std::time::Duration::from_secs(3600)));
                // Spec dışı, ağ sağlamlığı düzeltmesi: kütüphanenin
                // varsayılan `request_timeout`'u (10sn) Tor üzerinden 256
                // KiB'lik bir dosya parçası (bkz. `FILE_CHUNK_SIZE`) için
                // çoğu zaman yetersiz — özellikle sıkışık bir devrede.
                // `retry_or_give_up_download` bir `OutboundFailure`'da AYNI
                // parçayı ANINDA (geri çekilmeden) yeniden ister, yani kısa
                // bir timeout burada "parçaya asla yetecek kadar süre
                // tanımadan sürekli yeniden deneme" döngüsüne yol açabilir.
                // 30sn, Tor'da tipik bir parça transferine (sıkışıklık dahil)
                // yetecek kadar cömert, ama gerçekten ölü bir bağlantıyı hâlâ
                // makul sürede (bkz. `DOWNLOAD_STALL_TIMEOUT_MS`) tespit
                // etmeyi engellemiyor.
                let file_chunks = request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new(FILE_TRANSFER_PROTOCOL), request_response::ProtocolSupport::Full)],
                    request_response::Config::default()
                        .with_request_timeout(std::time::Duration::from_millis(server_client::BLOB_REQUEST_TIMEOUT_MS)),
                );
                // bkz. `P2PBehaviour.relay` alan dokümantasyonu — Node modu
                // kapalıyken röle HOP davranışını TAMAMEN devre dışı
                // bırakıyoruz (`Toggle::from(None)`), sıfır kapasiteyle
                // inşa etmiyoruz — libp2p-relay'in HOP handler'ı `Config`'e
                // bakmadan protokolü her zaman advertise ettiğinden, sıfır
                // kapasiteli bir `Behaviour` bile identify üzerinden "röle
                // adayıyım" yalanını yayardı. Node modu daha sonra
                // `set_node_mode` ile açılırsa, röle GÖREVİ görme kapasitesi
                // bir sonraki ağ yeniden başlatmasına kadar etkinleşmez
                // (bkz. `set_node_mode` dokümantasyonu).
                let relay: Toggle<relay::Behaviour> = if node_mode {
                    Some(relay::Behaviour::new(peer_id, relay_server_config())).into()
                } else {
                    None.into()
                };
                // bkz. `P2PBehaviour.keepalive`/`KeepAliveState` dokümantasyonu.
                // Gönderim ZAMANLAMASI (hızlı/genişletilmiş aralık) burada
                // DEĞİL, `poll_events` içindeki "süresi gelmiş keepalive"
                // taraması içinde uygulanıyor (stok `ping::Config`in aksine —
                // bu davranışın TÜM bağlantılara AYNI sabit aralığı
                // uygulamasını önlemek tam olarak bu özel protokolün amacı).
                // `with_request_timeout`, tek bir isteğin yanıt için beklediği
                // azami süre (bkz. `KEEPALIVE_TIMEOUT_SECS`).
                let keepalive = request_response::cbor::Behaviour::new(
                    [
                        (StreamProtocol::new(KEEPALIVE_PROTOCOL), request_response::ProtocolSupport::Full),
                        (StreamProtocol::new(KEEPALIVE_QUIET_PROTOCOL), request_response::ProtocolSupport::Full),
                    ],
                    request_response::Config::default()
                        .with_request_timeout(std::time::Duration::from_secs(KEEPALIVE_TIMEOUT_SECS)),
                );
                // bkz. `P2PBehaviour.server_rpc` — `BLOB_REQUEST_TIMEOUT_MS` (90 sn) timeout,
                // `file_chunks` ile aynı gerekçe (Tor üzerinden büyük bir
                // yük için kütüphanenin 10 sn'lik varsayılanı yetersiz).
                let server_rpc = request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new(server_proto::SERVER_PROTOCOL), request_response::ProtocolSupport::Full)],
                    request_response::Config::default()
                        .with_request_timeout(std::time::Duration::from_millis(server_client::BLOB_REQUEST_TIMEOUT_MS)),
                );
                // bkz. `ACK_PROTOCOL` — Tor devresinde gidiş-dönüş saniyeler sürebilir.
                let acks = request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new(ACK_PROTOCOL), request_response::ProtocolSupport::Full)],
                    request_response::Config::default()
                        .with_request_timeout(std::time::Duration::from_secs(ACK_REQUEST_TIMEOUT_SECS)),
                );
                let envelopes = request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new(ENVELOPE_PROTOCOL), request_response::ProtocolSupport::Full)],
                    request_response::Config::default()
                        .with_request_timeout(std::time::Duration::from_secs(ACK_REQUEST_TIMEOUT_SECS)),
                );
                let stream = libp2p_stream::Behaviour::new();
                Ok(P2PBehaviour { server_rpc, gossipsub, kad, identify, file_chunks, relay_client, relay, keepalive, acks, envelopes, stream })
            })(keypair_ref, relay_client)
            .map_err(|e| e.to_string())?;
            // Spec dışı, ağ sağlamlığı düzeltmesi (kullanıcı isteği: "her şey
            // onaylanana/çok çok uzun bir zaman aşımına kadar denenmeli"):
            // AÇIKÇA belirtilmediğinde libp2p-swarm'ın VARSAYILAN
            // `idle_connection_timeout`'u kullanılır — bu, HİÇBİR protokol
            // substream'i açık olmayan (ör. iki mesaj arasındaki sessiz
            // dönemler) bir bağlantıyı kısa sürede KAPATIR, `reconnect_sweep`'in
            // (bkz. `RECONNECT_SWEEP_INTERVAL_MS`) her seferinde yeniden dial
            // etmesini gerektirir — gereksiz devre/el sıkışma trafiği,
            // özellikle Tor gibi devre kurulumu YAVAŞ olan taşıyıcılarda
            // (her kopuş, dakikalarca sürebilecek yeni bir devre kurulumu
            // demektir). 10 dakikaya çıkarılarak sohbetler arasındaki normal
            // sessiz dönemlerde bağlantı CANLI tutulur, gereksiz yeniden
            // bağlanma döngüsü önlenir.
        let mut swarm = Swarm::new(
            transport,
            behaviour,
            local_peer_id,
            libp2p::swarm::Config::with_tokio_executor()
                .with_idle_connection_timeout(std::time::Duration::from_secs(600)),
        );

        // Always Client. Kademlia is only the address book behind peer-id
        // dials here; nothing ever queries it. In Server mode (node mode) it
        // answered FIND_NODE from any stranger that reached the onion address
        // with the peer ids and onion addresses of the user's contacts.
        swarm.behaviour_mut().kad.set_mode(Some(kad::Mode::Client));

        let peer_id = *swarm.local_peer_id();

        // SABİT port: onion köprüsü buraya bağlanır — bkz. TOR_LIBP2P_PORT.
        //
        // Onion-only (deanon fix): `0.0.0.0` DEĞİL `127.0.0.1` — dinleyici
        // yalnızca loopback'te. Onion köprüsü (`bridge_incoming_stream`) zaten
        // `127.0.0.1:<port>`'a bağlanır (bkz. tor.rs:247), yani gelen onion
        // trafiği etkilenmez; buna karşılık LAN/internetten doğrudan clearnet
        // bağlantı KABUL EDİLMEZ ve identify eşlere yönlendirilebilir bir
        // adres duyurmaz.
        swarm.listen_on(format!("/ip4/127.0.0.1/tcp/{}", listen_port).parse().map_err(|_| "bad multiaddr")?)
            .map_err(|e| e.to_string())?;

        // bkz. `own_mailbox_topic_fp` dokümantasyonu: bu abonelik OLMADAN
        // cihaza hiçbir paket teslim edilemez. Başarısızlık artık SESSİZCE
        // yutulmuyor — kimlik henüz yoksa (servis kimlik oluşturulmadan
        // başlatılmışsa) AÇIKÇA loglanır ve `ensure_own_mailbox_subscription`
        // ilerideki bir `poll_events` turunda kendi kendine tamamlar.
        match self.get_active_own_device_fingerprint() {
            Ok(active_fp) => {
                let own_topic = gossipsub::IdentTopic::new(format!("p2p_msg_{}", active_fp));
                swarm.behaviour_mut().gossipsub.subscribe(&own_topic).map_err(|e| e.to_string())?;
                info!("Kendi posta kutusu topic'ine abone olundu: p2p_msg_{}", crate::log_id(&active_fp));
                self.own_mailbox_topic_fp = Some(active_fp);
            }
            Err(e) => {
                error!(
                    "start_network: aktif kimlik YOK ({}) — posta kutusu aboneliği şimdilik atlandı, \
                     kimlik hazır olunca otomatik tamamlanacak (bkz. ensure_own_mailbox_subscription)",
                    e
                );
            }
        }

        // bkz. `topic_for_root_key` dokümantasyonu: `load_ratchet_states_from_db`
        // (init_db sırasında, swarm henüz yokken) diskten yüklenmiş her
        // mevcut oturum için, o oturumun rotasyonlu topic'ine de abone ol —
        // aksi halde bu kişilerden gelen (fingerprint tabanlı posta kutusu
        // ARTIK dinlenmediği için) hiçbir mesaj alınamaz.
        for state in self.ratchets.values() {
            if let Err(e) = swarm.behaviour_mut().gossipsub.subscribe(&Self::topic_for_root_key(&state.root_key)) {
                error!("Oturum topic'ine abone olunamadı: {:?}", e);
            }
            // Güvenilirlik düzeltmesi (rotasyon penceresi): bir önceki
            // root'un topic'i de dinlenmeye devam eder — karşı taraf bizim
            // son rotasyonumuzu henüz uygulamadıysa bize hâlâ o topic'ten
            // yayın yapıyordur (bkz. `maybe_rotate_ratchet` resubscribe notu).
            if let Some(prev) = &state.prev_root_key {
                if let Err(e) = swarm.behaviour_mut().gossipsub.subscribe(&Self::topic_for_root_key(prev)) {
                    error!("Oturum topic'ine abone olunamadı: {:?}", e);
                }
            }
        }

        let mut stream_control = swarm.behaviour().stream.new_control();
        call::spawn_media_acceptor(&mut stream_control);
        self.stream_control = Some(stream_control);
        // Set only now: an error return above left them changed (M-195).
        self.node_mode_enabled = node_mode;
        self.tor_enabled = tor_enabled;
        self.own_listen_addrs.clear();
        self.advertised_onion = None; // new swarm: announce again
        // bkz. `tor_was_ready` alanı dokümantasyonu — taze bir Tor
        // istemcisi/oturumu başlıyor, "hazır" geçişini sıfırdan izle.
        self.tor_was_ready = false;
        self.swarm = Some(swarm);
        self.tor = tor_handle;
        self.tor_dormant = false;

        // bkz. `server_client` — yapılandırılmış sunuculara bağlanma/kayıt
        // ilk `server_sweep` turunda yapılır.
        self.server_sweep_at = 0;

        // bkz. `DEFAULT_BOOTSTRAP_RELAYS` dokümantasyonu — boşsa no-op.
        for addr in DEFAULT_BOOTSTRAP_RELAYS {
            if let Err(e) = self.add_known_relay_address(addr) {
                error!("Varsayılan bootstrap röle eklenemedi ({}): {}", addr, e);
            }
        }

        Ok(peer_id.to_string())
    }

    /// bkz. `KeepAliveState.suspect`.
    pub(crate) fn mark_connection_suspect(&mut self, peer: PeerId) {
        let Some(st) = self.keepalive_state.get_mut(&peer) else { return };
        if st.suspect {
            return;
        }
        st.suspect = true;
        if st.outstanding.is_none() {
            st.next_due_at = 0;
        }
        // Yoklamanın zaman aşımını beklemeden onion üzerinden paralel yeni
        // bağlantı aç; kurulursa eskisi kapatılır (bkz. `peer_conns`). Ölü
        // bağlantı fark edilene kadar geçen süre ile yeniden dial süresi
        // böylece üst üste binmek yerine paralel ilerliyor.
        let onion = self.device_to_peer_id.iter()
            .find(|(_, p)| **p == peer)
            .and_then(|(fp, _)| self.device_onion_addr.get(fp))
            .and_then(|a| a.parse::<Multiaddr>().ok());
        if let (Some(addr), Some(swarm)) = (onion, self.swarm.as_mut()) {
            let opts = libp2p::swarm::dial_opts::DialOpts::peer_id(peer)
                .addresses(vec![addr])
                .condition(libp2p::swarm::dial_opts::PeerCondition::Always)
                .build();
            let _ = swarm.dial(opts);
        }
    }

    /// See `RADIO_WINDOW_MS`. Wi-Fi too: with Tor awake a night on Wi-Fi woke
    /// the CPU ~once a second (2026-10-04: 64 % in 7 h, screen off).
    pub(crate) fn radio_saver(&self) -> bool {
        self.power_save
    }

    pub(crate) fn radio_window_ms(&self) -> u64 {
        if self.metered { RADIO_WINDOW_MS } else { RADIO_WINDOW_WIFI_MS }
    }

    pub(crate) fn set_metered(&mut self, metered: bool) {
        if self.metered != metered {
            info!("Ölçülü ağ: {}", metered);
        }
        self.metered = metered;
    }

    /// Pil düzeltmesi (2026-08-28): Kotlin/GTK tarafı, uygulama arka plana
    /// düşüp ekran kapandığında bunu açıyor. Ağ davranışını BOZMUYOR —
    /// sadece zaten sağlıklı ve sessiz bekleyen bağlantıların yoklama
    /// sıklığını düşürüyor (bkz. `power_save` alan notu).
    pub(crate) fn set_power_save(&mut self, enabled: bool) {
        if self.power_save == enabled {
            return;
        }
        self.power_save = enabled;
        info!("Güç tasarrufu modu: {}", if enabled { "açık" } else { "kapalı" });
        // Moddan ÇIKARKEN bekleyen yoklamaları öne çek: kullanıcı ekranı
        // açtığı anda bağlantıların canlılığı hemen doğrulansın, 60 saniye
        // beklemesin.
        if !enabled {
            let now = mono_ms();
            self.resync_since = now;
            for state in self.keepalive_state.values_mut() {
                if state.next_due_at > now + KEEPALIVE_FAST_INTERVAL_MS {
                    state.next_due_at = now + KEEPALIVE_FAST_INTERVAL_MS;
                }
            }
        }
    }

    /// Only stores the flag. Node mode means one thing in code: this device
    /// serves as a relay (`P2PBehaviour.relay`), chosen in `start_network`, so
    /// a change takes effect at the next network start. There is no DHT
    /// contribution: Kademlia always runs in Client mode (Server mode answered
    /// FIND_NODE with contacts' peer ids/onions) and no DHT record is written
    /// (H-16).
    pub(crate) fn set_node_mode(&mut self, enabled: bool) {
        self.node_mode_enabled = enabled;
    }

    /// Spec dışı, kullanıcı isteği: Ayarlar'daki geçmiş/ek depolama sınırı
    /// slider'ından çağrılır. Kullanıcı sınırı düşürürse hemen (bir sonraki
    /// `periodic_storage_sweep` turunu beklemeden) uygular — bkz.
    /// `enforce_history_storage_limit`.
    pub(crate) fn set_history_storage_limit_bytes(&mut self, bytes: u64) {
        // M58: both UIs stop at 32 GB; u64::MAX made the limit meaningless.
        self.history_storage_limit_bytes = bytes.min(64 << 30);
        self.enforce_history_storage_limit();
    }

    /// QR/"Kodum" ekranında gösterilecek ve karşı tarafa taşınacak
    /// `rendezvous_node` — swarm'ın gerçekten dinlemeye başladığı bir adres
    /// (`own_listen_addrs`, bkz. `poll_events`) artı kendi PeerId'imiz
    /// (`/p2p/<peer_id>` son eki). Bu son ek olmadan `extract_peer_id`
    /// karşı tarafta hiçbir zaman bir PeerId bulamaz ve taranan QR'ın
    /// adresi `kad.add_address`/`dial` için sessizce kullanılmaz kalır
    /// (bkz. process_qr_packet). The onion address, else a relay circuit
    /// address; `None` while Tor bootstraps — never the loopback listener,
    /// which no peer can dial (M-25).
    pub(crate) fn get_node_address(&self) -> Option<String> {
        let swarm = self.swarm.as_ref()?;
        let peer_id = *swarm.local_peer_id();
        // Spec dışı, kullanıcı isteği (Tor): Tor açık VE onion service yayında
        // ise, HER ŞEYDEN ÖNCE .onion adresini paylaş — bu, CGNAT dahil HER
        // ağdan (karşı tarafta da Tor açıksa) ulaşılabilir tek adres. Biçim:
        // `/dns/<host>.onion/tcp/<port>/p2p/<peer_id>` (bkz. tor.rs
        // ArtiDialTransport `onion_host_port`). Port keyfi — onion köprüsü
        // gelen HER portu yerel libp2p'ye yönlendiriyor (bkz.
        // bridge_incoming_stream), tutarlılık için TOR_LIBP2P_PORT kullanılıyor.
        if let Some(tor) = &self.tor {
            if let Some(onion_host) = tor.onion_host() {
                return Some(format!("/dns/{}/tcp/{}/p2p/{}", onion_host, TOR_LIBP2P_PORT, peer_id));
            }
        }
        // M-28: the node is onion-only (Tor is mandatory, see `start_network`):
        // a listen address is a clearnet/UPnP leak and nobody can dial it.
        None
    }

    /// Spec dışı, kullanıcı isteği (Tor): UI için Tor durumu — "disabled" /
    /// "bootstrapping" / "ready" / "failed" (+ hazırsa .onion host adı).
    pub(crate) fn tor_status(&self) -> String {
        match &self.tor {
            None => "disabled".to_string(),
            Some(h) => {
                let st = h.status().as_str();
                match h.onion_host() {
                    Some(host) if h.status() == tor::TorStatus::Ready => format!("{st}|{host}"),
                    _ => st.to_string(),
                }
            }
        }
    }

    /// Çekirdekte GERÇEKTEN yapılacak iş var mı — Android tarafındaki
    /// yoklama aralığı kararı için (bkz. P2PService `nextPollDelayMs`).
    ///
    /// Pil düzeltmesi (2026-08-28): swarm YALNIZCA `poll_events`
    /// çağrıldığında ilerliyor (`now_or_never`, arka planda süren bir görev
    /// yok) — bu yüzden yoklama aralığını körlemesine açmak ağı bozar:
    /// el sıkışmalar, Tor devresi kurulumu ve gossipsub mesh bakımı da o
    /// hızda yavaşlar. Bunun yerine aralık, çekirdeğin GERÇEK durumuna
    /// bakılarak seçiliyor. "Meşgul" sayılan haller:
    ///   * bağlı en az bir eş var (gelen mesaj olabilir, keepalive sürüyor),
    ///   * onay bekleyen bir paket var (yeniden deneme zamanlayıcısı işliyor),
    ///   * süren bir dosya indirmesi/yüklemesi var,
    ///   * gönderilememiş bir zarf kuyrukta,
    ///   * sunucuya bırakılacak/çekilecek iş var.
    /// Hiçbiri yoksa yapılacak tek şey GELEN bir bağlantıyı kabul etmek —
    /// o da saniyede bir yoklamayı gerektirmiyor.
    pub(crate) fn has_pending_work(&self) -> bool {
        // Pil: BAĞLI eş tek başına "meşgul" sayılmaz — sürekli açık bir Tor/sunucu
        // bağlantısı ekran kapalıyken wake lock'u 7/24 tutup günde %20-40 pil
        // yiyordu. Yalnızca gerçek bekleyen iş uyanık tutar.
        // awaiting_confirmation / pending_envelopes / pending_group_messages burada YOK:
        // çevrimdışı eşe bekleyen mesajlar saatlerce kalır; zamanlayıcıyla yeniden denenir,
        // CPU'yu 7/24 uyanık tutmaz (ölçüldü: wake lock 15/15 dk tutuluyordu).
        // Aktif eşleşme (TTL'li, 15 dk): IdentityExchange/Handshake turları hızlı poll ister;
        // bu olmadan eşleşme derin boşta 60 sn'lik bekleyişlere takılıp tamamlanmıyordu.
        // Sunucu işleri YALNIZCA sunucuya bağlıyken "iş" sayılır: sunucu erişilmezken bu
        // kuyruklar ilerleyemez, sayılırlarsa wake lock yine 7/24 tutuluyordu (ölçüldü:
        // 15/15 dk). `server_archive_queue` arka plan senkron birikimi: hiç sayılmaz.
        self.pairing_is_fresh()
            || self.downloads_busy() > 0
            // `server_inflight` is NOT work: the 30 s Fetch sweep is sent in
            // the very poll turn the service then checks, so it read "busy"
            // every time and no phone ever reached deep idle (measured
            // 2026-09-26: wake lock 30/30 min, LTE radio active 93 %, 35 mAh
            // per half hour). Its reply is a network event, which wakes the
            // native wait anyway.
            // Not while the server refuses deposits (quota): the upload only
            // waits for the backoff then.
            // And only with a routing server up: uploads go nowhere else.
            || self.blob_upload_can_run()
            // Ertelenmiş gelen paket varsa kesinlikle boşta değiliz —
            // aksi halde 30 sn'lik derin boşta kademesine düşüp teslimi
            // geciktirirdik (bkz. `deferred_incoming`).
            // Not while they only wait for the storage keys: that wait ends with
            // a call from the app, not with work here, and must not hold the CPU.
            || (!self.deferred_incoming.is_empty() && self.storage_keys_ready())
            || self.call.is_some()
    }

    /// H71: downloads that moved within the stall timeout and are not waiting
    /// for `retry_at`. A stalled one is probed by `check_stalled_downloads`
    /// on the next poll; its answer is a network event that wakes the native
    /// wait, so it need not hold the wake lock between probes.
    pub(crate) fn downloads_busy(&self) -> usize {
        let now = current_time_ms();
        self.active_downloads.values()
            .filter(|s| s.retry_at == 0 && now.saturating_sub(s.last_progress_at) < DOWNLOAD_STALL_TIMEOUT_MS)
            .count()
    }

    /// A pairing counts as work for its first two minutes only: one that
    /// never completes held the wake lock for the whole 15 min TTL.
    pub(crate) fn pairing_is_fresh(&self) -> bool {
        let now = current_time_ms();
        self.pairing_mailbox_subs.values().any(|at| now.saturating_sub(*at) < 2 * 60 * 1000)
    }

    /// Which `has_pending_work` terms are true — logged when busy so a phone
    /// that never reaches deep idle (seen: Note 9S, wake lock held 30/30 min)
    /// says why.
    pub(crate) fn busy_reasons(&self) -> String {
        let mut r = Vec::new();
        if self.pairing_is_fresh() { r.push(format!("pairing={}", self.pairing_mailbox_subs.len())); }
        if self.downloads_busy() > 0 { r.push(format!("downloads={}", self.downloads_busy())); }
        if self.blob_upload_can_run() { r.push(format!("blob_uploads={}", self.server_blob_uploads.len())); }
        if !self.deferred_incoming.is_empty() && self.storage_keys_ready() { r.push(format!("deferred_incoming={}", self.deferred_incoming.len())); }
        if self.call.is_some() { r.push("call".into()); }
        r.join(",")
    }

    /// Spec dışı, kullanıcı isteği: sohbet ekranının üst çubuğunda BU
    /// cihazın (karşı tarafın DEĞİL, bkz. `has_active_session`/
    /// `is_peer_connected`) genel ağ bağlantı durumunu göstermek için ham
    /// sinyalleri JSON olarak döner — insana okunur özet metni Kotlin
    /// tarafında hesaplanır (i18n ve gelecekte ince ayar esnekliği için,
    /// bkz. P2PLib.kt/ChatActivity notu). "Gerçekten internet var mı"
    /// sorusu BURADAN yanıtlanamaz (libp2p/Rust'ın işletim sistemi ağ
    /// arayüzlerine erişimi yok) — o kontrol Android tarafında
    /// `ConnectivityManager` ile yapılır, bu JSON'a `has_internet` olarak
    /// Kotlin ekler.
    pub(crate) fn own_connection_status(&self) -> serde_json::Value {
        let connected_peers = self.swarm.as_ref().map(|s| s.connected_peers().count()).unwrap_or(0);
        let busy = self.has_pending_work();
        if busy {
            log::debug!("Çekirdek meşgul: {}", self.busy_reasons());
        }
        // Coming out of power save: true until every link's pulled-forward
        // keepalive probe was answered (the UI shows a spinner meanwhile);
        // 10 s cap so a dead link cannot keep it spinning.
        let syncing = self.resync_since != 0
            && mono_ms().saturating_sub(self.resync_since) < 10_000
            && self.keepalive_state.values().any(|s| {
                s.outstanding.is_some() || s.next_due_at <= self.resync_since + KEEPALIVE_FAST_INTERVAL_MS
            });
        serde_json::json!({
            "busy": busy,
            "syncing": syncing,
            "connected_peers": connected_peers,
            "listening": !self.own_listen_addrs.is_empty(),
            "tor_enabled": self.tor_enabled,
            "tor_status": self.tor.as_ref().map(|h| h.status().as_str().to_string()).unwrap_or_else(|| "disabled".to_string()),
            "node_mode": self.node_mode_enabled,
        })
    }

    /// Spec dışı, güvenlik denetimi düzeltmesi: gossipsub topic adı önceden
    /// DOĞRUDAN alıcının cihaz fingerprint'inden türetiliyordu
    /// (`p2p_msg_<fingerprint>`) — ağdaki herhangi bir gözlemci, içeriği
    /// okuyamasa bile HANGİ fingerprint'e mesaj gittiğini ve NE ZAMAN
    /// gittiğini doğrudan görebiliyordu (bkz. SECURITY.md "Trafik analizi"
    /// notu). Bir ratchet oturumu KURULDUKTAN SONRA artık bunun yerine, o
    /// oturumun `root_key`'inden HKDF ile türetilen sözde-rastgele bir
    /// topic adı kullanılıyor — bu, sadece o oturumun paylaşılan sırrına
    /// sahip iki tarafın hesaplayabileceği bir değer, fingerprint'ten
    /// GERİYE türetilemez. `root_key` her DH/KEM rotasyonunda (30 dakikada
    /// bir, bkz. ratchet.rs) değiştiğinden, topic adı da otomatik olarak
    /// rotate olur — uzun vadeli bir gözlemci bile "bu iki topic aynı
    /// çifte ait" bağlantısını kuramaz.
    ///
    /// BİLİNEN SINIR: henüz hiçbir ratchet oturumu yokken (ilk eşleşmenin
    /// `IdentityExchange`/`HandshakeInit` çifti) paylaşılacak bir sır da
    /// yok — bu durumda kaçınılmaz olarak eski `p2p_msg_<fingerprint>`
    /// "posta kutusu" topic'ine düşülür (birini tanımadan önce onunla
    /// nasıl bir "rastgele buluşma noktası" paylaşılabilir ki?). Yani bu
    /// düzeltme, bir kişiyle YAPILAN TÜM GERÇEK KONUŞMA trafiğini korur;
    /// sadece BİR KEZLİK ilk eşleşme anı fingerprint üzerinden görünür
    /// kalır (SECURITY.md'de belgelendi).
    pub(crate) fn topic_for_root_key(root_key: &[u8]) -> gossipsub::IdentTopic {
        use sha2::Sha256;
        let hk = Hkdf::<Sha256>::new(None, root_key);
        let mut topic_id = [0u8; 16];
        hk.expand(b"p2pmsg-v0.1-gossip-topic", &mut topic_id).expect("HKDF expand failed");
        gossipsub::IdentTopic::new(format!("p2p_rt_{}", hex::encode(topic_id)))
    }

    /// `topic_for_root_key` dokümantasyonuna bkz. Bir ratchet oturumu
    /// kurulduğunda/rotasyon geçirdiğinde/silindiğinde çağrılan ortak
    /// abonelik yardımcı fonksiyonu — `old_root_key: Some(..)` ise önce o
    /// topic'ten abonelik iptal edilir (rotasyon/silme), sonra
    /// `new_root_key: Some(..)` ise o topic'e abone olunur (oluşturma/
    /// rotasyon). Swarm henüz başlamamışsa (`self.swarm == None`) sessizce
    /// no-op — `load_ratchet_states_from_db` süreç başlangıcında,
    /// `start_network`'ten ÖNCE çağrıldığı için bu durum normaldir (bkz.
    /// `start_network`'teki toplu abonelik döngüsü).
    pub(crate) fn resubscribe_ratchet_topic(&mut self, old_root_key: Option<&[u8]>, new_root_key: Option<&[u8]>) {
        if let Some(swarm) = &mut self.swarm {
            if let Some(old) = old_root_key {
                let _ = swarm.behaviour_mut().gossipsub.unsubscribe(&Self::topic_for_root_key(old));
            }
            if let Some(new) = new_root_key {
                if let Err(e) = swarm.behaviour_mut().gossipsub.subscribe(&Self::topic_for_root_key(new)) {
                    error!("Oturum topic'ine abone olunamadı: {:?}", e);
                }
            }
        }
    }

    /// Spec dışı, güvenlik denetimi devamı (bkz. SECURITY.md "Cross-network
    /// connectivity" notu): `known_relay_peers`'e yeni bir aday ekler,
    /// `MAX_KNOWN_RELAYS` dolmuşsa rastgele bir eskisini atar (gerçek LRU
    /// değil — bu sadece opportunistic bir önbellek, kalıcı da değil,
    /// her süreç kendi görüşüyle yeniden doldurur, bu yüzden hangi girdinin
    /// atıldığı önemli değil, sadece sınırsız büyümemesi önemli).
    pub(crate) fn record_known_relay(&mut self, peer_id: PeerId, addr: Multiaddr) {
        // LRU tahliyesi (bkz. alan dokümantasyonu): dolu haritadan EN ESKİ
        // görülmüş girdi atılır — önceden `keys().next()` (HashMap'in keyfi
        // iterasyon sırası) rastgele bir girdi atıyordu, çalışan tek röle
        // gidip ölüler kalabiliyordu. identify her karşılaşmada bu fonksiyonu
        // yeniden çağırdığından zaman damgası doğal olarak tazelenir.
        if !self.known_relay_peers.contains_key(&peer_id) && self.known_relay_peers.len() >= MAX_KNOWN_RELAYS {
            if let Some(evict) = self.known_relay_peers.iter()
                .min_by_key(|(_, (_, last_seen))| *last_seen)
                .map(|(pid, _)| *pid)
            {
                self.known_relay_peers.remove(&evict);
            }
        }
        if !self.known_relay_peers.contains_key(&peer_id) {
            info!("Röle adayı kaydedildi: {} {}", crate::log_id(&peer_id), addr);
        }
        self.known_relay_peers.insert(peer_id, (addr, current_time_ms()));
    }

    /// Yapılandırılmış bir sunucunun onion adresi (`/p2p/<id>` son ekiyle).
    pub(crate) fn server_onion_addr(&self, peer: &PeerId) -> Option<Multiaddr> {
        let id = peer.to_string();
        let rec = self.servers.iter().find(|r| r.server_id == id)?;
        let addr: Multiaddr = rec.address.split(',')
            .map(str::trim)
            .find(|a| a.contains(".onion") || a.contains("/onion3/"))?
            .parse().ok()?;
        Some(if extract_peer_id(&addr).is_some() { addr } else { addr.with(MultiaddrProtocol::P2p(*peer)) })
    }

    /// Bilinen her röleden bir Circuit Relay v2 REZERVASYONU alır
    /// (`listen_on <röle>/p2p-circuit`). Önceden hiçbir cihaz rezervasyon
    /// yapmıyordu; `dial_with_relay_fallback`'in `/p2p-circuit/p2p/<hedef>`
    /// dial'ı röle tarafında hedefin rezervasyonu olmadığı için HER ZAMAN
    /// reddediliyordu — yani iki NAT'lı cihaz röle üzerinden hiç
    /// buluşamıyordu. Kabul edilen rezervasyon `swarm.listeners()`'ta bir
    /// circuit adresi olarak görünür; görünmüyorsa ve son deneme
    /// `RELAY_RESERVATION_RETRY_MS`'den eskiyse yeniden istenir (röle
    /// koptuğunda dinleyici kapanır, adres kaybolur). `reconnect_sweep`'ten
    /// çağrılır.
    pub(crate) fn ensure_relay_reservations(&mut self) {
        let Some(swarm) = &mut self.swarm else { return };
        let now = current_time_ms();
        let local = *swarm.local_peer_id();
        // Kabul edilmiş rezervasyonlar: `<röle>/p2p/<röle_id>/p2p-circuit...`
        // — circuit'ten önceki ilk /p2p röleye aittir.
        let active: std::collections::HashSet<PeerId> = swarm.listeners()
            .filter(|a| a.iter().any(|p| matches!(p, MultiaddrProtocol::P2pCircuit)))
            .filter_map(|a| a.iter().find_map(|p| match p { MultiaddrProtocol::P2p(pid) => Some(pid), _ => None }))
            .collect();
        let known = &self.known_relay_peers;
        self.relay_listeners.retain(|pid, (lid, _)| {
            let keep = known.contains_key(pid);
            if !keep { swarm.remove_listener(*lid); }
            keep
        });
        for (pid, (addr, _)) in known {
            // Same reason as `dial_with_relay_fallback`: a reservation on an
            // unconnected relay is a dial to it every RELAY_RESERVATION_RETRY_MS.
            if *pid == local || active.contains(pid) || !swarm.is_connected(pid) { continue; }
            if let Some((lid, at)) = self.relay_listeners.get(pid) {
                if now.saturating_sub(*at) < RELAY_RESERVATION_RETRY_MS { continue; }
                swarm.remove_listener(*lid);
            }
            match swarm.listen_on(addr.clone().with(MultiaddrProtocol::P2pCircuit)) {
                Ok(lid) => {
                    info!("Röle rezervasyonu isteniyor: röle={}", crate::log_id(&pid));
                    self.relay_listeners.insert(*pid, (lid, now));
                }
                Err(e) => warn!("Röle rezervasyonu istenemedi (röle={}): {}", crate::log_id(&pid), e),
            }
        }
    }

    /// Spec dışı, güvenlik denetimi devamı (bkz. SECURITY.md "Cross-network
    /// connectivity" notu): `direct_addr` (varsa) DOĞRUDAN dial edilir VE
    /// (varsa) bilinen HER röle adayı üzerinden `/p2p-circuit/` adresiyle
    /// de AYNI ANDA dial denenir — libp2p aynı `PeerId`'ye birden fazla
    /// eşzamanlı dial denemesini sorunsuz yönetir (ilk başarılı olan
    /// kazanır, diğerleri iptal edilir). Bu, "önce doğrudan dene,
    /// başarısız olursa röleyi dene" sırasına göre daha düşük gecikmeli
    /// (röle denemesi, başarısız bir doğrudan denemenin zaman aşımını
    /// beklemeden hemen başlar) VE daha basit (ayrı bir asenkron
    /// başarısızlık-sonrası-yeniden-dene durum makinesi gerekmiyor).
    /// Toplu aktarım sürerken ilgili eşlere fazladan bağlantı açar, bitince
    /// kapatır — bkz. `BULK_PARALLEL_CONNECTIONS`.
    ///
    /// `poll_events`'ten her turda çağrılır; kendi zaman kapısı var.
    pub(crate) fn manage_bulk_connections(&mut self) {
        // Şu an toplu iş olan eşler: indirmenin KAYNAĞI ve blob yüklemesi
        // bekleyen sunucular.
        let mut want: std::collections::HashSet<PeerId> = self
            .active_downloads
            .values()
            .map(|d| d.peer_id)
            .collect();
        if self.blob_upload_can_run() {
            for p in self.server_peer_ids() {
                want.insert(p);
            }
        }

        let now = mono_ms();
        for peer in &want {
            // Extra connections to a peer we have a first one to. `have`
            // assumes it: without, this dialed an unreachable server or
            // download source again and again, outside the radio window.
            if !self.swarm.as_ref().map_or(false, |s| s.is_connected(peer)) {
                continue;
            }
            // Dials still in flight count: an onion dial takes 10-30 s, and a
            // new one was started every `BULK_DIAL_MIN_INTERVAL_MS` until the
            // first one landed.
            let have = 1 + self.extra_conns.get(peer).map(|v| v.len()).unwrap_or(0)
                + self.bulk_dials.values().filter(|p| *p == peer).count();
            if have >= BULK_PARALLEL_CONNECTIONS {
                continue;
            }
            let h = self.bulk_health.entry(*peer).or_default();
            // Paralellikten vazgeçildiyse soğuma bitene kadar tek devre.
            if now < h.giveup_until {
                continue;
            }
            if h.giveup_until != 0 && now >= h.giveup_until {
                // Soğuma bitti: temiz sayfa.
                *h = BulkHealth::default();
            }
            if now < h.next_dial_at {
                continue;
            }
            let Some(addr) = self.peer_id_to_addr.get(peer).cloned() else { continue };
            if let Some(h) = self.bulk_health.get_mut(peer) {
                h.next_dial_at = now + BULK_DIAL_MIN_INTERVAL_MS.max(h.backoff_ms);
            }
            // `PeerCondition::Always`: zaten bağlıyken de YENİ bir bağlantı
            // aç — varsayılan koşul "bağlıysa dial etme"dir ve tam olarak
            // istemediğimiz şey odur.
            let opts = libp2p::swarm::dial_opts::DialOpts::peer_id(*peer)
                .addresses(vec![addr])
                .condition(libp2p::swarm::dial_opts::PeerCondition::Always)
                .build();
            let cid = opts.connection_id();
            if let Some(swarm) = &mut self.swarm {
                match swarm.dial(opts) {
                    Ok(()) => {
                        self.bulk_dials.insert(cid, *peer);
                        info!("Toplu aktarım için fazladan bağlantı açılıyor: peer={} (mevcut {})", crate::log_id(&peer), have)
                    }
                    Err(e) => warn!("Fazladan bağlantı açılamadı: {}", e),
                }
            }
        }

        // Toplu işi biten eşlerin fazladan bağlantılarını kapat.
        let stale: Vec<(PeerId, Vec<libp2p::swarm::ConnectionId>)> = self
            .extra_conns
            .iter()
            .filter(|(p, _)| !want.contains(p))
            .map(|(p, v)| (*p, v.clone()))
            .collect();
        for (peer, conns) in stale {
            if let Some(swarm) = &mut self.swarm {
                for cid in &conns {
                    swarm.close_connection(*cid);
                }
            }
            info!("Toplu aktarım bitti, {} fazladan bağlantı kapatılıyor: peer={}", conns.len(), crate::log_id(&peer));
            self.extra_conns.remove(&peer);
            self.bulk_dials.retain(|_, p| *p != peer);
            // Sağlık durumu aktarıma özgüdür; bir sonraki aktarım temiz
            // sayfayla başlasın.
            self.bulk_health.remove(&peer);
        }
    }

    /// Bir parça zaman aşımını kaydeder ve GEREKİRSE paralelliği bir kademe
    /// geri çeker — bkz. `BulkHealth`.
    ///
    /// Eski davranış "ilk zaman aşımında bütün fazladan bağlantıları kapat"
    /// idi ve iki yönden yanlıştı: (a) Tor'da tek bir zaman aşımı gürültüdür,
    /// üç devrenin üçünü birden atmak için gerekçe değil; (b) yol kalıcı
    /// olarak kötüyse sürekli devre açıp kapamak durumu kötüleştirir, çünkü
    /// her kurulum ~5-15 sn sürer ve o sırada veri trafiğiyle yarışır.
    ///
    /// Yeni davranış kademeli: pencere içinde yeterince zaman aşımı birikirse
    /// TEK bir devre düşürülür (3→2→1), her düşürmede yeniden deneme
    /// beklemesi ikiye katlanır, ve düşürme sayısı tavanı aşarsa bu aktarım
    /// için paralellik bir süre tamamen bırakılır.
    pub(crate) fn note_bulk_timeout(&mut self, peer: PeerId) {
        let now = mono_ms();
        let h = self.bulk_health.entry(peer).or_default();
        h.strikes.retain(|t| now.saturating_sub(*t) < BULK_STRIKE_WINDOW_MS);
        h.strikes.push(now);
        if h.strikes.len() < BULK_STRIKES_TO_DROP {
            return;
        }
        h.strikes.clear();
        h.drops += 1;
        h.backoff_ms = if h.backoff_ms == 0 {
            BULK_DIAL_MIN_INTERVAL_MS * 2
        } else {
            (h.backoff_ms * 2).min(BULK_DIAL_MAX_BACKOFF_MS)
        };
        h.next_dial_at = now + h.backoff_ms;
        let drops = h.drops;
        if drops >= BULK_MAX_DROPS_BEFORE_GIVEUP {
            h.giveup_until = now + BULK_GIVEUP_COOLDOWN_MS;
            warn!(
                "Paralel aktarım bu eşte {} kez geri çekildi, tek devreye dönülüyor: peer={}",
                drops, crate::log_id(&peer)
            );
            self.drop_extra_connections(peer, "Paralellikten vazgeçildi", usize::MAX);
            return;
        }
        // TEK bir devre düşür — üçünü birden değil.
        self.drop_extra_connections(peer, "Tekrarlayan parça zaman aşımı", 1);
    }

    /// Bir eşin FAZLADAN bağlantılarını kapatır — bkz. `extra_conns`.
    ///
    /// Zaman aşımı görülünce çağrılır. Paralel devrelerin getirdiği yeni
    /// başarısızlık biçimi şu: devrelerden biri ölürse `request_response`
    /// istekleri ona dağıtmaya DEVAM eder (açık bağlantılar arasında
    /// round-robin yapıyor) ve isteklerin 1/N'i zaman aşımına gider. Gerçek
    /// cihazda görüldü: aktarımın ortasında 58 saniyelik duraklama, pencere
    /// 19'dan 9'a düştü. Ölü devreyi taşıyan bağlantıyı kapatmak trafiği
    /// sağlam devrelere toplar; yönetici (bkz. `manage_bulk_connections`)
    /// bekleme süresi dolunca TAZE bir devreyle yenisini açar.
    pub(crate) fn drop_extra_connections(&mut self, peer: PeerId, reason: &str, how_many: usize) {
        let Some(list) = self.extra_conns.get_mut(&peer) else { return };
        if list.is_empty() {
            return;
        }
        // EN YENİLERİ at: `manage_bulk_connections` sırayla açıyor, yani en
        // son eklenen en genç devredir ve sorunun ondan gelme ihtimali daha
        // yüksek. (Hangi devrenin bozuk olduğunu KESİN bilemiyoruz:
        // `request_response`'un `OutboundFailure` olayı `connection_id`
        // taşımıyor, yani başarısız isteği bir bağlantıya bağlayamıyoruz.)
        let n = how_many.min(list.len());
        let victims: Vec<libp2p::swarm::ConnectionId> = list.split_off(list.len() - n);
        let remaining = list.len();
        if list.is_empty() {
            self.extra_conns.remove(&peer);
        }
        if let Some(swarm) = &mut self.swarm {
            for cid in &victims {
                swarm.close_connection(*cid);
            }
        }
        warn!(
            "{} — {} fazladan bağlantı kapatıldı ({} kaldı): peer={}",
            reason, victims.len(), remaining, crate::log_id(&peer)
        );
    }


    /// Bir dosyanin parca boyutu — satirda NULL ise MIRAS 256 KiB.
    ///
    /// Boyut dosya basina saklaniyor cunku `.enc` bicimi SABIT ADIMLI: eski
    /// bir dosyayi yeni adimla okumak cop uretir. Yeni dosyalar
    /// `FILE_CHUNK_SIZE_V2` (512 KiB) kullaniyor.
    pub(crate) fn file_chunk_size(&self, file_id: &str) -> usize {
        self.db
            .as_ref()
            .and_then(|c| {
                c.query_row("SELECT chunk_size FROM files WHERE file_id = ?1", params![file_id], |r| {
                    r.get::<_, Option<i64>>(0)
                })
                .ok()
                .flatten()
            })
            .map(|v| v as usize)
            // Rows stored before `receive_file_offer` checked the size.
            .filter(|v| attachments::chunk_size_ok(*v))
            .unwrap_or(attachments::FILE_CHUNK_SIZE)
    }

    pub(crate) fn dial_with_relay_fallback(&mut self, target_peer_id: PeerId, direct_addr: Option<Multiaddr>) {
        let Some(swarm) = &mut self.swarm else { return };
        if let Some(addr) = direct_addr {
            if let Err(e) = swarm.dial(addr) {
                error!("Doğrudan dial başarısız: {}", e);
            }
        }
        for (relay_peer_id, (relay_addr, _)) in &self.known_relay_peers {
            // Only through a relay we are already connected to. Dialing the
            // circuit address of an unreachable relay dials the relay first:
            // with the server offline every reconnect to any peer became one
            // more failed onion lookup (9S overnight 2026-09-30: 444 failed
            // dials to the server, one per ~80 s, CPU and radio never idle).
            // Connecting to the relay itself is `server_sweep`'s job.
            if *relay_peer_id == target_peer_id || !swarm.is_connected(relay_peer_id) {
                continue;
            }
            let circuit_addr = relay_addr.clone()
                .with(MultiaddrProtocol::P2pCircuit)
                .with(MultiaddrProtocol::P2p(target_peer_id));
            if let Err(e) = swarm.dial(circuit_addr) {
                error!("Röle üzerinden dial başarısız (röle={}): {}", crate::log_id(&relay_peer_id), e);
            }
        }
    }

    /// Spec dışı, ağ sağlamlığı düzeltmesi (kendini iyileştiren yeniden
    /// bağlanma): `poll_events`'ten periyodik olarak (bkz.
    /// `RECONNECT_SWEEP_INTERVAL_MS`) çağrılır. Bilinen + aktif her uzak
    /// cihaz için, o an CANLI bir libp2p bağlantısı YOKSA VE kalıcı bir
    /// adres ipucumuz varsa (`device_last_addr`), `try_reconnect_device`
    /// ile yeniden bağlanmayı dener.
    ///
    /// Bu, EN GENİŞ kapsamlı ağ-sağlamlığı güvencesidir — tarih boyunca
    /// birkaç kez genişletildi: önce (bu fonksiyonun kendisi) periyodik
    /// tarama eklendi (önceden yeniden bağlanmanın TEK yolu mDNS [yalnızca
    /// aynı yerel ağ] veya elle QR yeniden taramaydı). Sonra keepalive
    /// (bkz. `P2PBehaviour.keepalive`) VE `ConnectionClosed` olayının KENDİSİ
    /// (bkz. `poll_events` — artık SADECE loglamıyor, `connections_lost`
    /// üzerinden ANINDA `try_reconnect_device` tetikliyor) eklenerek bir
    /// disconnect'in bu periyodik taramayı (≤15sn) BEKLEMEDEN saniyeler
    /// içinde fark edilip iyileşmesi sağlandı — bu fonksiyon artık ASIL
    /// kurtarma mekanizması değil, bir GÜVENLİK AĞI (ör. keepalive/ConnectionClosed
    /// bir şekilde kaçırılırsa, ya da süreç bir bağlantı hiç kurulmadan
    /// önce başladıysa).
    ///
    /// BİLİNEN SINIR: karşı tarafın adresi tamamen değiştiyse (yeni public
    /// IP, UPnP eşlemesi yok, ortak röle yok) doğrudan yeniden bağlanma yine
    /// başarısız olur — bu, merkezi bir rendezvous sunucusu olmayan her P2P
    /// sistemin yapısal sınırıdır. Tarama yine de denemeye devam eder;
    /// adres bir şekilde tazelendiğinde (mDNS, yeni QR, röle keşfi) bağlanır.
    /// A contact device, a sibling device or a configured server. The device
    /// map holds only fingerprints of known devices, tied to a PeerId by a
    /// verified packet or by the address of the pairing code.
    pub(crate) fn is_known_peer(&self, peer: &PeerId) -> bool {
        self.is_server_peer(peer) || self.device_to_peer_id.values().any(|p| p == peer)
    }

    /// Inbound connections of peers that are not known hold at most
    /// `MAX_UNKNOWN_INBOUND` slots together, each for at most
    /// `UNKNOWN_INBOUND_GRACE_MS`: every one is a slot of the Tor inbound
    /// bridge. Pairing makes the peer known well inside that time.
    /// ponytail: off in node mode, where strangers hold relay reservations
    /// on purpose; there the bridge's own slot count is the only cap.
    pub(crate) fn sweep_unknown_inbound(&mut self) {
        if self.unknown_inbound.is_empty() {
            return;
        }
        let mut held: Vec<(libp2p::swarm::ConnectionId, u64)> = Vec::new();
        let mut done: Vec<libp2p::swarm::ConnectionId> = Vec::new();
        for (cid, (peer, at)) in &self.unknown_inbound {
            let open = self.peer_conns.get(peer).map_or(false, |v| v.contains(cid));
            if !open || self.node_mode_enabled || self.is_known_peer(peer) {
                done.push(*cid);
            } else {
                held.push((*cid, *at));
            }
        }
        let close = unknown_inbound_to_close(held, mono_ms());
        for cid in done.iter().chain(&close) {
            self.unknown_inbound.remove(cid);
        }
        if let Some(swarm) = self.swarm.as_mut() {
            for cid in close {
                warn!("Closing an inbound connection of an unknown peer (slot cap or 2 min without pairing)");
                swarm.close_connection(cid);
            }
        }
    }

    pub(crate) fn reconnect_sweep(&mut self) {
        let now = mono_ms();
        // bkz. `fast_reconnect_until`: ağ yeni değiştiyse 3 sn'de bir, geri
        // çekilmeyi yok sayarak dene — ilk denemeler Tor henüz hazır değilken
        // düşüyor ve sıradan geri çekilme sonrakini ~20 sn erteliyordu.
        // Saver: fast only for the peers of `fast_reconnect_fps`.
        let saver_fast = self.radio_saver() && !self.fast_reconnect_fps.is_empty();
        let fast = now < self.fast_reconnect_until && (!self.radio_saver() || saver_fast);
        // Radio saver: dials (onion circuit builds) only inside the window.
        if !fast && !self.radio_window_open {
            return;
        }
        let interval = if fast { FAST_RECONNECT_INTERVAL_MS } else { RECONNECT_SWEEP_INTERVAL_MS };
        if now.saturating_sub(self.last_reconnect_sweep_at) < interval {
            return;
        }
        let first_sweep_of_minute = self.last_reconnect_sweep_at / 60_000 != now / 60_000;
        self.last_reconnect_sweep_at = now;
        if fast && saver_fast && !self.radio_window_open {
            // Outside the radio window: those peers only, nothing else of the sweep.
            for fp in self.fast_reconnect_fps.clone() {
                self.try_reconnect_device(&fp, false);
            }
            return;
        }
        self.ensure_relay_reservations();
        // L-07: a session topic whose subscribe failed (rotation, start) is
        // tried again here. Subscribing again to a live topic is a no-op.
        if first_sweep_of_minute {
            if let Some(swarm) = &mut self.swarm {
                for state in self.ratchets.values() {
                    for root in std::iter::once(&state.root_key).chain(state.prev_root_key.as_ref()) {
                        if let Err(e) = swarm.behaviour_mut().gossipsub.subscribe(&Self::topic_for_root_key(root)) {
                            debug!("Oturum topic'ine yeniden abone olunamadı: {:?}", e);
                        }
                    }
                }
            }
        }

        // Spec dışı, ağ sağlamlığı düzeltmesi (refactor): asıl dial/backoff
        // mantığı artık `try_reconnect_device`'te — `ensure_connected` VE
        // ping/ConnectionClosed-tetiklemeli anında yeniden bağlanma (bkz.
        // `poll_events`) ile PAYLAŞILIYOR, böylece hepsi AYNI geri-çekilme
        // durumunu görüyor (dial fırtınası riski azalır). Burada SADECE
        // "bilinen + Aktif" filtrelemesi kalıyor (bkz. `try_reconnect_device`
        // dokümantasyonu — bu filtre kasıtlı olarak `ensure_connected`'ta
        // YOK, o yüzden burada, çağıran tarafta kalmalı).
        let fps: Vec<String> = self.known_remote_devices.values()
            .filter(|d| d.is_active)
            .map(|d| d.device_fingerprint.clone())
            .collect();
        // Not forced even in the fast window: `reconnect_all_known_now`
        // already forced one dial and reset the backoff to 15 s; forcing
        // every 3 s stacked parallel onion dials to peers that are offline.
        for fp in fps {
            self.try_reconnect_device(&fp, false);
        }
        // Spec dışı, gerçek cihaz çökmesi düzeltmesi ("QR tarandı, iki
        // cihazda da hiçbir şey olmadı", ilk dial bir Tor onion timeout'uyla
        // başarısız oldu): `approve_device_link`'in bıraktığı bir bağlama
        // denemesi (`pending_link_target`) henüz `known_remote_devices`'a HİÇ
        // girmemiştir (girmesi için karşılıklı IdentityExchange'in TAMAMLANMASI
        // gerekir — tam da başarısız olan şey bu) — yukarıdaki döngü bu
        // yüzden bu fingerprint'i asla göremez ve ilk dial denemesi başarısız
        // olduğunda otomatik bir yeniden deneme YOKTU. `try_reconnect_device`
        // `known_remote_devices` üyeliği GEREKTİRMEZ (sadece `remember_device_addr`
        // ile zaten yazılmış `device_last_addr`'a bakar) — bu yüzden burada
        // AYRICA, doğrudan bu tek bekleyen hedef için de denenir.
        // bkz. `PENDING_LINK_RETRY_HORIZON_MS` — hiç tamamlanmayan bir
        // bağlama denemesi için süresiz dial/yeniden-gönderim sızıntısını
        // durdurur; ufuk içindeki davranış değişmedi.
        let link_within_horizon = current_time_ms().saturating_sub(self.pending_link_started_at) <= PENDING_LINK_RETRY_HORIZON_MS;
        if let Some(fp) = self.pending_link_target.clone().filter(|_| link_within_horizon) {
            self.try_reconnect_device(&fp, false);
            // ...ve AYRICA `IdentityExchange`'i yeniden gönder (bkz.
            // `poll_events`'teki `connections_established` kolunun uzun
            // notu — zarf, `PENDING_ENVELOPE_TIMEOUT_MS` dolduğunda kalıcı
            // olarak atılıyor ve onu yeniden üreten hiçbir yol yoktu).
            // Orası bağlantının KURULDUĞU anı yakalar; burası ise genel
            // güvenlik ağıdır (ör. bağlantı bu süreç başlamadan önce
            // kurulmuşsa, ya da mesh ilk denemeden sonra bozulup
            // toparlanmışsa). Kuyrukta bu hedef için zaten bekleyen bir
            // `IdentityExchange` varsa TEKRAR eklenmez — aksi halde her
            // taramada bir kopya daha birikirdi.
            let already_queued = self.pending_envelopes.iter().any(|q| {
                q.target == fp && matches!(q.envelope, NetworkEnvelope::IdentityExchange(_))
            });
            // Once a minute: a publish that worked leaves nothing queued, so
            // every sweep (15 s, 3 s in the fast window) sent a new one.
            if !already_queued && first_sweep_of_minute {
                if let Err(e) = self.send_identity_exchange(&fp) {
                    error!("Bağlanma IdentityExchange'i (periyodik tarama) gönderilemedi, yeniden denenecek: {}", e);
                }
            }
        }
        // Çoklu-cihaz (spec 1.7): kardeş cihazlardan periyodik geçmiş
        // geri-doldurma (kendi içinde debounce'lu — bkz.
        // SIBLING_BACKFILL_INTERVAL_MS) — çevrimdışıyken kaçırdığım kişi
        // mesajlarını yakalamak için.
        self.request_sibling_backfill();
    }

    /// Sadece ham gossipsub publish — kuyruğa EKLEMEZ, durum güncellemez.
    /// `publish_envelope` (ilk deneme) ve `poll_events`'teki retry döngüsü
    /// (sonraki denemeler) tarafından ortak kullanılır.
    ///
    /// Güvenilirlik düzeltmesi (kalıcı-hata ayrımı): hata artık tipli —
    /// `MessageTooLarge` (gossipsub `max_transmit_size` aşıldı) gibi KALICI
    /// bir hata, AYNI baytlarla ne kadar yeniden denenirse denensin asla
    /// başaramaz; önceden tüm hatalar geçici sayılıp 2 güne kadar boşuna
    /// yeniden deneniyordu (kullanıcıya da hiçbir zaman "başarısız"
    /// denmiyordu). Ayrıca `swarm` henüz yokken publish önceden SESSİZCE
    /// `Ok(())` dönüyordu — mesajlar hiç yayınlanmadan "sent" işaretleniyordu;
    /// artık dürüstçe Transient hata döner (retry kuyrukları devralır).
    /// `first_attempt_at`: bu zarfın İLK yayın denemesinin zamanı. Sunucu
    /// yolu bunu `ServerInflight::Deposit`'e taşır ki bir sunucu hatası
    /// sonrası zarf kuyruğa AYNI son-kullanma tarihiyle dönsün (bkz. orada
    /// ve `poll_events` retry döngüsündeki `timeout` hesabı).
    pub(crate) fn try_publish_raw(
        &mut self,
        target_device_fingerprint: &str,
        envelope: &NetworkEnvelope,
        first_attempt_at: u64,
    ) -> Result<(), PublishFailure> {
        self.try_publish_raw_via(target_device_fingerprint, envelope, first_attempt_at, true)
    }

    /// See `ENVELOPE_PROTOCOL`. `false` = no mapped peer / no swarm.
    pub(crate) fn send_envelope_direct(&mut self, fp: &str, envelope: &NetworkEnvelope, bytes: Vec<u8>, first_attempt_at: u64, retried: bool) -> bool {
        let (Some(pid), Some(swarm)) = (self.device_to_peer_id.get(fp).copied(), self.swarm.as_mut()) else { return false };
        let request_id = swarm.behaviour_mut().envelopes.send_request(&pid, EnvelopeRequest { bytes });
        self.envelopes_inflight.insert(request_id, (fp.to_string(), envelope.clone(), first_attempt_at, retried));
        true
    }

    /// `allow_direct = false`: the `ENVELOPE_PROTOCOL` attempt already failed,
    /// so use gossipsub/server.
    pub(crate) fn try_publish_raw_via(
        &mut self,
        target_device_fingerprint: &str,
        envelope: &NetworkEnvelope,
        first_attempt_at: u64,
        allow_direct: bool,
    ) -> Result<(), PublishFailure> {
        // Öz-denetim düzeltmesi (2026-08-28): engelleme TEK YÖNLÜYDÜ.
        // Gelen paketleri düşürüyor ve dial etmiyorduk, ama GÖNDERME yolunda
        // hiçbir kontrol yoktu — `announce_address_to_all_contacts`,
        // `set_own_profile_picture`, grup fan-out'u ve ortak bir gruptaki
        // kuyruk, engellenen kişiye paket yollamaya devam ediyordu. Yani
        // kendi adresimizi ve çevrimiçi olduğumuzu ona sızdırıyorduk.
        //
        // Burası BÜTÜN giden zarfların tek geçiş noktası — mesaj, düzenleme,
        // silme, ack, el sıkışma, kimlik tanıtımı, dosya teklifi, grup
        // güncellemesi. `Permanent` dönüyoruz ki yeniden deneme kuyruğuna
        // hiç girmesin.
        if self.is_blocked_device(target_device_fingerprint) {
            return Err(PublishFailure::Permanent(
                "Alıcı engellenmiş — gönderilmedi".to_string(),
            ));
        }
        if self.known_remote_devices.get(target_device_fingerprint)
            .map_or(false, |d| self.deleted_identities.contains(&d.identity_id))
        {
            return Err(PublishFailure::Permanent("Alıcı hesabını sildi — gönderilmedi".to_string()));
        }
        let bytes = ciborium_bytes(envelope).map_err(PublishFailure::Permanent)?;
        // Every path caps at 1 MiB (gossipsub `max_transmit_size`, the cbor
        // request-response default, the server). The direct path has no check
        // of its own: it reported "sent" and the request then failed, again
        // on every retry for days.
        // Headroom: gossipsub measures the whole protobuf frame (topic, seqno,
        // ...) against the cap, so an envelope of exactly 1 MiB never went out.
        if bytes.len() + 4096 > MAX_ENVELOPE_BYTES {
            return Err(PublishFailure::Permanent(format!("Zarf çok büyük ({} bayt)", bytes.len())));
        }
        let mailbox_topic = || gossipsub::IdentTopic::new(format!("p2p_msg_{}", target_device_fingerprint));
        // Spec dışı, hata ayıklama düzeltmesi (gerçek bir cihazda "hiçbir
        // mesaj gitmiyor da gelmiyor da" olarak rapor edildi): bkz.
        // `topic_for_root_key` dokümantasyonu — bir ratchet oturumu varsa
        // fingerprint yerine paylaşılan sırdan türetilen rotasyonlu topic
        // kullanılır, AMA bunun İKİ istisnası var, ikisi de "karşı taraf bu
        // ANDA hangi topic'i dinliyor olabilir" sorusuna dayanıyor:
        //
        // 1. `Handshake`/`IdentityExchange`: bunlar HER ZAMAN posta kutusu
        //    topic'inden gider, `self.ratchets`'te bu peer için bir kayıt
        //    olsa BİLE. Sebep: `initiate_handshake_with` kendi ratchet
        //    state'ini `self.ratchets`'e, HandshakeInit'i publish etmeden
        //    ÖNCE ekliyor (bkz. o fonksiyon) — bu yüzden `self.ratchets.get`
        //    kontrolü burada "true" dönerdi ve rotasyonlu topic seçilirdi.
        //    Ama karşı taraf bu paketi ALMADAN o rotasyonlu topic'i asla
        //    hesaplayamaz/abone olamaz (root_key'i bilmiyor) — bu, karşı
        //    tarafın HİÇBİR ZAMAN dinlemediği bir topic'e mesaj göndermek
        //    anlamına gelirdi (gerçek üretim hatasıydı, bu düzeltme onu
        //    kapatıyor).
        // 2. `Message` içindeki paket bir rotasyon ANONS EDİYORSA
        //    (`rotation_kyber_ciphertext` dolu): aynı sebepten, karşı taraf
        //    bu paketi almadan yeni root_key'i (dolayısıyla yeni topic'i)
        //    bilemez — bu yüzden rotasyonu tetikleyen tarafın kaydettiği
        //    `prev_root_key`'e (bkz. o alanın dokümantasyonu) karşılık gelen
        //    ESKİ topic kullanılır. Rotasyon içermeyen sıradan `Message`'lar
        //    her zamanki gibi GÜNCEL `root_key`'in topic'ini kullanır.
        let topic = match envelope {
            NetworkEnvelope::Handshake(_) | NetworkEnvelope::IdentityExchange(_) => mailbox_topic(),
            NetworkEnvelope::Message(packet) if packet.header.rotation_kyber_ciphertext.is_some() => {
                match self.ratchets.get(target_device_fingerprint).and_then(|r| r.prev_root_key.as_ref()) {
                    Some(prev_root_key) => Self::topic_for_root_key(prev_root_key),
                    None => mailbox_topic(),
                }
            }
            _ => match self.ratchets.get(target_device_fingerprint) {
                Some(ratchet) => Self::topic_for_root_key(&ratchet.root_key),
                None => mailbox_topic(),
            },
        };
        // --- Sunucu yolu (bkz. `server_client`) ---
        //
        // Topic SEÇİMİ yukarıda olduğu gibi kalıyor; sunucu, aynı topic
        // dizesinin körleştirilmiş hâlini kutu kimliği olarak kullanıyor.
        // Böylece yukarıdaki iki istisna (Handshake/IdentityExchange her
        // zaman posta kutusu topic'i; rotasyon duyuran Message eski
        // root_key'in topic'i) sunucu yoluna da BEDAVA devroluyor — ikisi de
        // gerçek üretim hatalarıydı, ikinci bir yerde tekrar yapılmamalı.
        let topic_str = topic.to_string();
        // Eşle CANLI bir libp2p bağlantısı varsa (LAN, Tor, röle) önce o yol:
        // sunucu kopyası yalnızca bu zarf ilk yeniden denemeye kadar
        // (`ACK_RETRY_INITIAL_MS`) onaylanmadıysa bırakılır. Önceden sunucu
        // ekliyken yan yana iki telefon bile her mesajı ilk 30 sn yalnızca
        // Tor üzerinden sunucuya yüklüyordu (mesaj başına ~15 KB + Tor
        // gidiş-dönüşü). Güvence aynı: Ack gelmezse sunucuya düşülüyor.
        // Handshake/IdentityExchange/rotasyon duyurusu yine hep iki yoldan
        // (bkz. `should_shadow_on_gossipsub` — kaybı telafi edilemez).
        let direct = self.is_connected_to_device(target_device_fingerprint);
        let critical = self.call_signal_sending || match envelope {
            NetworkEnvelope::Handshake(_) | NetworkEnvelope::IdentityExchange(_) => true,
            NetworkEnvelope::Message(m) => m.header.rotation_kyber_ciphertext.is_some(),
        };
        let unconfirmed_past_first_retry = match envelope {
            NetworkEnvelope::Message(m) => self.awaiting_confirmation.get(&m.header.message_id)
                .map_or(false, |pc| current_time_ms().saturating_sub(pc.first_sent_at) >= ACK_SUSPECT_MS),
            _ => false,
        };
        let mut deposited = (!direct || critical || unconfirmed_past_first_retry)
            && self.try_server_deposit(target_device_fingerprint, &topic_str, envelope, &bytes, first_attempt_at);
        // See `ENVELOPE_PROTOCOL`. Failure falls back to gossipsub/server in
        // `poll_events` (`EnvelopeEventLocal::Failed`).
        if direct && allow_direct && self.send_envelope_direct(target_device_fingerprint, envelope, bytes.clone(), first_attempt_at, false) {
            return Ok(());
        }
        // Same when the direct copy is already out and unconfirmed
        // (`!allow_direct`): a gossipsub copy is one more send to a peer the
        // server now covers.
        if deposited && (!direct || (!allow_direct && unconfirmed_past_first_retry)) && !self.should_shadow_on_gossipsub(envelope) {
            // Sunucu zarfı DİSKE yazacak — `gossipsub.publish()`in yerel
            // başarısından kesinlikle daha güçlü bir garanti. Uçtan uca
            // garanti yine de karşı tarafın `Ack`'i (bkz.
            // `awaiting_confirmation`), o mekanizma hiç değişmedi.
            return Ok(());
        }

        match &mut self.swarm {
            Some(swarm) => match swarm.behaviour_mut().gossipsub.publish(topic, bytes.clone()) {
                Ok(_) => Ok(()),
                // Aynı baytları tekrar denemek boyutu küçültmez — kalıcı.
                Err(gossipsub::PublishError::MessageTooLarge) => Err(PublishFailure::Permanent(
                    "Mesaj gossipsub azami boyutunu aşıyor (MessageTooLarge)".to_string(),
                )),
                // Sunucu zaten kabul ettiyse gossipsub'ın başarısızlığı bir
                // başarısızlık DEĞİL — gölge kopya en iyi çabaydı. Doğrudan
                // yol denenip başarısız olduysa (bağlı ama topic aboneliği
                // henüz yok) sunucuyu şimdi dene.
                Err(e) => {
                    if direct {
                        warn!(
                            "gossipsub yayını başarısız ({}): hedef={} tür={}",
                            e, &target_device_fingerprint[..target_device_fingerprint.len().min(8)],
                            server_client::envelope_kind(envelope)
                        );
                    }
                    if !deposited && direct {
                        deposited = self.try_server_deposit(target_device_fingerprint, &topic_str, envelope, &bytes, first_attempt_at);
                    }
                    if deposited {
                        Ok(())
                    } else {
                        Err(PublishFailure::Transient(e.to_string()))
                    }
                }
            },
            None => {
                if deposited {
                    Ok(())
                } else {
                    Err(PublishFailure::Transient("Ağ katmanı henüz başlatılmadı".to_string()))
                }
            }
        }
    }

    /// Herhangi bir zarfı (Handshake/IdentityExchange/Message/GroupUpdate/...)
    /// bir karşı tarafın gossipsub topic'ine yayınlar. İlk bağlantıdan sonraki
    /// ilk birkaç saniyede gossipsub mesh'i henüz oluşmamış olabilir — bu
    /// durumda publish anında "InsufficientPeers"/"NoPeersSubscribedToTopic"
    /// ile başarısız olur. Bunu MERKEZİ olarak burada ele alıyoruz: başarısız
    /// olan HER zarf `pending_envelopes`'e eklenir, `poll_events` her turda
    /// aynı zarfı (yeniden şifreleme/imzalama YAPMADAN) yeniden göndermeyi
    /// dener. Bu, önceden her çağıranın kendi tip-özel kuyruğunu tutmasından
    /// (ve HandshakeInit'in hiç kapsanmamasından) daha basit ve eksiksiz.
    /// `envelope` bir `Message` ise `message_status` da güncellenir (bkz. o
    /// alanın dokümantasyonu — UI'nin gönderim/hata ikonları için).
    pub(crate) fn publish_envelope(&mut self, target_device_fingerprint: &str, envelope: &NetworkEnvelope) -> Result<(), String> {
        self.publish_envelope_at(target_device_fingerprint, envelope, current_time_ms())
    }

    /// Adds to `pending_envelopes` unless the same envelope is already queued
    /// for this target. M-181: keys are cached per entry; only the new one is
    /// encoded.
    pub(crate) fn enqueue_pending(&mut self, queued: QueuedEnvelope) {
        let already_queued = queued.key.is_some()
            && self.pending_envelopes.iter().any(|q| q.target == queued.target && q.key == queued.key);
        if !already_queued {
            self.pending_envelopes.push(queued);
        }
    }

    /// `publish_envelope`, ama zarfın kuyruktaki yaşlanma sayacını çağıran
    /// belirler. Sunucu hatası sonrası yeniden kuyruğa koyma yolu bunu
    /// ORİJİNAL zamanla çağırır — bkz. `server_client::retry_deposit_over_gossipsub`.
    pub(crate) fn publish_envelope_at(
        &mut self,
        target_device_fingerprint: &str,
        envelope: &NetworkEnvelope,
        first_attempt_at: u64,
    ) -> Result<(), String> {
        match self.try_publish_raw(target_device_fingerprint, envelope, first_attempt_at) {
            Err(PublishFailure::Permanent(e)) => {
                // bkz. `PublishFailure` — yeniden denemek asla başaramaz,
                // kuyruğa EKLEME; hemen Failed işaretle ve UI'ye bildir.
                if let NetworkEnvelope::Message(m) = envelope {
                    self.set_message_status(&m.header.message_id, MessageSendStatus::Failed);
                    self.attachment_events.push(serde_json::json!({
                        "type": "status", "peer": self.canonical_peer_key(target_device_fingerprint),
                        "message_id": m.header.message_id, "status": "error"
                    }).to_string());
                }
                Err(e)
            }
            Err(PublishFailure::Transient(e)) => {
                if let NetworkEnvelope::Message(m) = envelope {
                    self.set_message_status(&m.header.message_id, MessageSendStatus::Pending);
                }
                // Aynı hedefe aynı zarf zaten kuyruktaysa İKİNCİ bir kopya
                // EKLEME: her sunucu gidiş-dönüşü bir kopya daha bırakıyor
                // ve kuyruk (dolayısıyla saniyede bir yeniden yatırma)
                // katlanarak büyüyordu.
                // `NetworkEnvelope` `PartialEq` türetmiyor (içi ham bayt
                // dolu paketler) — kimlik için sunucu yolunun ZATEN
                // kullandığı tekilleştirme anahtarını kullanıyoruz.
                self.enqueue_pending(QueuedEnvelope::new(target_device_fingerprint.to_string(), envelope.clone(), first_attempt_at));
                Err(e)
            }
            Ok(()) => {
                if let NetworkEnvelope::Message(m) = envelope {
                    self.set_message_status(&m.header.message_id, MessageSendStatus::Sent);
                }
                Ok(())
            }
        }
    }

    /// bkz. `awaiting_confirmation` alanı dokümantasyonu — `publish_envelope`
    /// gibi ilk denemeyi hemen yapar (durumu/aynı şekilde günceller), ama
    /// SONRASINDA da (ilk deneme başarılı olsa BİLE) karşı taraftan bir
    /// onay gelene kadar paketi periyodik olarak yeniden göndermeye devam
    /// eder — `pending_envelopes`'in aksine bir üst zaman sınırı yoktur.
    ///
    /// `original_sent_at_override`/`retry_interval_ms_override`: SADECE
    /// `regen_content` tazelemesinden (bkz. `retry_unconfirmed_messages`
    /// yaş-aşımı kolu) çağrıldığında `Some(...)` — mesajın İLK kuyruğa
    /// girdiği an VE o ana kadar ulaşılmış üstel geri çekilme aralığını
    /// KORUR. Pil ömrü düzeltmesi: bunlar korunmadan her 25 dakikalık
    /// tazelemede `retry_interval_ms` `ACK_RETRY_INITIAL_MS`'ye (15s)
    /// sıfırlanırdı — karşı taraf günlerce çevrimdışıyken bu, her 25
    /// dakikada bir 15s→30s→60s→120s hızlı bir "patlama"
    /// anlamına gelirdi. Artık zaten `ACK_RETRY_MAX_MS` (120s) tavanına
    /// ulaşmış bir mesaj, tazelemeler arasında da o TAVANDA kalır — sabit,
    /// öngörülebilir ~2 dakikalık bir nabız, patlama yok.
    pub(crate) fn publish_with_ack_tracking(
        &mut self,
        target_device_fingerprint: &str,
        message_id: &str,
        envelope: NetworkEnvelope,
        regen_content: Option<MessageContent>,
        original_sent_at_override: Option<u64>,
        retry_interval_ms_override: Option<u64>,
    ) {
        let now = current_time_ms();
        match self.try_publish_raw(target_device_fingerprint, &envelope, now) {
            Ok(()) => {
                if let NetworkEnvelope::Message(m) = &envelope {
                    self.set_message_status(&m.header.message_id, MessageSendStatus::Sent);
                }
            }
            // bkz. `PublishFailure` — kalıcı hata (ör. MessageTooLarge):
            // onay-takip kuyruğuna HİÇ girme, hemen Failed işaretle ve
            // UI'ye bildir; yeniden denemek asla başaramazdı.
            Err(PublishFailure::Permanent(e)) => {
                error!("Gönderim KALICI olarak başarısız (yeniden denenmeyecek): {}", e);
                // A refresh of an entry that is already tracked: drop the old
                // entry too, or it stays due and is re-encrypted every turn.
                self.awaiting_confirmation.remove(message_id);
                self.remove_durable_retry(message_id);
                if let NetworkEnvelope::Message(m) = &envelope {
                    self.set_message_status(&m.header.message_id, MessageSendStatus::Failed);
                    self.attachment_events.push(serde_json::json!({
                        "type": "status", "peer": self.canonical_peer_key(target_device_fingerprint),
                        "message_id": m.header.message_id, "status": "error"
                    }).to_string());
                }
                return;
            }
            Err(PublishFailure::Transient(e)) => {
                error!("İlk gönderim denemesi başarısız (onay alınana kadar yeniden denenecek): {}", e);
                if let NetworkEnvelope::Message(m) = &envelope {
                    self.set_message_status(&m.header.message_id, MessageSendStatus::Pending);
                }
            }
        }
        // bkz. `persist_durable_retry` dokümantasyonu — süreç öldürülüp
        // yeniden başlasa bile bu kaybolmasın diye şifreli DB'ye de yazılır.
        // Struct'a taşınmadan (move) ÖNCE, referans üzerinden.
        // bkz. `persist_durable_retry` — diske GERÇEK başlangıç anı yazılır,
        // `now` değil; yoksa 7 günlük vazgeçme penceresi her tazelemede
        // sıfırlanırdı.
        let original_sent_at = original_sent_at_override.unwrap_or(now);
        if let Some(content) = &regen_content {
            self.persist_durable_retry(message_id, target_device_fingerprint, content, original_sent_at);
        }
        let retry_interval_ms = retry_interval_ms_override.unwrap_or(ACK_RETRY_INITIAL_MS);
        self.awaiting_confirmation.insert(message_id.to_string(), PendingConfirmation {
            suspect_probed: false,
            direct_delivered: false,
            // bkz. `chain_stamp` alan notu — paket hangi zincir kuşağıyla
            // şifrelendiyse o damgalanır.
            chain_stamp: self.chain_stamp_for(target_device_fingerprint),
            peer_device_fingerprint: target_device_fingerprint.to_string(),
            envelope,
            next_retry_at: now + retry_interval_ms,
            retry_interval_ms,
            first_sent_at: now,
            original_sent_at,
            last_attempt_at: now,
            regen_content,
        });
    }

    /// `poll_events`'ten çağrılır — `awaiting_confirmation`'daki, süresi
    /// gelmiş her girdiyi (yeniden şifrelemeden) tekrar yayınlar ve bir
    /// sonraki deneme aralığını üstel olarak büyütür (`ACK_RETRY_MAX_MS`
    /// ile sınırlı).
    pub(crate) fn retry_unconfirmed_messages(&mut self) {
        // Revoked devices whose last notice had its time to go out.
        if !self.revoked_disconnects.is_empty() {
            let now = mono_ms();
            let (due, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut self.revoked_disconnects).into_iter().partition(|(_, at)| now >= *at);
            self.revoked_disconnects = keep;
            if let Some(swarm) = &mut self.swarm {
                for (peer, _) in due {
                    let _ = swarm.disconnect_peer_id(peer);
                }
            }
        }
        // Spec dışı, performans denetimi düzeltmesi: `poll_events` bunu
        // her turda çağırır (bkz. o fonksiyonun dokümantasyonu);
        // `reconnect_sweep`/`group_sync_sweep`/`periodic_storage_sweep`'in
        // aksine bu fonksiyonun kendi aralık kontrolü YOKTU — boş bir
        // `awaiting_confirmation` haritasında (yeniden gönderilecek hiçbir
        // mesaj olmayan sıradan bir bekleme durumunda, ki en yaygın durum
        // budur) bile aşağıdaki `.iter().filter().map().collect()` +
        // `sort_by_key` her turda gereksiz bir tahsis/tarama yapıyordu.
        if self.awaiting_confirmation.is_empty() {
            return;
        }
        let now = current_time_ms();
        // M-181: the scan below (whole map, HKDF per peer, sort) at most once
        // a second, not on every poll turn.
        if now.saturating_sub(self.last_unconfirmed_retry_at) < 1_000 {
            return;
        }
        self.last_unconfirmed_retry_at = now;
        // bkz. `KeepAliveState.suspect`: canlı sandığımız bir bağlantıdan
        // `ACK_SUSPECT_MS` içinde onay gelmediyse bağlantıyı hemen yokla.
        let mut suspects: Vec<PeerId> = Vec::new();
        let mut early_deposit: Vec<(String, NetworkEnvelope)> = Vec::new();
        for p in self.awaiting_confirmation.values_mut() {
            if !p.suspect_probed && !p.direct_delivered && now.saturating_sub(p.first_sent_at) >= ACK_SUSPECT_MS {
                p.suspect_probed = true;
                early_deposit.push((p.peer_device_fingerprint.clone(), p.envelope.clone()));
                if let Some(pid) = self.device_to_peer_id.get(&p.peer_device_fingerprint) {
                    suspects.push(*pid);
                }
            }
        }
        for pid in suspects {
            self.mark_connection_suspect(pid);
        }
        // Doğrudan gönderilmiş ama `ACK_SUSPECT_MS` içinde onaylanmamış paketi
        // 15 sn'lik (`ACK_RETRY_INITIAL_MS`) ilk yeniden denemeyi beklemeden sunucuya da bırak: gönderici
        // bu arada çevrimdışı kalırsa mesaj sunucuda olsun. Aynı baytları
        // gossipsub zaten `Duplicate` diye tekrar göndermez.
        for (fp, envelope) in early_deposit {
            // Server copy only (`allow_direct = false`): the direct copy is in
            // flight, and `try_publish_raw` sent the envelope a second time.
            if self.is_connected_to_device(&fp) && !self.ready_server_peers().is_empty() {
                if let Err(PublishFailure::Transient(e) | PublishFailure::Permanent(e)) = self.try_publish_raw_via(&fp, &envelope, now, false) {
                    warn!("Early server copy for suspect peer {} failed: {}", crate::log_id(&fp), e);
                }
            }
        }
        // KRİTİK: `awaiting_confirmation` bir `HashMap` — Rust'ın std
        // `HashMap`'i her süreçte rastgele tohumlanmış bir hasher
        // kullanır (DoS direnci için), yani `.iter()` sırası KOMPOZİSYON
        // sırasıyla HİÇ ilgili değildir. Kullanıcı çevrimdışıyken art
        // arda birkaç mesaj biriktiyse, bu sıralama olmadan yeniden
        // gönderim sırası her `poll_events` turunda değişebilen, rastgele
        // bir sıraydı — kullanıcı isteği: ilk gönderilemeyen mesajlar
        // BİRİKTİYSE gönderilme (composition) sırasına göre denenmeli.
        // `original_sent_at` zaten her `PendingConfirmation`'da var, bu
        // yüzden `due_ids`'i ona göre sıralamak yeterli (yapıyı
        // `BTreeMap`'e çevirmek gibi daha büyük bir değişikliğe gerek
        // yok — tüm `.get`/`.get_mut`/`.remove`/`.insert` çağrı yerlerini
        // etkilerdi).
        // Öz-denetim düzeltmesi (2026-08-28): zincir kuşağı damgasına
        // (bkz. `PendingConfirmation.chain_stamp`) yalnızca SIRASI GELEN
        // paketler için bakılıyordu — yani kuşak değişmiş olsa bile paket,
        // kendi geri çekilme aralığı (2 dakikaya kadar) dolana dek karşı
        // tarafın ARTIK ÇÖZEMEYECEĞİ ciphertext'le yeniden denenmeye devam
        // ediyordu. "Kuşak değişince hemen tazelenir" ancak şimdi doğru.
        //
        // Damga eş BAŞINA bir kez hesaplanıyor (`topic_for_root_key` bir
        // HKDF adımı), mesaj başına değil.
        let mut stamp_cache: HashMap<String, String> = HashMap::new();
        // Unique first: one String per peer, not one per held message.
        let peers: Vec<String> = self
            .awaiting_confirmation
            .values()
            .map(|p| p.peer_device_fingerprint.as_str())
            .collect::<std::collections::HashSet<&str>>()
            .into_iter()
            .map(str::to_owned)
            .collect();
        for fp in peers {
            if !stamp_cache.contains_key(&fp) {
                let stamp = self.chain_stamp_for(&fp);
                stamp_cache.insert(fp, stamp);
            }
        }
        // Radio saver: retries wait for the window like every other periodic
        // job. They ran on their own clock (5 s doubling to 120 s), so one
        // connected peer that never acks kept the LTE radio up all the time:
        // an 8 KB envelope re-sent every minute or two, for days (9S
        // 2026-10-02: radio 74 % of a 10-min screen-off run). A packet queued
        // in the last minute is still sent at once.
        let hold_retries = self.radio_saver() && !self.radio_window_open;
        let mut due_ids: Vec<(String, u64)> = self.awaiting_confirmation.iter()
            .filter(|(_, p)| {
                // `next_retry_at == 0`: the peer just connected or subscribed,
                // so the radio is up anyway.
                if hold_retries && p.next_retry_at != 0 && now.saturating_sub(p.original_sent_at) > 60_000 {
                    return false;
                }
                if p.next_retry_at <= now {
                    return true;
                }
                match stamp_cache.get(&p.peer_device_fingerprint) {
                    Some(current) => {
                        !current.is_empty() && !p.chain_stamp.is_empty() && current != &p.chain_stamp
                    }
                    None => false,
                }
            })
            .map(|(id, p)| (id.clone(), p.original_sent_at))
            .collect();
        // `original_sent_at`: `first_sent_at` is reset by every regeneration,
        // which sent a regenerated message to the back of the queue.
        due_ids.sort_by_key(|(_, original_sent_at)| *original_sent_at);
        for (message_id, _) in due_ids {
            let (peer_fp, envelope, first_sent_at, original_sent_at, retry_interval_ms, regen_content, chain_stamp) = match self.awaiting_confirmation.get(&message_id) {
                Some(p) => (
                    p.peer_device_fingerprint.clone(), p.envelope.clone(), p.first_sent_at,
                    p.original_sent_at, p.retry_interval_ms, p.regen_content.clone(), p.chain_stamp.clone(),
                ),
                None => continue,
            };
            // KRİTİK (bkz. `MAX_UNCONFIRMED_AGE_MS` dokümantasyonu): bu yaşı
            // aşan bir paket, karşı tarafın ratchet'i muhtemelen bir DH/KEM
            // rotasyonu yaşadığı için ARTIK KRİPTOGRAFİK OLARAK ÇÖZÜLEMEZ —
            // yeniden göndermeye devam etmek sadece alıcıya sonsuza dek
            // "Decryption failed" ürettirir.
            // bkz. `PendingConfirmation.chain_stamp`: oturumun kuşağı
            // değiştiyse bu paket karşı tarafta ARTIK çözülemez — süre
            // dolmasını beklemeden hemen tazele. Süre ölçütü yalnızca
            // "hiç rotasyon olmadı" hâli için yedek olarak duruyor.
            // Damga eş başına önceden hesaplandı (bkz. `stamp_cache`) —
            // mesaj başına bir HKDF adımı tekrarlamıyoruz.
            let stale_chain = match stamp_cache.get(&peer_fp) {
                Some(current) => !current.is_empty() && !chain_stamp.is_empty() && current != &chain_stamp,
                None => false,
            };
            if stale_chain || now.saturating_sub(first_sent_at) > MAX_UNCONFIRMED_AGE_MS {
                // Spec dışı, kullanıcı isteği: gerçek vazgeçme sınırı artık
                // `original_sent_at` (mesajın İLK kuyruğa girdiği an, bkz. o
                // alanın dokümantasyonu — tazelemeler arasında SABİT)
                // üzerinden `TEXT_RETRY_GIVE_UP_MS`. Bu, `regen_content`
                // dolu olsa BİLE kontrol edilir — aksi halde bir mesaj
                // sonsuza dek (günler/haftalar) tazelenip denenmeye devam
                // ederdi, "7 gün" sınırının hiçbir anlamı kalmazdı.
                let give_up_for_real = now.saturating_sub(original_sent_at) > TEXT_RETRY_GIVE_UP_MS;
                // Sync packets are not refreshed: re-encrypting and re-depositing
                // them every ~30 min for 7 days to a device that is switched off
                // cost ~1000 server deposits a day on mobile data. The first
                // deposit stays on the server, and a returning device catches up
                // anyway (sibling backfill, roster on reconnect, next read mark,
                // next digest).
                if matches!(regen_content, Some(
                    MessageContent::SiblingEcho { .. } | MessageContent::ReadStateSync { .. }
                    | MessageContent::DeviceSync(_) | MessageContent::WbDigest { .. })) {
                    info!("Paket {} (senkron -> {}) tazelenmeden bırakıldı", message_id, &peer_fp[..peer_fp.len().min(8)]);
                    self.awaiting_confirmation.remove(&message_id);
                    self.remove_durable_retry(&message_id);
                    continue;
                }
                if !give_up_for_real {
                    // Clone (not move) so `regen_content` is still available below for the give-up event.
                    if let Some(content) = regen_content.clone() {
                        // Spec dışı, kullanıcı geri bildirimi ("give up time
                        // bazı yerlerde sorun çıkarabilir... adam 6 saat
                        // interneti açmadı, ne yapalım?" + kullanıcı isteği:
                        // sıradan Text de dahil, karşı taraf onaylayana
                        // kadar ~7 güne kadar dener): AYNI bayatlamış
                        // şifreli paketi tekrar göndermenin anlamı yok —
                        // orijinal düz metni TAZE bir ratchet adımıyla
                        // yeniden şifreleyip AYNI `message_id`/`original_sent_at`
                        // (bkz. `send_message_content_inner`) ile devam
                        // ediyoruz, böylece UI balonu/`awaiting_confirmation`
                        // girdisi KESİNTİSİZ aynı kalır.
                        // Kind and target: the pending-messages screen lists only
                        // Text, so this line is the only place the rest shows up.
                        let kind = content.kind();
                        warn!("Paket {} ({} -> {}) onaylanmadan azami yaşı aştı, TAZELENİP AYNI kimlikle yeniden deneniyor",
                            message_id, kind, &peer_fp[..peer_fp.len().min(8)]);
                        if let Err(e) = self.send_message_content_inner(
                            peer_fp.clone(), &content, None,
                            Some(message_id.clone()), Some(original_sent_at), Some(retry_interval_ms),
                        ) {
                            // Düzeltme: log metni "kalıcı olarak vazgeçildi"
                            // diyordu ama vazgeçilmiyordu — girdi
                            // `next_retry_at <= now` ile kuyrukta kaldığı
                            // için HER `poll_events` turunda (saniyede bir)
                            // yeniden tazelenmeye çalışılıyordu; iki gün
                            // boyunca, her turda bir ratchet adımıyla
                            // birlikte. Artık geri çekilme aralığı ileri
                            // alınıyor: yeniden deneme sürüyor ama makul bir
                            // hızda (`TEXT_RETRY_GIVE_UP_MS` tavanı hâlâ
                            // geçerli).
                            error!("Tazeleme gönderim denemesi başarısız, geri çekilme aralığıyla yeniden denenecek: {}", e);
                            if let Some(pending) = self.awaiting_confirmation.get_mut(&message_id) {
                                pending.retry_interval_ms =
                                    (pending.retry_interval_ms * 2).min(ACK_RETRY_MAX_MS);
                                pending.next_retry_at = current_time_ms() + pending.retry_interval_ms;
                                pending.last_attempt_at = current_time_ms();
                                // A stale stamp makes the entry due every turn,
                                // past the backoff just set. Without it the
                                // age path decides.
                                pending.chain_stamp.clear();
                            }
                        }
                        continue;
                    }
                }
                self.awaiting_confirmation.remove(&message_id);
                self.remove_durable_retry(&message_id);
                // Marked failed: the relay copy must not deliver it later.
                self.cancel_server_deposit(&message_id);
                // Types without `regen_content` (e.g. HistorySyncResponse) OR
                // anything past `TEXT_RETRY_GIVE_UP_MS`: "Failed" olarak
                // işaretle (kullanıcı isterse manuel olarak yeniden
                // gönderebilir).
                if let NetworkEnvelope::Message(m) = &envelope {
                    self.set_message_status(&m.header.message_id, MessageSendStatus::Failed);
                    // Same fix as the Ack arm: resolve the real target from regen_content.
                    if let Some(content) = &regen_content {
                        self.note_group_copy_failed(content, &peer_fp);
                    }
                    let (event_message_id, event_group_id) = match &regen_content {
                        Some(MessageContent::Edit { target_message_id: real_target, group_id, .. }) =>
                            (real_target.clone(), group_id.clone()),
                        Some(MessageContent::Delete { target_message_id: real_target, group_id, .. }) =>
                            (real_target.clone(), group_id.clone()),
                        // As in `cancel_pending_message`: the group bubble is keyed
                        // by the group-wide id. With the packet id and no
                        // `group_id` no screen could match this event.
                        Some(MessageContent::Text { group_id: Some(gid), group_message_local_id, .. }) =>
                            (group_message_local_id.clone().unwrap_or_else(|| m.header.message_id.clone()), Some(gid.clone())),
                        _ => (m.header.message_id.clone(), None),
                    };
                    let mut status_event = serde_json::json!({
                        "type": "status", "peer": self.canonical_peer_key(&peer_fp),
                        "message_id": event_message_id, "status": "error"
                    });
                    if let Some(gid) = event_group_id {
                        status_event["group_id"] = serde_json::Value::String(gid);
                    }
                    self.attachment_events.push(status_event.to_string());
                }
                if give_up_for_real {
                    error!("Paket {} {} ms (TEXT_RETRY_GIVE_UP_MS) boyunca onaylanmadı, KESİN olarak vazgeçiliyor", message_id, TEXT_RETRY_GIVE_UP_MS);
                } else {
                    error!("Paket {} onaylanmadan azami yaşı ({} ms) aştı, vazgeçiliyor (muhtemelen ratchet rotasyonu geçti)", message_id, MAX_UNCONFIRMED_AGE_MS);
                }
                continue;
            }
            match self.try_publish_raw(&peer_fp, &envelope, current_time_ms()) {
                Ok(()) => {
                    if let NetworkEnvelope::Message(m) = &envelope {
                        // A group bubble is keyed by the group-wide id, as in
                        // the give-up arm above; the packet id matched no row.
                        let (row_id, row_group) = match &regen_content {
                            Some(MessageContent::Text { group_id: Some(gid), group_message_local_id: Some(local), .. }) =>
                                (local.clone(), Some(gid.clone())),
                            _ => (m.header.message_id.clone(), None),
                        };
                        // The bubble shows the error mark until told otherwise.
                        let was_failed = self.db.as_ref().map_or(false, |c| c.query_row(
                            "SELECT 1 FROM messages WHERE message_id = ?1 AND status = ?2 AND direction = 'sent'
                               AND (?3 IS NULL OR group_id = ?3)",
                            params![row_id, MessageSendStatus::Failed.as_str(), row_group], |_| Ok(())).is_ok());
                        if was_failed {
                            let mut ev = serde_json::json!({
                                "type": "status", "peer": self.canonical_peer_key(&peer_fp),
                                "message_id": row_id, "status": "sent"
                            });
                            if let Some(gid) = &row_group {
                                ev["group_id"] = serde_json::Value::String(gid.clone());
                                if let Some(conn) = &self.db {
                                    let _ = conn.execute(
                                        "UPDATE messages SET status = 'sent' WHERE message_id = ?1 AND group_id = ?2 AND direction = 'sent' AND status = ?3",
                                        params![row_id, gid, MessageSendStatus::Failed.as_str()],
                                    );
                                }
                            }
                            self.attachment_events.push(ev.to_string());
                        }
                        self.set_message_status(&m.header.message_id, MessageSendStatus::Sent);
                    }
                }
                // bkz. `PublishFailure` — kalıcı hata: bu zarf bir daha ASLA
                // yayınlanamaz, kuyruğu meşgul etmeye devam etmesin.
                Err(PublishFailure::Permanent(e)) => {
                    error!("Bekleyen paket {} KALICI yayın hatasıyla bırakılıyor: {}", message_id, e);
                    self.awaiting_confirmation.remove(&message_id);
                    self.remove_durable_retry(&message_id);
                    if let NetworkEnvelope::Message(m) = &envelope {
                        self.set_message_status(&m.header.message_id, MessageSendStatus::Failed);
                        self.attachment_events.push(serde_json::json!({
                            "type": "status", "peer": self.canonical_peer_key(&peer_fp),
                            "message_id": m.header.message_id, "status": "error"
                        }).to_string());
                    }
                    continue;
                }
                Err(PublishFailure::Transient(_)) => {
                    // Sessizce bir sonraki turda tekrar denenecek — henüz
                    // "Failed" olarak işaretlemiyoruz, kullanıcı açıkça
                    // "onaylanana kadar sürekli dene" istedi.
                }
            }
            if let Some(pending) = self.awaiting_confirmation.get_mut(&message_id) {
                // Spec dışı, kullanıcı isteği: Ayarlar'daki bekleyen
                // mesajlar listesinde (bkz. `list_pending_messages`)
                // gösterilecek "son deneme" zamanı.
                pending.last_attempt_at = current_time_ms();
                pending.retry_interval_ms = (pending.retry_interval_ms * 2).min(ACK_RETRY_MAX_MS);
                pending.next_retry_at = current_time_ms() + pending.retry_interval_ms;
            }
        }
    }

    /// Güvenilirlik düzeltmesi ("rotasyonu kesen mesajlar 25 dakika takılı
    /// kalıyor"): bu peer'la olan oturumda az önce bir DH/KEM rotasyonu
    /// gerçekleşti (BİZ tetikledik ya da karşı tarafın rotasyonuna cevap
    /// verdik) — `awaiting_confirmation`'da bu peer için bekleyen, ESKİ
    /// zincirle şifrelenmiş her paket artık KRİPTOGRAFİK OLARAK ÇÖZÜLEMEZ
    /// (bkz. `MAX_UNCONFIRMED_AGE_MS` notu). Önceden bu paketler 25
    /// dakikalık yaş aşımına kadar boşuna aynen yeniden gönderiliyordu —
    /// artık rotasyon ANINDA: `regen_content` taşıyanlar AYNI `message_id`/
    /// `original_sent_at`/geri-çekilme aralığıyla taze zincir altında hemen
    /// yeniden şifrelenip gönderilir; taşımayanlar (Ack/Seen/
    /// HistorySyncResponse — hiçbiri yeniden üretilemez ve hepsinin kaybı
    /// zararsızdır: Ack'lenmemiş orijinal zaten yeniden gönderilir, yanıt
    /// isteğin yeniden denemesiyle tazelenir) sessizce bırakılır.
    pub(crate) fn regen_pending_for_peer(&mut self, peer_fp: &str) {
        let mut regen: Vec<(String, MessageContent, u64, u64)> = Vec::new();
        let mut drop_ids: Vec<String> = Vec::new();
        for (id, p) in &self.awaiting_confirmation {
            if p.peer_device_fingerprint != peer_fp || self.regen_skip_id.as_ref() == Some(id) {
                continue;
            }
            if !matches!(p.envelope, NetworkEnvelope::Message(_)) {
                continue;
            }
            match &p.regen_content {
                Some(c) => regen.push((id.clone(), c.clone(), p.original_sent_at, p.retry_interval_ms)),
                None => drop_ids.push(id.clone()),
            }
        }
        if regen.is_empty() && drop_ids.is_empty() {
            return;
        }
        info!(
            "Rotasyon sonrası bekleyenler yenileniyor (peer={}): {} paket taze zincirle yeniden şifreleniyor, {} kurtarılamaz paket bırakılıyor",
            crate::log_id(&peer_fp), regen.len(), drop_ids.len()
        );
        for id in drop_ids {
            // H86: reported like the age arm of `retry_unconfirmed_messages`
            // (FileOffer/ProfileUpdate/HistorySync… cannot be re-encrypted).
            if let Some(NetworkEnvelope::Message(m)) = self.awaiting_confirmation.remove(&id).map(|p| p.envelope) {
                warn!("Rotasyon: yeniden üretilemeyen paket {} bırakıldı (Failed)", crate::log_id(&id));
                self.set_message_status(&m.header.message_id, MessageSendStatus::Failed);
                self.attachment_events.push(serde_json::json!({
                    "type": "status", "peer": self.canonical_peer_key(&peer_fp), "message_id": m.header.message_id, "status": "error"
                }).to_string());
            }
            self.remove_durable_retry(&id);
        }
        for (id, content, original_sent_at, retry_interval_ms) in regen {
            if let Err(e) = self.send_message_content_inner(
                peer_fp.to_string(), &content, None,
                Some(id.clone()), Some(original_sent_at), Some(retry_interval_ms),
            ) {
                error!("Rotasyon sonrası yeniden şifreleme başarısız (normal yaş-aşımı yolu devralır): {}", e);
                // See `retry_unconfirmed_messages`: or the stale stamp retries it every turn.
                if let Some(pending) = self.awaiting_confirmation.get_mut(&id) {
                    pending.chain_stamp.clear();
                }
            }
        }
    }

    /// Spec dışı, kullanıcı isteği: uygulama ön plana geldiğinde (bkz.
    /// Kotlin `P2PApplication` foreground algılama + JNI `retryAllPendingNow`)
    /// çağrılır — HERHANGİ bir bekleyen mesajın bir sonraki deneme zamanını
    /// (`next_retry_at`) HEMEN'e çeker, üstel geri çekilmenin doğal
    /// aralığını (şu an 120s'ye kadar) beklemeden. `awaiting_confirmation`
    /// zaten SADECE `TEXT_RETRY_GIVE_UP_MS` (7 gün) içindeki girdileri
    /// tutar — daha eskiler `retry_unconfirmed_messages`'ın yaş-aşımı
    /// kolunda zaten kalıcı olarak temizlenmiştir — bu yüzden burada AYRICA
    /// bir yaş filtresi gerekmez, mevcut TÜM girdiler zaten "son 7 gün"
    /// kapsamındadır. Gerçek gönderim denemesi, bir sonraki `poll_events`
    /// turunda (saniyede bir, Kotlin tarafından zaten çağrılıyor) normal
    /// `retry_unconfirmed_messages` yolundan geçer — burada AYRI bir ağ
    /// I/O'su YAPILMAZ (pil dostu: sadece bir zaman damgası ileri çekilir).
    pub(crate) fn retry_all_pending_now(&mut self) {
        let now = current_time_ms();
        for pending in self.awaiting_confirmation.values_mut() {
            pending.next_retry_at = now;
        }
    }

    /// Spec dışı, kullanıcı isteği: Ayarlar'daki bekleyen mesajlar
    /// listesindeki TEK bir satır için manuel "Şimdi Dene" düğmesi — bkz.
    /// `retry_all_pending_now` aynı mekanizma, ama sadece BU mesaja
    /// uygulanır. Gerçek gönderim denemesi burada YAPILMAZ (pil dostu,
    /// AYNI gerekçe) — sadece `next_retry_at`'i HEMEN'e çeker, bir sonraki
    /// `poll_events` turu (saniyede bir, zaten çalışıyor) gerçek denemeyi
    /// yapar.
    pub(crate) fn retry_pending_message_now(&mut self, message_id: &str) -> Result<(), String> {
        let pending = self.awaiting_confirmation.get_mut(message_id).ok_or("Bekleyen mesaj bulunamadı")?;
        pending.next_retry_at = current_time_ms();
        Ok(())
    }

    /// bkz. `PendingMessageSummary` dokümantasyonu.
    pub(crate) fn list_pending_messages(&self) -> Vec<PendingMessageSummary> {
        self.awaiting_confirmation.iter().filter_map(|(message_id, p)| {
            match &p.regen_content {
                Some(MessageContent::Text { group_id, text, .. }) => Some(PendingMessageSummary {
                    message_id: message_id.clone(),
                    peer_device_fingerprint: p.peer_device_fingerprint.clone(),
                    // bkz. `PendingMessageSummary.device_name` dokümantasyonu.
                    device_name: self.known_remote_devices.get(&p.peer_device_fingerprint)
                        .map(|d| d.device_name.clone())
                        .unwrap_or_default(),
                    group_id: group_id.clone(),
                    text: text.clone(),
                    original_sent_at: p.original_sent_at,
                    last_attempt_at: p.last_attempt_at,
                }),
                // Edit/Delete/GroupUpdate (veya regen_content taşımayan
                // diğer türler, ör. HistorySyncRequest/FileOffer) — bunlar
                // kullanıcının "yazdığı bir mesaj" değil, UI'da ayrı bir
                // satır olarak gösterilecek bir şeyleri yok.
                _ => None,
            }
        }).collect()
    }

    /// Spec dışı, kullanıcı isteği: Ayarlar'daki bekleyen mesajlar
    /// listesindeki "İptal" düğmesi — bir mesajı artık yeniden
    /// DENENMEYECEK şekilde kalıcı olarak bırakır (Failed olarak
    /// işaretlenir, kullanıcı isterse sohbet ekranından manuel olarak
    /// yeniden gönderebilir — bkz. mevcut `retryMessage` akışı).
    pub(crate) fn cancel_pending_message(&mut self, message_id: &str) -> Result<(), String> {
        let pending = self.awaiting_confirmation.remove(message_id).ok_or("Bekleyen mesaj bulunamadı")?;
        self.remove_durable_retry(message_id);
        // bkz. `cancel_server_deposit`: iptal, sunucudaki kopyayı da geri
        // çekmeli — aksi halde "vazgeçtim" demenin hiçbir karşılığı olmuyor
        // ve paket 30 gün sonra bile teslim edilebiliyordu.
        self.cancel_server_deposit(message_id);
        if let NetworkEnvelope::Message(m) = &pending.envelope {
            self.set_message_status(&m.header.message_id, MessageSendStatus::Failed);
            // Same fix as the Ack arm.
            if let Some(content) = &pending.regen_content {
                self.note_group_copy_failed(content, &pending.peer_device_fingerprint);
            }
            let (event_message_id, event_group_id) = match &pending.regen_content {
                Some(MessageContent::Edit { target_message_id: real_target, group_id, .. }) =>
                    (real_target.clone(), group_id.clone()),
                Some(MessageContent::Delete { target_message_id: real_target, group_id, .. }) =>
                    (real_target.clone(), group_id.clone()),
                // A group text: the bubble is keyed by the group-wide id, and
                // without `group_id` the event is taken for a 1:1 status.
                Some(MessageContent::Text { group_id: Some(gid), group_message_local_id, .. }) =>
                    (group_message_local_id.clone().unwrap_or_else(|| m.header.message_id.clone()), Some(gid.clone())),
                _ => (m.header.message_id.clone(), None),
            };
            let mut status_event = serde_json::json!({
                "type": "status", "peer": self.canonical_peer_key(&pending.peer_device_fingerprint),
                "message_id": event_message_id, "status": "error"
            });
            if let Some(gid) = event_group_id {
                status_event["group_id"] = serde_json::Value::String(gid);
            }
            self.attachment_events.push(status_event.to_string());
        }
        Ok(())
    }

    /// bkz. `own_mailbox_topic_fp` dokümantasyonu — cihazın kendi posta
    /// kutusu topic'ine aboneliğini (gerekiyorsa) tamamlar. Her `poll_events`
    /// turunda çağrılır; normal durumda ilk turda bir kez iş yapar, sonra
    /// yalnızca bir karşılaştırmadır. Kimlik `start_network`'ten SONRA
    /// oluşturulduysa/yüklendiyse (bkz. o alanın uzun notu) aboneliği burada
    /// kurar — ağ katmanını yeniden başlatmaya GEREK KALMADAN.
    ///
    /// Fingerprint'e göre karşılaştırılır (sadece "abone oldum mu" bayrağına
    /// göre değil): `import_recovery` gibi bir yol cihazın aktif
    /// fingerprint'ini DEĞİŞTİREBİLİR — o durumda yeni posta kutusuna da
    /// abone olunması gerekir.
    pub(crate) fn ensure_own_mailbox_subscription(&mut self) {
        let active_fp = match self.get_active_own_device_fingerprint() {
            Ok(fp) => fp,
            // Hâlâ kimlik yok — sessizce geç (her saniye loglamak logcat'i
            // boğardı; `start_network` bunu zaten bir kez AÇIKÇA loglamıştı).
            Err(_) => return,
        };
        if self.own_mailbox_topic_fp.as_deref() == Some(active_fp.as_str()) {
            return;
        }
        let topic = gossipsub::IdentTopic::new(format!("p2p_msg_{}", active_fp));
        let old = self.own_mailbox_topic_fp.as_ref().map(|fp| gossipsub::IdentTopic::new(format!("p2p_msg_{}", fp)));
        let subscribed = match &mut self.swarm {
            Some(swarm) => {
                // The fingerprint changed (`import_recovery`): staying on the
                // old mailbox topic keeps its traffic coming and links the
                // old and the new fingerprint for an observer.
                if let Some(old) = old {
                    let _ = swarm.behaviour_mut().gossipsub.unsubscribe(&old);
                }
                swarm.behaviour_mut().gossipsub.subscribe(&topic)
            }
            None => return,
        };
        match subscribed {
            Ok(_) => {
                info!(
                    "Kendi posta kutusu topic'ine (sonradan) abone olundu: p2p_msg_{} \
                     — bu olmadan cihaza hiçbir paket teslim edilemezdi",
                    crate::log_id(&active_fp)
                );
                self.own_mailbox_topic_fp = Some(active_fp);
            }
            Err(e) => error!("Kendi posta kutusu topic'ine abone olunamadı: {}", e),
        }
    }

    /// bkz. `pairing_mailbox_subs` — eşleşme süresince karşı tarafın posta
    /// kutusu topic'ine de abone ol (idempotent; zaten aboneyse ya da bir
    /// ratchet zaten varsa no-op).
    pub(crate) fn subscribe_pairing_mailbox(&mut self, peer_fp: &str) {
        if peer_fp.is_empty() { return; }
        if self.ratchets.contains_key(peer_fp) { return; }
        if self.own_mailbox_topic_fp.as_deref() == Some(peer_fp) { return; }
        if self.pairing_mailbox_subs.contains_key(peer_fp) { return; }
        let topic = gossipsub::IdentTopic::new(format!("p2p_msg_{}", peer_fp));
        let outcome = match &mut self.swarm {
            // Swarm yoksa: sessizce geç — ağsız eşleşme zaten tamamlanamaz,
            // IdentityExchange `pending_envelopes`'te bekler.
            None => return,
            Some(swarm) => swarm.behaviour_mut().gossipsub.subscribe(&topic),
        };
        match outcome {
            Ok(_) => {
                info!("Eşleşme: karşı tarafın posta kutusu topic'ine abone olundu (p2p_msg_{})", crate::log_id(&peer_fp));
                self.pairing_mailbox_subs.insert(peer_fp.to_string(), current_time_ms());
            }
            Err(e) => error!("Eşleşme posta kutusu aboneliği başarısız (p2p_msg_{}): {}", crate::log_id(&peer_fp), e),
        }
    }

    /// bkz. `subscribe_pairing_mailbox` — aboneliği bırak (ratchet kuruldu
    /// ya da TTL doldu).
    pub(crate) fn drop_pairing_mailbox(&mut self, peer_fp: &str) {
        if self.pairing_mailbox_subs.remove(peer_fp).is_none() { return; }
        // Kendi posta kutusu topic'imizi ASLA bırakma (fp çakışması olmamalı
        // ama savunma amaçlı).
        if self.own_mailbox_topic_fp.as_deref() == Some(peer_fp) { return; }
        let topic = gossipsub::IdentTopic::new(format!("p2p_msg_{}", peer_fp));
        if let Some(swarm) = &mut self.swarm {
            let _ = swarm.behaviour_mut().gossipsub.unsubscribe(&topic);
            info!("Eşleşme posta kutusu aboneliği bırakıldı (p2p_msg_{})", crate::log_id(&peer_fp));
        }
    }

    /// `poll_events`'ten her turda: ratchet'i kurulmuş ya da TTL'i dolmuş
    /// eşleşme aboneliklerini bırakır.
    pub(crate) fn flush_pairing_mailbox_subs(&mut self) {
        if self.pairing_mailbox_subs.is_empty() { return; }
        let now = current_time_ms();
        let done: Vec<String> = self.pairing_mailbox_subs.iter()
            .filter_map(|(fp, since)| {
                if self.ratchets.contains_key(fp)
                    || now.saturating_sub(*since) > PAIRING_MAILBOX_TTL_MS
                {
                    Some(fp.clone())
                } else {
                    None
                }
            })
            .collect();
        for fp in done {
            self.drop_pairing_mailbox(&fp);
        }
    }
}
