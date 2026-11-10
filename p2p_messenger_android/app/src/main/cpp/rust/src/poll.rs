//! `poll_events`, early-packet buffering, rate limiting and incoming envelopes.

use super::*;

impl P2PCore {

    pub(crate) fn poll_events(&mut self) -> Vec<String> {
        lock_watch::phase("swarm_events");
        // M-180: a caught panic may have left the core half-updated; tell the
        // frontend once so it can restart the service.
        if CORE_PANICKED.swap(false, std::sync::atomic::Ordering::SeqCst) {
            self.attachment_events.push(r#"{"type":"core_panic"}"#.to_string());
        }
        if self.network_change_pending
            && mono_ms().saturating_sub(self.last_network_change_at) >= NETWORK_CHANGE_DEBOUNCE_MS
        {
            self.reconnect_all_known_now();
        }
        {
            let now = mono_ms();
            let saver = self.radio_saver();
            self.radio_window_open = !saver || now >= self.radio_window_at;
            if saver && self.radio_window_open {
                self.radio_window_at = now + self.radio_window_ms();
                // Every window fetches. A sleeping phone can miss the
                // server's Notify (its CPU was suspended: device test
                // 2026-10-08), and with the 5 min fetch sweep a window could
                // pass without one. The radio is up for the window anyway.
                for rt in self.server_rt.values_mut() {
                    rt.fetch_due_at = 0;
                }
                self.server_sweep_at = 0;
                if now >= self.tor_wake_at {
                    self.tor_wake_at = now + TOR_FULL_WAKE_MS;
                }
            }
            // Tor dormant in radio-saver mode; awake RADIO_AWAKE_MS after a
            // full wake (dir refresh, circuit pool) and during calls.
            let dormant = saver
                && self.call.is_none()
                // A transfer needs circuits rebuilt when one breaks.
                && self.active_downloads.is_empty()
                && !self.blob_upload_can_run()
                && now >= (self.tor_wake_at + RADIO_AWAKE_MS).saturating_sub(TOR_FULL_WAKE_MS);
            if dormant != self.tor_dormant {
                if let Some(tor) = &self.tor {
                    tor.set_dormant(dormant);
                    info!("Tor dormant: {}", dormant);
                    self.tor_dormant = dormant;
                }
            }
        }
        self.call_sweep();
        // bkz. `ensure_own_mailbox_subscription` — cihazın ulaşılabilirliğinin
        // ÖN KOŞULU; kimlik ağ katmanından sonra oluşmuş olabilir.
        self.ensure_own_mailbox_subscription();
        // bkz. `pairing_mailbox_subs` — ratchet'i kurulmuş/TTL'i dolmuş
        // eşleşme aboneliklerini bırak.
        self.flush_pairing_mailbox_subs();
        // `Option<PeerId>` — gossipsub `Signed` authenticity modu (bkz.
        // start_network) her gelen mesajda gönderenin gerçek `PeerId`'sini
        // taşır; bu, dosya eki indirmesi (`request_response`, bkz.
        // `device_to_peer_id`) için gereken PeerId eşlemesinin KAYNAĞI —
        // önceden bu bilgi okunup hemen atılıyordu.
        let mut incoming: Vec<(Option<PeerId>, Vec<u8>)> = Vec::new();
        // (connection it came over, author, data)
        let mut gossip_incoming: Vec<(PeerId, Option<PeerId>, Vec<u8>)> = Vec::new();
        // `true` = new, `false` = expired; in event order.
        let mut listen_addr_changes: Vec<(Multiaddr, bool)> = Vec::new();
        let mut closed_listener_ids: Vec<libp2p::core::transport::ListenerId> = Vec::new();
        let mut direct_requests: Vec<(PeerId, Vec<u8>, request_response::ResponseChannel<EnvelopeResponse>)> = Vec::new();
        let mut new_peer_addrs: Vec<(PeerId, Multiaddr)> = Vec::new();
        let mut new_peer_onions: Vec<(PeerId, Multiaddr)> = Vec::new();
        // bkz. `known_relay_peers` alanı dokümantasyonu — identify'dan
        // "bu peer röle protokolünü konuşuyor" öğrenildiğinde doldurulur,
        // döngü bitince (aşağıda `self.record_known_relay` ile) uygulanır
        // (döngü içinde `self.swarm` zaten `&mut` borrow'lu, `self`'in
        // TAMAMINA erişemiyoruz — bkz. dosyadaki aynı desenin diğer
        // örnekleri, ör. `new_peer_addrs`).
        let mut new_relay_peers: Vec<(PeerId, Multiaddr)> = Vec::new();
        let mut file_chunk_events: Vec<FileChunkEventLocal> = Vec::new();
        let mut ack_events: Vec<AckEventLocal> = Vec::new();
        let mut subscribed_peers: Vec<PeerId> = Vec::new();
        // bkz. `server_client::ServerEventLocal` — `file_chunk_events` ile
        // AYNI "önce topla, sonra işle" deseni: swarm `&mut` borrow'u
        // altındayken `self`'in tamamına erişemiyoruz.
        let mut server_events: Vec<server_client::ServerEventLocal> = Vec::new();
        // Spec dışı, ağ sağlamlığı düzeltmesi ("connection testing and
        // re-connecting automatically should be better"): bir bağlantı
        // kapandığında (temiz kapanış VEYA aşağıdaki Ping kolunun
        // AÇIKÇA kapattığı bir "yarı açık" bağlantı) ilgili `PeerId`
        // buraya toplanır — döngü bitince (bkz. `self.swarm` borrow'unun
        // kapanması gerektiği dosyadaki diğer örnekler) karşılık gelen
        // cihaz fingerprint'i için ANINDA yeniden bağlanma denenir (bkz.
        // `try_reconnect_device`) — periyodik `reconnect_sweep`'in bir
        // sonraki turunu (≤15sn) BEKLEMEDEN.
        let mut connections_lost: Vec<PeerId> = Vec::new();
        // bkz. `extra_conns` — swarm borrow'u altında `self`'e yazamıyoruz,
        // dosyadaki diğer örneklerle aynı "önce topla, sonra işle" deseni.
        let mut new_extra_conns: Vec<(PeerId, libp2p::swarm::ConnectionId)> = Vec::new();
        let mut closed_conns: Vec<(PeerId, libp2p::swarm::ConnectionId)> = Vec::new();
        let mut failed_dials: Vec<libp2p::swarm::ConnectionId> = Vec::new();
        let mut established_conns: Vec<(PeerId, libp2p::swarm::ConnectionId)> = Vec::new();
        let mut new_conn_ranks: Vec<(libp2p::swarm::ConnectionId, u8)> = Vec::new();
        let mut new_inbound: Vec<(libp2p::swarm::ConnectionId, PeerId)> = Vec::new();
        // (server peer, answered?) — see `server_rpc_timeouts`
        let mut server_rpc_outcomes: Vec<(PeerId, bool)> = Vec::new();
        let mut envelope_events: Vec<EnvelopeEventLocal> = Vec::new();
        // Spec dışı, ağ sağlamlığı düzeltmesi ("üç Tor eşli, biri hariç
        // ikisi hem online görünüp hem hiç mesajlaşamıyor" hatası): bir
        // bağlantı kurulduğunda (yeniden bağlanma DAHİL) buraya toplanır —
        // döngü bitince (`self.ratchets`e erişebilmek için, `self.swarm`
        // borrow'u kapandıktan sonra) bu peer için ZATEN bir ratchet
        // oturumu varsa `resubscribe_ratchet_topic` YENİDEN çağrılır. Bu
        // NORMALDE gereksizdir (gossipsub kendi abonelik durumunu her yeni
        // bağlantıda karşı tarafa otomatik bildirir) — ama Tor devreleri
        // (özellikle röle/DCUtR üzerinden kurulanlar) düz TCP'den ÇOK daha
        // sık kopup yeniden kuruluyor, ve bu otomatik bildirimin SESSİZCE
        // başarısız olduğu (ör. gossipsub davranışı henüz yeni bağlantıyı
        // işlemeden bir sonraki devre kopması) tek bir durum bile o çift
        // için mesh'i KALICI OLARAK bozup `awaiting_confirmation`'ın
        // süresiz yeniden deneme döngüsüne (bkz. o alanın dokümantasyonu)
        // hiç sonuçsuz kalan bir "pending" mesaja yol açabilir — idempotent
        // ve ucuz olduğundan (zaten abone bir topic'e tekrar `subscribe`
        // çağırmak no-op) HER bağlantıda bir güvenlik ağı olarak tekrarlanır.
        let mut connections_established: Vec<PeerId> = Vec::new();
        // bkz. `keepalive_state` alanı dokümantasyonu — aşağıdaki Keepalive
        // kolunun `self.swarm` borrow'u bitene kadar `self`'in TAMAMINA
        // erişemediği için (dosyadaki aynı desenin diğer örnekleri,
        // `mem::take` kullanımı için bkz. `pending_envelopes`) buraya
        // taşınır, döngü içinde serbestçe güncellenir, döngü bitince geri
        // konur.
        let mut keepalive_state = std::mem::take(&mut self.keepalive_state);
        // A panic in an earlier turn left the map taken out (empty) while the
        // connections live on: watch them again instead of never pinging them.
        if keepalive_state.is_empty() {
            if let Some(swarm) = &self.swarm {
                for peer_id in swarm.connected_peers() {
                    keepalive_state.insert(*peer_id, KeepAliveState {
                        connected_since: mono_ms(),
                        next_due_at: mono_ms() + KEEPALIVE_FAST_INTERVAL_MS,
                        consecutive_failures: 0,
                        outstanding: None,
                        suspect: false,
                        interval_ms: 0,
                        quiet_capable: false,
                    });
                }
            }
        }
        // bkz. aşağıdaki keepalive filtresi — `self` `swarm` borrow'u altında
        // erişilemeyeceği için ÖNCEDEN toplanıyor.
        let server_peers: Vec<PeerId> = self.server_peer_ids();
        // `self` aşağıdaki `block_on` içinde swarm üzerinden ödünç alındığı
        // için bayrak ÖNCEDEN yerel bir kopyaya alınıyor (bkz. `server_peers`
        // aynı desen).
        let power_save = self.power_save;
        let saver = self.radio_saver();
        let window_ms = self.radio_window_ms();
        let window_open = self.radio_window_open;
        // bkz. `deferred_swarm_events` — geçen turun flush'ında düşen
        // olaylar, taze olaylardan ÖNCE işlenmeli (geliş sırası).
        let mut deferred = std::mem::take(&mut self.deferred_swarm_events);
        deferred.reverse(); // `pop()` ile FIFO tüketilebilsin
        if let Some(swarm) = &mut self.swarm {
            RUNTIME.block_on(async {
                // bkz. `KeepAliveState`/`KEEPALIVE_FAST_INTERVAL_MS`
                // dokümantasyonu — süresi gelmiş (ve zaten yanıt beklemeyen)
                // her bağlantı için taze bir keepalive isteği gönderir,
                // bir sonraki gönderim zamanını bağlantının YAŞINA göre
                // (henüz stabilize olmadıysa hızlı, olduysa genişletilmiş
                // aralık) planlar. `poll_events` saniyede bir çağrıldığından
                // (bkz. o fonksiyonun dokümantasyonu) bu, en fazla ~1sn'lik
                // bir hata payıyla zamanında çalışır — ayrı bir zamanlayıcıya
                // gerek yok.
                let now = mono_ms();
                let due: Vec<PeerId> = keepalive_state.iter()
                    .filter(|(_, s)| s.outstanding.is_none() && now >= s.next_due_at && window_open)
                    .map(|(peer, _)| *peer)
                    // Sunucu bu protokolü konuşmuyor: her yoklama boşa bir
                    // gidiş-dönüş (üstelik veriyi taşıyan AYNI Tor devresinde)
                    // ve 20 saniyede bir "Keepalive desteklenmiyor" uyarısı
                    // demekti. Sunucu bağlantısının canlılığı zaten her
                    // `Fetch`/`Deposit` yanıtından biliniyor.
                    .filter(|peer| !server_peers.contains(peer))
                    .collect();
                for peer in due {
                    let request_id = swarm.behaviour_mut().keepalive.send_request(&peer, KeepAliveRequest);
                    if let Some(state) = keepalive_state.get_mut(&peer) {
                        state.outstanding = Some(request_id);
                    }
                }
                // A bounded drain: a peer that never lets the swarm go idle
                // kept the core lock in this loop. The rest waits in the
                // swarm (or `deferred`) for the next turn, which starts at once.
                let mut budget = MAX_SWARM_EVENTS_PER_TURN;
                loop {
                    if budget == 0 {
                        break;
                    }
                    budget -= 1;
                    let event = match deferred.pop() {
                        Some(e) => e,
                        None => match swarm.next().now_or_never().flatten() {
                            Some(e) => e,
                            None => break,
                        },
                    };
                    match event {
                        libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                            // Gerçek dinleme adresi — QR/"Kodum" ekranındaki
                            // `node_address`'in kaynağı budur (bkz.
                            // own_listen_addrs alanı dokümantasyonu ve
                            // get_node_address).
                            if address.iter().any(|p| matches!(p, MultiaddrProtocol::P2pCircuit)) {
                                info!("Röle rezervasyonu kabul edildi: {}", address);
                            }
                            listen_addr_changes.push((address, true));
                        }
                        libp2p::swarm::SwarmEvent::ExpiredListenAddr { address, .. } => {
                            listen_addr_changes.push((address, false));
                        }
                        // A closed listener (a dropped relay reservation) reports
                        // its addresses here only, not as `ExpiredListenAddr`.
                        libp2p::swarm::SwarmEvent::ListenerClosed { listener_id, addresses, .. } => {
                            closed_listener_ids.push(listener_id);
                            listen_addr_changes.extend(addresses.into_iter().map(|a| (a, false)));
                        }
                        // Karşı taraf bir topic'imize abone oldu: yeni bağlantıda
                        // mesh artık hazır — bekleyenleri 15 sn'lik denemeyi
                        // beklemeden gönder (bkz. aşağıda `subscribed_peers`).
                        libp2p::swarm::SwarmEvent::Behaviour(P2PBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, .. })) => {
                            subscribed_peers.push(peer_id);
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(P2PBehaviourEvent::Gossipsub(gossipsub::Event::Message { propagation_source, message, .. })) => {
                            gossip_incoming.push((propagation_source, message.source, message.data));
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(P2PBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                            if info.protocols.iter().any(|p| p.as_ref() == KEEPALIVE_QUIET_PROTOCOL) {
                                if let Some(state) = keepalive_state.get_mut(&peer_id) {
                                    state.quiet_capable = true;
                                }
                            }
                            // bkz. `known_relay_peers` alanı dokümantasyonu
                            // (SECURITY.md "Cross-network connectivity"):
                            // bu peer röle (Circuit Relay v2 HOP) protokolünü
                            // konuşuyorsa VE en az bir dinleme adresi
                            // bildiriyorsa, ileride başka bir erişilemez
                            // peer'a ulaşmak için kullanılabilecek bir röle
                            // adayı olarak kaydediyoruz. `listen_addrs`
                            // tüketilmeden (aşağıdaki kad.add_address
                            // döngüsü onu MOVE eder) önce, ilk adresi
                            // kopyalıyoruz.
                            if info.protocols.iter().any(|p| *p == relay::HOP_PROTOCOL_NAME) {
                                // Loopback karşı tarafta anlamsız. Röle istemcisi
                                // röleye zaten bağlıysa o bağlantıyı kullanır;
                                // adres yalnızca yeniden dial için.
                                if let Some(addr) = info.listen_addrs.iter().find(|a| !is_loopback_multiaddr(a)) {
                                    new_relay_peers.push((peer_id, addr.clone().with(MultiaddrProtocol::P2p(peer_id))));
                                }
                            }
                            // bkz. ConnectionEstablished'teki `is_dialer()`
                            // notu: GELEN bir bağlantıdan dialable bir adres
                            // öğrenemiyoruz. Identify ise karşı tarafın
                            // KENDİ bildirdiği dinleme adreslerini taşır —
                            // yeniden bağlanma ipucunun doğru kaynağı budur.
                            // Loopback'i atlıyoruz (karşı tarafta bize göre
                            // anlamsız); LAN adresi tercih edilir, yoksa ilk
                            // dialable adres. `.onion` burada KASITLI olarak
                            // alınmıyor — onun kendi tablosu var
                            // (`device_onion_addr`, bkz. AddressAnnounce).
                            if let Some(addr) = info.listen_addrs.iter()
                                .find(|a| is_private_lan_multiaddr(a))
                                .or_else(|| info.listen_addrs.iter()
                                    .find(|a| !is_loopback_multiaddr(a) && !is_onion_multiaddr(a)))
                            {
                                new_peer_addrs.push((peer_id, addr.clone().with(MultiaddrProtocol::P2p(peer_id))));
                            }
                            // Kademlia'ya Identify'dan öğrenilen adresleri
                            // ekle — bölüm 4.2, Kademlia'nın kendiliğinden
                            // yapamadığı adres öğrenme adımı.
                            // Not loopback: a peer-id-only dial asks Kademlia for addresses,
                            // and 127.0.0.1 reaches our own node.
                            // Not the peer's relay reservation (`/dns/relay.onion/../p2p-circuit`):
                            // that address carries the RELAY's id, and the device was
                            // then bound to the relay.
                            if let Some(addr) = info.listen_addrs.iter().find(|a| {
                                is_onion_multiaddr(a) && !a.iter().any(|p| matches!(p, MultiaddrProtocol::P2pCircuit))
                            }) {
                                new_peer_onions.push((peer_id, addr.clone()));
                            }
                            for addr in info.listen_addrs.into_iter().filter(|a| !is_loopback_multiaddr(a)) {
                                swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                            }
                        }
                        // DHT peers (the server node) pass on the loopback listen addresses
                        // other clients advertised. Dialing 127.0.0.1 only ever reaches
                        // ourselves, so remove them before a dial uses one.
                        libp2p::swarm::SwarmEvent::Behaviour(P2PBehaviourEvent::Kad(kad::Event::RoutingUpdated { peer, addresses, .. })) => {
                            for a in addresses.iter().filter(|a| is_loopback_multiaddr(a)) {
                                swarm.behaviour_mut().kad.remove_address(&peer, a);
                            }
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(P2PBehaviourEvent::ServerRpc(rr_event)) => {
                            match rr_event {
                                request_response::Event::Message { peer, message: request_response::Message::Request { request, channel, .. } } => {
                                    server_events.push(server_client::ServerEventLocal::Request { peer, request, channel });
                                }
                                request_response::Event::Message { peer, message: request_response::Message::Response { request_id, response } } => {
                                    server_rpc_outcomes.push((peer, true));
                                    server_events.push(server_client::ServerEventLocal::Response { request_id, response });
                                }
                                request_response::Event::OutboundFailure { peer, request_id, error } => {
                                    if matches!(error, request_response::OutboundFailure::Timeout) {
                                        server_rpc_outcomes.push((peer, false));
                                    }
                                    warn!("Sunucu isteği başarısız: {:?}", error);
                                    server_events.push(server_client::ServerEventLocal::OutboundFailure { request_id });
                                }
                                request_response::Event::InboundFailure { error, .. } => {
                                    warn!("Sunucuya yanıt gönderilemedi: {:?}", error);
                                }
                                request_response::Event::ResponseSent { .. } => {}
                            }
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(P2PBehaviourEvent::Envelopes(rr_event)) => {
                            match rr_event {
                                request_response::Event::Message { peer, message: request_response::Message::Request { request, channel, .. } } => {
                                    // Answered below, once the rate limit is known.
                                    direct_requests.push((peer, request.bytes, channel));
                                }
                                request_response::Event::Message { message: request_response::Message::Response { request_id, .. }, .. } => {
                                    envelope_events.push(EnvelopeEventLocal::Delivered { request_id });
                                }
                                request_response::Event::OutboundFailure { request_id, error, .. } => {
                                    envelope_events.push(EnvelopeEventLocal::Failed { request_id, error: error.to_string() });
                                }
                                request_response::Event::InboundFailure { .. } | request_response::Event::ResponseSent { .. } => {}
                            }
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(P2PBehaviourEvent::Acks(rr_event)) => {
                            match rr_event {
                                request_response::Event::Message { peer, message: request_response::Message::Request { request, channel, .. }, .. } => {
                                    ack_events.push(AckEventLocal::Request { peer, ids: request.ids, channel });
                                }
                                request_response::Event::Message { message: request_response::Message::Response { request_id, .. }, .. } => {
                                    ack_events.push(AckEventLocal::Delivered { request_id });
                                }
                                request_response::Event::OutboundFailure { request_id, error, .. } => {
                                    warn!("Toplu Ack isteği başarısız, şifreli pakete düşülüyor: {:?}", error);
                                    ack_events.push(AckEventLocal::Failed { request_id });
                                }
                                request_response::Event::InboundFailure { .. } | request_response::Event::ResponseSent { .. } => {}
                            }
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(P2PBehaviourEvent::FileChunks(rr_event)) => {
                            match rr_event {
                                request_response::Event::Message { peer, message: request_response::Message::Request { request, channel, .. }, .. } => {
                                    file_chunk_events.push(FileChunkEventLocal::Request { peer, request, channel });
                                }
                                request_response::Event::Message { message: request_response::Message::Response { request_id, response }, .. } => {
                                    file_chunk_events.push(FileChunkEventLocal::Response { request_id, response });
                                }
                                request_response::Event::OutboundFailure { request_id, error, .. } => {
                                    error!("Dosya parça isteği başarısız: {:?}", error);
                                    file_chunk_events.push(FileChunkEventLocal::OutboundFailure { request_id });
                                }
                                request_response::Event::InboundFailure { error, .. } => {
                                    error!("Dosya parça yanıtı gönderilemedi: {:?}", error);
                                }
                                request_response::Event::ResponseSent { .. } => {}
                            }
                        }
                        // NOT (tanı amaçlı): dial()'ın kendisi SADECE senkron/
                        // anlık hataları (bkz. process_qr_packet) yakalar —
                        // asıl bağlantı denemesi ASENKRON yürür ve
                        // başarılı/başarısız olduğunda buraya
                        // ConnectionEstablished/OutgoingConnectionError olarak
                        // düşer. Bunları loglamadan "handshake neden
                        // tamamlanmıyor" sorusu tamamen kör kalırdı — bkz.
                        // `adb logcat` ile bu satırları arayın.
                        libp2p::swarm::SwarmEvent::ConnectionEstablished { peer_id, endpoint, connection_id, num_established, .. } => {
                            info!("libp2p bağlantısı kuruldu: peer={} adres={:?} giden_mi={} bağlantı_sayısı={}", crate::log_id(&peer_id), endpoint.get_remote_address(), endpoint.is_dialer(), num_established);
                            established_conns.push((peer_id, connection_id));
                            new_conn_ranks.push((connection_id, conn_path_rank(endpoint.get_remote_address())));
                            if !endpoint.is_dialer() {
                                new_inbound.push((connection_id, peer_id));
                            }
                            // İKİ CİHAZLI GERÇEK TESTTE BULUNDU: burada
                            // `is_dialer()` koşulu YOKTU ve bu, aynı LAN'daki
                            // iki cihazın yeniden bağlanmasını KALICI olarak
                            // bozuyordu.
                            //
                            // `get_remote_address()` GİDEN bir bağlantıda
                            // dial ettiğimiz adresi verir (dialable, doğru).
                            // GELEN bir bağlantıda ise `send_back_addr`'ı
                            // verir — yani karşı tarafın o TCP oturumu için
                            // kullandığı EPHEMERAL KAYNAK PORTU. Hiçbir şey
                            // o portu dinlemiyor; oturum bitince yok oluyor.
                            //
                            // Bu adres `peer_id_to_addr`'a, oradan
                            // `record_peer_id_if_known` ile `device_addrs`
                            // tablosuna KALICI "yeniden bağlanma ipucu"
                            // olarak yazılıyordu. Gözlenen sonuç: A'nın
                            // B için sakladığı adres
                            // `/ip4/192.168.1.103/tcp/55230` idi, oysa B
                            // 42611'i dinliyor. B yeniden başlayınca A onu
                            // LAN üzerinden bir daha ASLA arayamıyor, tüm
                            // trafik Tor'a/sunucuya düşüyordu.
                            //
                            // Gelen bağlantılarda karşı tarafın GERÇEK
                            // dinleme adresi identify'dan öğrenilir (bkz.
                            // aşağıdaki Identify kolu).
                            if endpoint.is_dialer() {
                                new_peer_addrs.push((peer_id, endpoint.get_remote_address().clone()));
                            }
                            // First connection only. An extra one (bulk circuit,
                            // suspect replacement) is not "the peer came back", and
                            // each of them restarted every retry and every failed
                            // download from this peer.
                            if num_established.get() == 1 {
                                connections_established.push(peer_id);
                            }
                            // İlkinden sonraki her bağlantı "fazladan"dır —
                            // aktarım bitince tam olarak bunlar kapatılacak
                            // (bkz. `extra_conns`). Yalnızca BİZİM açtığımız:
                            // gelen fazladan bağlantıları karşı taraf kendi
                            // indirmesi için açmıştır; önceden dosyayı sunan
                            // taraf "benim aktarımım yok" deyip onları aktarım
                            // sürerken kapatıyor, parça istekleri
                            // ConnectionClosed ile düşüyordu (cihazda görüldü).
                            if num_established.get() > 1 && endpoint.is_dialer() {
                                new_extra_conns.push((peer_id, connection_id));
                            }
                            // bkz. `KeepAliveState` dokümantasyonu — taze bir
                            // bağlantı HENÜZ stabilize sayılmaz, hızlı
                            // aralıkla başlar (`KEEPALIVE_FAST_INTERVAL_MS`).
                            // `entry().or_insert_with()`: aynı peer'a İKİNCİ
                            // bir bağlantı (mDNS doğrudan + Tor + röle aynı
                            // anda kurulabiliyor, bkz. dial_with_relay_fallback)
                            // mevcut keepalive geçmişini/stabilizasyon saatini
                            // SIFIRLAMAMALI — peer zaten izleniyor.
                            keepalive_state.entry(peer_id).or_insert_with(|| KeepAliveState {
                                connected_since: mono_ms(),
                                next_due_at: mono_ms() + KEEPALIVE_FAST_INTERVAL_MS,
                                consecutive_failures: 0,
                                outstanding: None,
                                suspect: false,
                                interval_ms: 0,
                                quiet_capable: false,
                            });
                        }
                        libp2p::swarm::SwarmEvent::OutgoingConnectionError { peer_id, error, connection_id } => {
                            error!("Dial başarısız: peer={:?} hata={}", peer_id.as_ref().map(|p| crate::log_id(p)), error);
                            failed_dials.push(connection_id);
                        }
                        libp2p::swarm::SwarmEvent::IncomingConnectionError { error, send_back_addr, .. } => {
                            error!("Gelen bağlantı başarısız: adres={} hata={}", send_back_addr, error);
                        }
                        libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, cause, num_established, connection_id, .. } => {
                            info!("libp2p bağlantısı kapandı: peer={} sebep={:?} kalan_bağlantı={}", crate::log_id(&peer_id), cause, num_established);
                            closed_conns.push((peer_id, connection_id));
                            // Spec dışı, ağ sağlamlığı düzeltmesi: bkz.
                            // `connections_lost` dokümantasyonu — önceden
                            // bu SADECE loglanıyordu.
                            //
                            // Güvenilirlik düzeltmesi (çoklu bağlantı): bu
                            // olay HER bağlantı kapanışında ayrı ayrı tetiklenir
                            // — aynı peer'a birden fazla bağlantı yaygın (mDNS
                            // doğrudan + Tor + röle). Önceden TEK bir bağlantının
                            // kapanması, peer hâlâ bağlıyken keepalive durumunu
                            // silip (bir daha ASLA yeniden kurulmuyordu — yeni
                            // ConnectionEstablished gelmeden `keepalive_state`'e
                            // giriş eklenmez) gereksiz yeniden-dial tetikliyordu.
                            // Peer ancak SON bağlantısı da kapandığında
                            // (num_established == 0) gerçekten "koptu" sayılır.
                            if num_established == 0 {
                                connections_lost.push(peer_id);
                            }
                        }
                        // Spec dışı, kullanıcı isteği ("connection testing",
                        // sonra "ilk ping başarısız olunca direkt reconnect
                        // denemek yerine 2sn aralıklarla 3 kere ping denesin
                        // önce", sonra pil sağlamlığı düzeltmesi): bkz.
                        // `P2PBehaviour.keepalive`/`KeepAliveState`/
                        // `KEEPALIVE_FAILURES_BEFORE_DISCONNECT` dokümantasyonu.
                        // Zaman aşımına uğrayan/I/O hatasıyla başarısız olan
                        // bir keepalive, bu bağlantının "yarı açık"
                        // olabileceğini gösterir — ama TEK başına kesin kanıt
                        // değildir (kaybolmuş tek bir paket/anlık gecikme de
                        // aynı sonucu verir). Bu yüzden İLK başarısızlıkta
                        // DEĞİL, `KEEPALIVE_FAILURES_BEFORE_DISCONNECT` (3)
                        // ardışık başarısızlıktan SONRA bağlantı AÇIKÇA
                        // kapatılıyor: bu hem `is_connected()`'ı (dolayısıyla
                        // UI'nin "Bağlı" göstergesi) doğru hâle getirir HEM DE
                        // yukarıdaki `ConnectionClosed` kolunu tetikleyip
                        // ANINDA yeniden bağlanmayı başlatır. Herhangi bir
                        // BAŞARILI keepalive sayacı sıfırlar VE (bağlantı
                        // yeterince eskiyse) gönderim aralığını genişletir —
                        // ardışıklık şartı bu şekilde korunur.
                        //
                        // `UnsupportedProtocols` FARKLI bir kategori — SADECE
                        // karşı taraf bu protokolü (henüz bu özel keepalive'ı
                        // desteklemeyen eski bir sürüm) hiç bilmediğinde
                        // oluşur; "yarı açık" bağlantı BELİRTİSİ DEĞİLDİR —
                        // eski `ping::Failure::Unsupported` koluyla AYNI
                        // gerekçe. Bunu zorla kapatmak sağlıklı bağlantılarda
                        // gereksiz kopma/yeniden bağlanma döngüsü YARATIRDI.
                        // Bu yüzden sadece logluyoruz, sayaca da katmıyoruz,
                        // bağlantıyı KAPATMIYORUZ.
                        libp2p::swarm::SwarmEvent::Behaviour(P2PBehaviourEvent::Keepalive(rr_event)) => {
                            match rr_event {
                                request_response::Event::Message { peer, message: request_response::Message::Request { channel, .. }, .. } => {
                                    let capable = keepalive_state.get(&peer).is_some_and(|s| s.quiet_capable);
                                    let quiet_ms = (saver && capable).then_some(window_ms);
                                    if swarm.behaviour_mut().keepalive.send_response(channel, KeepAliveResponse { quiet_ms }).is_err() {
                                        debug!("Keepalive answer to {} not sent (channel closed)", peer);
                                    }
                                    if let Some(state) = keepalive_state.get_mut(&peer) {
                                        if !saver && state.outstanding.is_none() && !state.suspect && state.interval_ms > 0 {
                                            state.consecutive_failures = 0;
                                            state.next_due_at = mono_ms() + state.interval_ms;
                                        }
                                    }
                                }
                                request_response::Event::Message { peer, message: request_response::Message::Response { response, .. }, .. } => {
                                    if let Some(state) = keepalive_state.get_mut(&peer) {
                                        state.consecutive_failures = 0;
                                        state.outstanding = None;
                                        state.suspect = false;
                                        let now = mono_ms();
                                        let stabilized = now.saturating_sub(state.connected_since) >= KEEPALIVE_STABILIZE_MS;
                                        // bkz. `power_save` / `KEEPALIVE_POWER_SAVE_INTERVAL_MS`:
                                        // ekran kapalıyken kanıtlanmış bir
                                        // bağlantı 60 sn'de bir yoklanıyor,
                                        // radyoya uzun uyku pencereleri açsın diye.
                                        // Radio saver: straight to the window,
                                        // no 2 s "stabilizing" probes (each
                                        // one is a radio wake on LTE).
                                        let interval = if saver {
                                            window_ms
                                        } else if !stabilized {
                                            KEEPALIVE_FAST_INTERVAL_MS
                                        } else if power_save {
                                            KEEPALIVE_POWER_SAVE_INTERVAL_MS
                                        } else {
                                            KEEPALIVE_IDLE_INTERVAL_MS
                                        };
                                        // The peer is saving radio: honour it.
                                        // `quiet_ms` is peer-supplied: an honest peer never asks for
                                        // more than `RADIO_WINDOW_MS`. Unclamped, a huge value turned
                                        // keepalive off, and `u64::MAX` wrapped `next_due_at`.
                                        let interval = interval.max(response.quiet_ms.unwrap_or(0).min(RADIO_WINDOW_MS));
                                        // Saver: the window is open for one poll turn. A due
                                        // time of "answer + window" is just after the next
                                        // window, so the peer was probed every second one.
                                        let wait = if saver { interval.saturating_sub(RADIO_AWAKE_MS) } else { interval };
                                        state.next_due_at = now.saturating_add(wait);
                                        state.interval_ms = interval;
                                    }
                                }
                                request_response::Event::OutboundFailure { peer, error, .. } => {
                                    if matches!(error, request_response::OutboundFailure::UnsupportedProtocols) {
                                        warn!("Keepalive desteklenmiyor (bağlantı sağlıklı kabul ediliyor, kapatılMIYOR): peer={}", crate::log_id(&peer));
                                        if let Some(state) = keepalive_state.get_mut(&peer) {
                                            state.outstanding = None;
                                            // Hourly, not never (L-12): a peer that upgrades
                                            // within this session is probed again.
                                            state.next_due_at = mono_ms().saturating_add(60 * 60_000);
                                        }
                                    } else if matches!(error, request_response::OutboundFailure::ConnectionClosed)
                                        && swarm.is_connected(&peer)
                                    {
                                        // The probe rode a connection we just closed (a surplus or a
                                        // suspect's replacement) while another is up. Counting it as a
                                        // failure made `disconnect_peer_id` kill the fresh connection
                                        // too (device, 2026-09-18). Probe again on the live one.
                                        if let Some(state) = keepalive_state.get_mut(&peer) {
                                            state.outstanding = None;
                                            state.next_due_at = mono_ms() + KEEPALIVE_FAST_INTERVAL_MS;
                                        }
                                    } else if let Some(state) = keepalive_state.get_mut(&peer) {
                                        state.outstanding = None;
                                        state.consecutive_failures += 1;
                                        let limit = if state.suspect { 1 } else { KEEPALIVE_FAILURES_BEFORE_DISCONNECT };
                                        if state.consecutive_failures >= limit {
                                            warn!(
                                                "Keepalive {} kez ardışık başarısız (bağlantı yarı açık kabul ediliyor), kapatılıp yeniden bağlanılacak: peer={} hata={}",
                                                state.consecutive_failures, crate::log_id(&peer), error
                                            );
                                            keepalive_state.remove(&peer);
                                            let _ = swarm.disconnect_peer_id(peer);
                                        } else {
                                            warn!(
                                                "Keepalive başarısız (deneme {}/{}), kısa süre sonra tekrar denenecek: peer={} hata={}",
                                                state.consecutive_failures, KEEPALIVE_FAILURES_BEFORE_DISCONNECT, crate::log_id(&peer), error
                                            );
                                            // Başarısız denemeden hemen sonra tekrar dene — tam
                                            // `KEEPALIVE_FAST_INTERVAL_MS`/`KEEPALIVE_IDLE_INTERVAL_MS`
                                            // kadar beklemek ardışıklık tespitini gereksiz yavaşlatırdı.
                                            state.next_due_at = mono_ms() + KEEPALIVE_FAST_INTERVAL_MS;
                                        }
                                    }
                                }
                                request_response::Event::InboundFailure { peer, error, .. } => {
                                    warn!("Keepalive yanıtı gönderilemedi: peer={} hata={}", crate::log_id(&peer), error);
                                }
                                request_response::Event::ResponseSent { .. } => {}
                            }
                        }
                        _ => {}
                    }
                }
            });
        }
        // Left over past the budget: first in line next turn.
        deferred.reverse();
        deferred.append(&mut self.deferred_swarm_events);
        self.deferred_swarm_events = deferred;
        // bkz. `keepalive_state` alanı dokümantasyonu — döngü boyunca
        // üzerinde çalışılan yerel kopya geri konuyor.
        self.keepalive_state = keepalive_state;
        // Second+ outbound connections that are not bulk-transfer dials: reconnect
        // races (onion + LAN + relay at once) or a suspect's parallel dial.
        let mut surplus_dials: std::collections::HashSet<libp2p::swarm::ConnectionId> = std::collections::HashSet::new();
        for (peer, cid) in new_extra_conns {
            if self.bulk_dials.remove(&cid).is_some() {
                self.extra_conns.entry(peer).or_default().push(cid);
            } else {
                surplus_dials.insert(cid);
            }
        }
        for (peer, cid) in &established_conns {
            self.peer_conns.entry(*peer).or_default().push(*cid);
            // A bulk dial that landed as the peer's only connection.
            self.bulk_dials.remove(cid);
        }
        // A failed bulk dial stayed in `bulk_dials` and did not back off: one
        // new Tor dial every `BULK_DIAL_MIN_INTERVAL_MS` for the whole transfer.
        for cid in failed_dials {
            if let Some(peer) = self.bulk_dials.remove(&cid) {
                let h = self.bulk_health.entry(peer).or_default();
                h.backoff_ms = (h.backoff_ms * 2).clamp(BULK_DIAL_MIN_INTERVAL_MS * 2, BULK_DIAL_MAX_BACKOFF_MS);
                h.next_dial_at = mono_ms() + h.backoff_ms;
            }
        }
        self.conn_rank.extend(new_conn_ranks);
        let inbound_at = mono_ms();
        self.unknown_inbound.extend(new_inbound.into_iter().map(|(cid, peer)| (cid, (peer, inbound_at))));
        for (peer, answered) in server_rpc_outcomes {
            if answered {
                self.server_rpc_timeouts.remove(&peer);
                continue;
            }
            let n = self.server_rpc_timeouts.entry(peer).or_insert(0);
            *n += 1;
            if *n >= SERVER_RPC_TIMEOUTS_BEFORE_DISCONNECT {
                warn!("Sunucu {} istekte üst üste yanıt vermedi, bağlantı ölü sayılıp yeniden kuruluyor: {}", n, crate::log_id(&peer));
                self.server_rpc_timeouts.remove(&peer);
                if let Some(swarm) = &mut self.swarm {
                    let _ = swarm.disconnect_peer_id(peer);
                }
            }
        }
        for (peer, cid) in &closed_conns {
            self.conn_rank.remove(cid);
            if let Some(v) = self.peer_conns.get_mut(peer) {
                v.retain(|c| c != cid);
                if v.is_empty() {
                    self.peer_conns.remove(peer);
                }
            }
        }
        // bkz. `mark_connection_suspect`: şüpheli eşe yeni bağlantı geldi —
        // eskiler muhtemelen ölü; gossipsub ilk bağlantıyı kullanmaya devam
        // edeceği için onları kapat.
        for (peer, cid) in &established_conns {
            let suspect = self.keepalive_state.get(peer).map_or(false, |s| s.suspect);
            let others: Vec<libp2p::swarm::ConnectionId> = self.peer_conns.get(peer)
                .map(|v| v.iter().copied().filter(|c| c != cid).collect())
                .unwrap_or_default();
            if surplus_dials.contains(cid) && !suspect && !others.is_empty() {
                // The existing connection is not in doubt, so one of them goes. Keep the
                // better path. Before this the new one was always closed: an early relay
                // circuit through the server beat the direct onion connection that came
                // up seconds later, and all traffic took the extra hop and the circuit's
                // limits (seen on device, Note 9S on mobile data, 2026-09-18).
                let rank = |c: &libp2p::swarm::ConnectionId| self.conn_rank.get(c).copied().unwrap_or(0);
                let new_rank = rank(cid);
                let bulk: Vec<libp2p::swarm::ConnectionId> = self.extra_conns.get(peer).cloned().unwrap_or_default();
                let worse: Vec<libp2p::swarm::ConnectionId> = others.iter().copied()
                    .filter(|c| rank(c) < new_rank && !bulk.contains(c))
                    .collect();
                let best_other = others.iter().map(|c| rank(c)).max().unwrap_or(0);
                if let Some(swarm) = &mut self.swarm {
                    if new_rank > best_other {
                        info!("Daha iyi yol kuruldu (seviye {} > {}), {} eski bağlantı kapatılıyor: peer={}", new_rank, best_other, worse.len(), crate::log_id(&peer));
                        for c in &worse {
                            swarm.close_connection(*c);
                        }
                    } else {
                        swarm.close_connection(*cid);
                    }
                }
                continue;
            }
            if suspect && !others.is_empty() {
                info!("Şüpheli bağlantının yerine yenisi kuruldu, {} eski bağlantı kapatılıyor: peer={}", others.len(), crate::log_id(&peer));
                if let Some(swarm) = &mut self.swarm {
                    for c in &others {
                        swarm.close_connection(*c);
                    }
                }
                // The survivor is the peer's only link now, not an "extra" one
                // for `manage_bulk_connections` to close after the transfer.
                self.extra_conns.remove(peer);
                if let Some(st) = self.keepalive_state.get_mut(peer) {
                    st.suspect = false;
                    st.outstanding = None;
                    st.consecutive_failures = 0;
                    st.next_due_at = mono_ms() + KEEPALIVE_FAST_INTERVAL_MS;
                }
            }
        }
        for (peer, cid) in closed_conns {
            if let Some(v) = self.extra_conns.get_mut(&peer) {
                v.retain(|c| *c != cid);
                if v.is_empty() {
                    self.extra_conns.remove(&peer);
                }
            }
        }
        // The author of a gossipsub message is a key the sender picks, a new
        // one per message if it likes. A message that came over another peer's
        // connection is counted on that connection (Noise-proven) first.
        for (via, source, data) in gossip_incoming {
            if source != Some(via) {
                match self.rate_verdict(via) {
                    RateVerdict::Allow => {}
                    // A contact relaying fast: hold it like the main loop does.
                    RateVerdict::Defer => {
                        self.defer_incoming(source, data);
                        continue;
                    }
                    RateVerdict::Drop => {
                        debug!("Hız sınırı (aktaran eş), paket düşürüldü: via={}", crate::log_id(&via));
                        continue;
                    }
                }
            }
            incoming.push((source, data));
        }
        // Direct envelopes: same path as a gossipsub message, with the
        // Noise-proven sender. A packet the rate limit is about to drop gets
        // no answer: the "delivered" reply made the sender skip its early
        // server deposit for a packet nobody processed.
        for (peer, bytes, channel) in direct_requests {
            if self.rate_would_drop(peer) {
                continue;
            }
            incoming.push((Some(peer), bytes));
            if let Some(swarm) = &mut self.swarm {
                let _ = swarm.behaviour_mut().envelopes.send_response(channel, EnvelopeResponse);
            }
        }
        // An expired address goes (a dropped relay reservation) and none is
        // listed twice: the list only grew.
        // M-193: a dead relay's listener id no longer blocks a new
        // reservation for `RELAY_RESERVATION_RETRY_MS`.
        if !closed_listener_ids.is_empty() {
            self.relay_listeners.retain(|_, (lid, _)| !closed_listener_ids.contains(lid));
        }
        for (addr, up) in listen_addr_changes {
            self.own_listen_addrs.retain(|a| *a != addr);
            if up {
                self.own_listen_addrs.push(addr);
            }
        }
        // A device added from the other side's IdentityExchange (not from a code)
        // had no onion address. It could reach the peer only through a relay,
        // which first needs its own Tor connection to the server: ~40 s after
        // mobile data came back (device, 2026-09-18). Peers now announce their
        // onion address over identify (see `advertised_onion`).
        for (pid, addr) in new_peer_onions {
            // An address that names another peer is not this peer's onion.
            let addr = match extract_peer_id(&addr) {
                Some(p) if p != pid => continue,
                Some(_) => addr,
                None => addr.with(MultiaddrProtocol::P2p(pid)),
            };
            let addr_str = addr.to_string();
            let fps: Vec<String> = self.device_to_peer_id.iter().filter(|(_, p)| **p == pid).map(|(fp, _)| fp.clone()).collect();
            for fp in fps {
                self.remember_onion_addr(&fp, &addr_str);
            }
            self.peer_onion_addr.insert(pid, addr_str);
        }
        if let Some(host) = self.tor.as_ref().and_then(|t| t.onion_host()) {
            let own = format!("/dns/{}/tcp/{}", host, TOR_LIBP2P_PORT);
            if self.advertised_onion.as_deref() != Some(own.as_str()) {
                if let (Ok(addr), Some(swarm)) = (own.parse::<Multiaddr>(), self.swarm.as_mut()) {
                    swarm.add_external_address(addr);
                    self.advertised_onion = Some(own);
                }
            }
        }
        for (pid, addr) in new_peer_addrs {
            if is_loopback_multiaddr(&addr) {
                continue;
            }
            // M-192: a peer-supplied clearnet address (identify) no longer
            // replaces the onion address we dialed — the node is onion-only.
            if !is_onion_multiaddr(&addr) && self.peer_id_to_addr.get(&pid).map_or(false, |a| is_onion_multiaddr(a)) {
                continue;
            }
            // Strangers' entries were never removed: past the cap only
            // devices and servers we know are kept.
            if self.peer_id_to_addr.len() >= 4096 && !self.peer_id_to_addr.contains_key(&pid) {
                let known: std::collections::HashSet<PeerId> = self.device_to_peer_id.values().copied().collect();
                let servers: Vec<PeerId> = self.peer_id_to_addr.keys().copied().filter(|p| self.is_server_peer(p)).collect();
                self.peer_id_to_addr.retain(|p, _| known.contains(p) || servers.contains(p));
            }
            self.peer_id_to_addr.insert(pid, addr);
        }
        for (pid, addr) in new_relay_peers {
            // Identify'ın bildirdiği adresler karşı tarafın KENDİ gözünden:
            // sunucunun LAN adresi mobil veride, genel IP'si aynı LAN'dan
            // (hairpin NAT) çevrilemiyor — ikisi de cihazda ölçüldü. Röle
            // bizim yapılandırdığımız bir sunucuysa onion adresi her ağdan
            // çalışır. Röleye zaten bağlıysak libp2p o bağlantıyı kullanır;
            // adres yalnızca bağlı değilken çevrilir.
            // Only our servers and proven devices of contacts. Any stranger that
            // connected and listed HOP became a relay: every reconnect target
            // was then dialed through it (it saw whom we reach, and when), and
            // ten of them pushed the real server out of the list.
            // Not a contact's device either: it supplied the address itself,
            // and got a circuit request naming the target each time we
            // reconnected to anybody else. Our own other devices may relay.
            let my_id = self.my_identity_id();
            let own_device = my_id.is_some() && self.device_to_peer_id.iter().any(|(fp, p)| {
                *p == pid && self.known_remote_devices.get(fp).map(|d| &d.identity_id) == my_id.as_ref()
            });
            if !self.is_server_peer(&pid) && !own_device {
                continue;
            }
            let addr = self.server_onion_addr(&pid).unwrap_or(addr);
            self.record_known_relay(pid, addr);
        }
        // Spec dışı, ağ sağlamlığı düzeltmesi: bkz. `connections_lost`
        // dokümantasyonu — kaybedilen her bağlantı için karşılık gelen
        // cihaz fingerprint'ini (`device_to_peer_id`'in tersini alarak)
        // bulup ANINDA yeniden bağlanmayı dener (`reconnect_backoff`'a
        // hâlâ tabi — bkz. `try_reconnect_device` — bu yüzden ard arda
        // hızlı kopan bir bağlantı dial fırtınası YARATMAZ, sadece İLK
        // kopuş periyodik taramayı beklemeden anında denenir). SADECE
        // bilinen+Aktif cihazlar (bkz. `reconnect_sweep` AYNI filtre) —
        // henüz IdentityExchange tamamlamamış bir peer'in bağlantı
        // kaybı burada YOK SAYILIR, o zaten kendi `pending_envelopes`/
        // `send_identity_exchange` yeniden deneme yoluna sahip.
        // Closed and established again within one batch (process frozen, then
        // the peer redialed): the peer is connected, nothing was lost.
        connections_lost.retain(|p| !self.swarm.as_ref().is_some_and(|s| s.is_connected(p)));
        if !connections_lost.is_empty() {
            // bkz. `keepalive_state` alanı dokümantasyonu — bağlantı
            // tamamen kapandığında (bu Vec'in kaynağı olan `ConnectionClosed`
            // kolu) ilgili durum da temizlenir (bir sonraki bağlantı taze bir
            // `KeepAliveState`'le, `ConnectionEstablished`'da, sıfırdan başlar).
            for peer_id in &connections_lost {
                self.keepalive_state.remove(peer_id);
                // Timeouts of the old link must not count against the next one.
                self.server_rpc_timeouts.remove(peer_id);
                // Learned again from identify on the next connection; the
                // device's own copy is in `device_onion_addr`.
                self.peer_onion_addr.remove(peer_id);
            }
            let fps: Vec<String> = self.device_to_peer_id.iter()
                .filter(|(_, pid)| connections_lost.contains(pid))
                .map(|(fp, _)| fp.clone())
                .collect();
            // Radio saver: redial in the next window, not now — on mobile
            // data every onion dial is a burst of circuit builds.
            let redial_now = self.radio_window_open;
            for fp in fps.into_iter().filter(|_| redial_now) {
                match self.known_remote_devices.get(&fp) {
                    Some(rec) if rec.is_active => {
                        self.try_reconnect_device(&fp, false);
                    }
                    _ => {}
                }
            }
        }

        // bkz. `connections_established` alanı dokümantasyonu (yukarısı) —
        // yeni kurulan/yeniden kurulan HER bağlantı için, zaten bir ratchet
        // oturumumuz varsa gossipsub aboneliğini tekrar (idempotent, no-op
        // olsa bile) tetikleyerek Tor devresi kopmalarının SESSİZCE mesh'i
        // bozmasına karşı bir güvenlik ağı sağlar.
        if !connections_established.is_empty() {
            // Found on device (2026-09-18, Note 9S on mobile data): the only
            // other way to fill `device_to_peer_id` is a packet received over
            // gossipsub. After a fresh pairing over a slow network (Tor/relay),
            // the IdentityExchange and Handshake were deposited to the server
            // before any connection existed. Their gossipsub copies found no
            // peers and were never retried. The relay connection that came up
            // seconds later was then never tied to the contact:
            // `is_connected_to_device` stayed false, the chat showed "Offline",
            // and every message and Ack went via the server even with a live
            // connection. The peer id at the end of the pairing address is the
            // device's own libp2p id (QR/manual code, trusted like the rest of
            // the code). Noise has just proven the connection is that id, so
            // tie them together. A mapping learned from a verified packet is
            // never overwritten.
            let learned: HashMap<String, PeerId> = self.device_last_addr.iter()
                .chain(self.device_onion_addr.iter())
                .filter(|(fp, _)| !self.device_to_peer_id.contains_key(*fp))
                .filter_map(|(fp, addr)| {
                    // The LAST /p2p is the device (a circuit address starts with the relay's).
                    let pid = addr.parse::<Multiaddr>().ok()?.iter()
                        .filter_map(|p| match p { MultiaddrProtocol::P2p(pid) => Some(pid), _ => None })
                        .last()?;
                    connections_established.contains(&pid).then(|| (fp.clone(), pid))
                })
                .collect();
            for (fp, pid) in learned {
                info!("Bağlantı eşleşme adresinden cihaza bağlandı: {} -> {}", &fp[..fp.len().min(8)], crate::log_id(&pid));
                if let Some(onion) = self.peer_onion_addr.get(&pid).cloned() {
                    self.remember_onion_addr(&fp, &onion);
                }
                self.device_to_peer_id.insert(fp, pid);
            }
            let fps: Vec<String> = self.device_to_peer_id.iter()
                .filter(|(_, pid)| connections_established.contains(pid))
                .map(|(fp, _)| fp.clone())
                .collect();
            // ÖNCE aboneliği tazele, SONRA kuyruğu boşalt. Sıra önemli: bu
            // döngü, Tor devresi kopmalarının sessizce bozduğu gossipsub
            // aboneliğini onarır — bekleyenleri bundan ÖNCE tetiklersek ilk
            // (ve en değerli) deneme hâlâ bozuk bir mesh'e yayınlanır.
            for fp in &fps {
                if let Some(root_key) = self.ratchets.get(fp).map(|r| r.root_key.clone()) {
                    self.resubscribe_ratchet_topic(None, Some(&root_key));
                }
            }

            // Spec dışı, kullanıcı geri bildirimi ("senkron çok geç geliyor"):
            // bu cihaz için onay bekleyen ne varsa HEMEN yeniden denenir.
            // Önceden hiçbir şey bir bağlantı kurulduğunda geri çekilmeyi
            // sıfırlamıyordu — kuyruk üstel olarak `ACK_RETRY_MAX_MS`'e (120
            // sn) kadar açıldığından, çevrimdışı kalmış bir kardeş cihaz geri
            // döndüğünde bekleyen mesajlar zaten bağlıyken DAKİKALARCA öylece
            // bekliyordu. Bağlantı kurulması, "şimdi dene" için elimizdeki en
            // güçlü sinyal. Aralık da başlangıç değerine çekiliyor: mesh
            // yine de hazır olmayabilir, o yüzden ilk deneme başarısız olursa
            // 120 sn değil 15 sn sonra tekrar denenmeli.
            let reconnected: std::collections::HashSet<String> = fps.into_iter().collect();
            let now = current_time_ms();
            for pending in self.awaiting_confirmation.values_mut() {
                // M-182: at most once per `ACK_RETRY_INITIAL_MS`: a peer that
                // reconnects in a loop got the whole queue on every turn.
                if reconnected.contains(&pending.peer_device_fingerprint)
                    && now.saturating_sub(pending.last_attempt_at) >= ACK_RETRY_INITIAL_MS
                {
                    pending.next_retry_at = 0; // due, and not held (bkz. `hold_retries`)
                    pending.retry_interval_ms = ACK_RETRY_INITIAL_MS;
                }
            }
            // M-181: queued envelopes for it are due now too (the 1 s flush
            // gate still applies).
            for queued in self.pending_envelopes.iter_mut() {
                if reconnected.contains(&queued.target) {
                    queued.next_at = 0;
                }
            }
            // Teslim garantisi (bkz. `maybe_redo_handshake`): eş GERİ DÖNDÜ
            // ama uzun süredir tek bir paketimizi bile onaylamadıysa,
            // oturumun karşı tarafta hiç kurulmamış olduğunu varsayıp el
            // sıkışmayı tazeliyoruz. Bu, "kapalıyken yazılan ilk mesaj"
            // senaryosunun en hızlı kurtarma noktası: 25 dakikalık tazeleme
            // turunu beklemeden, eş çevrimiçi olur olmaz. Kendi içinde hem
            // "onaylanmamış paket var mı" hem de `HANDSHAKE_REDO_MIN_INTERVAL_MS`
            // kısıtını uyguluyor, yani sağlıklı bir yeniden bağlanmada no-op.
            for fp in &reconnected {
                self.maybe_redo_handshake(fp);
            }
            // Spec dışı (dış AI incelemesi düzeltmesi): onay bekleyen mesajlar
            // gibi, kaynağı az önce geri dönmüş YARIM/BAŞARISIZ dosya
            // indirmeleri de hemen sürdürülür — bkz.
            // `resume_incomplete_downloads_for`.
            self.resume_incomplete_downloads_for(&reconnected, false);
            // Kendini-onarma (bkz. `SIBLING_ROSTER_SYNC_INTERVAL_MS`): bağlanan
            // taraflardan biri kardeş cihazımsa, cihaz listesini yeniden
            // gönder. Bir kardeşin duyuruyu kaçırmış olması aksi halde KALICI
            // (ikisi birbirini tanımadığı için birbirine ulaşamazlar).
            let sibling_reconnected = self
                .sibling_active_devices()
                .into_iter()
                .any(|fp| reconnected.contains(&fp));
            if sibling_reconnected
                && now.saturating_sub(self.last_sibling_roster_sync_at) >= SIBLING_ROSTER_SYNC_INTERVAL_MS
            {
                self.last_sibling_roster_sync_at = now;
                // The siblings that are connected, not all: see `request_sibling_backfill`.
                let connected: Vec<String> = self.sibling_active_devices().into_iter()
                    .filter(|fp| self.is_connected_to_device(fp)).collect();
                self.sync_roster_to(connected);
            }

            // Spec dışı, gerçek cihaz hatası düzeltmesi ("QR tarandı, iki
            // cihazda da hiçbir şey olmadı" — bağlantı SONUNDA kuruluyordu
            // ama bağlanma yine tamamlanmıyordu): bekleyen bir cihaz
            // bağlama hedefi (`pending_link_target`) için `IdentityExchange`,
            // `approve_device_link` içinde QR TARAMA ANINDA gönderilmeye
            // çalışılır — o an henüz bağlantı yoktur, bu yüzden
            // `pending_envelopes`'e düşer ve oradaki `PENDING_ENVELOPE_TIMEOUT_MS`
            // (20 sn) sayacı TARAMA anından işlemeye başlar. Tor üzerinden
            // ilk dial 10-17 sn sürebildiğinden (üstelik ilk deneme zaman
            // aşımına uğrayıp yeniden denenebildiğinden), zarf tam da
            // gossipsub mesh'i daha yeni kurulurken süresi dolup ATILIYOR,
            // ve onu bir daha gönderen HİÇBİR yol yoktu — bağlanma sonsuza
            // kadar yarım kalıyordu.
            //
            // Yukarıdaki döngü bu hedefi göremez: `device_to_peer_id` SADECE
            // o cihazdan DOĞRULANMIŞ bir paket alındığında dolar (bkz.
            // `record_peer_id_if_known`) — tam da henüz gerçekleşmemiş olan
            // şey bu. Bu yüzden PeerId'yi, eşleşme anında kaydedilmiş
            // adresten (`device_last_addr`/`device_onion_addr`) çözüp
            // karşılaştırıyoruz. Bağlantı YENİ kurulduğuna göre zarfı
            // yeniden gönderiyoruz — mesh o an hâlâ hazır olmasa bile bu,
            // 20 sn'lik pencereyi TARAMA anından değil BAĞLANTI anından
            // başlatır (asıl kritik nokta bu).
            if let Some(fp) = self.pending_link_target.clone() {
                let link_peer_id = self.device_last_addr.get(&fp)
                    .or_else(|| self.device_onion_addr.get(&fp))
                    .and_then(|a| a.parse::<Multiaddr>().ok())
                    .and_then(|a| extract_peer_id(&a));
                if link_peer_id.map(|p| connections_established.contains(&p)).unwrap_or(false) {
                    if let Err(e) = self.send_identity_exchange(&fp) {
                        error!("Bağlanma IdentityExchange'i (bağlantı kurulduğunda) gönderilemedi, yeniden denenecek: {}", e);
                    }
                }
            }
        }

        // Dosya parça olaylarını işle — `self.swarm`'ın dışında toplandı
        // (bkz. yukarısı), böylece burada hem `&mut self` (durum
        // güncellemesi) hem de (yanıt göndermek için) `self.swarm`'a ayrı
        // ayrı erişebiliyoruz (aynı anda ikisi birden mümkün değil).
        let mut pending_chunk_responses: Vec<(request_response::ResponseChannel<FileChunkResponse>, FileChunkResponse)> = Vec::new();
        for evt in file_chunk_events {
            match evt {
                FileChunkEventLocal::Request { peer, request, channel } => {
                    // Own counter, so a download does not use up the message
                    // budget. 600 chunks per window is 15 MB/s, above any
                    // real transfer; past it the file is refused.
                    let now = mono_ms();
                    let rate = self.chunk_rate_limiter.entry(peer).or_insert((now, 0));
                    if now.saturating_sub(rate.0) > RATE_LIMIT_WINDOW_MS {
                        *rate = (now, 0);
                    }
                    rate.1 += 1;
                    // Over the limit: no answer (the channel is dropped).
                    // The requester sees an `OutboundFailure` and retries;
                    // `NotFound` made it fail the whole download (M-187).
                    if rate.1 > RATE_LIMIT_MAX_ESTABLISHED {
                        drop(channel);
                        continue;
                    }
                    let response = self.serve_chunk_request(peer, &request);
                    pending_chunk_responses.push((channel, response));
                }
                FileChunkEventLocal::Response { request_id, response } => {
                    if let Some((file_id, chunk_index)) = self.download_request_ids.remove(&request_id) {
                        self.handle_chunk_response(&file_id, chunk_index, response);
                    }
                }
                FileChunkEventLocal::OutboundFailure { request_id } => {
                    // Spec dışı, ağ sağlamlığı düzeltmesi: önceden TEK bir
                    // ağ hatası (ör. geçici bir Tor devresi kopması) indirmeyi
                    // HEMEN başarısız sayardı — artık `DOWNLOAD_GIVE_UP_TIMEOUT_MS`'ye
                    // (10 dk) kadar aynı parçayı yeniden dener.
                    if let Some((file_id, chunk_index)) = self.download_request_ids.remove(&request_id) {
                        // Havadan düş — `retry_or_give_up_download` pencereyi
                        // yeniden dolduracak.
                        if let Some(s) = self.active_downloads.get_mut(&file_id) {
                            s.inflight_chunks.remove(&chunk_index);
                            s.chunk_sent_at.remove(&chunk_index);
                            // Zaman aşımı/hata = hat boğuldu ya da koptu:
                            // pencereyi yarıya indir (bkz. `DOWNLOAD_WINDOW_MIN`).
                            s.window = (s.window / 2).max(DOWNLOAD_WINDOW_MIN);
                            // A source that is gone is asked again ten times
                            // slower: every request to it fails at once, and
                            // at the normal delay that was a dial every 3 s
                            // for the 10 minutes before giving up. Waiting for
                            // `retry_at` does not hold the wake lock (`downloads_busy`).
                            let connected = self.swarm.as_ref().map_or(false, |sw| sw.is_connected(&s.peer_id));
                            s.retry_at = current_time_ms() + if connected { DOWNLOAD_RETRY_DELAY_MS } else { 10 * DOWNLOAD_RETRY_DELAY_MS };
                        }
                        // Ölü bir paralel devre olabilir — tek olayda karar
                        // verme, sayaca yaz (bkz. `note_bulk_timeout`).
                        if let Some(p) = self.active_downloads.get(&file_id).map(|s| s.peer_id) {
                            self.note_bulk_timeout(p);
                        }
                        // Only this one request failed: not `retry_or_give_up_download`,
                        // which threw away every other request in flight (their
                        // answers then matched no id) and counted toward a source
                        // switch. The index is asked for again by the next chunk
                        // answer, or after `DOWNLOAD_RETRY_DELAY_MS` (`retry_at`).
                    }
                }
            }
        }
        if !pending_chunk_responses.is_empty() {
            if let Some(swarm) = &mut self.swarm {
                for (channel, response) in pending_chunk_responses {
                    let _ = swarm.behaviour_mut().file_chunks.send_response(channel, response);
                }
            }
        }

        if !subscribed_peers.is_empty() {
            let fps: std::collections::HashSet<String> = self.device_to_peer_id.iter()
                .filter(|(_, pid)| subscribed_peers.contains(pid))
                .map(|(fp, _)| fp.clone())
                .collect();
            let now = current_time_ms();
            for pending in self.awaiting_confirmation.values_mut() {
                if fps.contains(&pending.peer_device_fingerprint) && pending.next_retry_at > now
                    && now.saturating_sub(pending.last_attempt_at) >= ACK_RETRY_INITIAL_MS
                {
                    pending.next_retry_at = 0; // due, and not held (bkz. `hold_retries`)
                }
            }
        }
        for evt in envelope_events {
            match evt {
                EnvelopeEventLocal::Delivered { request_id } => {
                    let Some((fp, envelope, _, _)) = self.envelopes_inflight.remove(&request_id) else { continue };
                    if let NetworkEnvelope::Message(m) = &envelope {
                        if let Some(p) = self.awaiting_confirmation.get_mut(&m.header.message_id) {
                            p.direct_delivered = true;
                        }
                    }
                    // A delivered request proves the connection like a keepalive answer does.
                    if let Some(st) = self.device_to_peer_id.get(&fp).and_then(|pid| self.keepalive_state.get_mut(pid)) {
                        st.suspect = false;
                        st.consecutive_failures = 0;
                    }
                }
                EnvelopeEventLocal::Failed { request_id, error } => {
                    let Some((fp, envelope, first_attempt_at, retried)) = self.envelopes_inflight.remove(&request_id) else { continue };
                    // The request rode a connection that just closed (surplus/suspect
                    // replacement) while another one is still up: resend there once.
                    if !retried && self.is_connected_to_device(&fp) {
                        if let Ok(bytes) = ciborium_bytes(&envelope) {
                            if self.send_envelope_direct(&fp, &envelope, bytes, first_attempt_at, true) {
                                continue;
                            }
                        }
                    }
                    warn!("Doğrudan zarf gönderimi başarısız ({}), gossipsub/sunucuya düşülüyor: {}", error, &fp[..fp.len().min(8)]);
                    match self.try_publish_raw_via(&fp, &envelope, first_attempt_at, false) {
                        Err(PublishFailure::Transient(_)) => {
                            // Tracked messages are resent by `retry_unconfirmed_messages`;
                            // queue the rest like `publish_envelope_at` does.
                            let tracked = matches!(&envelope, NetworkEnvelope::Message(m) if self.awaiting_confirmation.contains_key(&m.header.message_id));
                            if !tracked {
                                self.enqueue_pending(QueuedEnvelope::new(fp, envelope, first_attempt_at));
                            }
                        }
                        // Like `publish_with_ack_tracking`: no retry can work.
                        Err(PublishFailure::Permanent(e)) => {
                            error!("Envelope failed permanently after the direct path: {}", e);
                            if let NetworkEnvelope::Message(m) = &envelope {
                                let id = m.header.message_id.clone();
                                self.awaiting_confirmation.remove(&id);
                                self.remove_durable_retry(&id);
                                self.set_message_status(&id, MessageSendStatus::Failed);
                                self.attachment_events.push(serde_json::json!({
                                    "type": "status", "peer": self.canonical_peer_key(&fp), "message_id": id, "status": "error"
                                }).to_string());
                            }
                        }
                        Ok(()) => {}
                    }
                }
            }
        }
        // bkz. `ACK_PROTOCOL`.
        let mut ack_replies: Vec<request_response::ResponseChannel<AckBatchResponse>> = Vec::new();
        for evt in ack_events {
            match evt {
                AckEventLocal::Request { peer, ids, channel } => {
                    let fps: Vec<String> = self.device_to_peer_id.iter()
                        .filter(|(_, p)| **p == peer)
                        .map(|(fp, _)| fp.clone())
                        .collect();
                    // The sender knows our PeerId (from the pairing address) before we know
                    // theirs (we learn it only from a packet received over gossipsub). Replying
                    // here told them "delivered" while every Ack was ignored, so our messages
                    // stayed unconfirmed and were retried for minutes (device, 2026-09-18).
                    // Dropping the channel fails their request, and they fall back to the
                    // encrypted Ack. That one also teaches us their PeerId.
                    if fps.is_empty() {
                        warn!("Toplu Ack tanınmayan peer'dan, yanıtlanmıyor (şifreli Ack'e düşecek): {}", crate::log_id(&peer));
                        drop(channel);
                        continue;
                    }
                    // M52: the sender chunks at ACK_BATCH_MAX; more is a broken peer.
                    if ids.len() > ACK_BATCH_MAX {
                        warn!("Toplu Ack {} kimlik taşıyor, ilk {} uygulanıyor (peer={})", ids.len(), ACK_BATCH_MAX, crate::log_id(&peer));
                    }
                    for id in ids.iter().take(ACK_BATCH_MAX) {
                        let owner = self.awaiting_confirmation.get(id).map(|p| p.peer_device_fingerprint.clone());
                        if let Some(fp) = owner.filter(|o| fps.contains(o)) {
                            if let Some(ev) = self.apply_incoming_ack(&fp, id) {
                                self.attachment_events.push(ev.to_string());
                            }
                        }
                    }
                    info!("Toplu Ack alındı: {} adet (peer={})", ids.len(), crate::log_id(&peer));
                    ack_replies.push(channel);
                }
                AckEventLocal::Delivered { request_id } => {
                    self.ack_batches_inflight.remove(&request_id);
                }
                AckEventLocal::Failed { request_id } => {
                    // L-71: back into the queue. `flush_outbound_acks` batches
                    // it again while the peer is connected and falls back to
                    // one packet per ack only without a connection (it fanned
                    // out up to 256 packets on exactly the flaky link).
                    if let Some((fp, ids)) = self.ack_batches_inflight.remove(&request_id) {
                        let queue = self.outbound_acks.entry(fp).or_default();
                        for id in ids {
                            if !queue.contains(&id) {
                                queue.push(id);
                            }
                        }
                    }
                }
            }
        }
        if !ack_replies.is_empty() {
            if let Some(swarm) = &mut self.swarm {
                for channel in ack_replies {
                    let _ = swarm.behaviour_mut().acks.send_response(channel, AckBatchResponse);
                }
            }
        }

        // Sunucu olayları — `incoming`'e ekleme YAPAR (çekilen zarflar), bu
        // yüzden aşağıdaki `for (source, raw) in incoming` drenajından ÖNCE
        // olmak ZORUNDA: aksi halde sunucudan gelen her mesaj bir tur (≈1 sn)
        // geç işlenirdi.
        if !server_events.is_empty() {
            lock_watch::phase("drive_server_sync");
            let replies = self.drive_server_sync(server_events, &mut incoming);
            if let Some(swarm) = &mut self.swarm {
                for (channel, response) in replies {
                    let _ = swarm.behaviour_mut().server_rpc.send_response(channel, response);
                }
            }
        }
        // Bağlantı durumu: sunucular da sıradan libp2p eşleri, bu yüzden
        // yeniden bağlanma/backoff mantığı `reconnect_sweep` ile ortak.
        for peer in &connections_established {
            if self.is_server_peer(peer) {
                self.note_server_connection(*peer, true);
            }
        }
        for peer in &connections_lost {
            if self.is_server_peer(peer) {
                self.note_server_connection(*peer, false);
            }
        }
        // bkz. `server_sweep` — bağlantı/kayıt/abonelik/çekme bakımı; kendi
        // aralık kontrolünü kendi yapar (`reconnect_sweep` deseni).
        lock_watch::phase("server_sweep");
        self.server_sweep();

        // UI events collect in `self.attachment_events` and are taken only at
        // the end: a panic in this turn no longer loses the ones gathered so
        // far, they go out with the next turn.
        // bkz. `DOWNLOAD_STALL_TIMEOUT_MS` — `file_failed` events of this call
        // go out in this turn.
        self.check_stalled_downloads();

        // bkz. `reconnect_sweep` dokümantasyonu — kopmuş kişilere periyodik
        // (≤15 sn) otomatik yeniden bağlanma. Kendi içinde aralık kontrolü
        // yapar, bu yüzden her poll turunda çağrılması ucuzdur.
        lock_watch::phase("reconnect_sweep");
        self.sweep_unknown_inbound();
        self.reconnect_sweep();
        // bkz. `pending_group_syncs` dokümantasyonu — hedef cihazı henüz
        // çözülemediği için gönderilemeyen grup üyelik/isim/avatar
        // güncellemelerini periyodik (≤20 sn) olarak yeniden dener.
        lock_watch::phase("group_sync_sweep");
        self.group_sync_sweep();
        // Whiteboard: batched strokes and the settling digest, see `whiteboard`.
        self.wb_sweep();
        // bkz. `early_packets` — el sıkışması hiç gelmeyen tamponlar süresi
        // dolunca temizlenir.
        self.prune_early_packets();
        // bkz. `pending_edits_deletes` — hedefi hiç gelmeyen tamponlanmış
        // Edit/Delete paketleri süresi dolunca temizlenir.
        self.prune_pending_edits_deletes();
        // bkz. `message_rate_limiter` — uzun süredir paket göndermemiş
        // peer'ların hız sınırı girdileri temizlenir.
        self.prune_rate_limiter();
        // bkz. `HISTORY_STORAGE_SWEEP_INTERVAL_MS` dokümantasyonu — node modu
        // eklerinin toplam boyutu sınırı aşarsa en eski dosyaları siler.
        self.periodic_storage_sweep();

        // Spec dışı, ağ sağlamlığı düzeltmesi (bkz. `tor_was_ready`/
        // `announce_address_to_all_contacts` dokümantasyonu): Tor durumu bu
        // turda İLK KEZ Ready olduysa (bootstrap + onion servisi yayına
        // girdi — bu genelde eşleşmeden dakikalar sonra olur), bilinen HER
        // kişiye o anki `.onion` adresimizi proaktif olarak bildir — onu
        // bağlantı kurulmadan önce öğrenmeleri gerekiyor.
        let tor_ready_now = self.tor.as_ref().map(|h| h.status() == tor::TorStatus::Ready).unwrap_or(false);
        if tor_ready_now && !self.tor_was_ready {
            // M-45: not the address itself — it is a stable pseudonym and
            // logcat is readable by adb and OEM log collectors.
            info!("Tor Ready durumuna geçti — bilinen kişilere .onion adresi bildiriliyor");
            self.announce_address_to_all_contacts();
        }
        self.tor_was_ready = tor_ready_now;

        // bkz. `pending_envelopes` alanı dokümantasyonu: ilk bağlantıdan
        // sonraki ilk birkaç saniyede gönderilemeyen HERHANGİ bir zarfı
        // (handshake, identity exchange, mesaj, edit, delete, grup
        // güncellemesi...) burada, her poll turunda yeniden dener.
        // `try_publish_raw` (kuyruğa EKLEMEYEN ham versiyon) kullanılıyor —
        // aksi halde `publish_envelope` her başarısız denemede AYNI girdiyi
        // tekrar kuyruğa ekler ve zaman aşımı asla işlemezdi. Bir `Message`
        // zarfı ise başarı/zaman aşımı durumunu `message_status` üzerinden
        // UI'ye bir "status" olayıyla bildiriyoruz (bkz. MessageSendStatus).
        // At most once a second: every turn encoded and published every queued
        // envelope again (a Handshake to an offline peer, for 5 min).
        if !self.pending_envelopes.is_empty()
            && mono_ms().saturating_sub(self.last_pending_flush_at) >= 1_000
        {
            let pending = std::mem::take(&mut self.pending_envelopes);
            let now = current_time_ms();
            self.last_pending_flush_at = mono_ms();
            for mut queued in pending {
                // M-181: per-entry backoff (bkz. `QueuedEnvelope::next_at`).
                if queued.next_at > now {
                    self.pending_envelopes.push(queued);
                    continue;
                }
                let (peer_fp, envelope, first_attempt_at) = (queued.target.clone(), &queued.envelope, queued.first_attempt_at);
                // A panic here used to lose every envelope after this one
                // (`pending` is already taken out of `self`). Now it costs
                // the one envelope that caused it.
                let published = catch_panic(|| self.try_publish_raw(&peer_fp, envelope, first_attempt_at));
                let Ok(published) = published else {
                    // H5: a Handshake/IdentityExchange has no other carrier
                    // (no `awaiting_confirmation`); it is tried again, later.
                    let handshake_class = matches!(queued.envelope, NetworkEnvelope::Handshake(_) | NetworkEnvelope::IdentityExchange(_));
                    if handshake_class && now.saturating_sub(first_attempt_at) <= PENDING_HANDSHAKE_TIMEOUT_MS {
                        error!("Bekleyen zarf yayınlanırken panik, sonra yeniden denenecek (peer={})", crate::log_id(&peer_fp));
                        queued.next_at = pending_retry_at(first_attempt_at, now);
                        self.pending_envelopes.push(queued);
                    } else {
                        error!("Bekleyen zarf yayınlanırken panik, zarf bırakıldı (peer={})", crate::log_id(&peer_fp));
                    }
                    continue;
                };
                match published {
                    Ok(()) => {
                        if let NetworkEnvelope::Message(m) = envelope {
                            self.set_message_status(&m.header.message_id, MessageSendStatus::Sent);
                            self.attachment_events.push(serde_json::json!({
                                "type": "status", "peer": self.canonical_peer_key(&peer_fp),
                                "message_id": m.header.message_id, "status": "sent"
                            }).to_string());
                        }
                    }
                    Err(failure) => {
                        // bkz. `PublishFailure` — kalıcı hata, zaman aşımını
                        // beklemeden hemen bırakılır (yeniden denemek asla
                        // başaramaz).
                        // bkz. `PENDING_HANDSHAKE_TIMEOUT_MS`: el sıkışma
                        // sınıfı zarflar `awaiting_confirmation`'a giremediği
                        // için tek dayanakları bu kuyruk — 20 sn onlar için
                        // teslim garantisini kıran bir süreydi.
                        let timeout = match envelope {
                            NetworkEnvelope::Handshake(_) | NetworkEnvelope::IdentityExchange(_) => {
                                PENDING_HANDSHAKE_TIMEOUT_MS
                            }
                            NetworkEnvelope::Message(_) => PENDING_ENVELOPE_TIMEOUT_MS,
                        };
                        let give_up = matches!(failure, PublishFailure::Permanent(_))
                            || now.saturating_sub(first_attempt_at) > timeout;
                        if give_up {
                            if let NetworkEnvelope::Message(m) = envelope {
                                // A tracked message stays in `awaiting_confirmation`
                                // and is retried there: not failed yet.
                                if self.awaiting_confirmation.contains_key(&m.header.message_id) {
                                    continue;
                                }
                                self.set_message_status(&m.header.message_id, MessageSendStatus::Failed);
                                self.attachment_events.push(serde_json::json!({
                                    "type": "status", "peer": self.canonical_peer_key(&peer_fp),
                                    "message_id": m.header.message_id, "status": "error"
                                }).to_string());
                            }
                            // Handshake/IdentityExchange gibi message_id'siz
                            // zarflar için de aynı şekilde vazgeçiliyor —
                            // sonsuza kadar erişilemeyen bir cihaz için
                            // sınırsız büyüyen bir kuyruk istemiyoruz.
                        } else {
                            queued.next_at = pending_retry_at(first_attempt_at, now);
                            self.pending_envelopes.push(queued);
                        }
                    }
                }
            }
        }

        // bkz. `manage_bulk_connections` — aktarım sürerken paralel Tor
        // devreleri açar, bitince kapatır.
        self.manage_bulk_connections();

        // Teslim garantisi (bkz. `RateVerdict`): önce ÖNCEKİ turdan
        // ertelenmiş paketler, sonra bu turda gelenler — sıra korunsun diye.
        // Hız sınırı burada uygulanıyor çünkü "ertele" sonucu paketi geri
        // kuyruğa koymayı gerektiriyor.
        let mail_was_deferred = self.server_mail_deferred();
        let deferred = std::mem::take(&mut self.deferred_incoming);
        let queued_before = deferred.len();
        lock_watch::phase("incoming_envelopes");
        // Nothing is decrypted before both storage keys are loaded: a packet
        // decrypted without them uses up its ratchet key and cannot be stored
        // (history key) or the session it advances is overwritten (ratchet
        // load). Held as received and processed, in order, once they are there.
        let keys_ready = self.storage_keys_ready();
        let (mut processed, mut rate_dropped) = (0usize, 0usize);
        for (source, raw) in deferred.into_iter().chain(incoming) {
            if !keys_ready {
                self.defer_incoming(source, raw);
                continue;
            }
            if let Some(peer) = source {
                match self.rate_verdict(peer) {
                    RateVerdict::Allow => {}
                    RateVerdict::Defer => {
                        // Tanıdık eş, yalnızca çok hızlı gönderiyor —
                        // ATMA, bir sonraki tura bırak.
                        self.defer_incoming(Some(peer), raw);
                        continue;
                    }
                    RateVerdict::Drop => {
                        debug!("Hız sınırı aşıldı (tanınmayan eş), paket düşürüldü: peer={}", crate::log_id(&peer));
                        rate_dropped += 1;
                        continue;
                    }
                }
            } else if !self.server_mail_allowed() {
                // M-16: not acked at the server until processed (bkz.
                // `commit_server_fetches`), so it waits, it is not dropped.
                self.defer_incoming(None, raw);
                continue;
            }
            processed += 1;
            // A panic costs this one packet, not the rest of this turn's packets
            // and the deferred queue (both were moved out of `self` above).
            match catch_panic(|| self.process_incoming_envelope(source, &raw)).and_then(|r| r) {
                Ok(Some(text)) => self.attachment_events.push(text),
                Ok(None) => {}
                Err(e) => {
                    error!("Gelen paket işlenemedi: {}", e);
                    // H14: covers both the Err result and a caught panic.
                    if source.is_none() {
                        self.server_item_failed(&raw);
                    }
                }
            }
        }
        if rate_dropped > 0 {
            warn!("Hız sınırı: bu turda {} paket düşürüldü", rate_dropped);
        }
        if keys_ready && (queued_before > 0 || !self.deferred_incoming.is_empty()) {
            info!(
                "Gelen kuyruk: {} işlendi ({} önceki turdan), {} bekliyor",
                processed,
                queued_before,
                self.deferred_incoming.len()
            );
        }
        // M-16: the held Fetch (bkz. `server_fetch`) goes out now, not at
        // the next radio window.
        if mail_was_deferred && !self.server_mail_deferred() {
            self.server_sweep_at = 0;
        }
        // H-06: server Acks go out only now, after this turn processed the
        // fetched items (bkz. `commit_server_fetches`).
        self.commit_server_fetches();

        // bkz. `flush_outbound_acks` — bu turda üretilen Ack'ler aşağıdaki son
        // swarm turuyla tele çıksın.
        self.flush_outbound_acks();

        // bkz. `awaiting_confirmation` alanı dokümantasyonu — Text (grup
        // dışı)/Edit/Delete/HistorySyncRequest için TEK gerçek uçtan uca
        // teslim garantisi burası; `pending_envelopes`'in aksine karşı
        // taraf onaylayana kadar süresiz devam eder.
        // After the incoming packets: an Ack read in this turn stops the
        // retry (and the suspect probe) that is due in the same turn.
        lock_watch::phase("retry_unconfirmed");
        self.retry_unconfirmed_messages();

        // Spec dışı, HIZ düzeltmesi — bkz. `deferred_swarm_events` alanı.
        // Bu turda kuyruğa konan istekler (dosya parçası istekleri, sunucu
        // RPC'leri, ack'ler) swarm bir kez daha pollanmadan tele ÇIKMAZ; bir
        // sonraki turu beklemek her gidiş-dönüşe ~1 sn ekliyordu. Yukarıdaki
        // ana döngü swarm'ı Pending'e kadar boşalttığı için bu tur neredeyse
        // her zaman anında Pending döner (yalnızca durum makinesini ilerletip
        // yazmayı tetikler); yine de bu arada bir olay düşerse ATILMAZ,
        // saklanıp bir sonraki turda ilk sırada işlenir.
        if self.swarm.is_some() {
            let mut dropped: Vec<libp2p::swarm::SwarmEvent<P2PBehaviourEvent>> = Vec::new();
            if let Some(swarm) = &mut self.swarm {
                RUNTIME.block_on(async {
                    for _ in 0..16 {
                        match swarm.next().now_or_never().flatten() {
                            Some(e) => dropped.push(e),
                            None => break,
                        }
                    }
                });
            }
            if !dropped.is_empty() {
                self.deferred_swarm_events.extend(dropped);
            }
        }
        // Events queued after the first drain (retry status, a failed
        // download, replayed early packets) go out in this turn too.
        std::mem::take(&mut self.attachment_events)
    }

    /// Spec dışı, hata düzeltmesi ("ilk mesaj yutuluyor") — bkz.
    /// `early_packets`. Ratchet henüz yokken gelen bir paketi tamponlar.
    /// Peer başına `MAX_EARLY_PACKETS_PER_PEER` ile sınırlı (en eskisi
    /// atılır) — kötü niyetli bir peer sınırsız bellek tüketemesin.
    pub(crate) fn buffer_early_packet(&mut self, sender_fp: String, source: Option<PeerId>, packet: MessagePacket) {
        let now = current_time_ms();
        // K-06: the header fingerprint is not verified yet, so the per-peer
        // caps alone let one peer fill memory under many names. Cap the total
        // too, evicting from the largest buffer.
        const MAX_EARLY_PACKET_BYTES_TOTAL: usize = 32 * 1024 * 1024;
        let buf_bytes = |b: &std::collections::VecDeque<(u64, Option<PeerId>, MessagePacket)>| b.iter().map(|(_, _, p)| p.ciphertext.len()).sum::<usize>();
        let mut total = packet.ciphertext.len() + self.early_packets.values().map(buf_bytes).sum::<usize>();
        while total > MAX_EARLY_PACKET_BYTES_TOTAL {
            let Some(fp) = self.early_packets.iter().max_by_key(|(_, b)| buf_bytes(*b)).map(|(k, _)| k.clone()) else { break };
            let Some(b) = self.early_packets.get_mut(&fp) else { break };
            let top = busiest_source(b.iter().map(|(_, s, _)| *s));
            let i = b.iter().position(|(_, s, _)| *s == top).unwrap_or(0);
            total -= b.remove(i).map_or(0, |p| p.2.ciphertext.len());
            if b.is_empty() {
                self.early_packets.remove(&fp);
            }
        }
        let buf = self.early_packets.entry(sender_fp.clone()).or_default();
        // Count and bytes: one packet may be close to 1 MiB.
        const MAX_EARLY_PACKET_BYTES_PER_PEER: usize = 8 * 1024 * 1024;
        let mut bytes = packet.ciphertext.len() + buf.iter().map(|(_, _, p)| p.ciphertext.len()).sum::<usize>();
        while !buf.is_empty() && (buf.len() >= MAX_EARLY_PACKETS_PER_PEER || bytes > MAX_EARLY_PACKET_BYTES_PER_PEER) {
            // Oldest packet of the source that holds the most entries: the
            // fingerprint in the header is not verified yet, so any peer could
            // name a contact's fingerprint and push that contact's packets out.
            let top = busiest_source(buf.iter().map(|(_, s, _)| *s));
            let i = buf.iter().position(|(_, s, _)| *s == top).unwrap_or(0);
            bytes -= buf.remove(i).map_or(0, |p| p.2.ciphertext.len());
        }
        buf.push_back((now, source, packet));
        info!(
            "Ratchet henüz yok (peer={}) — paket tamponlandı, el sıkışma sonrası oynatılacak ({} bekliyor)",
            crate::log_id(&sender_fp),
            buf.len()
        );
    }

    /// El sıkışma tamamlandıktan sonra, o peer için tamponlanmış paketleri
    /// GELİŞ SIRASINDA işler. Üretilen olaylar `attachment_events`'e
    /// eklenir (poll_events onu drenaj edip Kotlin'e iletir).
    pub(crate) fn replay_early_packets(&mut self, sender_fp: &str) {
        let buffered = match self.early_packets.remove(sender_fp) {
            Some(b) if !b.is_empty() => b,
            _ => return,
        };
        info!("El sıkışma tamam (peer={}) — {} tamponlanmış paket oynatılıyor", crate::log_id(&sender_fp), buffered.len());
        for (_, source, packet) in buffered {
            match self.receive_message(source, &packet) {
                Ok(event) => self.attachment_events.push(event),
                Err(e) => error!("Tamponlanmış paket işlenemedi (peer={}): {}", crate::log_id(&sender_fp), e),
            }
        }
    }

    /// `poll_events`'ten çağrılır — el sıkışması hiç gelmeyen peer'ların
    /// tamponlanmış paketlerini süresi dolunca temizler (bkz.
    /// `EARLY_PACKET_TTL_MS`).
    pub(crate) fn prune_early_packets(&mut self) {
        let now = current_time_ms();
        self.early_packets.retain(|_, buf| {
            buf.retain(|(t, _, _)| now.saturating_sub(*t) <= EARLY_PACKET_TTL_MS);
            !buf.is_empty()
        });
        // bkz. `early_handshakes` — IdentityExchange hiç gelmezse tampondaki
        // el sıkışma da eskir.
        self.early_handshakes.retain(|_, buf| {
            buf.retain(|(t, _, _)| now.saturating_sub(*t) <= EARLY_PACKET_TTL_MS);
            !buf.is_empty()
        });
    }

    /// bkz. `early_handshakes` — `process_identity_exchange` gönderen cihazı
    /// `known_remote_devices`'a ekler eklemez çağrılır; tamponlanmış bir
    /// `HandshakeInit` varsa şimdi işlenebilir (artık imzası doğrulanabilir).
    pub(crate) fn replay_early_handshake(&mut self, sender_fp: &str) {
        let Some(buf) = self.early_handshakes.remove(sender_fp) else { return };
        // Each buffered init in turn: the first one that verifies wins.
        for (_, source, handshake) in buf {
            info!("Tamponlanmış HandshakeInit oynatılıyor (peer={})", crate::log_id(&sender_fp));
            match self.process_handshake_init(source, &handshake) {
                Ok(()) => {
                    self.replay_early_packets(sender_fp);
                    return;
                }
                Err(e) => error!("Tamponlanmış HandshakeInit işlenemedi (peer={}): {}", crate::log_id(&sender_fp), e),
            }
        }
    }

    /// bkz. `message_rate_limiter`/`RATE_LIMIT_WINDOW_MS` dokümantasyonu.
    /// `true` = izin ver, `false` = bu pencerede sınır aşıldı, çağıran
    /// paketi işlemeden (imza doğrulama/ratchet decrypt'e HİÇ girmeden)
    /// atmalı.
    ///
    /// Güvenilirlik düzeltmesi (kardeş cihaz patlamaları): DOĞRULANMIŞ bir
    /// kardeş cihaz (`device_to_peer_id` imza-doğrulaması sonrası dolduğu
    /// için PeerId→fp eşlemesi güvenilir; fp'nin identity'si bizimkiyle
    /// aynıysa kardeştir) 4 kat daha yüksek pencere tavanı alır — yeniden
    /// bağlanma anında `retry_all_pending_now` + kardeş yankıları + Ack'ler
    /// + geri-doldurma AYNI saniyelere yığılır ve 60/10sn tavanını meşru
    /// olarak aşabiliyordu; düşen paketler yeniden denemelerle eninde
    /// sonunda geliyordu ama "yeniden bağlanınca anında senkron" hedefi
    /// pencere pencere sürünmeye dönüşüyordu. Yabancı/normal kişiler için
    /// tavan değişmedi.
    /// Bu `PeerId` KURULMUŞ bir oturuma sahip, kimliği doğrulanmış bir eş mi?
    ///
    /// Ölçüt kasıtlı olarak paketin İÇİNDEKİ iddia değil, TAŞIMA katmanının
    /// kanıtladığı `PeerId`: `device_to_peer_id` yalnızca imza doğrulandıktan
    /// sonra dolduruluyor (bkz. `record_peer_id_if_known`), dolayısıyla
    /// saldırgan başlığa tanıdık bir parmak izi yazarak bu yolu açamaz.
    pub(crate) fn is_established_peer(&self, peer: PeerId) -> bool {
        self.device_to_peer_id.iter().any(|(fp, pid)| {
            *pid == peer
                && self.ratchets.contains_key(fp)
                && self.known_remote_devices.get(fp).map(|d| d.is_active).unwrap_or(false)
        })
    }

    /// Whether `rate_verdict` is going to drop this peer's next packet. Does
    /// not count the packet.
    pub(crate) fn rate_would_drop(&self, peer: PeerId) -> bool {
        let now = mono_ms();
        let (start, count) = self.unknown_peer_rate;
        let all_full = now.saturating_sub(start) <= RATE_LIMIT_WINDOW_MS && count >= RATE_LIMIT_MAX_UNKNOWN_TOTAL;
        (all_full || self.message_rate_limiter.get(&peer).map_or(false, |(start, count)| {
            now.saturating_sub(*start) <= RATE_LIMIT_WINDOW_MS && *count >= RATE_LIMIT_MAX_PER_WINDOW
        })) && !self.is_established_peer(peer)
    }

    /// bkz. `RATE_LIMIT_MAX_ESTABLISHED` — hız sınırının üç sonuçlu hâli.
    pub(crate) fn rate_verdict(&mut self, peer: PeerId) -> RateVerdict {
        let established = self.is_established_peer(peer);
        let max_per_window = if established {
            RATE_LIMIT_MAX_ESTABLISHED
        } else {
            RATE_LIMIT_MAX_PER_WINDOW
        };
        let now = mono_ms();
        let entry = self.message_rate_limiter.entry(peer).or_insert((now, 0));
        let within = if now.saturating_sub(entry.0) > RATE_LIMIT_WINDOW_MS {
            *entry = (now, 1);
            true
        } else {
            entry.1 += 1;
            entry.1 <= max_per_window
        };
        if within {
            // M-190: peer ids cost nothing, so all non-established peers also
            // share one budget, checked before the packet is decoded. Charged
            // only for packets within the peer's own cap: one peer then takes
            // at most its share, not the whole budget.
            if !established && !window_allow(&mut self.unknown_peer_rate, RATE_LIMIT_MAX_UNKNOWN_TOTAL) {
                return RateVerdict::Drop;
            }
            RateVerdict::Allow
        } else if established {
            // Tanıdık eş: ASLA atma, sıraya al. Not counted: the deferred
            // packet is counted once, in the turn it is processed.
            entry.1 -= 1;
            RateVerdict::Defer
        } else {
            RateVerdict::Drop
        }
    }

    /// M-16: budget for server-delivered mail, as much as one established
    /// peer gets (`RATE_LIMIT_MAX_ESTABLISHED` per `RATE_LIMIT_WINDOW_MS`).
    pub(crate) fn server_mail_allowed(&mut self) -> bool {
        window_allow(&mut self.server_mail_rate, RATE_LIMIT_MAX_ESTABLISHED)
    }

    /// Server mail waiting for its rate budget (bkz. `server_mail_allowed`).
    pub(crate) fn server_mail_deferred(&self) -> bool {
        self.deferred_incoming.iter().any(|(s, _)| s.is_none())
    }

    /// bkz. `deferred_incoming` — kuyruk doluysa en eskisi düşer.
    /// bkz. `poll_events` "incoming_envelopes": history key and sessions loaded.
    pub(crate) fn storage_keys_ready(&self) -> bool {
        self.history_key.is_some() && self.ratchets_loaded
    }

    pub(crate) fn defer_incoming(&mut self, source: Option<PeerId>, raw: Vec<u8>) {
        // Count and bytes: 2000 packets of up to 1 MiB each were 2 GB.
        const MAX_DEFERRED_INCOMING_BYTES: usize = 32 * 1024 * 1024;
        let mut bytes = raw.len() + self.deferred_incoming.iter().map(|(_, r)| r.len()).sum::<usize>();
        let mut evicted = 0usize;
        while !self.deferred_incoming.is_empty()
            && (self.deferred_incoming.len() >= MAX_DEFERRED_INCOMING || bytes > MAX_DEFERRED_INCOMING_BYTES)
        {
            // Oldest packet of the peer that holds the most entries: one busy
            // peer must not push out the packets of the others.
            let top = busiest_source(self.deferred_incoming.iter().map(|(s, _)| *s));
            let i = self.deferred_incoming.iter().position(|(s, _)| *s == top).unwrap_or(0);
            if let Some((src, dropped)) = self.deferred_incoming.remove(i) {
                bytes -= dropped.len();
                // H87: server mail is not resent by anyone; keep it on the server.
                if src.is_none() {
                    self.server_item_failed(&dropped);
                }
            }
            evicted += 1;
        }
        if evicted > 0 {
            warn!("Ertelenmiş gelen paket kuyruğu doldu, {} girdi düştü (gönderen yeniden deneyecek)", evicted);
        }
        self.deferred_incoming.push_back((source, raw));
    }

    /// `poll_events`'ten çağrılır — uzun süredir hiç paket göndermemiş
    /// peer'ların hız sınırı girdilerini temizler (bellek koruması, aynı
    /// desen `prune_early_packets` ile).
    pub(crate) fn prune_rate_limiter(&mut self) {
        let now = mono_ms();
        self.message_rate_limiter.retain(|_, (window_start, _)| {
            now.saturating_sub(*window_start) <= RATE_LIMIT_WINDOW_MS
        });
        self.chunk_rate_limiter.retain(|_, (window_start, _)| {
            now.saturating_sub(*window_start) <= RATE_LIMIT_WINDOW_MS
        });
    }

    /// bkz. `INBOUND_DEDUP_WINDOW_MS` — çok yollu teslimin ürettiği
    /// bayt-aynısı zarf tekrarlarını, `process_incoming_envelope_inner`'ı
    /// (imza doğrulama + ratchet decrypt) hiç çağırmadan eler. Tekrar eden
    /// bir `Message` için gönderene Ack yeniden gönderilir — çünkü Ack'in
    /// ona ulaşmamış olması, tekrar göndermesinin OLAĞAN sebebi (bkz.
    /// `receive_message` içindeki decrypt-hatası kolu, AYNI mantık).
    pub(crate) fn process_incoming_envelope(&mut self, source: Option<PeerId>, raw: &[u8]) -> Result<Option<String>, String> {
        let digest = {
            use std::hash::BuildHasher;
            // Per-process random key; `DefaultHasher::new()` is fixed-key.
            static DEDUP_KEY: std::sync::OnceLock<std::collections::hash_map::RandomState> = std::sync::OnceLock::new();
            DEDUP_KEY.get_or_init(std::collections::hash_map::RandomState::new).hash_one(raw)
        };
        let now = current_time_ms();
        // Periyodik budama + sert tavan — her zarfta `retain` çalıştırmamak için.
        if now.saturating_sub(self.last_inbound_dedup_prune_at) > 60_000
            || self.recent_inbound_digests.len() > INBOUND_DEDUP_MAX_ENTRIES
        {
            self.last_inbound_dedup_prune_at = now;
            self.recent_inbound_digests
                .retain(|_, seen_at| now.saturating_sub(*seen_at) < INBOUND_DEDUP_WINDOW_MS);
            if self.recent_inbound_digests.len() > INBOUND_DEDUP_MAX_ENTRIES {
                // Still over the cap: the older half goes. Clearing it all
                // let a flood make every retried packet be verified again.
                // By count, not by a time cutoff: under a flood the entries
                // share a millisecond and a `> median` test kept none.
                let mut entries: Vec<(u64, u64)> = self.recent_inbound_digests.drain().collect();
                entries.sort_unstable_by_key(|e| std::cmp::Reverse(e.1));
                entries.truncate(INBOUND_DEDUP_MAX_ENTRIES / 2);
                self.recent_inbound_digests.extend(entries);
            }
        }
        let seen_at = self.recent_inbound_digests.get(&digest).copied();
        if let Some(seen_at) = seen_at {
            if now.saturating_sub(seen_at) < INBOUND_DEDUP_WINDOW_MS {
                // The time stamp is NOT refreshed: the sender retries every
                // 15-120 s, so a window that slides never ended.
                // Bu zarfın bayt-aynısı bir kopyasını bu pencerede zaten
                // işledik (Ok ya da Err — fark etmez, sonuç deterministik).
                // `Message` ise gönderene Ack'i yeniden yolla (decrypt
                // GEREKMEZ — `MessagePacketHeader` imzalı ama şifreli değil,
                // `message_id`'yi düz taşır ve ilk geçişte zaten doğrulandı;
                // yalnızca arşivde GERÇEKTEN varsa Ack atıyoruz — hâlâ teslim
                // edilmemiş bir mesajı yanlışlıkla onaylamayız).
                if let Ok(NetworkEnvelope::Message(m)) = ciborium::from_reader(raw) {
                    self.reack_if_already_handled(&m.header);
                }
                return Ok(None);
            }
        }
        let result = self.process_incoming_envelope_inner(source, raw);
        // Sonuç Ok OLSUN OLMASIN kaydedilir. İKİ CİHAZLI TESTTE (2026-09-06,
        // 2. tur) görüldü: çözülemeyen bir kontrol paketi (ratchet ilerledi,
        // arşivde de yok — typing/receipt gibi) `_inner`'dan Err dönüyor, bu
        // yüzden haritaya girmiyordu; ağ aynı baytları tekrar getirdikçe HER
        // seferinde yeniden `error!("Gelen paket işlenemedi")` logluyordu
        // (bir mesaj numarası 11 kez). Bayt-aynısı bir zarfın yeniden
        // işlenmesi DETERMİNİSTİK olarak aynı sonucu verir — Err ise sonsuza
        // dek Err. `regen_content` sonrası tazelenen paket FARKLI ciphertext
        // (farklı digest) taşıdığından yine de teslim olur; bu yüzden Err'i
        // de kaydetmek güvenli.
        // İstisna: `_inner` "erken paket" olarak tamponladıysa Ok(None) döner
        // ve digest kaydedilir — buffer'daki kopya el sıkışmadan sonra
        // `replay_early_packets` ile zaten işlenecek, ağ tekrarına gerek yok.
        // One failure does depend on state: the sender's IdentityExchange has
        // not arrived yet. That one is forgotten after 30 s, so the sender's
        // retry of the same bytes is processed again. Not every Err: a packet
        // that cannot be decrypted would count toward `note_undecryptable`
        // on each retry.
        // Every failure can depend on state (a packet that came before the
        // rotation it needs): forgotten after 30 s, so a retry of the same
        // bytes is processed again.
        // An IdentityExchange is the same bytes every time: a contact that
        // was deleted and paired again within the window got no answer. It
        // is remembered for 30 s, like a failed packet.
        let short = result.is_err()
            || matches!(ciborium::from_reader::<NetworkEnvelope, _>(raw), Ok(NetworkEnvelope::IdentityExchange(_)));
        let seen_at = if short { now.saturating_sub(INBOUND_DEDUP_WINDOW_MS - 30_000) } else { now };
        self.recent_inbound_digests.insert(digest, seen_at);
        result
    }

    pub(crate) fn process_incoming_envelope_inner(&mut self, source: Option<PeerId>, raw: &[u8]) -> Result<Option<String>, String> {
        // bkz. `rate_verdict` dokümantasyonu — imza doğrulama/ratchet
        // decrypt gibi pahalı işlemlerden ÖNCE, en ucuz noktada kontrol
        // edilir. `source: None` (gerçek bir ağ bağlantısından gelmeyen,
        // ör. tamponlanmış bir yeniden oynatma) hız sınırına TABİ değildir
        // — o paket zaten bir kez sayılmıştı.
        // Hız sınırı artık BURADA değil, `poll_events`'in gelen döngüsünde
        // uygulanıyor — çünkü "ertele" sonucu (bkz. `RateVerdict::Defer`)
        // paketi geri kuyruğa koymayı gerektiriyor ve bu, döngünün işi.
        let envelope: NetworkEnvelope = ciborium::from_reader(raw).map_err(|e| e.to_string())?;
        // bkz. `blocked_identities`: engelli bir kişiden gelen HİÇBİR paket
        // işlenmez — ne mesaj, ne el sıkışma, ne de kimlik tanıtımı. Uyarı
        // da üretilmez, aksi halde engellenen taraf "yeni cihaz" uyarısı
        // yağdırarak rahatsız edebilirdi.
        let blocked_sender = match &envelope {
            NetworkEnvelope::IdentityExchange(x) => self.is_blocked(&x.identity_id),
            NetworkEnvelope::Handshake(h) => {
                self.is_blocked(&h.sender_identity_id) || self.is_blocked_device(&h.sender_device_fingerprint)
            }
            NetworkEnvelope::Message(m) => {
                self.is_blocked(&m.header.sender_identity_id)
                    || self.is_blocked_device(&m.header.sender_device_fingerprint)
            }
        };
        if blocked_sender {
            return Ok(None);
        }
        match envelope {
            NetworkEnvelope::IdentityExchange(x) => {
                // Spec dışı, güvenlik denetimi düzeltmesi: `record_peer_id_if_known`
                // artık BURADA çağrılmıyor — `x.device_fingerprint` bu
                // noktada henüz doğrulanmamış, sadece gönderenin İDDİASI
                // (bkz. `process_identity_exchange` içindeki taşınma notu).
                // Fonksiyon, fingerprint'in taşınan public key'lerden
                // gerçekten türediğini doğruladıktan SONRA kendi içinde
                // kaydediyor.
                self.process_identity_exchange(source, &x)?;
                // A sibling brought back our own revoke: everything is wiped
                // (`self_revoked` is queued by `apply_device_revoke_notice`).
                if self.identity.is_none() {
                    return Ok(None);
                }
                Ok(None)
            }
            NetworkEnvelope::Handshake(h) => {
                let sender_fp = h.sender_device_fingerprint.clone();
                // bkz. yukarıdaki IdentityExchange notu — `process_handshake_init`
                // artık imza doğrulandıktan SONRA kendi içinde kaydediyor.
                match self.process_handshake_init(source, &h) {
                    Ok(()) => {}
                    // H2: the state itself, not the error text.
                    Err(e) if !self.known_remote_devices.contains_key(&sender_fp) => {
                        // bkz. `early_handshakes` — gönderenin IdentityExchange'i
                        // henüz gelmedi; DÜŞÜRME, tamponla. Yalnızca bu kişiyle
                        // aktif eşleşme sürecindeysek ya da kişi zaten
                        // biliniyorsa (sınırsız tampon önlemi).
                        let expected = self.pairing_mailbox_subs.contains_key(&sender_fp)
                            || self.identity_to_contact.contains_key(&h.sender_identity_id);
                        // `sender_identity_id` is an unverified claim and each
                        // init is several KB: capped.
                        // And 4 per claimed identity: one known identity id
                        // was enough to take all 64 slots.
                        let same_identity = self.early_handshakes.values().flatten().filter(|(_, _, e)| e.sender_identity_id == h.sender_identity_id).count();
                        // M100: a claim not backed by a pairing in progress or
                        // a device the contact already lists gets 16 of the 64
                        // slots: ~16 known identity ids filled them all and a
                        // real pairing's init was refused.
                        let listed = |fp: &str, id: &str| self.identity_to_contact.get(id)
                            .and_then(|cid| self.contacts.get(cid))
                            .map_or(false, |c| c.find_device(fp).is_some());
                        let vouched = self.pairing_mailbox_subs.contains_key(&sender_fp) || listed(&sender_fp, &h.sender_identity_id);
                        let unvouched = self.early_handshakes.iter()
                            .filter(|(fp, buf)| !self.pairing_mailbox_subs.contains_key(*fp)
                                && !buf.iter().any(|(_, _, e)| listed(fp, &e.sender_identity_id)))
                            .count();
                        let held = self.early_handshakes.get(&sender_fp).map_or(0, |b| b.len());
                        if expected && same_identity < 4 && (vouched || unvouched < 16) && held < 3
                            && (self.early_handshakes.len() < 64 || held > 0)
                        {
                            info!("HandshakeInit erken geldi (peer={}) — IdentityExchange bekleniyor, tamponlandı", crate::log_id(&sender_fp));
                            self.early_handshakes.entry(sender_fp.clone()).or_default().push((current_time_ms(), source, h));
                            return Ok(None);
                        }
                        // Not buffered: an Err, so the dedup forgets it soon (bkz.
                        // `process_incoming_envelope`).
                        return Err(e);
                    }
                    Err(e) => return Err(e),
                }
                // Spec dışı, hata düzeltmesi ("ilk mesaj yutuluyor"): el
                // sıkışmadan ÖNCE gelip tamponlanan paketleri şimdi işle
                // (bkz. `early_packets`). Olaylar `attachment_events`
                // kuyruğuna gider, `poll_events` onu zaten drenaj ediyor.
                self.replay_early_packets(&sender_fp);
                Ok(None)
            }
            NetworkEnvelope::Message(m) => {
                let sender_fp = m.header.sender_device_fingerprint.clone();
                // bkz. `early_packets` / `EARLY_PACKET_TTL_MS`: henüz ratchet
                // yoksa (mesaj el sıkışmadan ÖNCE geldi — gossipsub sıra
                // garantisi vermez) paketi ATMA, tamponla; el sıkışma gelince
                // yeniden oynatılacak. Sadece BİLİNEN cihazlar tamponlanır
                // (tanınmayan gönderen zaten reddedilirdi; sınırsız tampon
                // dolmasını da önler). `source` de paketle BİRLİKTE
                // tamponlanır (bkz. `early_packets` alan notu) — imza henüz
                // doğrulanmadığından burada kaydedilmiyor, replay anında
                // `receive_message` kendi içinde (doğrulama sonrası) kaydeder.
                if !self.ratchets.contains_key(&sender_fp) {
                    if let Some(sender) = self.known_remote_devices.get(&sender_fp).filter(|d| d.is_active).cloned() {
                        // The signature first (the keys are known): the
                        // fingerprint in the header is only a claim, and a
                        // stranger with throw-away peer ids filled this
                        // device's buffer and pushed the real packets out.
                        let to_verify = packet_signing_input(m.header.raw(), &m.ciphertext, &self.get_active_own_device_fingerprint()?);
                        verify_hybrid_signature(&to_verify, &m.signature_classical, &m.signature_pq, &sender)?;
                        self.buffer_early_packet(sender_fp, source, m);
                        return Ok(None);
                    }
                }
                // bkz. yukarıdaki notlar — `receive_message` artık imza
                // doğrulandıktan SONRA kendi içinde kaydediyor.
                let text = self.receive_message(source, &m)?;
                Ok(Some(text))
            }
        }
    }
}
