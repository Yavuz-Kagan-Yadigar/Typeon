//! TypeOn — paylaşılan kripto çekirdeği.
//!
//! `p2p_messenger_core`'dan ayrıştırıldı: aynı denetlenmiş kod hem native
//! (Android/Linux/`typeon-relay`) hem de tarayıcı (`wasm32`, `typeon-web`)
//! tarafında çalışsın diye — protokolün iki ucu arasında elle senkron tutulacak
//! ikinci bir kopya yok. Burada SQLite, libp2p, Tor veya JNI YOK.
//!
//! Modüller (çekirdekteki eski yollar `pub use` ile korunuyor):
//! - `identity`     : Identity/Device modeli, fingerprint
//! - `packet`       : ağ paket formatları, `MessageContent`
//! - `ratchet`      : hibrit KEM + Double Ratchet
//! - `server_proto` : store-and-forward kablo tipleri
//! - `server_seal`  : sunucu için ikinci şifreleme katmanı

pub mod identity;
pub mod packet;
pub mod ratchet;
pub mod server_proto;
pub mod server_seal;
