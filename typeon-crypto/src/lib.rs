//! Shared crypto core: primitives, identity model and wire formats.
//!
//! Used by the native clients (Android, Linux) and by the `wasm32` target.
//! Protocol logic only: no SQLite, libp2p, Tor or JNI.
//!
//! Modules:
//! - `identity`: identity and device model, fingerprints
//! - `packet`: wire packet formats, `MessageContent`
//! - `ratchet`: hybrid KEM and Double Ratchet
//! - `server_proto`: store-and-forward wire types
//! - `server_seal`: second encryption layer for the server

pub mod identity;
pub mod packet;
pub mod ratchet;
pub mod server_proto;
pub mod server_seal;
