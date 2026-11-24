# Typeon Android

A fully decentralized peer-to-peer messaging app for Android, implemented in Rust with Kotlin UI.

## Protocol Specification

This implementation follows the P2P Messaging Protocol v0.2 as defined in `Description.md`.

### Key Features

- **Hybrid Classical + Post-Quantum Cryptography**
  - Ed25519 + ML-DSA-87 for signatures
  - X25519 + ML-KEM-1024 for key exchange
  - Fingerprint = SHA3-256(all public keys)

- **Identity/Device Two-Layer Model**
  - One identity per user (immutable `identity_id`)
  - Up to 5 active devices per identity
  - Device add/revoke with signed packets

- **TOFU Trust Model**
  - Trust On First Use for initial contact
  - Device change detection with security warnings
  - Identity-level verification (safety numbers)

- **Double Ratchet Encryption**
  - Forward secrecy with 30-minute ratchet rotation
  - ChaCha20-Poly1305 for message encryption
  - Hybrid signatures on all packets

- **Pairwise Group Messaging**
  - Messages encrypted separately for each group member
  - Founder-only membership management
  - Signed `GroupUpdate` packets

- **Multi-Device Sync**
  - `SyncPayload` for contacts, groups, ratchet states
  - Read receipts synced across devices
  - Optional message history sync

- **Recovery File**
  - ChaCha20-Poly1305 encrypted backup, key derived with Argon2id from the password
  - Password-protected master seed
  - Base32 encoded text format

## Project Structure

```
p2p_messenger_android/
├── app/
│   ├── src/main/
│   │   ├── cpp/
│   │   │   ├── rust/
│   │   │   │   ├── Cargo.toml          # Rust dependencies
│   │   │   │   └── src/lib.rs          # Core protocol (topic modules under src/)
│   │   ├── java/com/p2p/messenger/
│   │   │   ├── MainActivity.kt         # Main UI
│   │   │   ├── P2PLib.kt               # JNI bindings
│   │   │   ├── service/P2PService.kt   # Background service
│   │   │   └── ui/ChatAdapter.kt       # Chat list adapter
│   │   ├── res/                        # Android resources
│   │   └── AndroidManifest.xml
│   └── build.gradle
├── build.gradle
├── settings.gradle
└── README.md
```

## Build Instructions

### Prerequisites

1. **Android Studio** (Arctic Fox or newer)
2. **Android NDK** (via SDK Manager)
3. **Rust toolchain** with cross-compilation targets:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
   cargo install cargo-ndk
   ```

### Building the Rust Library

```bash
cd app/src/main/cpp/rust

# Build for all Android targets
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -t x86 -o ../../jniLibs build --release
```

This creates the native libraries in:
```
app/src/main/jniLibs/
├── arm64-v8a/libp2p_messenger.so
├── armeabi-v7a/libp2p_messenger.so
├── x86_64/libp2p_messenger.so
└── x86/libp2p_messenger.so
```

A Gradle run that builds only the debug variant writes `app/src/debug/jniLibs/` instead. Any other run writes `app/src/main/jniLibs/` and deletes `app/src/debug/jniLibs/`.

### Building the Android App

1. Open the project folder in Android Studio
2. Wait for Gradle sync to complete
3. Click **Build > Make Project** (or `Ctrl+F9`)
4. Run on device/emulator (`Shift+F10`)

## Usage

### First Launch

1. The app generates a new identity with hybrid key pairs
2. View your **Identity Code** (Base32, 5-char groups)
3. View your **Safety Number** (8 groups of 5 digits)

### Adding Contacts

**Via QR Code:**
1. Tap menu → "My QR" to display your code
2. Other person scans with their app
3. Or tap "Scan QR" to scan their code

**Manual Entry:** menu "Copy my code" on one phone, then "Add Manually" on the
other and paste the one-line code:
```
identity_id|device_fingerprint|nonce|device_name|rendezvous_node
```
`rendezvous_node` is the onion address: `/dns/<host>.onion/tcp/<port>/p2p/<peer_id>`.

### Creating Groups

1. Menu → "Create Group"
2. Enter group name
3. Add members by selecting contacts
4. Only founder can add/remove members

### Backup & Recovery

1. Settings → "Identity Recovery" → "Export Recovery File…"
2. Enter a strong password
3. Save the recovery file securely
4. To restore: enter file content + password on new device

## Protocol Details

### Message Packet Structure

```rust
MessagePacket {
    header: {
        sender_identity_id: bytes[32],
        sender_device_fingerprint: bytes[32],
        ratchet_pubkey: bytes,
        message_number: u32,
        prev_chain_length: u32,
    },
    ciphertext: bytes,      // ChaCha20-Poly1305 encrypted
    signature: HybridSignature,  // Ed25519 + ML-DSA
}
```

### QR Payload (Compact)

```rust
QRPayload {
    version: u8,            // = 2
    device_name: String,
    identity_id: bytes[32],
    device_fingerprint: bytes[32],
    rendezvous_node: String,  // Multiaddr
}
```

### Recovery File Format

The file is ChaCha20-Poly1305 ciphertext under an Argon2id key from the password.
The exact layout is in `app/src/main/cpp/rust/src/recovery.rs`; the old
`BEGIN/END P2P RECOVERY FILE` block was not what the code writes.

## Security Considerations

1. **Verify identities** in person using safety numbers
2. **Watch for device change warnings** - may indicate MITM
3. **Backup recovery file** immediately after setup
4. **Keep password secret** - no recovery without it
5. **Update regularly** for security patches

## Limitations

The old v0.1 prototype list (no network, no persistence, no file transfer, no calls) was
removed: all of those now exist.

## License

The Android client is GPL-3.0-or-later (see the License section of the root README.md). The root `LICENSE` file is Apache-2.0 and covers only the remaining code such as `typeon-crypto`.
