//! Key bundles, device records, summaries and transfer state used by `P2PCore`.

use super::*;


// --- The device's local secret keys. Never written to the network or DB in plaintext;
// only the export_recovery path, which is encrypted ---
/// How long a prekey is handed out before a new one is made.
pub(crate) const PREKEY_ROTATE_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// How long its secret half is kept: while it is handed out, plus the time a
/// HandshakeInit made with it can wait for this device (`HANDSHAKE_MAX_AGE_MS`),
/// plus a week for a peer that missed one rotation. After that the secret is
/// deleted, and what was sent to it can no longer be opened from this device.
pub(crate) const PREKEY_KEEP_MS: u64 = PREKEY_ROTATE_MS + HANDSHAKE_MAX_AGE_MS + 7 * 24 * 60 * 60 * 1000;

/// One of this device's prekeys with its secret half (`packet::SignedPrekey`).
pub(crate) struct OwnPrekey {
    pub(crate) signed: SignedPrekey,
    pub(crate) sk_x25519: StaticSecret,
    pub(crate) sk_mlkem: MlKem1024DecapsulationKey,
}

/// `OwnPrekey` as stored (CBOR, sealed with the local storage key).
#[derive(Serialize, Deserialize)]
pub(crate) struct StoredPrekey {
    pub(crate) signed: SignedPrekey,
    #[serde(with = "serde_bytes")]
    pub(crate) sk_x25519: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) sk_mlkem: Vec<u8>,
}

pub(crate) struct DeviceKeys {
    pub(crate) sign_sk_ed25519: SigningKey,
    #[allow(dead_code)]
    pub(crate) sign_pk_ed25519: VerifyingKey,
    /// Like the siblings (`sign_pk_ed25519`/`kem_pk_x25519`): these two PUBLIC keys are used only to compute the fingerprint at creation time. The
    /// authoritative copy then lives in `own_devices` (`DeviceRecord`). They are kept in the struct for symmetry and readability, and the compiler's
    /// `dead_code` warning is silenced for that reason.
    #[allow(dead_code)]
    pub(crate) sign_pk_mldsa: MlDsaVerifyingKey<MlDsa87>,
    pub(crate) sign_sk_mldsa: MlDsaSigningKey<MlDsa87>,
    pub(crate) kem_sk_x25519: StaticSecret,
    #[allow(dead_code)]
    pub(crate) kem_pk_x25519: X25519PublicKey,
    #[allow(dead_code)]
    pub(crate) kem_pk_mlkem: MlKem1024EncapsulationKey,
    pub(crate) kem_sk_mlkem: MlKem1024DecapsulationKey,
}

/// Carries all secret keys of a device across the JNI boundary to and from Kotlin. Rust NEVER writes this block to disk. Reading and writing to disk is
/// entirely Kotlin's job (encrypted with KeystoreCrypto and stored in a separate table or file). So Rust never sees the master encryption key: it only
/// generates and consumes plaintext keys, and encryption and disk writes are Kotlin's responsibility.
// `Debug` is deliberately NOT derived. This struct holds four raw secret key byte arrays. If someone later added a line like `error!("{:?}", bundle)`,
// the long-term identity keys would be written to Android logcat in plaintext. It is also zeroed on `Drop` when freed (see the "zeroize" feature note in
// Cargo.toml: the typed `DeviceKeys`/`DeviceRatchetState` get that from the upstream crates' `ZeroizeOnDrop`, but this struct uses raw `Vec<u8>`, so it
// has to be done by hand).
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SecretKeyBundle {
    pub(crate) device_fingerprint: String,
    #[serde(with = "serde_bytes")]
    pub(crate) sign_sk_ed25519: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) sign_sk_mldsa: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) kem_sk_x25519: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) kem_sk_mlkem: Vec<u8>,
}

impl Drop for SecretKeyBundle {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.sign_sk_ed25519.zeroize();
        self.sign_sk_mldsa.zeroize();
        self.kem_sk_x25519.zeroize();
        self.kem_sk_mlkem.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct DeviceRecord {
    pub(crate) device_fingerprint: String,
    pub(crate) identity_id: String,
    #[serde(with = "serde_bytes")]
    pub(crate) sign_pubkey_ed25519: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) sign_pubkey_mldsa: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) kem_pubkey_x25519: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) kem_pubkey_mlkem: Vec<u8>,
    pub(crate) device_name: String,
    pub(crate) is_active: bool,
    pub(crate) last_seen: u64,
}

/// Summary of a "device changed" condition detected during connection setup, passed to Kotlin (the warning screen).
// `Deserialize` was added (to this and the five summary structs below): the Linux desktop client (see the `api` module) reads these types back from JSON.
// If it defined its own mirror structs, a field change here would be silently lost there. The Android side does not use this derive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAlertInfo {
    pub contact_display_name: String,
    pub identity_id: String,
    pub new_device_fingerprint: String,
    pub known_device_short_codes: Vec<String>,
    pub new_device_short_code: String,
}

/// For the "pending messages" list in Settings (see `P2PCore::list_pending_messages`). These are chat messages the user actually wrote that are still
/// waiting for confirmation in `awaiting_confirmation` (not internal packets such as Edit/Delete/GroupUpdate; see the filter in that function). The
/// `peer_device_fingerprint`/`group_id` are turned into names on the Kotlin side with the `listContacts()`/`listGroups()` it already has. No name
/// resolution logic is duplicated here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingMessageSummary {
    pub message_id: String,
    pub peer_device_fingerprint: String,
    /// The name of the TARGET DEVICE (see `DeviceRecord.device_name`). A contact or group name alone does not say WHICH device has not yet confirmed
    /// (in pairwise group fan-out, each `PendingMessageSummary` maps to one device of one member). Empty if unknown (rare: the device record may have been
    /// deleted or revoked). In that case Kotlin falls back to a short fingerprint.
    pub device_name: String,
    /// Display name of the contact that owns the target device; empty when it is none (a sibling, a removed contact).
    #[serde(default)]
    pub contact_name: String,
    pub group_id: Option<String>,
    pub text: String,
    pub original_sent_at: u64,
    pub last_attempt_at: u64,
}

/// Summary used by the UI's contact picker list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactSummary {
    pub contact_id: String,
    pub display_name: String,
    pub identity_id: String,
    /// None: the IdentityExchange has not completed yet, so no message can be sent.
    pub active_device_fingerprint: Option<String>,
    /// The profile photo this contact sent us (if any), hex-encoded with the same pattern as `preview_hex` in `list_attachments`, since JSON cannot carry raw binary.
    pub avatar_hex: Option<String>,
    /// `true` if this contact was added through a group, with the FOUNDER'S VOUCH, not through face-to-face QR/manual pairing. The UI shows a "added via group,
    /// not verified" warning (see the `GroupUpdate.member_devices` security note).
    pub added_via_group: bool,
    /// The contact deleted its account (`AccountDeleted`). The UI disables sending.
    #[serde(default)]
    pub account_deleted: bool,
}

/// One message, decrypted from the local encrypted archive and returned to Kotlin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivedMessage {
    pub direction: String, // "sent" | "received"
    pub text: String,
    pub timestamp: u64,
    /// Effective time for DISPLAY and SORTING: the sender's send time (`sent_at_ms`), or the local `timestamp` if that is unknown. `timestamp` (the local
    /// receive time) is kept separately for sync and paging. Kotlin sorts bubbles by this value, so a delayed message appears at its SEND position, not its
    /// receive position.
    pub sent_at_ms: u64,
    /// Send status is persisted now: `Some("pending"|"sent"|"error")` for a row we sent. `None` for received messages. Older rows (written before this
    /// column existed) also have `None`, and Kotlin treats `None` as "sent" (the safest assumption for old rows; otherwise they would show "pending"
    /// forever).
    pub status: Option<String>,
    /// Filled ONLY for group messages. In a group there can be several senders (unlike 1:1, where `direction` alone is enough). GroupChatActivity needs this
    /// to show the correct sender name and avatar.
    pub sender_identity_id: Option<String>,
    /// This row's stable message id (if any). Used for the "seen" match after a reload and for status updates (see the BUGS/LIMITS note at the top of the file;
    /// now partly resolved).
    pub message_id: Option<String>,
    /// The stable id of the message this one replies to (`message_id` in 1:1, `group_message_local_id` in a group). See the `MessageContent::Text.reply_to_message_id` docs in packet.rs.
    pub reply_to_message_id: Option<String>,
    /// Truncated text summary of the replied-to message, as embedded by the sender. Kotlin does not look it up in its own archive.
    pub reply_to_preview: Option<String>,
    /// Filled ONLY for group messages: the `identity_id` of the sender of the replied-to message.
    pub reply_to_sender_identity_id: Option<String>,
    /// True if this message was deleted (see apply_delete_to_archive) — the
    /// archived text is stale/meaningless once this is set, Kotlin should
    /// render a deleted placeholder instead.
    pub is_deleted: bool,
    /// True once this message has been edited. Without it the "(edited)"
    /// marker was live-only on BOTH clients: the archive stored the new text
    /// but nothing recorded that it had changed, so reopening a chat quietly
    /// presented an edited message as if it were the original.
    pub is_edited: bool,
    /// The row came from a contact's 1:1 history answer (`mark_synced`).
    #[serde(default)]
    pub via_sync: bool,
    /// Ready-made summary of the reactions on this message (e.g. `"👍2 ❤️"`). Empty string = no reactions. Kotlin writes it straight into the reaction pill
    /// without a separate query (see `reactions_summary`).
    #[serde(default)]
    pub reactions: String,
    /// Who has seen this message: the same "embedded summary" pattern as `reactions` (see `seen_by_json`), `[{"identity_id":..,"seen_at_ms":..}]`. Before,
    /// this information was NEVER persisted. It was a live event that existed only while the chat screen was open, so every "seen" notice arriving while the
    /// screen was closed or in the background was lost for good.
    #[serde(default)]
    pub seen_by: String,
    /// Group rows: the author's signature, see `group_author_statement`.
    /// Carried in the server archive so a restored device can still hand
    /// the row on with the group history.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_proof: Option<String>,
    /// Group rows: this message @mentions me (local only, see `mentions_me`
    /// column).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub mentions_me: bool,
    /// Disappearing message: the timer in seconds (see `MessageContent::Text.expire_secs`). Local only: such a row never goes to the server archive
    /// or into a history answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expire_secs: Option<u32>,
    /// When the row goes, local clock (ms). An unread received row holds the unread cap here; reading it lowers the value (see `start_expiry`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expire_at_ms: Option<u64>,
}

/// Summary for the Groups tab list and detail view. (`list_groups` did not exist before, so the Groups tab never showed a real group list.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupSummary {
    pub group_id: String,
    pub name: String,
    pub founder_identity_id: String,
    pub is_founder: bool,
    pub member_identity_ids: Vec<String>,
    /// Same hex-encoding pattern as `ContactSummary.avatar_hex`.
    pub avatar_hex: Option<String>,
}

/// List of file attachments in a chat, returned to Kotlin (see the `list_attachments` JNI export).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentSummary {
    pub file_id: String,
    pub file_name: String,
    pub mime_type: String,
    pub total_size: u64,
    pub direction: String, // "sent" | "received"
    pub status: String,    // "offered" | "downloading" | "complete" | "failed"
    pub bytes_transferred: u64,
    pub created_at: u64,
    /// Same format as `preview_hex` in the `file_offer` poll event, so Kotlin can show the thumbnail at once while rebuilding history, without waiting for a
    /// download (see `SimpleChatAdapter.AttachmentInfo`).
    pub preview_hex: Option<String>,
    /// Playback duration in milliseconds for voice messages (see `MessageContent::FileOffer.duration_ms`).
    pub duration_ms: Option<u32>,
    /// Filled ONLY by `list_group_attachments`. In a group, attachments can come from DIFFERENT senders (unlike 1:1, where the query is already fixed to one
    /// peer). `download_file` needs it to know where to download from. Always an empty string for `list_attachments` (1:1).
    pub peer_device_fingerprint: String,
    /// Filled ONLY for group attachments: to show the sender's name and avatar (same reason as `ArchivedMessage.sender_identity_id`).
    pub sender_identity_id: Option<String>,
    /// The caption sent with the file and the replied-to message context (if any). Read from the archive so that when the chat reopens, the attachment bubble
    /// can rebuild them the same way as text messages (see the same-named columns in the `files` table).
    #[serde(default)]
    pub caption: String,
    #[serde(default)]
    pub reply_to_message_id: Option<String>,
    #[serde(default)]
    pub reply_to_preview: Option<String>,
    #[serde(default)]
    pub reply_to_sender_identity_id: Option<String>,
    /// Shown without a bubble frame, see `MessageContent::FileOffer.sticker`.
    #[serde(default)]
    pub sticker: bool,
    /// The sender's send time (ms): the order key of the bubble, like a text's `sent_at_ms`. `created_at` for older rows.
    #[serde(default)]
    pub sent_at_ms: u64,
    /// My own file only: the send status of its offer ("pending" | "sent" | "error" | "delivered"); None when not known.
    #[serde(default)]
    pub send_status: Option<String>,
    /// Disappearing attachment: timer seconds and when it goes (local clock, ms). See `ArchivedMessage.expire_secs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expire_secs: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expire_at_ms: Option<u64>,
}

/// In-memory state of an ongoing download (see `download_file`, `request_next_chunk` and the attachments.rs module note). Chunks are ALWAYS requested in
/// order (0, 1, 2, ...), so the `.enc` file is only ever APPENDED to, and no seek is needed.
pub(crate) struct DownloadState {
    /// `FileOffer.chunk_hashes` of this file (from the `files` row): one
    /// SHA-256 per group of `per_hash` chunks, over their ciphertext.
    pub(crate) chunk_hashes: Vec<u8>,
    /// `attachments::chunks_per_hash` of this file.
    pub(crate) per_hash: u32,
    /// Chunks on disk whose group is not complete yet (only when `per_hash`
    /// > 1): the source that served each and its plaintext length. They move
    /// to `received_chunks` once the group hash matches.
    pub(crate) pending_chunks: std::collections::HashMap<u32, (PeerId, usize)>,
    /// Sources that served a chunk which did not match `chunk_hashes`: not
    /// asked again in this attempt.
    pub(crate) bad_sources: std::collections::HashSet<PeerId>,
    pub(crate) peer_id: PeerId,
    /// See `P2PCore::peer_for_file`. Needed to fill the `"peer"` field of `file_progress`/`file_complete`/`file_failed` events. Without it, the chat screen's
    /// event listener silently IGNORED the event (no match on `"peer"`). Since this field was never filled, the UI never heard about a download even when it
    /// finished successfully on the Rust side.
    pub(crate) peer_device_fingerprint: String,
    pub(crate) total_size: u64,
    pub(crate) total_chunks: u32,
    pub(crate) next_chunk_index: u32,
    pub(crate) bytes_done: u64,
    pub(crate) file_key: [u8; 32],
    pub(crate) enc_path: std::path::PathBuf,
    /// When the last REAL progress happened (a chunk was received and written), or when the download started if no chunk has arrived yet. See
    /// `DOWNLOAD_GIVE_UP_TIMEOUT_MS`. Updated ONLY when real data arrives in `handle_chunk_response`. Unlike `last_retry_at`, this tracks how long the download
    /// has made NO progress (retries are not counted). It is used for the "give up now" decision.
    pub(crate) last_progress_at: u64,
    /// The last time the SAME CHUNK was requested again. See `DOWNLOAD_STALL_TIMEOUT_MS`, `check_stalled_downloads` and `retry_or_give_up_download`. Kept
    /// SEPARATE from `last_progress_at`: if they were the same field, a retry (which does not update it until a reply arrives) would make
    /// `check_stalled_downloads` fire again on EVERY `poll_events` turn (once a second) and re-request the same chunk over and over. With this field, retries
    /// are spaced out at `DOWNLOAD_STALL_TIMEOUT_MS`. It catches the case where the TCP dial never completes (neither success nor a clear error, typical when both
    /// devices are behind NAT): there, libp2p's `request_response` produces no event at all (no reply, no OutboundFailure, no timeout). Without this, the download
    /// would stay "Downloading" forever.
    pub(crate) last_retry_at: u64,
    /// If this is a GROUP file (see `download_file`), the devices of other members who may already have finished the same file. If the current source keeps
    /// failing or stalling (see `retry_or_give_up_download` and the `NotFound` arm of `handle_chunk_response`), they are tried in turn. We do not know in
    /// advance who really has the file (the protocol has no "who has this" announcement). So the candidates are tried in order, and on `NotFound` the next one
    /// is used. This is harmless: `serve_chunk_request` answers at once if the file is not there.
    pub(crate) alt_source_peer_ids: std::collections::VecDeque<PeerId>,
    /// How many times the CURRENT peer was retried without real progress. See `retry_or_give_up_download`: past a threshold, the next candidate is tried.
    /// Reset when the source changes or on real progress (see `handle_chunk_response`).
    pub(crate) retries_on_current_source: u32,
    /// Chunk indices currently in flight (the pipeline, see `DOWNLOAD_PIPELINE_DEPTH`). Before, only ONE chunk could be in flight, so the speed was capped at
    /// `chunk size / round-trip time`, whatever the bandwidth. The real figure measured over Tor was about 70 KB/s.
    pub(crate) inflight_chunks: std::collections::HashSet<u32>,
    /// Chunks already WRITTEN to disk. Chunks arrive out of order in the pipeline, so a counter is not enough: each index that completed has to be tracked.
    /// Only chunks whose group matched `chunk_hashes` are in it.
    pub(crate) received_chunks: std::collections::HashSet<u32>,
    /// Adaptive pipeline window (see `DOWNLOAD_WINDOW_START`): how many chunks may be in flight at once. It grows on success and halves on a timeout or error.
    pub(crate) window: usize,
    /// When each in-flight chunk was requested. Used for the round-trip measurement (see `DOWNLOAD_RTT_TARGET_MS`). Removed when a reply or error arrives.
    pub(crate) chunk_sent_at: std::collections::HashMap<u32, u64>,
    /// The SMALLEST round trip seen in this download: the path's queue-free base latency. The window growth is judged against it (see `DOWNLOAD_RTT_GROW_FACTOR`).
    pub(crate) rtt_min: u64,
    /// When the download started. Used for the throughput log in `finalize_download`, which shows whether the adaptive window helps.
    pub(crate) started_at: u64,
    /// `files.chunk_size` of this file, read once (see `file_chunk_size`).
    pub(crate) chunk_size: usize,
    /// Ask for the missing chunks again at this time (0 = not set): a failed
    /// request, or a server that does not have the file yet. See
    /// `DOWNLOAD_RETRY_DELAY_MS`.
    pub(crate) retry_at: u64,
}

/// File chunk events collected INSIDE the `RUNTIME.block_on` block of `poll_events` (under the swarm borrow), and processed AFTER the block ends, when `self`
/// can be accessed freely. Same "collect first, then process" pattern as `incoming` and `new_listen_addrs` (see poll_events).
/// See `ENVELOPE_PROTOCOL`: collected under the swarm borrow, handled afterwards.
pub(crate) enum EnvelopeEventLocal {
    Delivered { request_id: request_response::OutboundRequestId },
    Failed { request_id: request_response::OutboundRequestId, error: String },
}

/// See `ACK_PROTOCOL`: collected under the swarm borrow, handled afterwards.
pub(crate) enum AckEventLocal {
    Request { peer: PeerId, ids: Vec<String>, channel: request_response::ResponseChannel<AckBatchResponse> },
    Delivered { request_id: request_response::OutboundRequestId },
    Failed { request_id: request_response::OutboundRequestId },
}

pub(crate) enum FileChunkEventLocal {
    /// `peer`: the requester, PROVEN by Noise. The access check in `serve_chunk_request` relies on it (see that function). No field of the packet, which is only a
    /// CLAIM, is used. Same reasoning as `is_established_peer` and the server rate limit.
    Request { peer: PeerId, request: FileChunkRequest, channel: request_response::ResponseChannel<FileChunkResponse> },
    Response { request_id: request_response::OutboundRequestId, response: FileChunkResponse },
    OutboundFailure { request_id: request_response::OutboundRequestId },
}

/// See `try_publish_raw`. It lets callers tell whether a publish error is worth retrying. (Fix: permanent errors such as `MessageTooLarge` were
/// retried for up to 2 days for nothing.)
#[derive(Debug)]
pub(crate) enum PublishFailure {
    /// Temporary (the mesh is not formed yet, no subscriber, network not started). Retrying makes sense.
    Transient(String),
    /// Permanent. Retrying the SAME envelope can NEVER succeed. The caller must mark it `Failed` at once and tell the user.
    Permanent(String),
}

/// The display status of a message WE sent, for the send and error icons the user asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MessageSendStatus {
    /// `publish_envelope` has not succeeded yet. It is waiting in `pending_envelopes`, and `poll_events` keeps retrying.
    Pending,
    /// `try_publish_raw` handed the envelope to the network (a direct peer stream or a server deposit). This is NOT a guarantee that the other
    /// side received it. Delivery is the end-to-end Ack (`Delivered`).
    Sent,
    /// Could not be sent within `PENDING_ENVELOPE_TIMEOUT_MS`, and was given up.
    Failed,
    /// A device of the peer (any member, in a group) sent the end-to-end Ack. Between sent and seen; "seen" lives in `message_seen`.
    Delivered,
}

impl MessageSendStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            MessageSendStatus::Pending => "pending",
            MessageSendStatus::Sent => "sent",
            MessageSendStatus::Failed => "error",
            MessageSendStatus::Delivered => "delivered",
        }
    }
}

/// See the `P2PCore.awaiting_confirmation` docs.
/// Known limit: a retry is encrypted under the ratchet chain step current when it was made. If a DH/KEM rotation happens before the confirmation arrives,
/// the receiver clears its skipped-key cache for the old chain (intended forward secrecy), so the old ciphertext can no longer be decrypted. Pending packets
/// are refreshed on rotation (see `regen_pending_for_peer` and `regen_content`). It is rare: the message must stay unconfirmed across a rotation (30 minutes).
pub(crate) struct PendingConfirmation {
    /// See `KeepAliveState.suspect`: whether the connection was probed once for this packet.
    pub(crate) suspect_probed: bool,
    /// The peer confirmed receiving the bytes over `ENVELOPE_PROTOCOL`. A late Ack is only latency (Tor round trips often exceed `ACK_SUSPECT_MS`),
    /// not a dead connection. A slow Ack must not mark the connection suspect, which would trigger parallel dials, close surplus connections and drop in-flight requests.
    pub(crate) direct_delivered: bool,
    /// The identity of the chain GENERATION this packet was encrypted under: a 16-byte topic id derived from the root key. It is not secret; it is already the gossipsub topic name.
    ///
    /// Pending packets are refreshed when the generation changes. When we rotate ourselves, `maybe_rotate_ratchet` runs and then `regen_pending_for_peer`. When the other side rotates,
    /// `receive_message` runs `regen_pending_for_peer`. The 25-minute timer is only a fallback.
    ///
    /// If the rotation announcement is lost, that event never happens, and the packet would keep retrying under a chain the peer can no longer decrypt.
    /// This stamp closes that gap: when the session's current generation differs from the stamp, the packet is refreshed at once. The criterion is generation equality, not elapsed time.
    pub(crate) chain_stamp: String,
    pub(crate) peer_device_fingerprint: String,
    /// Already encrypted and signed packet. It is sent AS IS on every retry and is NOT re-encrypted. Encrypting again would advance the ratchet, and the other side
    /// could then not recognise it as the "same logical message" (see the symmetric chain note in ratchet.rs).
    pub(crate) envelope: NetworkEnvelope,
    pub(crate) next_retry_at: u64,
    pub(crate) retry_interval_ms: u64,
    /// When the CURRENT retry LOOP started. Reset to a new value each time `regen_content` is refreshed (the new ciphertext gets its own 25-minute window).
    /// For "when it first entered the queue", see `original_sent_at` (which is NOT reset).
    pub(crate) first_sent_at: u64,
    /// When this message FIRST entered the queue. It stays FIXED across `regen_content` refreshes (unlike `first_sent_at`). `TEXT_RETRY_GIVE_UP_MS` (7 days) is
    /// measured against it. So "does the message keep being retried while the other side is offline for days" depends on when the message was WRITTEN, not on which
    /// rotation round the ciphertext is in. It is also shown to the user in the pending messages list (see `list_pending_messages`).
    pub(crate) original_sent_at: u64,
    /// When the LAST real send attempt was made (successful or not). Shown as "last try: ..." in the pending messages list in Settings. `next_retry_at` is the
    /// FUTURE (when the next try is due). This field is the PAST.
    pub(crate) last_attempt_at: u64,
    /// User feedback ("the give-up time could cause problems in some places; what if someone does not open the internet for 6 hours?"): once
    /// `MAX_UNCONFIRMED_AGE_MS` passes, re-sending the SAME (probably undecryptable) encrypted packet makes no sense. But GIVING UP is wrong too for some content
    /// types. The right behaviour there is to re-encrypt the original plaintext fresh (a new ratchet step, under the SAME message_id, see the
    /// `message_id_override` in `send_message_content_inner`), and keep retrying up to `TEXT_RETRY_GIVE_UP_MS`. Scope: Edit/Delete/GroupUpdate, and now,
    /// at the user's request, plain `Text` too (1:1 and group fan-out copies). Because the SAME `message_id` is kept, the UI bubble and the `awaiting_confirmation`
    /// entry stay continuous. It does not clash with the manual resend flow (`retryMessage(oldId,newId,status)`), which is still for messages that are really
    /// `Failed` (past the 7-day limit).
    pub(crate) regen_content: Option<MessageContent>,
}
