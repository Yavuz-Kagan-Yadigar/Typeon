//! The conversation view — one implementation for both 1:1 and group chats.
//! On Android these are two near-identical activities (about 850 lines each,
//! ChatActivity and GroupChatActivity) that duplicate each other
//! almost line for line, differing only in which core call to use and whether
//! a sender name belongs on the bubble. Here that difference is a two-armed
//! `Conversation` match, so a fix to bubble ordering, reply handling or
//! attachment state lands in both at once.
//! Message identity is the thing to get right. Every bubble is keyed by the
//! id the core considers stable for it — the shared conversation id for 1:1
//! (so an edit, delete or read receipt from the peer lands on the same bubble
//! on every one of my devices) and `group_message_local_id` for groups (which
//! collapses the per-member fan-out copies into one). Attachments are keyed by
//! `file_id`, which cannot collide with either.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use adw::prelude::*;
use gtk::gio;
use gtk::glib;

use crate::app::{self, App, Event};
use crate::core;
use crate::ui::dialogs;
use crate::ui::window::{Conversation, MainUi};
use crate::util;

mod header;
mod history;
mod message_list;
mod attachments;
mod actions;
mod composer;
mod search;
mod reactions;
mod events;
mod group;
mod disappear;
use header::*;
use message_list::*;
use attachments::*;
use composer::*;
use search::*;
use group::*;
use disappear::*;
pub(crate) use disappear::DISAPPEAR_PULSE_STEPS;

/// How many messages (texts and files together) a page of history holds,
/// matching the Android chat.
const PAGE_SIZE: u32 = 100;
/// Hard cap on bubbles kept alive in one open chat (~8 GTK widgets each):
/// two pages. Past it, loading an older page drops the newest bubbles (see
/// `trim_newest`); reaching the bottom reloads them from the archive.
const MAX_BUBBLES: usize = 200;
const FETCH_HISTORY_LABEL: &str = "Fetch older history";
/// Hard cap on bubble width, in pixels.
/// A wrapping GtkLabel's `max-width-chars` turned out not to bound the
/// allocation here — measured naturals of ~310px were still being allocated
/// 872px, so long messages stretched the full width of the window and ran off
/// the edge. AdwClamp caps the natural width outright, which is exactly the
/// guarantee a chat bubble needs.
const BUBBLE_MAX_WIDTH: i32 = 460;
/// Messages from the same sender that arrive within this window merge into one visual group, like the Android
/// `MergedBubbleDecoration` with the same threshold. The edges that touch shrink their corner radius, and the gap between
/// them narrows. Android draws the full merged outline in one canvas pass. GTK CSS has no `::before` / `::after`
/// pseudo-elements, so the corner patch needs its own widget (see `mark_group_seam` and `SEAM_NOTCH_SIZE`). So this
/// side uses the cheap method: corner radii are reduced with the `sq-*` and `rd-*` classes (see theme.rs), and a
/// small fixed circular notch is added at seams where the width changes. It is not an
/// exact geometric match, but it gives the same soft-join feel at much lower cost.
const BUBBLE_GROUP_WINDOW_MS: u64 = 2 * 60 * 1000;
/// A seam whose width difference is below this gets no notch. A difference that small is not worth an extra widget or render cost.
// Steps narrower than this are drawn as a plain, slightly rounded join.
const SEAM_NOTCH_MIN_DELTA: i32 = 8;
/// Largest fillet radius; smaller steps / shorter bubbles get a smaller one
/// (see `seam_radius`), in the even sizes the stylesheet has classes for.
const SEAM_RADIUS_MAX: i32 = 12;
/// Number of screen-space shade steps; theme.rs generates `shade-0..N-1`.
const SHADE_STEPS: i32 = 24;
/// Dev harness only (`demo_bubbles`).
#[cfg(debug_assertions)]
const SEAM_NOTCH_SIZE: i32 = 12;
/// Diameter of the notch circle, in px. It is FIXED. It does not grow with the real width difference. It is a cheap
/// visual hint, not exact geometry.

/// Seen-by avatars shown under a message; more viewers show as "+N".
const SEEN_AVATARS: usize = 5;

/// Idle time after the last keystroke before we say we stopped typing.
const TYPING_TIMEOUT_MS: u64 = 4_000;
/// How long the peer's typing bubble stays up without a fresh `typing` event
/// — matches Android's `TYPING_INDICATOR_TIMEOUT_MS`, long enough to survive
/// normal event jitter but short enough not to lie once someone stops.
const TYPING_INDICATOR_TIMEOUT_S: u32 = 8;

// --- data ---

#[derive(Clone)]
struct Attachment {
    file_id: String,
    file_name: String,
    mime: String,
    total_size: u64,
    /// Which device to fetch from. For groups this is the sending member's
    /// device, which is not the conversation key — hence carrying it here.
    source_fingerprint: String,
    status: String,
    preview_hex: Option<String>,
    bytes_done: u64,
    /// Voice message length, in milliseconds — `None` for anything else.
    duration_ms: Option<u32>,
    /// A sticker: shown without a bubble frame.
    sticker: bool,
}

#[derive(Clone)]
struct Entry {
    id: String,
    mine: bool,
    sender_identity: String,
    text: String,
    /// Send time when known, receive time otherwise — a message delayed in
    /// transit belongs where the sender wrote it, not where it landed.
    order_key: u64,
    status: Option<String>,
    reply_preview: Option<String>,
    reply_sender: Option<String>,
    /// Id of the replied-to message: a click on the quote scrolls there.
    reply_id: Option<String>,
    deleted: bool,
    /// Rendered as an "(edited)" suffix. Comes from the archive, so it
    /// survives a reload instead of only existing while the edit event is
    /// fresh on screen.
    edited: bool,
    attachment: Option<Attachment>,
    /// Who saw this message, from the archive row (`ArchivedMessage.seen_by`).
    seen_by: Vec<core::SeenEntry>,
    /// Reaction summary from the core ("😂2 👍"), empty when none.
    reactions: String,
    /// Disappearing message: (timer seconds, when it goes on this device's clock in ms). See `disappear.rs`.
    expire: Option<(u32, u64)>,
}

/// The widgets of one rendered bubble that later events may need to touch.
struct Bubble {
    root: gtk::Widget,
        /// Same widget as `root`, kept typed. `mark_group_seam` adds a small notch to it after the fact, when a LATER bubble
        /// turns out to continue this one (see the `BUBBLE_GROUP_WINDOW_MS` note at the top of the file). `root` alone (a bare
        /// `gtk::Widget`) cannot take `add_overlay`.
    overlay: gtk::Overlay,
    /// The actual coloured bubble box (`.bubble` CSS class) — `mark_group_seam`
    /// toggles its corner-radius classes; `root`/`overlay` are just the
    /// alignment/notch wrapper around it.
    skin: gtk::Box,
    /// Natural width at build time (post max-width clamp) — used to place the
    /// seam notch without a second, possibly-stale `measure()` call later.
    #[allow(dead_code)]
    content_width: i32,
    /// Empty for a 1:1 received message (there is only one possible sender);
    /// real in a group. Needed alongside `mine` to tell "same run" apart from
    /// "different member, `mine` just happens to differ" — see `insert_entry`.
    sender_identity: String,
    text: gtk::Label,
    meta: gtk::Label,
    attachment: Option<Rc<AttachmentState>>,
    /// The attachment card/voice-player row itself — kept so `apply_delete`
    /// can hide it and reveal `text` (built, but not shown, for an attachment
    /// bubble until this happens) in its place. Without this, a deletion of
    /// an attachment message updated `text` correctly but `text` was never in
    /// the bubble's widget tree to begin with, so nothing on screen changed —
    /// the card just sat there as if the delete had never arrived.
    attachment_widgets: Option<gtk::Box>,
    order_key: u64,
    mine: bool,
    /// Seen-by avatars under my newest seen message (see `show_seen_by`).
    seen_row: gtk::Box,
    /// Screen-space shade step currently applied (`shade-N`), -1 = none yet.
    shade: Cell<i32>,
    /// Concave fillets drawn in this bubble's row, with their colour role;
    /// they take the bubble's shade so the join has no seam.
    fillets: RefCell<Vec<(gtk::Box, &'static str)>>,
    /// Reaction pill under the bubble; hidden while there are none.
    reactions: gtk::Label,
    /// Last known delivery status ("pending"/"sent"/"delivered"/"error"), kept
    /// so a later edit can redraw the meta label (time + tick + "edited")
    /// without forgetting the tick that was already showing there.
    status: RefCell<Option<String>>,
    /// Set once an edit lands, so the meta label shows a small "edited" next
    /// to the time — matching Android's `txtEditedLabel`, which sits beside
    /// the timestamp rather than appended onto the message text itself.
    edited: Cell<bool>,
    /// Disappearing message: the accent "time left" line under the bubble.
    expire_label: Option<gtk::Label>,
    /// The message as it is now (live edits, deletes, reactions, status
    /// applied): the context menu acts on this, not on the build-time copy.
    entry: RefCell<Entry>,
}

/// Live, mutable state for one attachment bubble, plus the widgets `file_*`
/// events update.
/// This exists (rather than the click handlers simply closing over a cloned
/// `Attachment`, as they used to) so a click on the action button always sees
/// the *current* status. A closure capturing a snapshot from build time would
/// still think a since-completed download was "offered" the moment the user
/// clicked "Open" — the button's label had moved on, but its handler had not,
/// so it would silently re-trigger a download instead of opening the file.
struct AttachmentState {
    file_id: String,
    file_name: String,
    mime: String,
    total_size: u64,
    source_fingerprint: String,
    status: RefCell<String>,
    bytes_done: Cell<u64>,
    /// When the current download began, for the ETA estimate — reset to 0
    /// between downloads so a retry measures its own rate fresh.
    download_started_at: Cell<u64>,
    // Generic (non-voice) attachment widgets.
    status_label: Option<gtk::Label>,
    progress: Option<gtk::ProgressBar>,
    eta: Option<gtk::Label>,
    action: Option<gtk::Button>,
    // Voice-message widgets, mutually exclusive with the above.
    voice: Option<VoicePlayer>,
    /// Sticker picture, filled once the file is here.
    sticker: Option<gtk::Picture>,
}

/// The inline voice-message player embedded in a bubble — a play/pause
/// button, a seek/progress scale, and a duration label, matching the Android
/// voice bubble instead of showing a generic file card for an audio MIME type.
struct VoicePlayer {
    play_button: gtk::Button,
    slider: gtk::Scale,
    duration_label: gtk::Label,
    /// Created lazily on first play — decrypting the attachment happens off
    /// the main thread, so there is nothing to play until that finishes.
    media: RefCell<Option<gtk::MediaFile>>,
    /// The offer's known duration, shown before playback has ever started
    /// (and so before there is a `GtkMediaFile` to ask instead).
    duration_ms: Cell<u32>,
}

struct ChatView {
    main: Rc<MainUi>,
    conversation: Conversation,
    messages: gtk::Box,
    scroller: gtk::ScrolledWindow,
    /// True while the view sits at the bottom (or a scroll there is pending):
    /// every content-size change then re-pins to the newest message.
    follow_bottom: Cell<bool>,
    fetch_history: gtk::Button,
    /// Over the top of the timeline while an older page loads.
    older_spinner: gtk::Spinner,
    /// Over the top of the timeline while scrolling: the day of the top
    /// visible message. `date_pill_hide` fades it out once scrolling stops.
    date_pill: gtk::Revealer,
    date_pill_label: gtk::Label,
    date_pill_hide: RefCell<Option<glib::SourceId>>,
    bubbles: RefCell<HashMap<String, Rc<Bubble>>>,
    /// Ids we have already sent a read receipt for. Survives `reload()`, which
    /// clears `bubbles` — see `insert_entry`.
    seen_sent: RefCell<HashSet<String>>,
    /// Received while nobody was looking: their receipts (and the local read
    /// mark) wait for `flush_deferred_reads`.
    seen_deferred: RefCell<Vec<Entry>>,
    read_deferred: Cell<bool>,
    /// A shading pass is already scheduled (see `schedule_shading`).
    shade_pending: Cell<bool>,
        /// See `send_seen`. Whether a debounced read boundary is pending.
    watermark_pending: Cell<bool>,
    /// The disappearing-message ticker runs (see `disappear.rs`).
    disappear_ticking: Cell<bool>,
    /// This chat's disappearing mode in seconds, 0 = off (header clock button, see `disappear.rs`).
    disappear_mode: Cell<u32>,
    /// The composer's Send button; its icon shows the disappearing mode.
    send_button: gtk::Button,
    /// Ascending by `order_key`; mirrors the widget order so an out-of-order
    /// arrival can be slotted in without walking the widget tree.
    order: RefCell<Vec<(u64, String)>>,
    subtitle: gtk::Label,
    composer: gtk::TextView,
    /// A bubble-styled "X is typing…" row, shown just above the reply bar —
    /// the same position `layoutTypingIndicator` sits in on Android. Before
    /// this it only ever showed as a change to the small header subtitle,
    /// which was too easy to miss for something meant to be a live signal.
    typing_indicator: gtk::Revealer,
    typing_indicator_label: gtk::Label,
    /// The pending auto-hide timeout — cleared on every new `typing` event
    /// (matching or restarting it) so it never fires early, and relied on
    /// instead of the peer's `is_typing: false` alone: that event can be lost
    /// in transit (the app closing mid-conversation, say) and leave the
    /// indicator stuck on forever without this backstop.
    typing_clear_source: RefCell<Option<glib::SourceId>>,
    reply_bar: gtk::Revealer,
    /// Wraps the reply bar and the composer bar; tinted only while a reply is
    /// active, so the quote and the bar read as one "island". Its paddings are
    /// constant, so the composer never changes size when a reply opens.
    reply_island: gtk::Box,
    reply_label: gtk::Label,
    reply_to: RefCell<Option<(String, String, Option<String>)>>,
    /// Oldest local receive timestamp on screen — the pagination cursor. The
    /// core paginates on receive time, so this must not use `order_key`.
    oldest_timestamp: Cell<u64>,
    /// Oldest attachment timestamp on screen — the pagination cursor of the
    /// file list (the core keeps the files in their own table, so they page
    /// separately from the messages). Zero until a page carried a file.
    oldest_attachment_timestamp: Cell<u64>,
    /// Bumped per `reload`; a page fetched off-thread is dropped if a newer
    /// reload started meanwhile.
    load_gen: Cell<u64>,
    /// live entries (fresh events) can arrive without a message id —
    /// they still need a unique map/order key. `fresh_local_id` mints one.
    live_serial: Cell<u64>,
    loading_older: Cell<bool>,
    exhausted_locally: Cell<bool>,
    /// `load_older` dropped the newest bubbles to stay under `MAX_BUBBLES`.
    /// Live messages are not appended past that gap; reaching the bottom
    /// reloads the newest page instead.
    trimmed_bottom: Cell<bool>,
    last_typing_sent: Cell<u64>,
    typing_active: Cell<bool>,
    /// Direct chat only: the contact deleted their account, so sending is off.
    account_deleted: Cell<bool>,
    /// In-progress voice recording, if any. Held here rather than in the
    /// button's closure so leaving the chat can stop it (see the `Drop` impl).
    recording: RefCell<Option<crate::audio::Recording>>,
    /// Bubble ids matching the current in-chat search, oldest first, plus which
    /// one is currently focused. Like the Android chat, this searches what is
    /// loaded rather than firing a network request — scrolling up loads more.
    search_matches: RefCell<Vec<String>>,
    search_index: Cell<usize>,
    /// Group read receipts waiting for the 700 ms flush (device, message id).
    seen_batch: RefCell<Vec<(String, String)>>,
    /// The bubble whose `seen_row` is showing: only my newest seen message.
    seen_shown: RefCell<Option<String>>,
    /// Lower-cased bubble text per id for `run_search`; cleared whenever a
    /// bubble's text can change (edit, delete, refresh, reload).
    search_lower: RefCell<HashMap<String, String>>,
    whiteboard: crate::ui::whiteboard::Board,
}

impl Drop for ChatView {
    fn drop(&mut self) {
        // Closing the conversation mid-recording must not leave ffmpeg running
        // with the microphone open.
        if let Some(recording) = self.recording.borrow_mut().take() {
            recording.cancel();
        }
    }
}

impl ChatView {
    fn app(&self) -> &Rc<App> {
        &self.main.app
    }

    /// See the `connect_destroy` in `build`.
    fn teardown(&self) {
        if let Some(recording) = self.recording.borrow_mut().take() {
            recording.cancel();
        }
        // A page fetch still in flight must not refill the view.
        self.load_gen.set(self.load_gen.get() + 1);
        let bubbles: Vec<Rc<Bubble>> = self.bubbles.borrow_mut().drain().map(|(_, bubble)| bubble).collect();
        for bubble in bubbles {
            let voice = bubble.attachment.as_ref().and_then(|state| state.voice.as_ref());
            if let Some(media) = voice.and_then(|voice| voice.media.borrow_mut().take()) {
                media.set_playing(false);
                media.clear();
            }
        }
        self.order.borrow_mut().clear();
        while let Some(child) = self.messages.first_child() {
            self.messages.remove(&child);
        }
        self.search_lower.borrow_mut().clear();
        self.search_matches.borrow_mut().clear();
        self.seen_deferred.borrow_mut().clear();
        self.seen_shown.borrow_mut().take();
    }

    fn is_group(&self) -> bool {
        matches!(self.conversation, Conversation::Group { .. })
    }

}

// --- construction ---

pub fn build(main: &Rc<MainUi>, conversation: &Conversation) -> adw::NavigationPage {
    // 0 px between rows (a run of bubbles touches); a bubble that starts a run adds 6 px of its own
    // margin (see `build_bubble`). GTK CSS rejects negative margins, so the
    // old "-4px" on grouped rows never took effect.
    let messages = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(0)
        .margin_top(12)
        .margin_bottom(12)
        .margin_start(12)
        .margin_end(12)
        .valign(gtk::Align::End)
        .vexpand(true)
        .hexpand(true)
        .build();

    // "Fetch older history" sits above the oldest loaded message, so it shows
    // only when the user has scrolled to the top. It is the only place the
    // chat asks the network for history; scrolling reads the local archive.
    let fetch_history = gtk::Button::builder()
        .label(FETCH_HISTORY_LABEL)
        .halign(gtk::Align::Center)
        .margin_top(8)
        .build();
    fetch_history.add_css_class("flat");
    let timeline = gtk::Box::builder().orientation(gtk::Orientation::Vertical).build();
    timeline.append(&fetch_history);
    timeline.append(&messages);

    let scroller = gtk::ScrolledWindow::builder()
        .vexpand(true)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .child(&timeline)
        .build();
    // Hook for the chat wallpaper (see theme.rs); harmless when none is set.
    scroller.add_css_class("chat-messages");

    let older_spinner = gtk::Spinner::builder()
        .halign(gtk::Align::Center)
        .valign(gtk::Align::Start)
        .margin_top(44)
        .width_request(24)
        .height_request(24)
        .visible(false)
        .build();
    let date_pill_label = gtk::Label::new(None);
    date_pill_label.add_css_class("caption");
    date_pill_label.add_css_class("date-pill");
    let date_pill = gtk::Revealer::builder()
        .transition_type(gtk::RevealerTransitionType::Crossfade)
        .halign(gtk::Align::Center)
        .valign(gtk::Align::Start)
        .margin_top(8)
        .can_target(false)
        .child(&date_pill_label)
        .build();
    let scroller_overlay = gtk::Overlay::builder().child(&scroller).vexpand(true).build();
    scroller_overlay.add_overlay(&date_pill);
    scroller_overlay.add_overlay(&older_spinner);

    let subtitle = gtk::Label::new(None);
    subtitle.add_css_class("caption");
    subtitle.add_css_class("dim-label");

    let composer = gtk::TextView::builder()
        .wrap_mode(gtk::WrapMode::WordChar)
        .accepts_tab(false)
        .top_margin(8)
        .bottom_margin(8)
        .left_margin(8)
        .right_margin(8)
        .build();

    let reply_label = gtk::Label::builder()
        .ellipsize(gtk::pango::EllipsizeMode::End)
        .xalign(0.0)
        .hexpand(true)
        .build();
    let reply_bar = gtk::Revealer::builder().reveal_child(false).build();
    let reply_island = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .margin_start(4)
        .margin_end(4)
        .margin_bottom(4)
        .build();
    reply_island.add_css_class("reply-island");

    let typing_indicator_label = gtk::Label::new(None);
    let typing_indicator = gtk::Revealer::builder().reveal_child(false).build();

    let view = Rc::new(ChatView {
        main: main.clone(),
        conversation: conversation.clone(),
        messages: messages.clone(),
        scroller: scroller.clone(),
        follow_bottom: Cell::new(true),
        fetch_history: fetch_history.clone(),
        older_spinner: older_spinner.clone(),
        date_pill: date_pill.clone(),
        date_pill_label: date_pill_label.clone(),
        date_pill_hide: RefCell::new(None),
        bubbles: RefCell::new(HashMap::new()),
        seen_sent: RefCell::new(HashSet::new()),
        seen_deferred: RefCell::new(Vec::new()),
        read_deferred: Cell::new(false),
        watermark_pending: Cell::new(false),
        disappear_ticking: Cell::new(false),
        disappear_mode: Cell::new(0),
        send_button: gtk::Button::builder()
            .icon_name("document-send-symbolic")
            .tooltip_text("Send")
            .valign(gtk::Align::End)
            .build(),
        shade_pending: Cell::new(false),
        order: RefCell::new(Vec::new()),
        subtitle: subtitle.clone(),
        composer: composer.clone(),
        typing_indicator: typing_indicator.clone(),
        typing_indicator_label: typing_indicator_label.clone(),
        typing_clear_source: RefCell::new(None),
        reply_bar: reply_bar.clone(),
        reply_island: reply_island.clone(),
        reply_label: reply_label.clone(),
        reply_to: RefCell::new(None),
        oldest_timestamp: Cell::new(0),
        oldest_attachment_timestamp: Cell::new(0),
        load_gen: Cell::new(0),
        live_serial: Cell::new(0),
        loading_older: Cell::new(false),
        exhausted_locally: Cell::new(false),
        trimmed_bottom: Cell::new(false),
        last_typing_sent: Cell::new(0),
        typing_active: Cell::new(false),
        account_deleted: Cell::new(false),
        recording: RefCell::new(None),
        search_matches: RefCell::new(Vec::new()),
        search_index: Cell::new(0),
        search_lower: RefCell::new(HashMap::new()),
        seen_batch: RefCell::new(Vec::new()),
        seen_shown: RefCell::new(None),
        whiteboard: match conversation {
            Conversation::Direct { fingerprint, .. } => crate::ui::whiteboard::Board::new(&main.app, fingerprint, ""),
            Conversation::Group { group_id, .. } => crate::ui::whiteboard::Board::new(&main.app, "", group_id),
        },
    });

    // reply bar content
    {
        let box_ = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(8)
            .margin_start(12)
            .margin_end(12)
            .margin_top(6)
            .margin_bottom(6)
            .build();
        let icon = gtk::Image::from_icon_name("mail-reply-sender-symbolic");
        let cancel = gtk::Button::builder()
            .icon_name("window-close-symbolic")
            .valign(gtk::Align::Center)
            .build();
        cancel.add_css_class("flat");
        {
            let view = view.clone();
            cancel.connect_clicked(move |_| view.clear_reply());
        }
        box_.append(&icon);
        box_.append(&reply_label);
        box_.append(&cancel);
        reply_bar.set_child(Some(&box_));
    }

    // typing indicator content — a left-aligned bubble, same skin a
    // received message uses, so it reads as "someone is about to say
    // something here" rather than a status line.
    {
        let row = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .halign(gtk::Align::Start)
            .margin_start(12)
            .margin_top(4)
            .margin_bottom(4)
            .build();
        let skin = gtk::Box::builder().orientation(gtk::Orientation::Vertical).build();
        skin.add_css_class("bubble");
        skin.add_css_class("bubble-theirs");
        let content = bubble_content();
        typing_indicator_label.set_xalign(0.0);
        content.append(&typing_indicator_label);
        skin.append(&content);
        row.append(&skin);
        typing_indicator.set_child(Some(&row));
    }

    let (search_bar, search_entry) = build_search_bar(&view);

    let page_content = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .build();
    page_content.append(&search_bar);
    page_content.append(&scroller_overlay);
    page_content.append(&typing_indicator);
    reply_island.append(&reply_bar);
    reply_island.append(&composer_bar(&view));
    page_content.append(&reply_island);
    if let Conversation::Direct { identity_id, .. } = &view.conversation {
        if view.app().contacts.borrow().iter().any(|c| c.identity_id == *identity_id && c.account_deleted) {
            view.lock_account_deleted();
        }
    }

    let header = build_header(&view, &subtitle, &search_bar, &search_entry);
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&page_content));

    let page = adw::NavigationPage::builder()
        .title(conversation.title().as_str())
        .child(&toolbar)
        .build();

    // Load history, then wire everything that can change it.
    view.reload();
    // Rows this desktop missed (a sender could not reach it) come from my
    // other devices; the answer reloads the chat.
    let (chat_key, is_group) = match conversation {
        Conversation::Direct { fingerprint, .. } => (fingerprint.clone(), false),
        Conversation::Group { group_id, .. } => (group_id.clone(), true),
    };
    crate::app::run_in_background(move || core::refresh_chat_from_siblings(&chat_key, is_group), |_| {});
    view.refresh_subtitle();

    // Mark read + tell sibling devices, both on open and on close.
    view.mark_read_and_sync();
    *view.app().active_conversation.borrow_mut() = Some(conversation.key());
    {
        let view = view.clone();
        page.connect_hidden(move |_| {
            // Not when nobody is looking (see `flush_deferred_reads`).
            if view.is_watched() || view.seen_deferred.borrow().is_empty() {
                view.mark_read_and_sync();
            }
            // A newer page may already have claimed it; only clear our own.
            let mut active = view.app().active_conversation.borrow_mut();
            if active.as_deref() == Some(view.conversation.key().as_str()) {
                *active = None;
            }
        });
    }

    {
        let view = view.clone();
        fetch_history.connect_clicked(move |_| view.fetch_server_history());
    }

    // Infinite scroll upward.
    {
        let view = view.clone();
        scroller.vadjustment().connect_value_changed(move |adjustment| {
            view.follow_bottom
                .set(adjustment.upper() - adjustment.page_size() - adjustment.value() < 80.0);
            view.update_shading();
            view.update_date_pill();
            if adjustment.value() <= 8.0 && adjustment.upper() > adjustment.page_size() {
                view.load_older();
            } else if view.trimmed_bottom.get()
                && adjustment.upper() - adjustment.page_size() - adjustment.value() < 80.0
            {
                view.reload();
            }
        });
    }

    // Stick to the bottom: new rows grow `upper` only at the next layout,
    // so the snap happens here, when the size actually changes.
    {
        let view = view.clone();
        scroller.vadjustment().connect_changed(move |adjustment| {
            if view.follow_bottom.get() {
                // `changed` fires inside the scroller's size allocation; a
                // value set there moved the scrollbar but not the content
                // (the viewport kept the old offset until the next scroll).
                // One idle later the allocation is over and `upper` is final.
                let adjustment = adjustment.clone();
                glib::idle_add_local_once(move || {
                    adjustment.set_value(adjustment.upper() - adjustment.page_size());
                });
            }
        });
    }

    // Live events.
    {
        let view = view.clone();
        main.app.subscribe(&page_content, move |event| view.handle_event(event));
    }

    // The page is gone. Many handlers on this view's widgets hold the view
    // itself, so it may never be dropped: release the heavy part (bubbles,
    // textures, players, a recording) here instead of in `Drop`.
    {
        let view = Rc::downgrade(&view);
        page_content.connect_destroy(move |_| {
            if let Some(view) = view.upgrade() {
                view.teardown();
            }
        });
    }

    // Connection/typing subtitle.
    {
        let view = view.clone();
        let page_content = page_content.clone();
        glib::timeout_add_seconds_local(3, move || {
            if page_content.root().is_none() {
                return glib::ControlFlow::Break;
            }
            // Hidden, minimized or in the background: skip the thread + core
            // round-trip.
            if !page_content.is_mapped() || !view.app().window().is_some_and(|w| w.is_active()) {
                return glib::ControlFlow::Continue;
            }
            view.refresh_subtitle();
            glib::ControlFlow::Continue
        });
    }

    // Stop the typing indicator once the user goes quiet.
    {
        let view = view.clone();
        let page_content = page_content.clone();
        glib::timeout_add_seconds_local(2, move || {
            if page_content.root().is_none() {
                return glib::ControlFlow::Break;
            }
            if view.typing_active.get()
                && util::now_ms().saturating_sub(view.last_typing_sent.get()) > TYPING_TIMEOUT_MS
            {
                view.set_typing(false);
            }
            // The user is back (focus, unlock, shown from the tray): the
            // receipts held while away go out now.
            view.flush_deferred_reads();
            // Back on screen with disappearing bubbles: their ticker stopped while hidden.
            view.start_disappear_tick();
            glib::ControlFlow::Continue
        });
    }

    if let Conversation::Direct { fingerprint, .. } = conversation {
        // Opening a chat proactively starts the handshake if there is not one
        // already, so the first message does not have to wait for it.
        let fingerprint = fingerprint.clone();
        std::thread::spawn(move || core::ensure_handshake(&fingerprint));
    }

    page
}

/// Visual harness for bubble layout — see `TYPEON_UI_TEST=bubbles`. Exercises
/// the same `bubble_text_label`/`bubble_content` the real conversation uses, so
/// what it shows is what a chat shows.
#[cfg(debug_assertions)] // dev harness only, not in release binaries
pub fn demo_bubbles() -> gtk::Widget {
    let messages = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(6)
        .margin_top(12)
        .margin_bottom(12)
        .margin_start(12)
        .margin_end(12)
        .valign(gtk::Align::End)
        .hexpand(true)
        .build();

        // Debugging helper. A user reported that none of five consecutive "mine" bubbles joined, on a screenshot. The first five
        // examples imitate that same short, consecutive "mine" layout. The point is to check in isolation that the
        // seam notch really renders, without clicking through the real chat screen. The grouping logic itself
        // (`insert_entry`) and the corner classes (`mark_group_seam`) are NOT here. Only the notch is applied by hand.
    let samples: [(bool, &str); 8] = [
        (true, "hey"),
        (true, "you there?"),
        (true, "short one"),
        (true, "a slightly longer message"),
        (true, "and one more to close the run"),
        (false, "hi"),
        (
            false,
            "supercalifragilisticexpialidociousandthensomemoretomakeitreallyquitelong",
        ),
        (false, "ok"),
    ];

    let mut previous: Option<(bool, i32)> = None;
    for (mine, sample) in samples {
        let column = bubble_content();
        column.append(&bubble_text_label(&gtk::glib::markup_escape_text(sample)));

        let meta = gtk::Label::builder().label("23:50 ✓").xalign(1.0).build();
        meta.add_css_class("caption");
        meta.add_css_class("dim-label");
        column.append(&meta);

        let (overlay, _) = place_bubble(&column, mine);
        let width = overlay.measure(gtk::Orientation::Horizontal, -1).1;

        let grouped = previous.as_ref().is_some_and(|(prev_mine, ..)| *prev_mine == mine);
        if let Some((_, prev_width)) = &previous {
            if grouped {
                let delta = (prev_width - width).abs();
                if delta >= SEAM_NOTCH_MIN_DELTA {
                    let notch = gtk::Box::builder()
                        .width_request(SEAM_NOTCH_SIZE)
                        .height_request(SEAM_NOTCH_SIZE)
                        .valign(if *prev_width > width { gtk::Align::End } else { gtk::Align::Start })
                        .halign(if mine { gtk::Align::End } else { gtk::Align::Start })
                        .build();
                    notch.add_css_class("bubble-seam-notch");
                    let wider = (*prev_width).max(width);
                    let margin = (wider - SEAM_NOTCH_SIZE / 2).max(0);
                    if mine {
                        notch.set_margin_end(margin);
                    } else {
                        notch.set_margin_start(margin);
                    }
                                        // For simplicity the notch is ALWAYS placed on the existing row here. The real `mark_group_seam` puts it on
                                        // whichever of the two wide bubbles it is. This is enough to isolate the CSS and render question. The geometry
                                        // itself was already tested separately, from the real code (see `mark_group_seam`).
                    overlay.add_overlay(&notch);
                }
            }
        }

        messages.append(&overlay);
        previous = Some((mine, width));
    }

    let scroller = gtk::ScrolledWindow::builder()
        .vexpand(true)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .child(&messages)
        .build();
    // Same class the real conversation uses, so the harness exercises the
    // wallpaper rule too rather than quietly diverging from it.
    scroller.add_css_class("chat-messages");
    scroller.upcast()
}

