//! The conversation view — one implementation for both 1:1 and group chats.
//!
//! On Android these are two ~2200-line activities that duplicate each other
//! almost line for line, differing only in which core call to use and whether
//! a sender name belongs on the bubble. Here that difference is a two-armed
//! `Conversation` match, so a fix to bubble ordering, reply handling or
//! attachment state lands in both at once.
//!
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

/// How many messages a page of history holds, matching the Android chat.
const PAGE_SIZE: u32 = 50;
/// H128: hard cap on bubbles kept alive in one open chat. ~8 GTK widgets per
/// bubble; past this the oldest page is dropped from the view (the archive
/// still has everything — scrolling up again, or reopening the chat, brings
/// it back). 600 ≈ 12 pages of history on screen at once.
const MAX_BUBBLES: usize = 600;
const FETCH_HISTORY_LABEL: &str = "Fetch older history";
/// Hard cap on bubble width, in pixels.
///
/// A wrapping GtkLabel's `max-width-chars` turned out not to bound the
/// allocation here — measured naturals of ~310px were still being allocated
/// 872px, so long messages stretched the full width of the window and ran off
/// the edge. AdwClamp caps the natural width outright, which is exactly the
/// guarantee a chat bubble needs.
const BUBBLE_MAX_WIDTH: i32 = 460;
/// Spec dışı, kullanıcı isteği ("merging message bubles on linux?" — bkz.
/// Android `MergedBubbleDecoration`, AYNI eşik): art arda, aynı göndericiden,
/// bu pencere içinde gelen mesajlar tek bir görsel grup gibi birleşir —
/// köşeleri değen kenarlarda küçülür, aralarındaki boşluk daralır.
///
/// Android'in tam union-path çizimi burada YOK: GTK CSS'te web'deki
/// `::before`/`::after` sözde-öğeleri karşılığı olmadığından "arka planla
/// aynı renkte bir yama ile köşeyi ye" numarası bile AYRI bir widget
/// gerektiriyor (bkz. `mark_group_seam`/`SEAM_NOTCH_SIZE`) — RecyclerView'ın
/// tek bir `Canvas`'a tüm balonları birden çizdiği Android tarafının aksine.
/// Bu yüzden burada "ucuz" yöntem: köşe yarıçapını CSS sınıflarıyla küçültüp
/// (bkz. theme.rs `.continued-top`/`.continued-bottom`) genişlik farkı olan
/// dikişlere SABİT boyutlu, dairesel küçük bir çentik ekliyoruz — tam
/// geometrik eşleşme değil ama aynı "düz kesim değil, yumuşak birleşim"
/// hissini çok daha ucuza veriyor.
const BUBBLE_GROUP_WINDOW_MS: u64 = 2 * 60 * 1000;
/// Bir dikişteki genişlik farkı bunun ALTINDAYSA çentik eklenmez — görünmez
/// kadar küçük bir fark için fazladan bir widget/render maliyetine değmez.
const SEAM_NOTCH_MIN_DELTA: i32 = 8;
/// Çentik dairesinin çapı (px) — SABİT, gerçek genişlik farkına göre
/// büyümez (bkz. dosya başı notu — kesin geometri yerine ucuz bir görsel
/// ipucu).
const SEAM_NOTCH_SIZE: i32 = 14;
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
    deleted: bool,
    /// Rendered as an "(edited)" suffix. Comes from the archive, so it
    /// survives a reload instead of only existing while the edit event is
    /// fresh on screen.
    edited: bool,
    attachment: Option<Attachment>,
    /// Spec dışı, hata düzeltmesi (kullanıcı: "flatpakda bu son ui
    /// düzeltmelerini hiçbirini görmüyorum" — Android tarafında aynı hata
    /// zaten düzeltilmişti, bkz. lib.rs `message_seen` tablosu): önceden bu
    /// alan hiç yoktu, `build_bubble` her zaman `false` ile başlıyordu —
    /// yani bir mesajın "görüldü" durumu SADECE o an sohbet ekranı açıkken
    /// gelen canlı bir olaydan geliyordu, sohbeti kapatıp yeniden açmak
    /// tikleri sıfırlıyordu. Artık kalıcı çekirdek tablosundan gelen
    /// `ArchivedMessage.seen_by` boş değilse (bkz. `load_page`) doğrudan
    /// burada taşınıyor.
    seen: bool,
    /// Reaction summary from the core ("😂2 👍"), empty when none.
    reactions: String,
}

/// The widgets of one rendered bubble that later events may need to touch.
struct Bubble {
    root: gtk::Widget,
    /// Same widget as `root`, kept typed — `mark_group_seam` adds a small
    /// notch to it after the fact (bkz. `BUBBLE_GROUP_WINDOW_MS` dosya başı
    /// notu) when a LATER bubble turns out to continue this one; `root`
    /// alone (a bare `gtk::Widget`) cannot take `add_overlay`.
    overlay: gtk::Overlay,
    /// The actual coloured bubble box (`.bubble` CSS class) — `mark_group_seam`
    /// toggles its corner-radius classes; `root`/`overlay` are just the
    /// alignment/notch wrapper around it.
    skin: gtk::Box,
    /// Natural width at build time (post max-width clamp) — used to place the
    /// seam notch without a second, possibly-stale `measure()` call later.
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
    /// Set once a `seen` receipt arrives, so a later `status` event cannot
    /// downgrade the tick back to "sent".
    seen: Cell<bool>,
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
}

/// Live, mutable state for one attachment bubble, plus the widgets `file_*`
/// events update.
///
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
    fetch_history: gtk::Button,
    bubbles: RefCell<HashMap<String, Rc<Bubble>>>,
    /// Ids we have already sent a read receipt for. Survives `reload()`, which
    /// clears `bubbles` — see `insert_entry`.
    seen_sent: RefCell<HashSet<String>>,
    /// bkz. `send_seen` — bekleyen debounce'lu okuma sınırı var mı.
    watermark_pending: Cell<bool>,
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
    /// M165: live entries (fresh events) can arrive without a message id —
    /// they still need a unique map/order key. `fresh_local_id` mints one.
    live_serial: Cell<u64>,
    loading_older: Cell<bool>,
    exhausted_locally: Cell<bool>,
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

    fn is_group(&self) -> bool {
        matches!(self.conversation, Conversation::Group { .. })
    }

}

// --- construction ---

pub fn build(main: &Rc<MainUi>, conversation: &Conversation) -> adw::NavigationPage {
    let messages = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(6)
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
        fetch_history: fetch_history.clone(),
        bubbles: RefCell::new(HashMap::new()),
        seen_sent: RefCell::new(HashSet::new()),
        watermark_pending: Cell::new(false),
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
        last_typing_sent: Cell::new(0),
        typing_active: Cell::new(false),
        account_deleted: Cell::new(false),
        recording: RefCell::new(None),
        search_matches: RefCell::new(Vec::new()),
        search_index: Cell::new(0),
        search_lower: RefCell::new(HashMap::new()),
        seen_batch: RefCell::new(Vec::new()),
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
    page_content.append(view.whiteboard.panel());
    page_content.append(&scroller);
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
    view.refresh_subtitle();

    // Mark read + tell sibling devices, both on open and on close.
    view.mark_read_and_sync();
    *view.app().active_conversation.borrow_mut() = Some(conversation.key());
    {
        let view = view.clone();
        page.connect_hidden(move |_| {
            view.mark_read_and_sync();
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
            if adjustment.value() <= 8.0 && adjustment.upper() > adjustment.page_size() {
                view.load_older();
            }
        });
    }

    // Live events.
    {
        let view = view.clone();
        main.app.subscribe(&page_content, move |event| view.handle_event(event));
    }

    // Connection/typing subtitle.
    {
        let view = view.clone();
        let page_content = page_content.clone();
        glib::timeout_add_seconds_local(3, move || {
            if page_content.root().is_none() {
                return glib::ControlFlow::Break;
            }
            // Hidden/minimized: skip the thread + core round-trip.
            if !page_content.is_mapped() {
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

fn build_header(
    view: &Rc<ChatView>,
    subtitle: &gtk::Label,
    search_bar: &gtk::Revealer,
    search_entry: &gtk::SearchEntry,
) -> adw::HeaderBar {
    let title = gtk::Label::new(Some(&view.conversation.title()));
    title.add_css_class("heading");

    let title_box = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .halign(gtk::Align::Center)
        .build();
    title_box.append(&title);
    title_box.append(subtitle);

    let header = adw::HeaderBar::builder().title_widget(&title_box).build();
    // bkz. `MainUi::toggle_sidebar` — kenar çubuğu kapatıldıysa geri açacak
    // yol bir sohbet açıkken de gerekli (yer tutucu sayfasıyla AYNI desen).
    header.pack_start(&crate::ui::window::sidebar_toggle_button(&view.main));

    let (popover, items) = crate::ui::widgets::menu_popover();

    let mut entries: Vec<(&str, Box<dyn Fn(&Rc<ChatView>)>)> = Vec::new();
    if view.is_group() {
        entries.push(("Members", Box::new(group_members)));
        entries.push(("Invite a contact", Box::new(group_invite)));
        entries.push(("Set group picture", Box::new(group_picture)));
    }
    entries.push((
        "Attachments",
        Box::new(|view: &Rc<ChatView>| attachments_overview(view)),
    ));
    {
        let bar = search_bar.clone();
        let entry = search_entry.clone();
        entries.push((
            "Search in chat",
            Box::new(move |_: &Rc<ChatView>| {
                let opening = !bar.reveals_child();
                bar.set_reveal_child(opening);
                if opening {
                    entry.grab_focus();
                }
            }),
        ));
    }

    for (label, action) in entries {
        let button = gtk::Button::builder().label(label).build();
        button.add_css_class("flat");
        if let Some(child) = button.child().and_downcast::<gtk::Label>() {
            child.set_xalign(0.0);
        }
        let view = view.clone();
        let popover = popover.clone();
        button.connect_clicked(move |_| {
            popover.popdown();
            action(&view);
        });
        items.append(&button);
    }

    header.pack_end(
        &gtk::MenuButton::builder()
            .icon_name("view-more-symbolic")
            .popover(&popover)
            .build(),
    );
    header.pack_end(view.whiteboard.toggle_button());
    for (icon, tip, video) in [("camera-video-symbolic", "Video call", true), ("call-start-symbolic", "Voice call", false)] {
        let button = gtk::Button::builder().icon_name(icon).tooltip_text(tip).build();
        let view = view.clone();
        button.connect_clicked(move |_| crate::ui::call::place(&view.main.app, &view.conversation, video));
        header.pack_end(&button);
    }
    header
}

fn composer_bar(view: &Rc<ChatView>) -> gtk::Box {
    let bar = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(6)
        .margin_top(6)
        .margin_bottom(6)
        .margin_start(6)
        .margin_end(6)
        .build();

    let attach = gtk::Button::builder()
        .icon_name("mail-attachment-symbolic")
        .tooltip_text("Send a file")
        .valign(gtk::Align::End)
        .build();
    attach.add_css_class("flat");
    {
        let view = view.clone();
        attach.connect_clicked(move |_| view.pick_attachment());
    }

    let record = gtk::Button::builder()
        .icon_name("audio-input-microphone-symbolic")
        .tooltip_text("Record a voice message")
        .valign(gtk::Align::End)
        .build();
    record.add_css_class("flat");
    let record_time = gtk::Label::new(None);
    record_time.add_css_class("caption");
    record_time.set_visible(false);

    // Discard, as opposed to the mic button's stop-and-send. Only visible while
    // recording: a voice message you did not mean to make should be throwable
    // away without sending it first.
    let record_cancel = gtk::Button::builder()
        .icon_name("window-close-symbolic")
        .tooltip_text("Discard this recording")
        .valign(gtk::Align::End)
        .build();
    record_cancel.add_css_class("flat");
    record_cancel.set_visible(false);
    if !crate::audio::is_available() {
        // No ffmpeg, no capture — say so rather than failing on click.
        record.set_sensitive(false);
        record.set_tooltip_text(Some(
            "Voice messages need ffmpeg installed (it captures through PipeWire).",
        ));
    } else {
        let view = view.clone();
        let record_time = record_time.clone();
        let record_cancel = record_cancel.clone();
        record.connect_clicked(move |button| {
            view.toggle_recording(button, &record_time, &record_cancel);
        });
    }
    {
        let view = view.clone();
        let record_time = record_time.clone();
        let record_button = record.clone();
        record_cancel.connect_clicked(move |cancel| {
            view.cancel_recording(&record_button, &record_time, cancel);
        });
    }

    let entry_scroller = gtk::ScrolledWindow::builder()
        .hexpand(true)
        .max_content_height(140)
        .propagate_natural_height(true)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .child(&view.composer)
        .build();
    entry_scroller.add_css_class("composer-input");
    // `border-radius` on the scrolled window's own CSS node rounds its box,
    // but does not by itself clip children — the `TextView` inside paints its
    // own opaque background edge to edge regardless, which is why this still
    // rendered as a plain rectangle. `Overflow::Hidden` is what actually
    // clips the child to the rounded box.
    entry_scroller.set_overflow(gtk::Overflow::Hidden);

    let send = gtk::Button::builder()
        .icon_name("document-send-symbolic")
        .tooltip_text("Send")
        .valign(gtk::Align::End)
        .build();
    send.add_css_class("suggested-action");
    send.add_css_class("circular");
    {
        let view = view.clone();
        send.connect_clicked(move |_| view.send());
    }

    // Enter sends, Shift+Enter inserts a newline — the convention every
    // desktop chat client uses.
    let keys = gtk::EventControllerKey::new();
    {
        let view = view.clone();
        keys.connect_key_pressed(move |_, key, _, state| {
            let is_enter = key == gtk::gdk::Key::Return || key == gtk::gdk::Key::KP_Enter;
            if is_enter && !state.contains(gtk::gdk::ModifierType::SHIFT_MASK) {
                view.send();
                return glib::Propagation::Stop;
            }
            glib::Propagation::Proceed
        });
    }
    view.composer.add_controller(keys);

    {
        // Take the buffer out first: `view.composer.buffer()` as the receiver
        // of a call whose argument moves `view` would borrow and move the same
        // binding in one expression.
        let buffer = view.composer.buffer();
        let view = view.clone();
        buffer.connect_changed(move |buffer| {
            view.set_typing(buffer.char_count() > 0);
        });
    }

    bar.append(&attach);
    bar.append(&record);
    bar.append(&record_cancel);
    bar.append(&record_time);
    bar.append(&entry_scroller);
    bar.append(&send);
    bar
}

// --- history ---

impl ChatView {
    /// Full rebuild from the local archive. Used on open and whenever an event
    /// changes history in a way that cannot be patched in place (a peer's
    /// history sync, a sibling backfill).
    fn reload(self: &Rc<Self>) {
        let generation = self.load_gen.get() + 1;
        self.load_gen.set(generation);
        let conversation = self.conversation.clone();
        let own_identity = self.app().own_identity_id.borrow().clone();
        let view = self.clone();
        // The core lock is shared with the poll thread; on the GTK thread this
        // read froze the window whenever a poll round was running.
        crate::app::run_in_background(
            move || fetch_page(&conversation, &own_identity, None, 0, None),
            move |page| {
                if view.load_gen.get() != generation {
                    return;
                }
                // Keep a reader of old messages where they are; only a view
                // already at the bottom follows to the newest.
                let adjustment = view.scroller.vadjustment();
                let distance_from_bottom = adjustment.upper() - adjustment.page_size() - adjustment.value();
                let at_bottom = distance_from_bottom < 80.0;
                while let Some(child) = view.messages.first_child() {
                    view.messages.remove(&child);
                }
                view.bubbles.borrow_mut().clear();
                view.order.borrow_mut().clear();
                view.search_lower.borrow_mut().clear();
                view.search_matches.borrow_mut().clear();
                view.search_index.set(0);
                view.exhausted_locally.set(false);
                view.oldest_timestamp.set(page.oldest);
                view.oldest_attachment_timestamp.set(page.oldest_attachment);

                let mut entries = page.entries;
                entries.sort_by_key(|entry| entry.order_key);
                let mut previous_day = 0u64;
                for entry in entries {
                    if util::is_new_day(previous_day, entry.order_key) {
                        view.messages.append(&day_separator(entry.order_key));
                    }
                    previous_day = entry.order_key;
                    view.insert_entry(entry, false);
                }
                if at_bottom {
                    view.scroll_to_bottom();
                } else {
                    glib::idle_add_local_once(move || {
                        adjustment.set_value(adjustment.upper() - adjustment.page_size() - distance_from_bottom);
                    });
                }
            },
        );
    }

    /// The "Fetch older history" button. The rows arrive later with a
    /// `history_backfilled` event, which reloads the chat.
    fn fetch_server_history(self: &Rc<Self>) {
        let (chat_key, is_group) = match &self.conversation {
            Conversation::Direct { fingerprint, .. } => (fingerprint.clone(), false),
            Conversation::Group { group_id, .. } => (group_id.clone(), true),
        };
        let before = self.order.borrow().first().map(|(key, _)| *key).unwrap_or(0);
        self.fetch_history.set_sensitive(false);
        self.fetch_history.set_label("Requested…");
        let view = self.clone();
        crate::app::run_in_background(
            move || core::fetch_server_history(&chat_key, is_group, before as i64),
            move |result| match result {
                Err(error) => {
                    view.reset_fetch_history();
                    view.app().toast(&error);
                }
                // No reply (server offline, nothing older): the button comes back.
                Ok(()) => {
                    glib::timeout_add_local_once(std::time::Duration::from_secs(20), move || view.reset_fetch_history());
                }
            },
        );
    }

    fn reset_fetch_history(&self) {
        self.fetch_history.set_sensitive(true);
        self.fetch_history.set_label(FETCH_HISTORY_LABEL);
    }

    fn load_older(self: &Rc<Self>) {
        if self.loading_older.get() || self.exhausted_locally.get() {
            return;
        }
        let cursor = self.oldest_timestamp.get();
        if cursor == 0 {
            return;
        }
        self.loading_older.set(true);

        let generation = self.load_gen.get();
        let conversation = self.conversation.clone();
        let own_identity = self.app().own_identity_id.borrow().clone();
        // The files page on their own cursor (the core keeps them in their own
        // table): the older ones come in below the oldest file on screen.
        let attachment_cursor = self.oldest_attachment_timestamp.get();
        let view = self.clone();
        crate::app::run_in_background(
            move || {
                // Local archive only: scrolling sends nothing to the network.
                fetch_page(
                    &conversation,
                    &own_identity,
                    Some(cursor as i64),
                    cursor,
                    Some(attachment_cursor),
                )
            },
            move |page| {
                view.loading_older.set(false);
                if view.load_gen.get() != generation {
                    return; // a reload replaced the timeline meanwhile
                }
                let mut older = page.entries;
                if older.is_empty() {
                    view.exhausted_locally.set(true);
                    return;
                }
                view.oldest_timestamp.set(page.oldest);
                if page.oldest_attachment > 0 {
                    view.oldest_attachment_timestamp.set(page.oldest_attachment);
                }
                older.sort_by_key(|entry| entry.order_key);

                // Preserve the reading position. Inserting above shifts
                // everything down by the height of what was added; distance
                // from the *bottom* is the invariant, and the restore waits for
                // the next layout pass because `upper` is stale until then.
                let adjustment = view.scroller.vadjustment();
                let distance_from_bottom = adjustment.upper() - adjustment.value();
                for entry in older {
                    view.insert_entry(entry, false);
                }
                // H128: a full page of 50 above the cap drops the oldest
                // page's worth of bubbles immediately, so the view settles at
                // ~MAX_BUBBLES instead of growing for as long as the user
                // keeps scrolling.
                view.evict_oldest();
                glib::idle_add_local_once(move || {
                    adjustment.set_value(adjustment.upper() - distance_from_bottom);
                });
            },
        );
    }

    /// H128: drops the oldest bubbles once more than `MAX_BUBBLES` are alive,
    /// then prunes any day-day separator left stranded by the evictions.
    /// Removing the widgets is safe from the GTK thread (that is where the
    /// rest of timeline surgery happens too).
    ///
    /// Note the reload cursor: refetching after an eviction still pages from
    /// `oldest_timestamp` (strictly older receive time), so evicted rows stay
    /// gone until a full `reload()` or the chat is reopened — by design, the
    /// user scrolled past them into the archive anyway.
    fn evict_oldest(self: &Rc<Self>) {
        let evicted: Vec<String> = {
            let mut order = self.order.borrow_mut();
            let excess = order.len().saturating_sub(MAX_BUBBLES);
            if excess == 0 {
                return;
            }
            order.drain(..excess).map(|(_, id)| id).collect()
        };

        {
            let mut bubbles = self.bubbles.borrow_mut();
            for id in &evicted {
                if let Some(bubble) = bubbles.remove(id) {
                    self.messages.remove(&bubble.root);
                }
            }
        }
        // The search index refers to bubble ids; keep only what survived, so
        // a match jump can never land on a removed bubble.
        self.search_matches.borrow_mut().retain(|id| {
            !evicted.iter().any(|gone| gone == id)
        });
        self.search_lower.borrow_mut().retain(|id, _| {
            !evicted.iter().any(|gone| gone == id)
        });

        // Two leading day separators (the bubble between them was evicted) or
        // a separator with nothing after it are leftovers; a separator still
        // followed by a bubble is legitimate and stays.
        while let Some(first) = self.messages.first_child() {
            if !first.has_css_class("day-separator") {
                break;
            }
            let stranded = first
                .next_sibling()
                .map(|next| next.has_css_class("day-separator"))
                .unwrap_or(true); // nothing after it at all
            if !stranded {
                break;
            }
            self.messages.remove(&first);
        }
    }
}

/// One page of a conversation: the merged timeline plus the two cursors the
/// next page starts from.
struct Page {
    entries: Vec<Entry>,
    /// Oldest message timestamp on the page — the message paging cursor.
    oldest: u64,
    /// Oldest attachment timestamp on the page — the attachment paging
    /// cursor (the core keeps the files in their own table, so they page on
    /// their own). Zero when the page carried no attachment.
    oldest_attachment: u64,
}

/// Reads one page of messages *and* attachments and merges them onto a
/// single timeline — the core stores them separately but the user sees one
/// conversation.
///
/// `before` is the message cursor (`None` = the newest page), and
/// `attachment_before` the attachment one: the `created_at` of the oldest
/// attachment already on screen (`None` = take the newest ones).
fn fetch_page(
    conversation: &Conversation,
    own_identity: &str,
    before: Option<i64>,
    mut oldest: u64,
    attachment_before: Option<u64>,
) -> Page {
    let mut entries = Vec::new();
    let peer_fingerprint = match conversation {
        Conversation::Direct { fingerprint, .. } => fingerprint.clone(),
        Conversation::Group { .. } => String::new(),
    };

    let archived = match (conversation, before) {
        (Conversation::Direct { fingerprint, .. }, None) => {
            core::message_history(fingerprint, PAGE_SIZE)
        }
        (Conversation::Direct { fingerprint, .. }, Some(cursor)) => {
            core::message_history_before(fingerprint, cursor, PAGE_SIZE)
        }
        (Conversation::Group { group_id, .. }, None) => {
            core::group_message_history(group_id, PAGE_SIZE)
        }
        (Conversation::Group { group_id, .. }, Some(cursor)) => {
            core::group_message_history_before(group_id, cursor, PAGE_SIZE)
        }
    };

    for message in archived {
        if oldest == 0 || message.timestamp < oldest {
            oldest = message.timestamp;
        }
        let sender_identity = message.sender_identity_id.clone().unwrap_or_default();
        let mine = message.direction == "sent"
            || (!sender_identity.is_empty() && sender_identity == own_identity);
        entries.push(Entry {
            id: message.message_id.clone().unwrap_or_else(|| {
                // Pre-`message_id` rows exist in old archives; a synthetic
                // key keeps them renderable, they just cannot be targeted
                // by an edit or a receipt.
                format!("legacy:{}:{}", message.timestamp, entries.len())
            }),
            mine,
            sender_identity,
            text: message.text.clone(),
            order_key: if message.sent_at_ms > 0 {
                message.sent_at_ms
            } else {
                message.timestamp
            },
            // A missing status is an archive row from before the column
            // existed; treating it as delivered is the safe reading.
            // Ticks describe delivery of MY messages; a received one has none.
            // "delivered" is the core's end-to-end Ack — a state between
            // "sent" and "seen" (bkz. `format_meta`).
            status: mine.then(|| message.status.clone().unwrap_or_else(|| "sent".to_string())),
            reply_preview: message.reply_to_preview.clone(),
            reply_sender: message.reply_to_sender_identity_id.clone(),
            deleted: message.is_deleted,
            edited: message.is_edited,
            attachment: None,
            seen: mine && !message.seen_by.is_empty(),
            reactions: message.reactions.clone(),
        });
    }

    // Attachments live in their own table in the core, so they page on a
    // cursor of their own: the first page takes the newest ones, an older
    // page (loaded while scrolling up) takes the ones below the oldest
    // already on screen.
    let listed: Vec<core::AttachmentSummary> = match conversation {
        Conversation::Direct { fingerprint, .. } => match (before, attachment_before) {
            (None, _) => core::list_attachments(fingerprint),
            (Some(_), Some(cursor)) if cursor > 0 => {
                core::list_attachments_before(fingerprint, cursor, PAGE_SIZE as usize)
            }
            (Some(_), _) => Vec::new(),
        },
        Conversation::Group { group_id, .. } => match (before, attachment_before) {
            (None, _) => core::list_group_attachments(group_id),
            (Some(_), Some(cursor)) if cursor > 0 => {
                core::list_group_attachments_before(group_id, cursor, PAGE_SIZE as usize)
            }
            (Some(_), _) => Vec::new(),
        },
    };

    let mut oldest_attachment = 0u64;
    for attachment in listed {
        if oldest_attachment == 0 || attachment.created_at < oldest_attachment {
            oldest_attachment = attachment.created_at;
        }
        entries.push(attachment_entry(&attachment, &peer_fingerprint));
    }

    Page {
        entries,
        oldest,
        oldest_attachment,
    }
}

/// One archive attachment row as a timeline entry — the core keeps the files
/// in their own table, but the user sees them inside the conversation.
fn attachment_entry(attachment: &core::AttachmentSummary, peer_fingerprint: &str) -> Entry {
    let sender_identity = attachment.sender_identity_id.clone().unwrap_or_default();
    // In a group the file belongs to the member who sent it, so the row
    // carries that member's device; in a 1:1 the conversation key is it.
    let source = if attachment.peer_device_fingerprint.is_empty() {
        peer_fingerprint.to_string()
    } else {
        attachment.peer_device_fingerprint.clone()
    };
    Entry {
        id: attachment.file_id.clone(),
        mine: attachment.direction == "sent",
        sender_identity,
        text: String::new(),
        order_key: attachment.created_at,
        status: None,
        reply_preview: None,
        reply_sender: None,
        deleted: false,
        edited: false,
        attachment: Some(Attachment {
            file_id: attachment.file_id.clone(),
            file_name: attachment.file_name.clone(),
            mime: attachment.mime_type.clone(),
            total_size: attachment.total_size,
            source_fingerprint: source,
            status: attachment.status.clone(),
            preview_hex: attachment.preview_hex.clone(),
            bytes_done: attachment.bytes_transferred,
            duration_ms: attachment.duration_ms,
            sticker: attachment.sticker,
        }),
        // Ekler için kalıcı bir "görüldü" kaynağı yok (bkz. `Entry.seen`
        // notu — `message_seen` tablosu `files`'a değil
        // `messages.message_id`'ye bağlı); ESKİ davranışla aynı, hiçbir
        // zaman görüldü göstermiyordu.
        seen: false,
        reactions: String::new(),
    }
}

// --- rendering ---

impl ChatView {
    /// M165: a live event without any id would key an empty-string bubble —
    /// two such messages then collide on `""` and the second silently
    /// overwrites the first's text in place. Mint a unique view-local key
    /// instead. It is not derivable again after a `reload()` (where the
    /// archive rebuilds bubbles under its own ids), but by then the core has
    /// stored the message anyway, so nothing is lost — the key only has to be
    /// unique for as long as this view lives.
    fn fresh_local_id(&self) -> String {
        let serial = self.live_serial.get() + 1;
        self.live_serial.set(serial);
        format!("live:{serial}")
    }

    /// Inserts a bubble at its `order_key` position. Scanning from the end is
    /// right for the common case (a new message is the newest) and still
    /// correct for a message delayed in transit, which slots into the spot it
    /// was written in rather than the spot it arrived in.
    fn insert_entry(self: &Rc<Self>, entry: Entry, scroll: bool) {
        if let Some(existing) = self.bubbles.borrow().get(&entry.id) {
            // Already on screen — a duplicate can legitimately arrive when a
            // reload races an event. Refresh in place instead of doubling it.
            existing.text.set_label(&display_text(&entry));
            self.search_lower.borrow_mut().clear();
            existing.edited.set(entry.edited);
            // Never downgrade: a stale archive row must not pull a bubble that
            // already got the end-to-end Ack back to "sent".
            let status = match (existing.status.borrow().as_deref(), entry.status.as_deref()) {
                (Some("delivered"), Some("sent" | "pending")) => Some("delivered".to_string()),
                _ => entry.status.clone(),
            };
            *existing.status.borrow_mut() = status.clone();
            existing.meta.set_markup(&format_meta(
                entry.order_key,
                status.as_deref(),
                existing.seen.get(),
                entry.edited,
            ));
            return;
        }

        // bkz. `BUBBLE_GROUP_WINDOW_MS` dosya başı notu — hangi konuma
        // gireceği (dolayısıyla hangi balonun "öncesi" sayılacağı) `build_bubble`'dan
        // ÖNCE bilinmeli, çünkü grup durumu balonun KENDİ üst köşesini
        // etkiliyor. Yalnızca GERİYE (önceki balona) bakılıyor — araya
        // sırasız (gecikmeli) bir mesaj girerse, ondan SONRAKİ balonun grup
        // durumu bu turda yeniden hesaplanmaz (bkz. dosya başı "ucuz yöntem"
        // notu — nadir bir sınır durumu, en yaygın durum olan "en sona ekle"
        // için tam doğru).
        let order = self.order.borrow();
        let position = order
            .iter()
            .rposition(|(key, _)| *key <= entry.order_key)
            .map(|index| index + 1)
            .unwrap_or(0);
        let previous_bubble = if position > 0 {
            self.bubbles.borrow().get(&order[position - 1].1).cloned()
        } else {
            None
        };
        drop(order);

        let grouped_with_previous = previous_bubble.as_ref().is_some_and(|previous| {
            previous.mine == entry.mine
                && previous.sender_identity == entry.sender_identity
                && previous.attachment.is_none()
                && entry.attachment.is_none()
                && entry.order_key.saturating_sub(previous.order_key) < BUBBLE_GROUP_WINDOW_MS
        });
        let bubble = self.build_bubble(&entry, grouped_with_previous);
        if grouped_with_previous {
            if let Some(previous) = &previous_bubble {
                self.mark_group_seam(previous, &bubble);
            }
        }

        let mut order = self.order.borrow_mut();
        if position == order.len() {
            self.messages.append(&bubble.root);
        } else {
            let after = if position == 0 {
                None
            } else {
                self.bubbles
                    .borrow()
                    .get(&order[position - 1].1)
                    .map(|previous| previous.root.clone())
            };
            self.messages.insert_child_after(&bubble.root, after.as_ref());
        }

        order.insert(position, (entry.order_key, entry.id.clone()));
        drop(order);
        self.bubbles.borrow_mut().insert(entry.id.clone(), bubble);

        // Acknowledge on screen: only for what someone else sent, and at most
        // once per message for as long as this view lives. Without the guard
        // every `reload()` — which several events trigger — would re-send a
        // receipt for the whole visible history.
        if !entry.mine
            && entry.attachment.is_none()
            && !entry.id.starts_with("legacy:")
            && self.seen_sent.borrow_mut().insert(entry.id.clone())
        {
            self.send_seen(&entry);
        }

        if scroll {
            self.scroll_to_bottom();
        }
    }

    fn build_bubble(self: &Rc<Self>, entry: &Entry, continued_top: bool) -> Rc<Bubble> {
        let column = bubble_content();

        // In a group, who said it matters; in a 1:1 it is obvious.
        if self.is_group() && !entry.mine && !entry.sender_identity.is_empty() {
            let sender = gtk::Label::builder()
                .label(self.app().identity_name(&entry.sender_identity).as_str())
                .xalign(0.0)
                .build();
            sender.add_css_class("caption-heading");
            column.append(&sender);
        }

        if let Some(preview) = &entry.reply_preview {
            let who = entry
                .reply_sender
                .as_ref()
                .map(|identity| self.app().identity_name(identity))
                .filter(|name| !name.is_empty());
            let quoted = match who {
                Some(name) => format!("↩ {}: {}", name, util::preview_text(preview, 80)),
                None => format!("↩ {}", util::preview_text(preview, 80)),
            };
            let reply = gtk::Label::builder().label(quoted.as_str()).xalign(0.0).wrap(true).build();
            reply.add_css_class("caption");
            reply.add_css_class("dim-label");
            column.append(&reply);
        }

        let text = bubble_text_label(&display_text(entry));
        if entry.deleted {
            text.add_css_class("dim-label");
        }

        let mut attachment_state = None;
        let mut attachment_widgets = None;
        if let Some(attachment) = &entry.attachment {
            let (widgets, state) = self.build_attachment(attachment);
            // An attachment message freshly loaded from the archive is never
            // itself the deleted one — a deletion purges its `files` row
            // outright, so it would not be here to load in the first place.
            // `text` still goes in (hidden) so a *live* delete arriving later
            // has a "Message deleted" placeholder ready to swap to.
            text.set_visible(false);
            column.append(&widgets);
            column.append(&text);
            attachment_widgets = Some(widgets);
            attachment_state = Some(state);
        } else {
            column.append(&text);
        }

        let meta = gtk::Label::builder().xalign(1.0).build();
        meta.add_css_class("caption");
        meta.add_css_class("dim-label");
        // Markup, not plain text: the delivered double tick carries its own
        // grey (see `format_meta`).
        meta.set_markup(&meta_text(entry, entry.seen));
        column.append(&meta);

        let reactions = gtk::Label::builder()
            .label(entry.reactions.as_str())
            .xalign(if entry.mine { 1.0 } else { 0.0 })
            .visible(!entry.reactions.is_empty())
            .build();
        reactions.add_css_class("caption");
        column.append(&reactions);

        let (overlay, skin) = place_bubble(&column, entry.mine);
        if entry.attachment.as_ref().is_some_and(|a| a.sticker) {
            skin.remove_css_class("bubble");
            skin.remove_css_class(if entry.mine { "bubble-mine" } else { "bubble-theirs" });
        }
        // bkz. `BUBBLE_GROUP_WINDOW_MS` dosya başı notu — `insert_entry`
        // önceki balonla aynı grupta olduğuna karar verdiyse üst köşeler
        // küçülür ve boşluk daralır (aynı sınıf `.bubble-mine`'ın tek başına
        // taşıdığı "kuyruk" köşesini de — bkz. theme.rs — daha yüksek
        // özgüllükle ezer, o yüzden `continued-bottom` ayrıca bir şey
        // KALDIRMAK zorunda değil).
        if continued_top {
            skin.add_css_class("continued-top");
            overlay.add_css_class("bubble-row-continued");
        }
        // Ölçüm burada (Clamp'ın üst sınırı hesaba katılmış hâliyle, ham
        // `skin` DEĞİL) yapılıyor ki `mark_group_seam` ikinci bir (ve o an
        // potansiyel olarak yanlış) `measure()` çağrısına gerek duymasın.
        let content_width = overlay.measure(gtk::Orientation::Horizontal, -1).1;
        let root: gtk::Widget = overlay.clone().upcast();

        // Right-click for reply / edit / delete / copy.
        let gesture = gtk::GestureClick::new();
        gesture.set_button(3);
        {
            let view = self.clone();
            let entry = entry.clone();
            let anchor = column.clone();
            gesture.connect_pressed(move |_, _, x, y| {
                view.bubble_menu(&anchor, &entry, x, y);
            });
        }
        column.add_controller(gesture);

        Rc::new(Bubble {
            root,
            overlay,
            skin,
            content_width,
            sender_identity: entry.sender_identity.clone(),
            text,
            meta,
            attachment: attachment_state,
            attachment_widgets,
            order_key: entry.order_key,
            mine: entry.mine,
            seen: Cell::new(entry.seen),
            reactions,
            status: RefCell::new(entry.status.clone()),
            edited: Cell::new(entry.edited),
        })
    }

    /// bkz. `BUBBLE_GROUP_WINDOW_MS` dosya başı notu. `current` az önce
    /// `previous`'un grubuna eklendi — `previous`'un artık grubun SONU
    /// olmadığını (bkz. `continued-bottom`) ve, genişlikleri belirgin
    /// şekilde farklıysa, aradaki dikişi yumuşatan küçük bir çentiği
    /// işaretler.
    fn mark_group_seam(&self, previous: &Rc<Bubble>, current: &Rc<Bubble>) {
        previous.skin.add_css_class("continued-bottom");

        let delta = (previous.content_width - current.content_width).abs();
        if delta < SEAM_NOTCH_MIN_DELTA {
            return;
        }
        // Çentik, İKİSİNDEN GENİŞ olanın "sarkan" köşesine gider — dikişte
        // görünen basamak orada oluşuyor (bkz. dosya başı "ucuz yöntem"
        // notu). `mine` her ikisinde de AYNI (bkz. `insert_entry` gruplama
        // koşulu), o yüzden hangisinden okunduğu önemli değil.
        let (host, valign, wider_width) = if previous.content_width > current.content_width {
            (previous, gtk::Align::End, previous.content_width)
        } else {
            (current, gtk::Align::Start, current.content_width)
        };

        let notch = gtk::Box::builder()
            .width_request(SEAM_NOTCH_SIZE)
            .height_request(SEAM_NOTCH_SIZE)
            .valign(valign)
            .halign(if current.mine { gtk::Align::End } else { gtk::Align::Start })
            .build();
        notch.add_css_class("bubble-seam-notch");
        // Çentiği köşenin TAM üstüne ortalar — dış hizalanan kenardan
        // (mine=sağ/theirs=sol) uzaklık, geniş balonun genişliği kadar.
        let margin = (wider_width - SEAM_NOTCH_SIZE / 2).max(0);
        if current.mine {
            notch.set_margin_end(margin);
        } else {
            notch.set_margin_start(margin);
        }
        host.overlay.add_overlay(&notch);
    }

    /// Returns the attachment block plus the live state later `file_*`
    /// events and click handlers need. Voice messages (an audio MIME type)
    /// get an inline play/pause + seek player, matching the Android voice
    /// bubble; everything else gets a generic file card.
    fn build_attachment(self: &Rc<Self>, attachment: &Attachment) -> (gtk::Box, Rc<AttachmentState>) {
        // Only an actual voice message gets the inline player. A plain audio
        // FILE the user attached from their file manager has no duration, and
        // rendering it as a player produced a bubble with no filename, no
        // size and an empty label — the recipient could not even tell what it
        // was. The sender puts `duration_ms` in the FileOffer for real voice
        // notes, so this still shows the player for one that has not been
        // downloaded yet.
        if attachment.sticker {
            self.build_sticker(attachment)
        } else if util::is_audio(&attachment.mime) && attachment.duration_ms.unwrap_or(0) > 0 {
            self.build_voice_player(attachment)
        } else {
            self.build_generic_attachment(attachment)
        }
    }

    /// A sticker: just the picture, no name, size or button (it downloads
    /// on its own). ponytail: an animated sticker shows its first frame.
    fn build_sticker(self: &Rc<Self>, attachment: &Attachment) -> (gtk::Box, Rc<AttachmentState>) {
        let block = gtk::Box::new(gtk::Orientation::Vertical, 0);
        let picture = gtk::Picture::new();
        picture.set_size_request(160, 160);
        picture.set_content_fit(gtk::ContentFit::Contain);
        picture.add_css_class("sticker");
        block.append(&picture);
        let state = Rc::new(AttachmentState {
            file_id: attachment.file_id.clone(),
            file_name: attachment.file_name.clone(),
            mime: attachment.mime.clone(),
            total_size: attachment.total_size,
            source_fingerprint: attachment.source_fingerprint.clone(),
            status: RefCell::new(attachment.status.clone()),
            bytes_done: Cell::new(attachment.bytes_done),
            download_started_at: Cell::new(0),
            status_label: None,
            progress: None,
            eta: None,
            action: None,
            voice: None,
            sticker: Some(picture),
        });
        if attachment.status == "complete" {
            load_sticker(&state);
        }
        (block, state)
    }

    fn build_generic_attachment(self: &Rc<Self>, attachment: &Attachment) -> (gtk::Box, Rc<AttachmentState>) {
        let block = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(6)
            .build();

        // A preview thumbnail is shipped with the offer, so a photo is visible
        // before anyone downloads anything.
        if let Some(texture) = attachment
            .preview_hex
            .as_deref()
            .and_then(util::texture_from_hex)
        {
            let image = gtk::Picture::for_paintable(&texture);
            image.set_size_request(240, 180);
            image.set_content_fit(gtk::ContentFit::Cover);
            image.add_css_class("attachment-preview");
            block.append(&image);
        }

        let display_name = if attachment.file_name.is_empty() {
            util::attachment_label(&attachment.mime, "")
        } else {
            attachment.file_name.clone()
        };
        let name = gtk::Label::builder()
            .label(display_name.as_str())
            .xalign(0.0)
            .ellipsize(gtk::pango::EllipsizeMode::Middle)
            .max_width_chars(34)
            .build();
        block.append(&name);

        let status_label = gtk::Label::builder()
            .label(attachment_status_text(attachment).as_str())
            .xalign(0.0)
            .build();
        status_label.add_css_class("caption");
        block.append(&status_label);

        let progress = gtk::ProgressBar::new();
        progress.set_visible(attachment.status == "downloading");
        if attachment.total_size > 0 {
            progress.set_fraction(attachment.bytes_done as f64 / attachment.total_size as f64);
        }
        block.append(&progress);

        // Hidden until there is enough data to estimate a rate from — see
        // `util::format_eta` — rather than flashing a misleading "0s left".
        let eta = gtk::Label::new(None);
        eta.add_css_class("caption");
        eta.add_css_class("dim-label");
        eta.set_visible(false);
        block.append(&eta);

        let action = gtk::Button::builder()
            .label(action_label(&attachment.status, attachment.bytes_done).as_str())
            .halign(gtk::Align::Start)
            .build();
        action.set_visible(attachment.status != "downloading");
        block.append(&action);

        let state = Rc::new(AttachmentState {
            file_id: attachment.file_id.clone(),
            file_name: attachment.file_name.clone(),
            mime: attachment.mime.clone(),
            total_size: attachment.total_size,
            source_fingerprint: attachment.source_fingerprint.clone(),
            status: RefCell::new(attachment.status.clone()),
            bytes_done: Cell::new(attachment.bytes_done),
            download_started_at: Cell::new(0),
            status_label: Some(status_label),
            progress: Some(progress),
            eta: Some(eta),
            action: Some(action.clone()),
            voice: None,
            sticker: None,
        });

        {
            let view = self.clone();
            let state = state.clone();
            action.connect_clicked(move |button| view.attachment_action(&state, button));
        }

        (block, state)
    }

    /// An inline voice-message player: a play/pause button plus a seek scale
    /// that doubles as a download-progress bar before the file is here.
    fn build_voice_player(self: &Rc<Self>, attachment: &Attachment) -> (gtk::Box, Rc<AttachmentState>) {
        let block = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(10)
            .build();

        let play_button = gtk::Button::builder()
            .icon_name("media-playback-start-symbolic")
            .valign(gtk::Align::Center)
            .build();
        play_button.add_css_class("flat");
        play_button.add_css_class("circular");

        let column = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(2)
            .hexpand(true)
            .valign(gtk::Align::Center)
            .build();

        // `hexpand` alone only means "take extra space if any is going" — it
        // does not make the *bubble itself* wide. `place_bubble`'s clamp sizes
        // to the content's natural width, and a `GtkScale` with nothing else
        // in the row demanding room has a natural width close to zero, so the
        // whole bubble (and the slider inside it) rendered tiny. It also
        // tripped a GTK warning ("slider reported min height/width -2, but
        // sizes must be >= 0") — a near-zero allocation is exactly the
        // pathological case where GTK's own min-size arithmetic for the
        // slider handle underflows. A concrete minimum width fixes both.
        let slider = gtk::Scale::builder()
            .orientation(gtk::Orientation::Horizontal)
            .hexpand(true)
            .width_request(180)
            .draw_value(false)
            .build();

        let duration_label = gtk::Label::builder().xalign(0.0).build();
        duration_label.add_css_class("caption");
        duration_label.add_css_class("dim-label");

        column.append(&slider);
        column.append(&duration_label);
        block.append(&play_button);
        block.append(&column);

        let state = Rc::new(AttachmentState {
            file_id: attachment.file_id.clone(),
            file_name: attachment.file_name.clone(),
            mime: attachment.mime.clone(),
            total_size: attachment.total_size,
            source_fingerprint: attachment.source_fingerprint.clone(),
            status: RefCell::new(attachment.status.clone()),
            bytes_done: Cell::new(attachment.bytes_done),
            download_started_at: Cell::new(0),
            status_label: None,
            progress: None,
            eta: None,
            action: None,
            voice: Some(VoicePlayer {
                play_button: play_button.clone(),
                slider: slider.clone(),
                duration_label,
                media: RefCell::new(None),
                duration_ms: Cell::new(attachment.duration_ms.unwrap_or(0)),
            }),
            sticker: None,
        });
        render_voice_state(&state);

        {
            let view = self.clone();
            let state = state.clone();
            play_button.connect_clicked(move |_| view.voice_play_clicked(&state));
        }
        {
            let view = self.clone();
            let state = state.clone();
            slider.connect_change_value(move |_, _, value| {
                view.voice_seek(&state, value);
                glib::Propagation::Proceed
            });
        }

        (block, state)
    }

    /// Download when it is not here yet, open when it is. `state` is shared
    /// with the widgets `file_*` events update, so this always sees the
    /// attachment's current status rather than a stale build-time snapshot.
    fn attachment_action(self: &Rc<Self>, state: &Rc<AttachmentState>, button: &gtk::Button) {
        if *state.status.borrow() == "complete" {
            self.open_attachment(state);
            return;
        }
        self.start_download(state, Some(button.clone()));
    }

    fn open_attachment(self: &Rc<Self>, state: &Rc<AttachmentState>) {
        let app = self.app().clone();
        let file_id = state.file_id.clone();
        let mime = state.mime.clone();
        let name = if state.file_name.is_empty() {
            util::attachment_label(&state.mime, "")
        } else {
            state.file_name.clone()
        };
        // Decryption copies the whole file, so it must not run on the main
        // thread — a large video would freeze the window outright.
        app::run_in_background(
            move || core::attachment_plaintext_path(&file_id),
            move |result| match result {
                Ok(path) => crate::ui::media::open(&app, &path, &mime, &name),
                Err(error) => app.toast(&format!("Could not open the file: {}", error)),
            },
        );
    }

    /// Kicks a download off the core. H125 straggler: `core::download_file`
    /// takes the global core mutex the poll thread can hold for seconds, so
    /// the inline call used to freeze the whole window (and every voice
    /// player with it) whenever the poller was mid-round. The work closure
    /// carries only Send data; the widget state is touched exclusively in
    /// `then`, which `run_in_background` runs back on the GTK thread.
    ///
    /// `hide_on_start` (the generic card's "Download" button) is hidden only
    /// on a confirmed start — exactly the old success/failure split: a failed
    /// start leaves the button up so there is still a way to retry.
    fn start_download(self: &Rc<Self>, state: &Rc<AttachmentState>, hide_on_start: Option<gtk::Button>) {
        state.download_started_at.set(util::now_ms());
        let file_id = state.file_id.clone();
        let source_fingerprint = state.source_fingerprint.clone();
        let view = self.clone();
        let state = state.clone();
        crate::app::run_in_background(
            move || core::download_file(&file_id, &source_fingerprint),
            move |result| match result {
                Ok(()) => {
                    if let Some(button) = &hide_on_start {
                        button.set_visible(false);
                    }
                    *state.status.borrow_mut() = "downloading".to_string();
                    if let Some(status) = &state.status_label {
                        status.set_label("Downloading…");
                    }
                    if let Some(progress) = &state.progress {
                        progress.set_visible(true);
                    }
                    render_voice_state(&state);
                }
                // A failed start emits no events at all, so the caller must
                // reflect that immediately or the row spins forever.
                Err(error) => {
                    state.download_started_at.set(0);
                    view.app().toast(&format!("Download failed: {}", error));
                }
            },
        );
    }

    /// Play/pause a voice message, downloading it first if it is not here yet.
    fn voice_play_clicked(self: &Rc<Self>, state: &Rc<AttachmentState>) {
        if *state.status.borrow() != "complete" {
            self.start_download(state, None);
            return;
        }
        let Some(voice) = &state.voice else { return };
        if let Some(media) = voice.media.borrow().clone() {
            media.set_playing(!media.is_playing());
            return;
        }

        // Not loaded yet: only one voice message plays at a time (matching
        // Android), so pause whatever else is going before decrypting this
        // one — decryption happens off the main thread since it copies the
        // whole file.
        self.pause_other_voices(&state.file_id);
        let view = self.clone();
        let file_id = state.file_id.clone();
        let state = state.clone();
        app::run_in_background(
            move || core::attachment_plaintext_path(&file_id),
            move |result| match result {
                Ok(path) => view.start_voice_playback(&state, &path),
                Err(error) => view.app().toast(&format!("Could not play the voice message: {}", error)),
            },
        );
    }

    fn pause_other_voices(&self, except_file_id: &str) {
        for bubble in self.bubbles.borrow().values() {
            let Some(state) = &bubble.attachment else { continue };
            if state.file_id == except_file_id {
                continue;
            }
            if let Some(voice) = &state.voice {
                if let Some(media) = voice.media.borrow().as_ref() {
                    if media.is_playing() {
                        media.pause();
                    }
                }
            }
        }
    }

    /// Seeking an unplayed slider is a no-op — pressing play first is the one
    /// extra step this leaves on the table (see `VoicePlayer::media` doc).
    fn voice_seek(&self, state: &Rc<AttachmentState>, position: f64) {
        let Some(voice) = &state.voice else { return };
        if let Some(media) = voice.media.borrow().as_ref() {
            media.seek(position.max(0.0) as i64);
        }
    }

    /// Creates the `GtkMediaFile` for a just-decrypted voice message and wires
    /// its notify signals to the slider/label/play-button, the same pattern
    /// the in-app video/audio viewer's transport bar uses.
    fn start_voice_playback(self: &Rc<Self>, state: &Rc<AttachmentState>, path: &str) {
        let Some(voice) = &state.voice else { return };
        let media = gtk::MediaFile::for_filename(path);

        {
            let button = voice.play_button.clone();
            media.connect_playing_notify(move |media| {
                button.set_icon_name(if media.is_playing() {
                    "media-playback-pause-symbolic"
                } else {
                    "media-playback-start-symbolic"
                });
            });
        }
        {
            let slider = voice.slider.clone();
            media.connect_duration_notify(move |media| {
                slider.set_range(0.0, (media.duration().max(0) as f64).max(1.0));
            });
        }
        {
            let slider = voice.slider.clone();
            let label = voice.duration_label.clone();
            media.connect_timestamp_notify(move |media| {
                let timestamp = media.timestamp().max(0);
                slider.set_value(timestamp as f64);
                let duration = media.duration().max(0);
                label.set_label(&util::format_duration_us((duration - timestamp).max(0)));
            });
        }
        {
            let app = self.app().clone();
            media.connect_error_notify(move |media| {
                if media.error().is_some() {
                    app.toast("Could not play the voice message.");
                }
            });
        }

        media.set_playing(true);
        *voice.media.borrow_mut() = Some(media);
    }

    fn bubble_menu(self: &Rc<Self>, anchor: &gtk::Box, entry: &Entry, x: f64, y: f64) {
        let (popover, items) = crate::ui::widgets::menu_popover();
        popover.set_parent(anchor);
        popover.set_pointing_to(Some(&gtk::gdk::Rectangle::new(x as i32, y as i32, 1, 1)));
        popover.connect_closed(|popover| popover.unparent());

        let mut actions: Vec<(&str, String, bool, Box<dyn Fn()>)> = Vec::new();

        if !entry.deleted && !entry.id.starts_with("legacy:") {
            let view = self.clone();
            let entry = entry.clone();
            let anchor = anchor.clone();
            actions.push((
                "face-smile-symbolic",
                "React".to_string(),
                false,
                Box::new(move || view.pick_reaction(&anchor, &entry)),
            ));
        }

        if !entry.deleted && entry.attachment.is_none() {
            {
                let view = self.clone();
                let entry = entry.clone();
                actions.push((
                    "mail-reply-sender-symbolic",
                    "Reply".to_string(),
                    false,
                    Box::new(move || view.start_reply(&entry)),
                ));
            }
            {
                let text = entry.text.clone();
                let anchor = anchor.clone();
                actions.push((
                    "edit-copy-symbolic",
                    "Copy".to_string(),
                    false,
                    Box::new(move || anchor.clipboard().set_text(&text)),
                ));
            }
        }

        // Spec dışı, hata düzeltmesi ("Linux'ta ekler hiç silinemiyor"):
        // `Edit`in metin girişi bir eke uygulanamaz (protokolün `Edit`
        // içeriği düz metin), o yüzden ek varken hâlâ atlanır — ama
        // `Delete` metinden bağımsız çalışır (bkz. `delete_message` — aynı
        // paylaşılan Rust çekirdek yolu, `purge_attachment_if_exists` dahil,
        // Android tarafı zaten bunu destekliyor). Önceden BU koşul da
        // `entry.attachment.is_none()` gerektiriyordu, yani bir ek
        // gönderildikten sonra Linux kullanıcısının onu silmesinin HİÇBİR
        // yolu yoktu (disk sızıntısı + yanlışlıkla gönderilen dosyayı
        // geri alamama).
        if entry.mine && !entry.deleted && !entry.id.starts_with("legacy:") {
            if entry.attachment.is_none() {
                let view = self.clone();
                let entry = entry.clone();
                actions.push((
                    "document-edit-symbolic",
                    "Edit".to_string(),
                    false,
                    Box::new(move || view.edit_message(&entry)),
                ));
            }
            {
                let view = self.clone();
                let entry = entry.clone();
                actions.push((
                    "edit-delete-symbolic",
                    "Delete".to_string(),
                    true,
                    Box::new(move || view.delete_message(&entry)),
                ));
            }
        }

        for (icon, label, destructive, action) in actions {
            let button = crate::ui::widgets::menu_item(icon, label.as_str());
            if destructive {
                button.add_css_class("destructive-action");
            }
            let popover = popover.clone();
            button.connect_clicked(move |_| {
                popover.popdown();
                action();
            });
            items.append(&button);
        }

        if items.first_child().is_some() {
            popover.popup();
        } else {
            popover.unparent();
        }
    }
}

// --- sending ---

impl ChatView {
    /// The contact deleted their account: grey out the whole composer bar and
    /// say why in the header. The core refuses the sends anyway.
    fn lock_account_deleted(&self) {
        self.account_deleted.set(true);
        if let Some(bar) = self.composer.parent().and_then(|scroller| scroller.parent()) {
            bar.set_sensitive(false);
        }
        self.subtitle.set_label("Deleted their account · messages can't be sent");
    }

    fn send(self: &Rc<Self>) {
        if self.account_deleted.get() {
            return;
        }
        let buffer = self.composer.buffer();
        let (start, end) = buffer.bounds();
        let text = buffer.text(&start, &end, false).to_string();
        let text = text.trim().to_string();
        if text.is_empty() {
            return;
        }

        let reply = self.reply_to.borrow().clone();
        let (reply_id, reply_preview, reply_sender) = match reply {
            Some((id, preview, sender)) => (Some(id), Some(preview), sender),
            None => (None, None, None),
        };

        let own_identity = self.app().own_identity_id.borrow().clone();
        let now = util::now_ms();

        // Composer clears first; the core call runs off the GTK thread and the
        // bubble appears on its result. A failed send puts the text back.
        buffer.set_text("");
        self.clear_reply();
        self.set_typing(false);

        let view = self.clone();
        let restore = text.clone();
        let preview_for_core = reply_preview.clone();
        let reply_sender_for_core = reply_sender.clone();
        let make_entry = move |id: String, status: String| Entry {
            id,
            mine: true,
            sender_identity: own_identity,
            text: restore.clone(),
            order_key: now,
            status: Some(status),
            reply_preview: reply_preview.clone(),
            reply_sender: reply_sender.clone(),
            deleted: false,
            edited: false,
            attachment: None,
            seen: false,
            reactions: String::new(),
        };
        let done = move |view: Rc<Self>, result: Result<Entry, String>, text: String| match result {
            Ok(entry) => view.insert_entry(entry, true),
            Err(error) => {
                view.app().toast(&format!("Could not send: {}", error));
                let buffer = view.composer.buffer();
                let (start, end) = buffer.bounds();
                if buffer.text(&start, &end, false).is_empty() {
                    buffer.set_text(&text);
                }
            }
        };
        match &self.conversation {
            Conversation::Direct { fingerprint, .. } => {
                let fingerprint = fingerprint.clone();
                let sent_text = text.clone();
                crate::app::run_in_background(
                    move || core::send_message(&fingerprint, &sent_text, reply_id, preview_for_core).map(|r| (r.message_id, r.status)),
                    move |result| {
                        let result = result.map(|(id, status)| make_entry(id, status));
                        done(view, result, text);
                    },
                );
            }
            Conversation::Group { group_id, .. } => {
                let group_id = group_id.clone();
                let sent_text = text.clone();
                crate::app::run_in_background(
                    move || {
                        core::send_group_message(&group_id, &sent_text, reply_id, preview_for_core, reply_sender_for_core)
                    },
                    move |result| {
                        // A group send fans out to every member; the core reports
                        // no single status, so it shows as sent and the pending
                        // queue owns the retries.
                        let result = result.map(|id| make_entry(id, "sent".to_string()));
                        done(view, result, text);
                    },
                );
            }
        }
    }

    /// Restores the composer to its idle look. Shared so stop, discard and
    /// failure paths cannot drift apart and leave the bar stuck mid-recording.
    fn reset_recording_ui(button: &gtk::Button, timer: &gtk::Label, cancel: &gtk::Button) {
        button.set_icon_name("audio-input-microphone-symbolic");
        button.remove_css_class("destructive-action");
        button.add_css_class("flat");
        button.set_tooltip_text(Some("Record a voice message"));
        timer.set_visible(false);
        cancel.set_visible(false);
    }

    /// Throws away an in-progress recording without sending it.
    fn cancel_recording(
        self: &Rc<Self>,
        button: &gtk::Button,
        timer: &gtk::Label,
        cancel: &gtk::Button,
    ) {
        if let Some(recording) = self.recording.borrow_mut().take() {
            recording.cancel();
            self.app().toast("Recording discarded.");
        }
        Self::reset_recording_ui(button, timer, cancel);
    }

    /// Starts or finishes a voice message.
    fn toggle_recording(
        self: &Rc<Self>,
        button: &gtk::Button,
        timer: &gtk::Label,
        cancel: &gtk::Button,
    ) {
        let active = self.recording.borrow().is_some();
        if !active {
            match crate::audio::Recording::start() {
                Ok(recording) => {
                    *self.recording.borrow_mut() = Some(recording);
                    button.set_icon_name("media-playback-stop-symbolic");
                    button.add_css_class("destructive-action");
                    button.remove_css_class("flat");
                    button.set_tooltip_text(Some("Stop and send"));
                    timer.set_visible(true);
                    timer.set_label("0:00");
                    cancel.set_visible(true);

                    // Tick the elapsed time, and stop ticking as soon as the
                    // recording ends (or the view goes away).
                    let view = self.clone();
                    let timer = timer.clone();
                    glib::timeout_add_local(std::time::Duration::from_millis(500), move || {
                        // Chat page gone (switched/closed): this timer keeps the
                        // view alive, so `Drop` never runs — stop the mic here.
                        if timer.root().is_none() {
                            if let Some(recording) = view.recording.borrow_mut().take() {
                                recording.cancel();
                            }
                            return glib::ControlFlow::Break;
                        }
                        let elapsed = match view.recording.borrow().as_ref() {
                            Some(recording) => recording.elapsed_ms(),
                            None => return glib::ControlFlow::Break,
                        };
                        let seconds = elapsed / 1000;
                        timer.set_label(&format!("{}:{:02}", seconds / 60, seconds % 60));
                        glib::ControlFlow::Continue
                    });
                }
                Err(error) => self.app().toast(&format!("Could not record: {}", error)),
            }
            return;
        }

        // Stop: restore the composer first so the UI never looks stuck while
        // ffmpeg finalises and the file is encrypted.
        Self::reset_recording_ui(button, timer, cancel);

        let Some(recording) = self.recording.borrow_mut().take() else {
            return;
        };
        // Below about a second it is almost always a mis-click.
        if recording.elapsed_ms() < 800 {
            recording.cancel();
            self.app().toast("Too short — hold on a moment longer.");
            return;
        }

        // bkz. `prompt_attachment_caption` dosya başı notu — sesli mesaj da
        // fotoğraf/eklenti ile AYNI akıştan geçer: isteğe bağlı açıklama +
        // (varsa) aktif yanıt.
        let reply = self.reply_to.borrow().clone();
        let (reply_id, reply_preview, reply_sender) = match reply {
            Some((id, preview, sender)) => (Some(id), Some(preview), sender),
            None => (None, None, None),
        };

        let view = self.clone();
        let app = self.app().clone();
        let conversation = self.conversation.clone();
        self.prompt_attachment_caption(false, move |caption, _| {
            let view = view.clone();
            let app = app.clone();
            let conversation = conversation.clone();
            let reply_id = reply_id.clone();
            let reply_preview = reply_preview.clone();
            let reply_sender = reply_sender.clone();
            app.toast("Sending voice message…");
            app::run_in_background(
                move || {
                    let (path, duration_ms) = recording.finish()?;
                    let source = path.to_string_lossy().to_string();
                    let name = format!("voice-{}.ogg", crate::util::now_ms());
                    let outcome = match &conversation {
                        Conversation::Direct { fingerprint, .. } => core::prepare_and_send_file(
                            fingerprint,
                            &source,
                            &name,
                            "audio/ogg",
                            None,
                            Some(duration_ms),
                            caption,
                            reply_id,
                            reply_preview,
                        )
                        .map(|receipt| receipt.message_id),
                        Conversation::Group { group_id, .. } => core::prepare_and_send_group_file(
                            group_id,
                            &source,
                            &name,
                            "audio/ogg",
                            None,
                            Some(duration_ms),
                            caption,
                            reply_id,
                            reply_preview,
                            reply_sender,
                        ),
                    };
                    // The core copies and encrypts the file, so the raw capture is
                    // no longer needed either way.
                    let _ = std::fs::remove_file(&path);
                    outcome
                },
                move |result| match result {
                    Ok(_) => {
                        view.clear_reply();
                        view.reload();
                    }
                    Err(error) => app.toast(&format!("Voice message failed: {}", error)),
                },
            );
        });
    }

    /// Recomputes the match set and jumps to the newest hit.
    fn run_search(self: &Rc<Self>, needle: &str, count: &gtk::Label) {
        self.clear_search_highlight();
        let needle = needle.trim().to_lowercase();
        if needle.is_empty() {
            self.search_matches.borrow_mut().clear();
            count.set_label("");
            return;
        }

        let bubbles = self.bubbles.borrow();
        let mut cache = self.search_lower.borrow_mut();
        let matches: Vec<String> = self
            .order
            .borrow()
            .iter()
            .filter(|(_, id)| {
                let Some(bubble) = bubbles.get(id) else { return false };
                cache
                    .entry(id.clone())
                    .or_insert_with(|| bubble.text.label().to_lowercase())
                    .contains(&needle)
            })
            .map(|(_, id)| id.clone())
            .collect();
        drop(cache);
        drop(bubbles);

        let found = matches.len();
        // Start at the most recent match: in a conversation the interesting hit
        // is almost always the latest one, not the oldest.
        self.search_index.set(found.saturating_sub(1));
        *self.search_matches.borrow_mut() = matches;

        if found == 0 {
            count.set_label("No matches");
        } else {
            self.focus_search_match(count);
        }
    }

    /// Moves through the match set, wrapping at both ends.
    fn step_search(self: &Rc<Self>, delta: i32, count: &gtk::Label) {
        let total = self.search_matches.borrow().len();
        if total == 0 {
            return;
        }
        let current = self.search_index.get() as i64;
        let next = (current + delta as i64).rem_euclid(total as i64) as usize;
        self.search_index.set(next);
        self.focus_search_match(count);
    }

    fn focus_search_match(self: &Rc<Self>, count: &gtk::Label) {
        self.clear_search_highlight();
        let matches = self.search_matches.borrow();
        let total = matches.len();
        let index = self.search_index.get().min(total.saturating_sub(1));
        let Some(id) = matches.get(index).cloned() else {
            return;
        };
        drop(matches);
        count.set_label(&format!("{} of {}", index + 1, total));

        let bubbles = self.bubbles.borrow();
        let Some(bubble) = bubbles.get(&id) else { return };
        bubble.root.add_css_class("bubble-match");

        // Scroll the hit into view. Bounds are relative to the message box, so
        // this has to wait for a layout pass after any highlight reflow.
        let root = bubble.root.clone();
        let messages = self.messages.clone();
        let adjustment = self.scroller.vadjustment();
        glib::idle_add_local_once(move || {
            if let Some(bounds) = root.compute_bounds(&messages) {
                let target = bounds.y() as f64 - adjustment.page_size() / 3.0;
                adjustment.set_value(target.clamp(0.0, (adjustment.upper() - adjustment.page_size()).max(0.0)));
            }
        });
    }

    fn clear_search_highlight(&self) {
        for bubble in self.bubbles.borrow().values() {
            bubble.root.remove_css_class("bubble-match");
        }
    }

    /// Spec dışı, kullanıcı isteği ("fotoğraf/eklenti/ses atarken de bir
    /// mesaj yanıtlanabilmeli ve altına bir yazı yazılabilmeli" — bkz.
    /// Android `ChatActivity.promptAttachmentCaption` AYNI tasarım kararı):
    /// eklenti/ses göndermeden hemen önce isteğe bağlı bir açıklama sorar.
    /// Yanıt için AYRI bir adım yok — ekran zaten aktif bir yanıt tutuyorsa
    /// (bkz. `reply_to`) eklenti onunla birlikte gider; bu diyalog SADECE
    /// açıklamayı sorar. Gerçek bir "vazgeç" yolu kasıtlı olarak yok — dosya
    /// zaten seçilmiş/kaydedilmiş, "Skip" boş açıklamayla göndermeye devam
    /// eder (Android'deki aynı davranış).
    fn prompt_attachment_caption(self: &Rc<Self>, offer_hi_res: bool, on_confirm: impl FnOnce(String, bool) + 'static) {
        let Some(window) = self.app().window() else {
            on_confirm(String::new(), false);
            return;
        };
        let field = gtk::Entry::builder()
            .placeholder_text("Add a caption (optional)")
            .activates_default(true)
            .build();
        let dialog = adw::MessageDialog::new(Some(&window), Some("Add a caption?"), None);
        let hi_res = gtk::CheckButton::with_label("Hi-res (lossless)");
        if offer_hi_res {
            let column = gtk::Box::new(gtk::Orientation::Vertical, 6);
            column.append(&crate::ui::widgets::dialog_field(&field));
            column.append(&hi_res);
            dialog.set_extra_child(Some(&column));
        } else {
            dialog.set_extra_child(Some(&crate::ui::widgets::dialog_field(&field)));
        }
        dialog.add_response("skip", "Skip");
        dialog.add_response("send", "Send");
        dialog.set_default_response(Some("send"));
        dialog.set_close_response("skip");
        dialog.set_response_appearance("send", adw::ResponseAppearance::Suggested);
        // `connect_response`'un beklediği `Fn` ile elimizdeki `FnOnce` (bkz.
        // ses kaydı çağıranı — `Recording::finish` `self`'i TÜKETİYOR, o
        // yüzden onu saran kapanış birden fazla kez ÇAĞRILAMAZ) arasındaki
        // farkı kapatan standart desen: `FnOnce`'u bir `RefCell<Option<_>>`'a
        // koy, sinyal (pratikte tek sefer ateşlenir) onu `take()` ile ÇEKİP
        // çağırır — ikinci bir ateşleme (olmaması gerekir) sessizce no-op.
        let on_confirm = std::cell::RefCell::new(Some(on_confirm));
        dialog.connect_response(None, move |_, response| {
            let caption = if response == "send" {
                field.text().to_string().trim().to_string()
            } else {
                String::new()
            };
            if let Some(f) = on_confirm.borrow_mut().take() {
                f(caption, hi_res.is_active());
            }
        });
        dialog.present();
    }

    fn pick_attachment(self: &Rc<Self>) {
        let Some(window) = self.app().window() else { return };
        let dialog = gtk::FileDialog::builder().title("Send a file").build();
        let view = self.clone();
        dialog.open(Some(&window), gio::Cancellable::NONE, move |result| {
            let Ok(file) = result else { return };
            let Some(path) = file.path() else { return };
            let send_view = view.clone();
            let offer_hi_res = file.basename().is_some_and(|name| util::is_image(&util::guess_mime(&name.to_string_lossy())));
            view.prompt_attachment_caption(offer_hi_res, move |caption, hi_res| send_view.send_attachment(&path, caption, hi_res));
        });
    }

    fn send_attachment(self: &Rc<Self>, path: &std::path::Path, caption: String, hi_res: bool) {
        let file_name = path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());
        let mime = util::guess_mime(&file_name);
        let source = path.to_path_buf();

        // Photos travel with a small cover so the receiver sees something
        // before downloading. Video previews would need a decoder we do not
        // ship, so those go without — the receiver still gets a file card.
        // Decoded in the worker below, never on the GTK thread.
        let want_preview = util::is_image(&mime);

        // bkz. `prompt_attachment_caption` dosya başı notu — ekran zaten
        // aktif bir yanıt tutuyorsa (metin mesajıyla AYNI mantık, bkz.
        // `send_message`) eklenti de onunla birlikte gider.
        let reply = self.reply_to.borrow().clone();
        let (reply_id, reply_preview, reply_sender) = match reply {
            Some((id, preview, sender)) => (Some(id), Some(preview), sender),
            None => (None, None, None),
        };

        let conversation = self.conversation.clone();
        let view = self.clone();
        let app = self.app().clone();
        app.toast(&format!("Encrypting {}…", file_name));

        // Encryption rewrites the whole file; on a 4 GB attachment this is very
        // much not instant.
        app::run_in_background(
            move || {
                let preview = if want_preview {
                    util::scaled_jpeg(&source.to_string_lossy(), 480, 85)
                } else {
                    None
                };
                let tmp_dir = crate::data_directory().join("attachments/plain_cache");
                let (sent, file_name, mime) = util::prepare_outgoing(&source, &file_name, &mime, hi_res, &tmp_dir);
                let sent_path = sent.to_string_lossy().to_string();
                let outcome = match &conversation {
                    Conversation::Direct { fingerprint, .. } => core::prepare_and_send_file(
                        fingerprint, &sent_path, &file_name, &mime, preview, None,
                        caption, reply_id, reply_preview,
                    )
                    .map(|receipt| receipt.message_id),
                    Conversation::Group { group_id, .. } => core::prepare_and_send_group_file(
                        group_id, &sent_path, &file_name, &mime, preview, None,
                        caption, reply_id, reply_preview, reply_sender,
                    ),
                };
                let unscrubbed = sent == source && util::is_video(&mime);
                if sent != source {
                    let _ = std::fs::remove_file(&sent);
                }
                (outcome, unscrubbed)
            },
            move |(result, unscrubbed)| match result {
                // The attachment row comes from the archive, so a reload is the
                // simplest way to show it exactly as a restart would.
                Ok(_) => {
                    if unscrubbed {
                        app.toast("Sent without removing metadata");
                    }
                    view.clear_reply();
                    view.reload();
                }
                Err(error) => app.toast(&format!("Could not send the file: {}", error)),
            },
        );
    }

    fn edit_message(self: &Rc<Self>, entry: &Entry) {
        let view = self.clone();
        let entry = entry.clone();
        let Some(window) = self.app().window() else { return };

        let field = gtk::Entry::builder()
            .text(&entry.text)
            .activates_default(true)
            .build();
        let dialog = adw::MessageDialog::new(Some(&window), Some("Edit message"), None);
        dialog.set_extra_child(Some(&crate::ui::widgets::dialog_field(&field)));
        dialog.add_response("cancel", "Cancel");
        dialog.add_response("save", "Save");
        dialog.set_default_response(Some("save"));
        dialog.set_close_response("cancel");
        dialog.set_response_appearance("save", adw::ResponseAppearance::Suggested);
        dialog.connect_response(None, move |_, response| {
            if response != "save" {
                return;
            }
            let new_text = field.text().to_string().trim().to_string();
            if new_text.is_empty() || new_text == entry.text {
                return;
            }
            let (direct, target) = match &view.conversation {
                Conversation::Direct { fingerprint, .. } => (true, fingerprint.clone()),
                Conversation::Group { group_id, .. } => (false, group_id.clone()),
            };
            let (id, text) = (entry.id.clone(), new_text.clone());
            let (view, done_id) = (view.clone(), entry.id.clone());
            crate::app::run_in_background(
                move || {
                    if direct {
                        core::edit_message(&target, &id, &text).map(|_| ())
                    } else {
                        core::edit_group_message(&target, &id, &text)
                    }
                },
                move |outcome| match outcome {
                    Ok(()) => view.apply_edit(&done_id, &new_text),
                    Err(error) => view.app().toast(&format!("Edit failed: {}", error)),
                },
            );
        });
        dialog.present();
    }

    fn delete_message(self: &Rc<Self>, entry: &Entry) {
        let view = self.clone();
        let entry = entry.clone();
        dialogs::confirm(
            self.app(),
            "Delete this message?",
            "It is removed for everyone in this conversation.",
            "Delete",
            true,
            move || {
                let (direct, target) = match &view.conversation {
                    Conversation::Direct { fingerprint, .. } => (true, fingerprint.clone()),
                    Conversation::Group { group_id, .. } => (false, group_id.clone()),
                };
                let id = entry.id.clone();
                let (view, done_id) = (view.clone(), entry.id.clone());
                crate::app::run_in_background(
                    move || {
                        if direct {
                            core::delete_message(&target, &id).map(|_| ())
                        } else {
                            core::delete_group_message(&target, &id)
                        }
                    },
                    move |outcome| match outcome {
                        Ok(()) => view.apply_delete(&done_id),
                        Err(error) => view.app().toast(&format!("Delete failed: {}", error)),
                    },
                );
            },
        );
    }

    fn start_reply(self: &Rc<Self>, entry: &Entry) {
        let preview = util::preview_text(&entry.text, 120);
        let sender = if self.is_group() {
            Some(entry.sender_identity.clone()).filter(|s| !s.is_empty())
        } else {
            None
        };
        self.reply_label
            .set_label(&format!("Replying to: {}", util::preview_text(&preview, 80)));
        self.reply_bar.set_reveal_child(true);
        self.reply_island.add_css_class("active");
        *self.reply_to.borrow_mut() = Some((entry.id.clone(), preview, sender));
        self.composer.grab_focus();
    }

    fn clear_reply(&self) {
        *self.reply_to.borrow_mut() = None;
        self.reply_bar.set_reveal_child(false);
        self.reply_island.remove_css_class("active");
    }

    /// Fire-and-forget; only sent on a false<->true transition, never per
    /// keystroke.
    fn set_typing(&self, typing: bool) {
        if typing {
            self.last_typing_sent.set(util::now_ms());
        }
        if self.typing_active.get() == typing {
            return;
        }
        self.typing_active.set(typing);
        match &self.conversation {
            Conversation::Direct { fingerprint, .. } => {
                let fingerprint = fingerprint.clone();
                bg_serial(move || core::send_typing_indicator(&fingerprint, typing));
            }
            Conversation::Group { group_id, .. } => {
                let group_id = group_id.clone();
                bg_serial(move || core::send_group_typing_indicator(&group_id, typing));
            }
        }
    }

    fn send_seen(self: &Rc<Self>, entry: &Entry) {
        match &self.conversation {
            // 1:1: tekil `Seen` yerine okuma sınırı (ReadStateSync) — karşı
            // taraf onu bu mesaja da uygular, güvenilir teslim edilir. Bir
            // okuma patlaması tek pakette toplanır; `reload()` sırasında
            // geçmişin tamamı bu yoldan geçse de sadece bir tane gider.
            Conversation::Direct { fingerprint, .. } => {
                if self.watermark_pending.replace(true) {
                    return;
                }
                let view = self.clone();
                let fingerprint = fingerprint.clone();
                glib::timeout_add_local_once(std::time::Duration::from_millis(700), move || {
                    view.watermark_pending.set(false);
                    let now = util::now_ms();
                    bg_serial(move || core::sync_read_state(&fingerprint, "", now));
                });
            }
            Conversation::Group { .. } => {
                // A group receipt goes back to the original sender's device
                // with the local id they can map to their own bubble.
                // Collected and sent from ONE worker per 700 ms burst, not a
                // thread per bubble.
                if let Some(sender) = self.sender_device(&entry.sender_identity) {
                    self.seen_batch.borrow_mut().push((sender, entry.id.clone()));
                    if self.watermark_pending.replace(true) {
                        return;
                    }
                    let view = self.clone();
                    glib::timeout_add_local_once(std::time::Duration::from_millis(700), move || {
                        view.watermark_pending.set(false);
                        let batch = std::mem::take(&mut *view.seen_batch.borrow_mut());
                        bg_serial(move || {
                            for (sender, id) in batch {
                                core::send_seen_receipt(&sender, &id, Some(id.clone()));
                            }
                        });
                    });
                }
            }
        }
    }

    /// Resolves a group member's identity to the device we would message.
    fn sender_device(&self, identity_id: &str) -> Option<String> {
        self.app()
            .contacts
            .borrow()
            .iter()
            .find(|contact| contact.identity_id == identity_id)
            .and_then(|contact| contact.active_device_fingerprint.clone())
    }

    /// Local only. Cheap enough to call per incoming message.
    fn mark_read(&self) {
        let key = self.conversation.key();
        self.app().prefs.borrow_mut().mark_read_now(&key);
    }

    /// Local, *and* tells my other devices so this chat is not left unread on
    /// the phone. Kept separate from `mark_read` because it puts a reliable
    /// message on the wire — doing that per arriving message (rather than on
    /// open and close, as the Android activities do) would be pure noise.
    fn mark_read_and_sync(&self) {
        self.mark_read();
        let now = util::now_ms();
        let (fingerprint, group_id) = match &self.conversation {
            Conversation::Direct { fingerprint, .. } => (fingerprint.clone(), String::new()),
            Conversation::Group { group_id, .. } => (String::new(), group_id.clone()),
        };
        bg_serial(move || core::sync_read_state(&fingerprint, &group_id, now));
    }
}

// --- live updates ---

/// One worker runs the fire-and-forget core calls (typing, read sync, seen
/// receipts) in order: no thread per transition, and a typing "false" can no
/// longer overtake its "true".
fn bg_serial(job: impl FnOnce() + Send + 'static) {
    type Job = Box<dyn FnOnce() + Send>;
    static TX: std::sync::OnceLock<std::sync::mpsc::Sender<Job>> = std::sync::OnceLock::new();
    let tx = TX.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel::<Job>();
        std::thread::spawn(move || {
            while let Ok(job) = rx.recv() {
                job();
            }
        });
        tx
    });
    let _ = tx.send(Box::new(job));
}

impl ChatView {
    fn handle_event(self: &Rc<Self>, event: &Event) {
        let own_identity = self.app().own_identity_id.borrow().clone();
        if event.kind == "whiteboard" {
            self.whiteboard.handle_event(event);
            return;
        }

        match (&self.conversation, event.kind.as_str()) {
            (Conversation::Direct { fingerprint, .. }, "account_deleted")
                if event.string("peer") == *fingerprint =>
            {
                self.lock_account_deleted();
            }
            // --- incoming text ---
            (Conversation::Direct { fingerprint, .. }, "message")
                if event.string("peer") == *fingerprint =>
            {
                self.insert_entry(
                    Entry {
                        // M165: `""` here would collide with every other
                        // id-less event on the empty key (see `fresh_local_id`).
                        id: nonempty_or(event.optional("message_id"), self.fresh_local_id()),
                        mine: false,
                        sender_identity: String::new(),
                        text: event.string("text"),
                        order_key: nonzero_or(event.number("sent_at_ms"), util::now_ms()),
                        status: None,
                        reply_preview: event.optional("reply_to_preview"),
                        reply_sender: None,
                        deleted: false,
                        edited: false,
                        attachment: None,
                        seen: false,
                        reactions: String::new(),
                    },
                    true,
                );
                self.mark_read();
            }
            (Conversation::Group { group_id, .. }, "group_message")
                if event.string("group_id") == *group_id =>
            {
                let sender = event.string("sender_identity_id");
                self.insert_entry(
                    Entry {
                        // M165: see `fresh_local_id`.
                        id: nonempty_or(
                            event.optional("group_message_local_id"),
                            nonempty_or(event.optional("message_id"), self.fresh_local_id()),
                        ),
                        mine: sender == own_identity,
                        sender_identity: sender,
                        text: event.string("text"),
                        order_key: nonzero_or(event.number("sent_at_ms"), util::now_ms()),
                        status: None,
                        reply_preview: event.optional("reply_to_preview"),
                        reply_sender: event.optional("reply_to_sender_identity_id"),
                        deleted: false,
                        edited: false,
                        attachment: None,
                        seen: false,
                        reactions: String::new(),
                    },
                    true,
                );
                self.mark_read();
            }

            // --- my own message, echoed from another of my devices ---
            (Conversation::Direct { fingerprint, .. }, "sibling_message")
                if event.string("peer") == *fingerprint =>
            {
                self.insert_entry(
                    Entry {
                        // M165: see `fresh_local_id`.
                        id: nonempty_or(event.optional("message_id"), self.fresh_local_id()),
                        mine: true,
                        sender_identity: own_identity,
                        text: event.string("text"),
                        order_key: nonzero_or(event.number("sent_at_ms"), util::now_ms()),
                        status: Some("sent".to_string()),
                        reply_preview: event.optional("reply_to_preview"),
                        reply_sender: None,
                        deleted: false,
                        edited: false,
                        attachment: None,
                        seen: false,
                        reactions: String::new(),
                    },
                    true,
                );
            }
            (Conversation::Group { group_id, .. }, "sibling_group_message")
                if event.string("group_id") == *group_id =>
            {
                self.insert_entry(
                    Entry {
                        // M165: see `fresh_local_id`.
                        id: nonempty_or(
                            event.optional("group_message_local_id"),
                            nonempty_or(event.optional("message_id"), self.fresh_local_id()),
                        ),
                        mine: true,
                        sender_identity: own_identity,
                        text: event.string("text"),
                        order_key: nonzero_or(event.number("sent_at_ms"), util::now_ms()),
                        status: Some("sent".to_string()),
                        reply_preview: event.optional("reply_to_preview"),
                        reply_sender: event.optional("reply_to_sender_identity_id"),
                        deleted: false,
                        edited: false,
                        attachment: None,
                        seen: false,
                        reactions: String::new(),
                    },
                    true,
                );
            }

            // --- edits and deletes, from either side ---
            (Conversation::Direct { fingerprint, .. }, "edit")
                if event.string("peer") == *fingerprint =>
            {
                self.apply_edit(&event.string("message_id"), &event.string("text"));
            }
            (Conversation::Direct { fingerprint, .. }, "delete")
                if event.string("peer") == *fingerprint =>
            {
                self.apply_delete(&event.string("message_id"));
            }
            (Conversation::Group { group_id, .. }, "group_edit")
                if event.string("group_id") == *group_id =>
            {
                self.apply_edit(&event.string("message_id"), &event.string("text"));
            }
            (Conversation::Group { group_id, .. }, "group_delete")
                if event.string("group_id") == *group_id =>
            {
                self.apply_delete(&event.string("message_id"));
            }

            // --- delivery state on my own bubbles ---
            (_, "status") | (_, "ack") => {
                let id = event.string("message_id");
                let status = if event.kind == "ack" {
                    "sent".to_string()
                } else {
                    event.string("status")
                };
                self.apply_status(&id, &status);
            }
            (_, "reaction") if self.event_belongs_here(event) => {
                self.apply_reactions(&event.string("message_id"), &event.string("reactions"));
            }
            // 1:1 read boundary (ReadStateSync): every message it covers, oldest first.
            (Conversation::Direct { .. }, "seen_bulk")
                if event.optional("group_id").is_none() && self.event_belongs_here(event) =>
            {
                if let Some(ids) = event.value.get("message_ids").and_then(|v| v.as_array()) {
                    for id in ids.iter().filter_map(|v| v.as_str()) {
                        self.apply_seen(id);
                    }
                }
            }
            (_, "seen") => {
                let id = nonempty_or(
                    event.optional("group_message_local_id"),
                    event.string("message_id"),
                );
                self.apply_seen(&id);
            }

            // --- typing ---
            (Conversation::Direct { fingerprint, .. }, "typing")
                if event.string("peer") == *fingerprint =>
            {
                self.show_typing(event.flag("is_typing"), None);
            }
            (Conversation::Group { group_id, .. }, "typing")
                if event.optional("group_id").as_deref() == Some(group_id.as_str()) =>
            {
                let who = self.app().identity_name(&event.string("sender_identity_id"));
                self.show_typing(event.flag("is_typing"), Some(who));
            }

            // --- attachments ---
            // H129: a full `reload()` per offer — every core round-trip it
            // implies, run for each file in a burst — is gone; the attachment
            // bubble is built in place instead, with exactly the fields the
            // reload's `fetch_page` merge would have produced (it merges
            // attachments on the first page from the very row the core just
            // wrote for this event, so pre-`reload()` this insert already
            // matches). `file_progress`/`file_complete` then drive the card
            // by `file_id` as before.
            // Ticks: attachment bubbles carry no delivery status (same as the
            // archive merge, which sets `status: None`) — see `fetch_page`.
            (_, "file_offer" | "sibling_file") if self.event_belongs_here(event) => {
                let attachment = Some(Attachment {
                    file_id: event.string("file_id"),
                    file_name: event.string("file_name"),
                    mime: event.string("mime_type"),
                    total_size: event.number("total_size"),
                    // The peer column: the canonical chat key for 1:1, the
                    // sending member's device in a group — matches
                    // `list_attachments`' `peer_device_fingerprint`.
                    source_fingerprint: event.string("peer"),
                    status: if event.flag("auto_downloading") {
                        "downloading".to_string()
                    } else {
                        "offered".to_string()
                    },
                    preview_hex: event.optional("preview_hex"),
                    bytes_done: 0,
                    duration_ms: u32::try_from(event.number("duration_ms"))
                        .ok()
                        .filter(|ms| *ms > 0),
                    sticker: event.flag("sticker"),
                });
                self.insert_entry(
                    Entry {
                        id: event.string("file_id"),
                        // A sibling echo is my own outgoing file, arrived via
                        // another of my devices.
                        mine: event.kind == "sibling_file",
                        sender_identity: event.string("sender_identity_id"),
                        text: event.string("caption"),
                        order_key: util::now_ms(),
                        status: None,
                        reply_preview: event.optional("reply_to_preview"),
                        reply_sender: event.optional("reply_to_sender_identity_id"),
                        deleted: false,
                        edited: false,
                        attachment,
                        seen: false,
                        reactions: String::new(),
                    },
                    true,
                );
            }
            (_, "file_progress") => {
                self.apply_progress(
                    &event.string("file_id"),
                    event.number("bytes_done"),
                    event.number("bytes_total"),
                );
            }
            (_, "file_complete") => {
                self.apply_attachment_state(&event.string("file_id"), "complete", None);
            }
            (_, "file_failed") => {
                let reason = event.string("error");
                self.apply_attachment_state(&event.string("file_id"), "failed", Some(reason));
            }
            // Defter #16: dosya yerelden silindi (depolama sınırı tahliyesi
            // ya da mesajın silinmesi). Hiçbir istemci dinlemiyordu, balon
            // "tamamlandı" görünmeye devam ediyordu.
            (_, "file_evicted") => {
                self.apply_attachment_state(&event.string("file_id"), "offered", None);
            }

            // --- bulk history changes: rebuild rather than patch ---
            (_, "history_sync") | (_, "older_history") | (_, "older_group_history") => {
                if self.event_belongs_here(event) {
                    self.reset_fetch_history();
                    self.reload();
                }
            }
            // `history_backfilled` is the one bulk event that may arrive
            // UNADDRESSED: a sibling backfill spanning several conversations
            // has no single `peer`/`group_id` to name (see the core's
            // `SiblingHistoryResponse` arm). `event_belongs_here` returns
            // false for that shape, so this reload never happened — new
            // history landed in the database and the open chat kept showing
            // the old view until it was closed and reopened. An unaddressed
            // one now reloads unconditionally; an addressed one (the server
            // archive restore) still has to match.
            (_, "history_backfilled") => {
                let unaddressed = event.optional("group_id").is_none()
                    && event.string("peer").is_empty();
                self.reset_fetch_history();
                if unaddressed || self.event_belongs_here(event) {
                    self.reload();
                }
            }

            (Conversation::Group { group_id, .. }, "group_updated" | "member_left")
                if event.string("group_id") == *group_id =>
            {
                self.app().refresh_caches();
                self.refresh_subtitle();
            }

            _ => {}
        }
    }

    /// Whether an event with a `peer`/`group_id` pair addresses this view.
    /// `file_*` and history events use both fields inconsistently (a 1:1 file
    /// event has no `group_id` at all), so this checks whichever is present.
    fn event_belongs_here(&self, event: &Event) -> bool {
        match &self.conversation {
            Conversation::Direct { fingerprint, .. } => {
                event.optional("group_id").is_none() && event.string("peer") == *fingerprint
            }
            Conversation::Group { group_id, .. } => {
                event.optional("group_id").as_deref() == Some(group_id.as_str())
            }
        }
    }

    fn apply_edit(&self, id: &str, new_text: &str) {
        if let Some(bubble) = self.bubbles.borrow().get(id) {
            bubble.text.set_label(new_text);
            self.search_lower.borrow_mut().clear();
            bubble.edited.set(true);
            bubble.meta.set_markup(&format_meta(
                bubble.order_key,
                bubble.status.borrow().as_deref(),
                bubble.seen.get(),
                true,
            ));
        }
    }

    fn apply_delete(&self, id: &str) {
        if let Some(bubble) = self.bubbles.borrow().get(id) {
            bubble.text.set_label("Message deleted");
            self.search_lower.borrow_mut().clear();
            bubble.text.add_css_class("dim-label");
            bubble.text.set_visible(true);
            // An attachment bubble's card is a separate widget from `text` —
            // see the `attachment_widgets` field doc for why this half is the
            // one that actually makes a deletion visible for those.
            if let Some(widgets) = &bubble.attachment_widgets {
                widgets.set_visible(false);
            }
        }
    }

    fn apply_status(&self, id: &str, status: &str) {
        let bubbles = self.bubbles.borrow();
        let Some(bubble) = bubbles.get(id) else { return };
        if !bubble.mine || bubble.seen.get() {
            return;
        }
        // Never downgrade: the end-to-end Ack ("delivered") is a stronger
        // promise than "sent", and the events can arrive out of order — a
        // late "sent" must not pull the double tick back to one.
        if bubble.status.borrow().as_deref() == Some("delivered")
            && matches!(status, "sent" | "pending")
        {
            return;
        }
        *bubble.status.borrow_mut() = Some(status.to_string());
        bubble
            .meta
            .set_markup(&format_meta(bubble.order_key, Some(status), false, bubble.edited.get()));
    }

    fn apply_reactions(&self, id: &str, summary: &str) {
        let bubbles = self.bubbles.borrow();
        let Some(bubble) = bubbles.get(id) else { return };
        bubble.reactions.set_label(summary);
        bubble.reactions.set_visible(!summary.is_empty());
    }

    fn pick_reaction(self: &Rc<Self>, anchor: &gtk::Box, entry: &Entry) {
        let chooser = gtk::EmojiChooser::new();
        chooser.set_parent(anchor);
        chooser.connect_closed(|chooser| chooser.unparent());
        let view = self.clone();
        let id = entry.id.clone();
        chooser.connect_emoji_picked(move |_, emoji| {
            let (direct, target) = match &view.conversation {
                Conversation::Direct { fingerprint, .. } => (true, fingerprint.clone()),
                Conversation::Group { group_id, .. } => (false, group_id.clone()),
            };
            let (view, id, emoji) = (view.clone(), id.clone(), emoji.to_string());
            crate::app::run_in_background(
                {
                    let id = id.clone();
                    move || {
                        if direct {
                            core::react_to_message(&target, &id, &emoji)
                        } else {
                            core::react_to_group_message(&target, &id, &emoji)
                        }
                    }
                },
                move |result| match result {
                    Ok(summary) => view.apply_reactions(&id, &summary),
                    Err(error) => view.app().toast(&format!("Reaction failed: {}", error)),
                },
            );
        });
        chooser.popup();
    }

    fn apply_seen(&self, id: &str) {
        let bubbles = self.bubbles.borrow();
        let Some(bubble) = bubbles.get(id) else { return };
        if !bubble.mine {
            return;
        }
        bubble.seen.set(true);
        bubble
            .meta
            .set_markup(&format_meta(bubble.order_key, Some("sent"), true, bubble.edited.get()));
    }

    fn apply_progress(&self, file_id: &str, done: u64, total: u64) {
        let bubbles = self.bubbles.borrow();
        let Some(bubble) = bubbles.get(file_id) else { return };
        let Some(state) = &bubble.attachment else { return };

        state.bytes_done.set(done);
        if state.download_started_at.get() == 0 {
            state.download_started_at.set(util::now_ms());
        }

        if let Some(voice) = &state.voice {
            // Before completion the slider doubles as a download-progress
            // bar; once complete it means something else (playback position)
            // and progress events stop arriving for it anyway.
            if *state.status.borrow() != "complete" {
                voice.slider.set_range(0.0, total.max(1) as f64);
                voice.slider.set_value(done as f64);
            }
            return;
        }

        if let Some(progress) = &state.progress {
            progress.set_visible(true);
            if total > 0 {
                progress.set_fraction(done as f64 / total as f64);
            }
        }
        if let Some(status) = &state.status_label {
            status.set_label(&format!(
                "{} of {}",
                util::human_size(done),
                util::human_size(total)
            ));
        }
        if let Some(eta) = &state.eta {
            match util::format_eta(state.download_started_at.get(), done, total) {
                Some(text) => {
                    eta.set_label(&text);
                    eta.set_visible(true);
                }
                None => eta.set_visible(false),
            }
        }
        if let Some(action) = &state.action {
            action.set_visible(false);
        }
    }

    fn apply_attachment_state(&self, file_id: &str, new_status: &str, detail: Option<String>) {
        let bubbles = self.bubbles.borrow();
        let Some(bubble) = bubbles.get(file_id) else { return };
        let Some(state) = &bubble.attachment else { return };

        *state.status.borrow_mut() = new_status.to_string();
        // A retry after a failure (or of a stalled download) starts its own
        // fresh ETA measurement rather than inheriting the last attempt's.
        if new_status != "downloading" {
            state.download_started_at.set(0);
        }

        if state.voice.is_some() {
            render_voice_state(state);
            return;
        }
        if state.sticker.is_some() {
            if new_status == "complete" {
                load_sticker(state);
            }
            return;
        }

        if let Some(progress) = &state.progress {
            progress.set_visible(false);
        }
        if let Some(eta) = &state.eta {
            eta.set_visible(false);
        }
        if let Some(status) = &state.status_label {
            status.set_label(&match (new_status, detail) {
                ("complete", _) => "Downloaded".to_string(),
                ("failed", Some(reason)) => format!("Failed: {}", reason),
                ("failed", None) => "Failed".to_string(),
                (other, _) => other.to_string(),
            });
        }
        if let Some(action) = &state.action {
            action.set_visible(true);
            action.set_label(&action_label(new_status, state.bytes_done.get()));
        }
    }

    /// Shows/hides the typing bubble and (re)arms its auto-hide timeout — see
    /// the `typing_clear_source` field doc for why the timeout exists at all.
    fn show_typing(self: &Rc<Self>, typing: bool, who: Option<String>) {
        if let Some(source) = self.typing_clear_source.borrow_mut().take() {
            source.remove();
        }
        if !typing {
            self.typing_indicator.set_reveal_child(false);
            return;
        }
        self.typing_indicator_label.set_label(&match who {
            Some(name) if !name.is_empty() => format!("{} is typing…", name),
            _ => "typing…".to_string(),
        });
        self.typing_indicator.set_reveal_child(true);

        let view = self.clone();
        let source = glib::timeout_add_seconds_local(TYPING_INDICATOR_TIMEOUT_S, move || {
            view.typing_indicator.set_reveal_child(false);
            *view.typing_clear_source.borrow_mut() = None;
            glib::ControlFlow::Break
        });
        *self.typing_clear_source.borrow_mut() = Some(source);
    }

    fn refresh_subtitle(self: &Rc<Self>) {
        match &self.conversation {
            Conversation::Direct { fingerprint, .. } => {
                let fingerprint = fingerprint.clone();
                let view = self.clone();
                crate::app::run_in_background(
                    move || {
                        if core::is_peer_connected(&fingerprint) {
                            "Connected"
                        } else if core::has_active_session(&fingerprint) {
                            "Offline · messages will be delivered later"
                        } else {
                            "Connecting…"
                        }
                    },
                    move |label| {
                        if !view.account_deleted.get() {
                            view.subtitle.set_label(label);
                        }
                    },
                );
            }
            Conversation::Group { group_id, .. } => {
                let count = self
                    .app()
                    .groups
                    .borrow()
                    .iter()
                    .find(|group| group.group_id == *group_id)
                    .map(|group| group.member_identity_ids.len())
                    .unwrap_or(0);
                if !self.account_deleted.get() {
                    self.subtitle
                        .set_label(&format!("{} member{}", count, if count == 1 { "" } else { "s" }));
                }
            }
        }
    }

    fn scroll_to_bottom(&self) {
        let adjustment = self.scroller.vadjustment();
        // The new row has not been allocated yet, so the scroll has to wait for
        // the next layout pass.
        glib::idle_add_local_once(move || {
            adjustment.set_value(adjustment.upper() - adjustment.page_size());
        });
    }
}

// --- group management ---

fn group_members(view: &Rc<ChatView>) {
    let Conversation::Group { group_id, name } = &view.conversation else {
        return;
    };
    let Some(window) = view.app().window() else { return };

    let group_summary = view
        .app()
        .groups
        .borrow()
        .iter()
        .find(|group| group.group_id == *group_id)
        .cloned();
    let Some(summary) = group_summary else { return };

    let list = adw::PreferencesGroup::builder().title("Members").build();
    for identity in &summary.member_identity_ids {
        let row = adw::ActionRow::builder()
            .title(glib::markup_escape_text(&view.app().identity_name(identity)).as_str())
            .subtitle(util::short_fingerprint(identity).as_str())
            .build();
        if let Some(texture) = view
            .app()
            .identity_avatar(identity)
            .as_deref()
            .and_then(util::texture_from_hex)
        {
            let avatar = adw::Avatar::new(32, None, true);
            avatar.set_custom_image(Some(&texture));
            row.add_prefix(&avatar);
        }
        // Only the founder can remove people, and never themselves.
        if summary.is_founder && *identity != summary.founder_identity_id {
            let remove = gtk::Button::builder()
                .icon_name("list-remove-symbolic")
                .valign(gtk::Align::Center)
                .tooltip_text("Remove from group")
                .build();
            remove.add_css_class("flat");
            let view = view.clone();
            let group_id = group_id.clone();
            let identity = identity.clone();
            remove.connect_clicked(move |_| {
                let (group_id, identity, view) = (group_id.clone(), identity.clone(), view.clone());
                crate::app::run_in_background(
                    move || core::remove_from_group(&group_id, &identity),
                    move |removed| {
                        if removed {
                            view.app().toast("Member removed.");
                            view.app().refresh_caches();
                        } else {
                            view.app().toast("Could not remove that member.");
                        }
                    },
                );
            });
            row.add_suffix(&remove);
        }
        list.add(&row);
    }

    // The founder can re-send the current group state to every member — the
    // fix for a member whose group update never arrived. The core rejects it
    // for anyone but the founder, so the button only exists for the founder.
    let mut resend_row = None;
    if summary.is_founder {
        let resend = adw::ActionRow::builder()
            .title("Resend group to everyone")
            .subtitle("Sends the current group state to every member again.")
            .build();
        let resend_button = gtk::Button::builder()
            .label("Resend")
            .valign(gtk::Align::Center)
            .build();
        {
            let view = view.clone();
            let group_id = group_id.clone();
            resend_button.connect_clicked(move |_| {
                let (view, group_id) = (view.clone(), group_id.clone());
                // The core call takes the shared core lock — off the GTK
                // thread, so a slow poll round cannot stall the window.
                crate::app::run_in_background(
                    move || core::resend_group_to_all(&group_id),
                    move |result| match result {
                        Ok(()) => view.app().toast("Group state sent to everyone."),
                        Err(error) => view.app().toast(&error),
                    },
                );
            });
        }
        resend.add_suffix(&resend_button);
        resend_row = Some(resend);
    }

    let page = adw::PreferencesPage::new();
    page.add(&list);
    if let Some(resend) = resend_row {
        let actions = adw::PreferencesGroup::builder().title("Group").build();
        actions.add(&resend);
        page.add(&actions);
    }
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    toolbar.set_content(Some(&page));

    adw::Window::builder()
        .modal(true)
        .transient_for(&window)
        .title(name.as_str())
        .default_width(420)
        .default_height(480)
        .content(&toolbar)
        .build()
        .present();
}

fn group_invite(view: &Rc<ChatView>) {
    let Conversation::Group { group_id, .. } = &view.conversation else {
        return;
    };
    let Some(window) = view.app().window() else { return };

    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .build();
    list.add_css_class("boxed-list");

    let already: Vec<String> = view
        .app()
        .groups
        .borrow()
        .iter()
        .find(|group| group.group_id == *group_id)
        .map(|group| group.member_identity_ids.clone())
        .unwrap_or_default();
    let group_id = group_id.clone();
    let view = view.clone();
    let rows_list = list.clone();

    app::run_in_background(
        core::list_contacts,
        move |contacts| {
            for contact in contacts {
                if already.contains(&contact.identity_id) {
                    continue;
                }
                let row = adw::ActionRow::builder()
                    .title(glib::markup_escape_text(&contact.display_name).as_str())
                    .activatable(true)
                    .build();
                let view = view.clone();
                let group_id = group_id.clone();
                let identity = contact.identity_id.clone();
                row.connect_activated(move |row| {
                    let view = view.clone();
                    let group_id = group_id.clone();
                    let identity = identity.clone();
                    let row = row.clone();
                    // Sending the invitation takes the shared core lock — off
                    // the GTK thread, so a slow poll round cannot stall it.
                    crate::app::run_in_background(
                        move || core::invite_to_group(&group_id, &identity),
                        move |invited| {
                            if invited {
                                view.app().toast("Invitation sent.");
                                view.app().refresh_caches();
                                row.set_sensitive(false);
                            } else {
                                view.app().toast("Could not invite that contact.");
                            }
                        },
                    );
                });
                rows_list.append(&row);
            }
        },
    );

    let content = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .margin_top(12)
        .margin_bottom(12)
        .margin_start(12)
        .margin_end(12)
        .build();
    content.append(&list);

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    toolbar.set_content(Some(
        &gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .child(&content)
            .build(),
    ));

    adw::Window::builder()
        .modal(true)
        .transient_for(&window)
        .title("Invite to group")
        .default_width(400)
        .default_height(480)
        .content(&toolbar)
        .build()
        .present();
}

fn group_picture(view: &Rc<ChatView>) {
    let Conversation::Group { group_id, .. } = &view.conversation else {
        return;
    };
    let Some(window) = view.app().window() else { return };

    let dialog = gtk::FileDialog::builder().title("Choose a group picture").build();
    let view = view.clone();
    let group_id = group_id.clone();
    dialog.open(Some(&window), gio::Cancellable::NONE, move |result| {
        let Ok(file) = result else { return };
        let Some(path) = file.path() else { return };
        let source = path.to_string_lossy().to_string();
        let view = view.clone();
        let group_id = group_id.clone();
        app::run_in_background(
            move || match util::scaled_jpeg(&source, 720, 85) {
                Some(jpeg) => core::set_group_profile_picture(&group_id, Some(jpeg)),
                None => Err("That file is not an image Typeon can read.".to_string()),
            },
            move |result| match result {
                // Only the founder may set it; the core enforces that.
                Ok(()) => {
                    view.app().toast("Group picture updated.");
                    view.app().refresh_caches();
                }
                Err(error) => view.app().toast(&error),
            },
        );
    });
}

fn attachments_overview(view: &Rc<ChatView>) {
    let Some(window) = view.app().window() else { return };
    let conversation = view.conversation.clone();
    let window = window.clone();

    // The attachment listing is a core query — off the GTK thread, like every
    // core call here. The window itself is built when the rows come back.
    app::run_in_background(
        move || match &conversation {
            Conversation::Direct { fingerprint, .. } => core::list_attachments(fingerprint),
            Conversation::Group { group_id, .. } => core::list_group_attachments(group_id),
        },
        move |attachments| {
            let group = adw::PreferencesGroup::builder()
                .title("Files in this conversation")
                .build();
            if attachments.is_empty() {
                group.add(&adw::ActionRow::builder().title("Nothing shared yet").build());
            }
            for attachment in attachments {
                let subtitle = format!(
                    "{} · {} · {}",
                    util::human_size(attachment.total_size),
                    attachment.status,
                    util::format_list_time(attachment.created_at)
                );
                group.add(
                    &adw::ActionRow::builder()
                        .title(glib::markup_escape_text(&attachment.file_name).as_str())
                        .subtitle(subtitle.as_str())
                        .build(),
                );
            }

            let page = adw::PreferencesPage::new();
            page.add(&group);
            let toolbar = adw::ToolbarView::new();
            toolbar.add_top_bar(&adw::HeaderBar::new());
            toolbar.set_content(Some(&page));

            adw::Window::builder()
                .modal(true)
                .transient_for(&window)
                .title("Attachments")
                .default_width(480)
                .default_height(480)
                .content(&toolbar)
                .build()
                .present();
        },
    );
}

// --- small helpers ---

/// The in-chat search strip: an entry plus previous/next and a match counter.
///
/// It searches the bubbles already on screen rather than the archive, which is
/// what the Android chat does too — scrolling up loads more history and widens
/// the search with it. Searching the whole archive would mean a decrypt pass
/// over every stored row on every keystroke.
fn build_search_bar(view: &Rc<ChatView>) -> (gtk::Revealer, gtk::SearchEntry) {
    let entry = gtk::SearchEntry::builder()
        .placeholder_text("Search in this conversation")
        .hexpand(true)
        .build();

    let count = gtk::Label::new(None);
    count.add_css_class("dim-label");
    count.add_css_class("caption");

    let previous = gtk::Button::builder()
        .icon_name("go-up-symbolic")
        .tooltip_text("Previous match")
        .build();
    previous.add_css_class("flat");
    let next = gtk::Button::builder()
        .icon_name("go-down-symbolic")
        .tooltip_text("Next match")
        .build();
    next.add_css_class("flat");
    let close = gtk::Button::builder()
        .icon_name("window-close-symbolic")
        .tooltip_text("Close search")
        .build();
    close.add_css_class("flat");

    let row = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(6)
        .margin_top(6)
        .margin_bottom(6)
        .margin_start(12)
        .margin_end(12)
        .build();
    row.append(&entry);
    row.append(&count);
    row.append(&previous);
    row.append(&next);
    row.append(&close);

    let bar = gtk::Revealer::builder().reveal_child(false).child(&row).build();

    {
        let view = view.clone();
        let count = count.clone();
        entry.connect_search_changed(move |entry| {
            view.run_search(&entry.text(), &count);
        });
    }
    {
        let view = view.clone();
        let count = count.clone();
        next.connect_clicked(move |_| view.step_search(1, &count));
    }
    {
        let view = view.clone();
        let count = count.clone();
        previous.connect_clicked(move |_| view.step_search(-1, &count));
    }
    {
        let view = view.clone();
        let bar = bar.clone();
        let entry = entry.clone();
        close.connect_clicked(move |_| {
            entry.set_text("");
            view.clear_search_highlight();
            bar.set_reveal_child(false);
        });
    }

    (bar, entry)
}

/// The content box of a bubble. Its margins are the bubble's padding: CSS
/// `padding` on the styled node does not affect this box's size request (a
/// 14px-vs-40px change measured identically), whereas margins always do.
fn bubble_content() -> gtk::Box {
    gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(2)
        .margin_top(8)
        .margin_bottom(8)
        .margin_start(14)
        .margin_end(14)
        .build()
}

/// The text inside a bubble.
///
/// `max_width_chars` bounds the *natural* width so a long message wraps into a
/// readable column instead of stretching across a wide window; `WordChar` lets
/// an unbroken run of characters (a URL, or someone mashing the keyboard) break
/// mid-word rather than force the bubble wider than its parent.
fn bubble_text_label(text: &str) -> gtk::Label {
    gtk::Label::builder()
        .label(text)
        .xalign(0.0)
        .wrap(true)
        .wrap_mode(gtk::pango::WrapMode::WordChar)
        .max_width_chars(40)
        .build()
}

/// Places a bubble on its side of the conversation.
///
/// The bubble goes straight into the vertical message box, which allocates
/// every child the full width — so `halign` alone puts it on the correct side
/// and simultaneously gives the wrapping label an upper bound to wrap against.
///
/// Wrapping each bubble in a *horizontal* row first (the obvious thing, and
/// what this used to do) is what broke both alignment and wrapping: a
/// horizontal GtkBox packs its children sequentially from the start and
/// ignores their `halign`, so every bubble sat on the left and the label was
/// measured with no width limit at all.
fn place_bubble(column: &gtk::Box, mine: bool) -> (gtk::Overlay, gtk::Box) {
    let skin = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .build();
    skin.add_css_class("bubble");
    skin.add_css_class(if mine { "bubble-mine" } else { "bubble-theirs" });
    skin.append(column);

    let clamp = adw::Clamp::builder()
        .maximum_size(BUBBLE_MAX_WIDTH)
        // Start tightening at the same size, so the bubble simply stops
        // growing rather than easing towards the cap.
        .tightening_threshold(BUBBLE_MAX_WIDTH)
        .child(&skin)
        .halign(if mine {
            gtk::Align::End
        } else {
            gtk::Align::Start
        })
        .build();

    // Spec dışı, kullanıcı isteği (bkz. dosya başı "birleşen balonlar" notu):
    // her balon artık bir `Overlay` içinde — normalde boş, ana çocusunun
    // (Clamp) boyutunu/hizalamasını AYNEN korur, sıfır ekstra maliyet. Sadece
    // `mark_group_seam` sonradan (bu balonun bir SONRAKİ mesajla aynı grupta
    // olduğu anlaşıldığında) küçük bir çentik bindirebilsin diye burada.
    let overlay = gtk::Overlay::builder().child(&clamp).build();
    (overlay, skin)
}

/// Visual harness for bubble layout — see `TYPEON_UI_TEST=bubbles`. Exercises
/// the same `bubble_text_label`/`bubble_row` the real conversation uses, so
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

    // Spec dışı, hata ayıklama (kullanıcı: "linux hala olmamış" — ekran
    // görüntüsünde 5 art arda "mine" balonun HİÇBİRİ birleşmiyordu):
    // gerçek sohbet ekranını TIKLAYARAK gezmeden `mark_group_seam`/
    // `.continued-top`/`.continued-bottom` CSS'inin GERÇEKTEN render
    // olup olmadığını izole etmek için ilk beş örnek, kullanıcının
    // ekran görüntüsündeki AYNI kısa/art arda "mine" düzenini taklit
    // ediyor — gruplama mantığının kendisi (`insert_entry`) burada YOK,
    // sadece SONUCU (köşe sınıfları + çentik) elle uygulanıyor.
    let samples: [(bool, &str); 8] = [
        (true, "ya abi"),
        (true, "yalan ya"),
        (true, "dümen ya"),
        (true, "a slightly longer message"),
        (true, "noldu lan o kadar css mss dedin"),
        (false, "hi"),
        (
            false,
            "supercalifragilisticexpialidociousandthensomemoretomakeitreallyquitelong",
        ),
        (false, "ok"),
    ];

    let mut previous: Option<(bool, gtk::Box, i32)> = None;
    for (mine, sample) in samples {
        let column = bubble_content();
        column.append(&bubble_text_label(sample));

        let meta = gtk::Label::builder().label("23:50 ✓").xalign(1.0).build();
        meta.add_css_class("caption");
        meta.add_css_class("dim-label");
        column.append(&meta);

        let (overlay, skin) = place_bubble(&column, mine);
        let width = overlay.measure(gtk::Orientation::Horizontal, -1).1;

        let grouped = previous.as_ref().is_some_and(|(prev_mine, ..)| *prev_mine == mine);
        if grouped {
            skin.add_css_class("continued-top");
            overlay.add_css_class("bubble-row-continued");
        }
        if let Some((_, prev_skin, prev_width)) = &previous {
            if grouped {
                prev_skin.add_css_class("continued-bottom");
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
                    // Basitlik için burada HER ZAMAN mevcut satıra
                    // bindiriliyor (gerçek `mark_group_seam` iki geniş
                    // balondan hangisi ise ona koyar) — sadece CSS/render
                    // sorusunu izole etmek yeterli, geometri gerçek
                    // koddan (bkz. `mark_group_seam`) zaten ayrı test
                    // edildi.
                    overlay.add_overlay(&notch);
                }
            }
        }

        messages.append(&overlay);
        previous = Some((mine, skin, width));
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

fn display_text(entry: &Entry) -> String {
    if entry.deleted {
        "Message deleted".to_string()
    } else {
        entry.text.clone()
    }
}

fn meta_text(entry: &Entry, seen: bool) -> String {
    format_meta(entry.order_key, entry.status.as_deref(), seen, entry.edited)
}

/// Time plus a delivery tick, and — small, right beside the time, matching
/// Android's `txtEditedLabel` — an "edited" marker instead of the old inline
/// suffix on the message text itself. The ticks mean what the core can
/// actually promise: one tick is "handed to the network", two GREY ticks are
/// "the peer's device acknowledged it" (delivered), two plain ticks are "the
/// peer's app told us it displayed this" (seen).
///
/// The result is Pango markup (the meta label is set with `set_markup`), so a
/// tick can carry its own colour — the delivered one is grey, the seen one
/// keeps the label's own tone. Everything in here is generated by us (a
/// timestamp and fixed glyphs), so there is no user text to escape.
fn format_meta(timestamp: u64, status: Option<&str>, seen: bool, edited: bool) -> String {
    let time = util::format_bubble_time(timestamp);
    let tick = match (status, seen) {
        // Seen wins over delivered: it is the later, stronger promise.
        (_, true) => " ✓✓",
        (Some("pending"), _) => " ⏱",
        (Some("error"), _) => " ⚠",
        // The end-to-end Ack (the core's `delivered` status) — a double tick
        // in grey, so it does not read as the "seen" tick.
        (Some("delivered"), _) => "<span foreground=\"grey\"> ✓✓</span>",
        (Some("sent"), _) => " ✓",
        _ => "",
    };
    if edited {
        format!("edited · {}{}", time, tick)
    } else {
        format!("{}{}", time, tick)
    }
}

fn attachment_status_text(attachment: &Attachment) -> String {
    match attachment.status.as_str() {
        "offered" => util::human_size(attachment.total_size),
        "downloading" => format!(
            "{} of {}",
            util::human_size(attachment.bytes_done),
            util::human_size(attachment.total_size)
        ),
        "complete" => format!("{} · downloaded", util::human_size(attachment.total_size)),
        "failed" => "Failed".to_string(),
        other => other.to_string(),
    }
}

/// The label of an attachment's action button.
///
/// A download that already moved some bytes is RESUMED, not started over —
/// the core keeps `bytes_transferred` and continues from there (bkz.
/// `Attachment.bytes_done`), so the button says so.
fn action_label(status: &str, bytes_done: u64) -> String {
    match status {
        "complete" => "Open".to_string(),
        "failed" if bytes_done > 0 => "Resume".to_string(),
        "failed" => "Retry".to_string(),
        _ => "Download".to_string(),
    }
}

/// Redraws a voice player's slider/label/play-icon for its current status —
/// shared by the initial build and every later status change so they cannot
/// drift apart. Only handles the *static* pre-/post-playback presentation;
/// once a `GtkMediaFile` exists, its own notify signals (wired in
/// `ChatView::start_voice_playback`) own the slider and label instead.
fn render_voice_state(state: &AttachmentState) {
    let Some(voice) = &state.voice else { return };
    let status = state.status.borrow().clone();
    if status == "complete" {
        voice.slider.set_sensitive(true);
        // Slider unit is microseconds, like `GtkMediaFile` timestamps/seek.
        let duration = voice.duration_ms.get().max(1) as f64 * 1000.0;
        voice.slider.set_range(0.0, duration);
        voice.slider.set_value(0.0);
        voice.play_button.set_icon_name("media-playback-start-symbolic");
        voice.duration_label.set_label(&util::format_duration_ms(voice.duration_ms.get() as i64));
    } else {
        voice.slider.set_sensitive(false);
        voice.slider.set_range(0.0, state.total_size.max(1) as f64);
        voice.slider.set_value(if status == "downloading" {
            state.bytes_done.get() as f64
        } else {
            0.0
        });
        voice.play_button.set_icon_name("media-playback-start-symbolic");
        voice.duration_label.set_label(&match status.as_str() {
            "failed" => "Failed".to_string(),
            "downloading" => "Downloading…".to_string(),
            _ => {
                let ms = voice.duration_ms.get();
                if ms > 0 {
                    util::format_duration_ms(ms as i64)
                } else {
                    String::new()
                }
            }
        });
    }
}

fn day_separator(timestamp: u64) -> gtk::Widget {
    let label = gtk::Label::new(Some(&util::format_day_separator(timestamp)));
    label.add_css_class("caption");
    label.add_css_class("dim-label");
    // H128: `evict_oldest` identifies separators by class when it prunes the
    // ones left stranded by evicted bubbles (they are not tracked in
    // `order`, which only mirrors bubbles).
    label.add_css_class("day-separator");
    label.set_margin_top(8);
    label.set_halign(gtk::Align::Center);
    label.upcast()
}

fn nonzero_or(value: u64, fallback: u64) -> u64 {
    if value == 0 {
        fallback
    } else {
        value
    }
}

fn nonempty_or(value: Option<String>, fallback: String) -> String {
    value.filter(|s| !s.is_empty()).unwrap_or(fallback)
}

/// Shows a downloaded sticker: the core decrypts it (JPEG XL to PNG/GIF) off
/// the main thread.
fn load_sticker(state: &Rc<AttachmentState>) {
    let Some(picture) = state.sticker.clone() else { return };
    let file_id = state.file_id.clone();
    app::run_in_background(
        move || core::attachment_plaintext_path(&file_id),
        move |result| {
            if let Ok(path) = result {
                picture.set_filename(Some(&path));
            }
        },
    );
}
