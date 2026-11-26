//! Message list: bubbles, grouping seams, shading, date pill, scrolling.

use super::*;

// --- rendering ---

impl ChatView {
    /// A live event without any id would key an empty-string bubble:
    /// two such messages then collide on `""` and the second silently
    /// overwrites the first's text in place. Mint a unique view-local key
    /// instead. It is not derivable again after a `reload()` (where the
    /// archive rebuilds bubbles under its own ids), but by then the core has
    /// stored the message anyway, so nothing is lost — the key only has to be
    /// unique for as long as this view lives.
    pub(super) fn fresh_local_id(&self) -> String {
        let serial = self.live_serial.get() + 1;
        self.live_serial.set(serial);
        format!("live:{serial}")
    }

    /// Inserts a bubble at its `order_key` position. Scanning from the end is
    /// right for the common case (a new message is the newest) and still
    /// correct for a message delayed in transit, which slots into the spot it
    /// was written in rather than the spot it arrived in.
    pub(super) fn insert_entry(self: &Rc<Self>, entry: Entry, scroll: bool) {
        // Live inserts include my own sends, which emit no event for the list.
        if scroll {
            self.main.refresh_chats();
        }
        if let Some(existing) = self.bubbles.borrow().get(&entry.id) {
            // Already on screen — a duplicate can legitimately arrive when a
            // reload races an event. Refresh in place instead of doubling it.
            let deleted = {
                let mut current = existing.entry.borrow_mut();
                let deleted = current.deleted || entry.deleted;
                let seen_by = if entry.seen_by.is_empty() { current.seen_by.clone() } else { entry.seen_by.clone() };
                let reactions = if entry.reactions.is_empty() { current.reactions.clone() } else { entry.reactions.clone() };
                *current = entry.clone();
                current.deleted = deleted;
                current.seen_by = seen_by;
                current.reactions = reactions;
                deleted
            };
            existing.text.set_markup(&display_text(&entry));
            self.search_lower.borrow_mut().clear();
            existing.edited.set(entry.edited);
            // Never downgrade: a stale archive row must not pull a bubble that
            // already got the end-to-end Ack back to "sent".
            let status = match (existing.status.borrow().as_deref(), entry.status.as_deref()) {
                (Some("delivered"), Some("sent" | "pending")) => Some("delivered".to_string()),
                _ => entry.status.clone(),
            };
            *existing.status.borrow_mut() = status.clone();
            existing.entry.borrow_mut().status = status.clone();
            existing.meta.set_markup(&format_meta(entry.order_key, status.as_deref(), entry.edited));
            // Shared borrows only, so these are safe under the lookup above.
            // A stale copy of a deleted message must not bring its text back.
            if deleted {
                self.apply_delete(&entry.id);
            }
            if !entry.reactions.is_empty() {
                self.apply_reactions(&entry.id, &entry.reactions);
            }
            return;
        }

                // The position a message will go to (and so which bubble counts as the one before it) must be known BEFORE
                // `build_bubble`, because the group state affects the bubble's OWN top corners. Only the PREVIOUS bubble is looked
                // at. If an out-of-order (late) message lands between, the group state of the bubble after it is not recomputed in
                // this pass (see the "cheap method" note at the top of `chat/mod.rs`). A rare edge case. The common case, appending at the
                // end, is handled exactly.
        let order = self.order.borrow();
        let position = order
            .iter()
            .rposition(|(key, _)| *key <= entry.order_key)
            .map(|index| index + 1)
            .unwrap_or(0);
        // The newest rows were trimmed off: the end of `order` is not the end
        // of the chat, so a row past it would sit after a gap. The reload on
        // reaching the bottom brings it in.
        if position == order.len() && self.trimmed_bottom.get() {
            // My own message: jump to the newest page so it shows. Scrolling
            // to the end lets the scroll handler reload; reload here only if
            // it did not.
            if entry.mine {
                drop(order);
                let adjustment = self.scroller.vadjustment();
                adjustment.set_value(adjustment.upper());
                if self.trimmed_bottom.get() {
                    self.reload();
                }
            }
            return;
        }
        let previous_bubble = if position > 0 {
            self.bubbles.borrow().get(&order[position - 1].1).cloned()
        } else {
            None
        };
        drop(order);

        let grouped_with_previous = previous_bubble.as_ref().is_some_and(|previous| {
            previous.mine == entry.mine
                // Own messages carry an empty sender in some paths (history
                // from the phone, sibling echoes) and the own identity id in
                // others: for "mine" the sender is the same person by
                // definition, so only other people's bubbles compare ids.
                && (entry.mine || previous.sender_identity == entry.sender_identity)
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
            // A live message at the bottom (sent or received) pops in; page
            // loads pass `scroll = false` and stay still. The class goes away
            // after the run so a later restyle cannot replay it.
            if scroll {
                let root = bubble.root.clone();
                root.add_css_class("msg-pop");
                if entry.mine {
                    root.add_css_class("msg-pop-mine");
                }
                glib::timeout_add_local_once(std::time::Duration::from_millis(300), move || {
                    root.remove_css_class("msg-pop");
                    root.remove_css_class("msg-pop-mine");
                });
            }
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
        // receipt for the whole visible history. Nobody looking (window
        // hidden, minimised, in the background, locked or idle): the receipt
        // waits for `flush_deferred_reads`.
        if !entry.mine
            && entry.attachment.is_none()
            && !entry.id.starts_with("legacy:")
            && self.seen_sent.borrow_mut().insert(entry.id.clone())
        {
            if self.is_watched() {
                self.send_seen(&entry);
            } else {
                self.seen_deferred.borrow_mut().push(entry.clone());
            }
        }

        self.schedule_shading();
        if scroll {
            // A live row may start a new day (after midnight, or a file sent
            // into an older day's slot).
            self.refresh_day_separators();
        }
        // Own messages always jump to the bottom. Others only follow when the
        // view is already there (`follow_bottom`), so reading history is not
        // interrupted.
        if scroll && entry.mine {
            self.scroll_to_bottom();
        }
    }

    /// Re-shades soon, once the rows have been laid out; many inserts in a row
    /// (a page load) collapse into one pass.
    pub(super) fn schedule_shading(self: &Rc<Self>) {
        if self.shade_pending.replace(true) {
            return;
        }
        let view = self.clone();
        glib::timeout_add_local_once(std::time::Duration::from_millis(60), move || {
            view.shade_pending.set(false);
            view.update_shading();
        });
    }

    /// Shows the day of the top visible message while the timeline scrolls,
    /// and fades it out 1.5 s after the last scroll. Hidden at the bottom, so
    /// opening a chat (a programmatic scroll to the end) does not flash it.
    pub(super) fn update_date_pill(self: &Rc<Self>) {
        let adjustment = self.scroller.vadjustment();
        if adjustment.upper() - adjustment.page_size() - adjustment.value() < 80.0 {
            self.date_pill.set_reveal_child(false);
            return;
        }
        // `order` is sorted top to bottom: the first bubble whose bottom is
        // below the top edge is the top visible one.
        // `try_borrow`: a scroll can fire while a bubble insert holds them.
        let (Ok(bubbles), Ok(order)) = (self.bubbles.try_borrow(), self.order.try_borrow()) else { return };
        let top_key = {
            order.iter().find_map(|(key, id)| {
                let bounds = bubbles.get(id)?.root.compute_bounds(&self.scroller)?;
                (bounds.y() + bounds.height() > 0.0).then_some(*key)
            })
        };
        drop((bubbles, order));
        let Some(key) = top_key else { return };
        self.date_pill_label.set_label(&util::format_day_separator(key));
        self.date_pill.set_reveal_child(true);
        if let Some(source) = self.date_pill_hide.take() {
            source.remove();
        }
        let view = Rc::downgrade(self);
        *self.date_pill_hide.borrow_mut() = Some(glib::timeout_add_local_once(
            std::time::Duration::from_millis(1500),
            move || {
                if let Some(view) = view.upgrade() {
                    view.date_pill_hide.take();
                    view.date_pill.set_reveal_child(false);
                }
            },
        ));
    }

    /// Screen-space shading: each bubble takes the shade step of its vertical
    /// position in the visible area (lighter at the top, darker at the bottom,
    /// like the phone), so the gradient runs across the screen, not across
    /// each message, and the background stays untouched.
    pub(super) fn update_shading(&self) {
        let height = self.scroller.height() as f32;
        if height <= 0.0 {
            return;
        }
        for bubble in self.bubbles.borrow().values() {
            let Some(bounds) = bubble.skin.compute_bounds(&self.scroller) else { continue };
            let mid = bounds.y() + bounds.height() / 2.0;
            if mid < -200.0 || mid > height + 200.0 {
                continue;
            }
            let step = ((mid / height).clamp(0.0, 1.0) * (SHADE_STEPS - 1) as f32).round() as i32;
            let old = bubble.shade.replace(step);
            if old == step {
                continue;
            }
            if old >= 0 {
                bubble.skin.remove_css_class(&format!("shade-{old}"));
            }
            bubble.skin.add_css_class(&format!("shade-{step}"));
            for (widget, colour) in bubble.fillets.borrow().iter() {
                if old >= 0 {
                    widget.remove_css_class(&format!("fshade-{colour}-{old}"));
                }
                widget.add_css_class(&format!("fshade-{colour}-{step}"));
            }
        }
    }

    pub(super) fn build_bubble(self: &Rc<Self>, entry: &Entry, continued_top: bool) -> Rc<Bubble> {
        let column = bubble_content();

        // In a group, who said it matters; in a 1:1 it is obvious.
        if self.is_group() && !entry.mine && !entry.sender_identity.is_empty() && !continued_top {
            let sender = gtk::Label::builder()
                .label(self.app().identity_name(&entry.sender_identity).as_str())
                .xalign(0.0)
                .build();
            sender.add_css_class("caption-heading");
            column.append(&sender);
        }
        if let Some(relayer) = entry.relayed_by.as_ref().filter(|_| self.is_group()) {
            let relayed = gtk::Label::builder()
                .label(tf!("Relayed by {} · unverified", self.app().identity_name(relayer)).as_str())
                .xalign(0.0)
                .build();
            relayed.add_css_class("caption");
            relayed.add_css_class("dim-label");
            column.append(&relayed);
        }

        // Disappearing: only the placeholder (see `display_text`), no quote, file or forwarded mark around it.
        let hidden = entry.expire.is_some();
        if let Some(preview) = entry.reply_preview.as_ref().filter(|_| !hidden) {
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
            if let Some(target) = entry.reply_id.clone() {
                self.click_to_scroll(&reply, target);
            }
            column.append(&reply);
        }

        // An inline (Android-style) quote at the start of the message is a
        // block of its own, like on the phone: darker rounded box over the text.
        let (forwarded, own_text) = util::split_forwarded(&entry.text);
        if forwarded && !entry.deleted && !hidden {
            let label = gtk::Label::builder().label(t("↪ Forwarded")).xalign(0.0).build();
            label.add_css_class("caption");
            label.add_css_class("dim-label");
            label.add_css_class("forwarded-label");
            column.append(&label);
        }
        if !entry.deleted && !hidden {
            if let (Some((target, preview)), _) = crate::util::split_leading_quote(own_text) {
                let quote = gtk::Label::builder()
                    .label(util::preview_text(&preview, 120).as_str())
                    .xalign(0.0)
                    .wrap(true)
                    .wrap_mode(gtk::pango::WrapMode::WordChar)
                    .max_width_chars(40)
                    .halign(gtk::Align::Start)
                    .build();
                quote.add_css_class("quote-block");
                self.click_to_scroll(&quote, target);
                column.append(&quote);
            }
        }

        let text = bubble_text_label(&display_text(entry));
        // Quotes further down the text are links (see `util::quote_markup`).
        {
            let view = Rc::downgrade(self);
            text.connect_activate_link(move |_, uri| {
                let Some(target) = uri.strip_prefix(crate::util::QUOTE_LINK) else { return glib::Propagation::Proceed };
                if let Some(view) = view.upgrade() {
                    view.scroll_to_message(target);
                }
                glib::Propagation::Stop
            });
        }
        if entry.deleted {
            text.add_css_class("dim-label");
        }

        let mut attachment_state = None;
        let mut attachment_widgets = None;
        if let Some(attachment) = entry.attachment.as_ref().filter(|_| !hidden) {
            let (widgets, state) = self.build_attachment(attachment);
            // An attachment message freshly loaded from the archive is never
            // itself the deleted one — a deletion purges its `files` row
            // outright, so it would not be here to load in the first place.
            // `text` still goes in so a *live* delete arriving later has a
            // "Message deleted" placeholder ready to swap to; it shows the
            // caption, hidden when there is none.
            text.set_visible(!own_text.is_empty());
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
        meta.set_markup(&meta_text(entry));
        column.append(&meta);
        // Disappearing: time left in accent bold, under the time.
        let expire_label = expire_label(entry);
        if let Some(label) = &expire_label {
            column.append(label);
        }

        // Filled by `show_seen_by`; a click lists who saw it and when.
        let seen_row = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(2)
            .halign(gtk::Align::End)
            .visible(false)
            .build();
        seen_row.set_cursor_from_name(Some("pointer"));
        {
            let click = gtk::GestureClick::new();
            let view = Rc::downgrade(self);
            let id = entry.id.clone();
            click.connect_released(move |_, _, _, _| {
                if let Some(view) = view.upgrade() {
                    view.show_seen_list(&id);
                }
            });
            seen_row.add_controller(click);
        }
        column.append(&seen_row);

        let reactions = gtk::Label::builder()
            .label(entry.reactions.as_str())
            .xalign(if entry.mine { 1.0 } else { 0.0 })
            .visible(!entry.reactions.is_empty())
            .build();
        reactions.add_css_class("caption");
        column.append(&reactions);

        let (overlay, skin) = place_bubble(&column, entry.mine);
        if !hidden && entry.attachment.as_ref().is_some_and(|a| a.sticker) {
            skin.remove_css_class("bubble");
            skin.remove_css_class(if entry.mine { "bubble-mine" } else { "bubble-theirs" });
        }
        if expire_label.is_some() {
            skin.add_css_class("disappear");
            self.start_disappear_tick();
        }
        // `continued_top` (this bubble joins the previous one's run, see `insert_entry`) leaves the 6 px top margin off.
        // Corner shapes come from the `sq-*`/`rd-*` classes that `mark_group_seam` adds later.
        if !continued_top {
            overlay.set_margin_top(6);
        }
        // Measured on the overlay, so the Clamp's upper limit is already applied (not the raw `skin`).
        let content_width = overlay.measure(gtk::Orientation::Horizontal, -1).1;
        let root: gtk::Widget = overlay.clone().upcast();

        // Right-click for reply / edit / delete / copy. The menu is built from
        // the bubble's current entry (edits, deletes, reactions that arrived
        // live), not the one it was built from. Weak and looked up by id: the
        // controller lives on the bubble, a strong capture would be a cycle.
        let gesture = gtk::GestureClick::new();
        gesture.set_button(3);
        {
            let view = Rc::downgrade(self);
            let id = entry.id.clone();
            gesture.connect_pressed(move |gesture, _, x, y| {
                let Some(view) = view.upgrade() else { return };
                let Some(anchor) = gesture.widget().and_downcast::<gtk::Box>() else { return };
                let current = view.bubbles.borrow().get(&id).map(|bubble| bubble.entry.borrow().clone());
                if let Some(entry) = current {
                    view.bubble_menu(&anchor, &entry, x, y);
                }
            });
        }
        column.add_controller(gesture);

        // Double click: quick-reaction bar. Capture phase and never claimed, so a selectable label still gets the clicks.
        if !entry.deleted && entry.attachment.is_none() && !entry.id.starts_with("legacy:") {
            let double = gtk::GestureClick::new();
            double.set_propagation_phase(gtk::PropagationPhase::Capture);
            let view = Rc::downgrade(self);
            let id = entry.id.clone();
            double.connect_pressed(move |gesture, n_press, _, _| {
                if n_press != 2 {
                    return;
                }
                let Some(view) = view.upgrade() else { return };
                let Some(anchor) = gesture.widget().and_downcast::<gtk::Box>() else { return };
                let current = view.bubbles.borrow().get(&id).map(|bubble| bubble.entry.borrow().clone());
                if let Some(entry) = current.filter(|entry| !entry.deleted) {
                    view.quick_reactions(&anchor, &entry);
                }
            });
            column.add_controller(double);
        }

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
            seen_row,
            shade: Cell::new(-1),
            fillets: RefCell::new(Vec::new()),
            reactions,
            status: RefCell::new(entry.status.clone()),
            edited: Cell::new(entry.edited),
            expire_label,
            entry: RefCell::new(entry.clone()),
        })
    }

    /// `current` just joined `previous`'s run. The join is drawn like the phone version: the edge both bubbles are aligned to
    /// stays straight (square corners). Where their widths differ, the wider bubble keeps its outer (convex) corner, while the
    /// narrower one's corner becomes square, with a concave fillet filling the inside corner between them. The widths are read
    /// from the real allocation once the rows have been laid out (a measure at build time is off by several pixels).
    pub(super) fn mark_group_seam(&self, previous: &Rc<Bubble>, current: &Rc<Bubble>) {
        // Time and ticks only on the last bubble of a run, like the phone.
        previous.meta.set_visible(false);

        // `s` is the aligned (shared) side, `o` the open one.
        let (s, o) = if current.mine { ("r", "l") } else { ("l", "r") };
        previous.skin.add_css_class(&format!("sq-b{s}"));
        current.skin.add_css_class(&format!("sq-t{s}"));

        let (previous, current) = (previous.clone(), current.clone());
        let tries = Cell::new(0u32);
        glib::timeout_add_local(std::time::Duration::from_millis(40), move || {
            let (wa, wb) = (previous.skin.width(), current.skin.width());
            if wa == 0 || wb == 0 {
                tries.set(tries.get() + 1);
                return if tries.get() < 50 { glib::ControlFlow::Continue } else { glib::ControlFlow::Break };
            }
            if (wa - wb).abs() < SEAM_NOTCH_MIN_DELTA {
                // Same width: the open side is only slightly rounded.
                previous.skin.add_css_class(&format!("seam-b{o}"));
                current.skin.add_css_class(&format!("seam-t{o}"));
                return glib::ControlFlow::Break;
            }
            let colour: &'static str = if current.mine { "mine" } else { "theirs" };
            // Fillet and the wider bubble's outer corner share one radius and
            // sit side by side along the step, so both together must fit in
            // the step (2r <= delta) and in the narrow bubble's height.
            let narrow_height = if wa > wb { current.skin.height() } else { previous.skin.height() };
            let r = seam_radius((wa - wb).abs(), narrow_height);
            let (host, narrow, valign, corner) = if wa > wb {
                // Upper is wider: the lower one's open top corner is square.
                current.skin.add_css_class(&format!("sq-t{o}"));
                previous.skin.add_css_class(&format!("rd-b{o}-{r}"));
                (&current, &current, gtk::Align::Start, if current.mine { "bl" } else { "br" })
            } else {
                // Lower is wider: the upper one's open bottom corner is square.
                previous.skin.add_css_class(&format!("sq-b{o}"));
                current.skin.add_css_class(&format!("rd-t{o}-{r}"));
                (&previous, &previous, gtk::Align::End, if current.mine { "tl" } else { "tr" })
            };
            let Some(bounds) = narrow.skin.compute_bounds(&host.overlay) else {
                return glib::ControlFlow::Break;
            };
            let widget = gtk::Box::builder()
                .width_request(r)
                .height_request(r)
                .valign(valign)
                .halign(if current.mine { gtk::Align::End } else { gtk::Align::Start })
                .can_target(false)
                .build();
            widget.add_css_class(&format!("fillet-{corner}-{r}"));
            // Colour follows the host bubble's shade (see `update_shading`).
            let step = if host.shade.get() >= 0 { host.shade.get() } else { SHADE_STEPS / 2 };
            widget.add_css_class(&format!("fshade-{colour}-{step}"));
            host.fillets.borrow_mut().push((widget.clone(), colour));
            if current.mine {
                widget.set_margin_end((host.overlay.width() as f32 - bounds.x()).round().max(0.0) as i32);
            } else {
                widget.set_margin_start((bounds.x() + bounds.width()).round().max(0.0) as i32);
            }
            host.overlay.add_overlay(&widget);
            glib::ControlFlow::Break
        });
    }

}

impl ChatView {
    pub(super) fn scroll_to_bottom(&self) {
        // The new row is not allocated yet; `follow_bottom` makes the
        // adjustment's `changed` handler finish the scroll after layout.
        let adjustment = self.scroller.vadjustment();
        adjustment.set_value(adjustment.upper() - adjustment.page_size());
        self.follow_bottom.set(true);
    }
}

/// The content box of a bubble. Its margins are the bubble's padding: CSS
/// `padding` on the styled node does not change this box's size request,
/// whereas margins do.
pub(super) fn bubble_content() -> gtk::Box {
    gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(2)
        .margin_top(5)
        .margin_bottom(5)
        .margin_start(11)
        .margin_end(11)
        .build()
}

/// The text inside a bubble.
/// `max_width_chars` bounds the *natural* width so a long message wraps into a
/// readable column instead of stretching across a wide window; `WordChar` lets
/// an unbroken run of characters (a URL, or someone mashing the keyboard) break
/// mid-word rather than force the bubble wider than its parent.
pub(super) fn bubble_text_label(text: &str) -> gtk::Label {
    // `text` is Pango markup (see `util::quote_markup`); callers escape.
    gtk::Label::builder()
        .use_markup(true)
        .label(text)
        .xalign(0.0)
        .wrap(true)
        .wrap_mode(gtk::pango::WrapMode::WordChar)
        .max_width_chars(40)
        .build()
}

/// Places a bubble on its side of the conversation.
/// The bubble goes straight into the vertical message box, which allocates
/// every child the full width — so `halign` alone puts it on the correct side
/// and simultaneously gives the wrapping label an upper bound to wrap against.
/// Do not wrap a bubble in a horizontal row: a horizontal GtkBox packs its
/// children from the start and ignores their `halign`, and the label is then
/// measured with no width limit.
pub(super) fn place_bubble(column: &gtk::Box, mine: bool) -> (gtk::Overlay, gtk::Box) {
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

        // Each bubble is now inside an `Overlay`. It is normally empty and keeps the child's (Clamp) size and alignment exactly, at
        // no extra cost. It is here so that `mark_group_seam` can later add a small notch to this bubble, when it is found to be in
        // the same group as a NEXT message.
    let overlay = gtk::Overlay::builder().child(&clamp).build();
    (overlay, skin)
}

/// Radius (even px, 2..=`SEAM_RADIUS_MAX`) for a width step of `delta` px next
/// to a bubble `height` px tall. Sizes match the generated classes in theme.rs.
pub(super) fn seam_radius(delta: i32, height: i32) -> i32 {
    let r = (delta / 2).min(height / 3).min(SEAM_RADIUS_MAX);
    (r / 2 * 2).max(2)
}

/// A disappearing message is never shown on the desktop, which has no FLAG_SECURE equivalent. The phone shows it; the desktop shows only this placeholder.

pub(super) fn display_text(entry: &Entry) -> String {
    if entry.deleted {
        glib::markup_escape_text(t("Message deleted")).to_string()
    } else if entry.expire.is_some() {
        format!("<i>{}</i>", glib::markup_escape_text(t("Disappearing message, view on primary device")))
    } else {
        let text = crate::util::split_forwarded(&entry.text).1;
        crate::util::quote_markup(crate::util::split_leading_quote(text).1)
    }
}

pub(super) fn meta_text(entry: &Entry) -> String {
    format_meta(entry.order_key, entry.status.as_deref(), entry.edited)
}

/// Time, an "edited" marker beside it (like Android's `txtEditedLabel`), and a mark only for a message that is not out yet
/// or failed, as on the phone: a sent message shows nothing, its read state is the seen-by avatars (`show_seen_by`).
/// Pango markup (the meta label uses `set_markup`); everything here is generated by us, so nothing needs escaping.
pub(super) fn format_meta(timestamp: u64, status: Option<&str>, edited: bool) -> String {
    let time = util::format_bubble_time(timestamp);
    let tick = match status {
        Some("pending") => " ⏱",
        Some("error") => " ⚠",
        _ => "",
    };
    if edited {
        glib::markup_escape_text(&tf!("edited · {}{}", time, tick)).to_string()
    } else {
        format!("{}{}", time, tick)
    }
}

pub(super) fn day_separator(timestamp: u64) -> gtk::Widget {
    let label = gtk::Label::new(Some(&util::format_day_separator(timestamp)));
    label.add_css_class("caption");
    label.add_css_class("dim-label");
    // `trim_newest` identifies separators by class when it prunes the
    // ones left stranded by evicted bubbles (they are not tracked in
    // `order`, which only mirrors bubbles).
    label.add_css_class("day-separator");
    label.set_margin_top(12);
    label.set_halign(gtk::Align::Center);
    label.upcast()
}

pub(super) fn nonzero_or(value: u64, fallback: u64) -> u64 {
    if value == 0 {
        fallback
    } else {
        value
    }
}

pub(super) fn nonempty_or(value: Option<String>, fallback: String) -> String {
    value.filter(|s| !s.is_empty()).unwrap_or(fallback)
}
