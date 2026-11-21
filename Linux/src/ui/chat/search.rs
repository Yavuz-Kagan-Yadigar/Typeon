//! In-chat search bar and match navigation.

use super::*;

impl ChatView {
    /// Recomputes the match set and jumps to the newest hit.
    pub(super) fn run_search(self: &Rc<Self>, needle: &str, count: &gtk::Label) {
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
                    .or_insert_with(|| bubble.text.text().to_lowercase())
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
    pub(super) fn step_search(self: &Rc<Self>, delta: i32, count: &gtk::Label) {
        let total = self.search_matches.borrow().len();
        if total == 0 {
            return;
        }
        let current = self.search_index.get() as i64;
        let next = (current + delta as i64).rem_euclid(total as i64) as usize;
        self.search_index.set(next);
        self.focus_search_match(count);
    }

    pub(super) fn focus_search_match(self: &Rc<Self>, count: &gtk::Label) {
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
        self.scroll_into_view(&bubble.root);
    }

    /// A click on `widget` (a quote) jumps to message `target`.
    pub(super) fn click_to_scroll(self: &Rc<Self>, widget: &impl IsA<gtk::Widget>, target: String) {
        let click = gtk::GestureClick::new();
        let view = Rc::downgrade(self);
        click.connect_released(move |_, _, _, _| {
            if let Some(view) = view.upgrade() {
                view.scroll_to_message(&target);
            }
        });
        widget.add_controller(click);
        widget.set_cursor_from_name(Some("pointer"));
    }

    /// Scrolls to a quoted message and flashes it, like the phone.
    pub(super) fn scroll_to_message(&self, id: &str) {
        let bubbles = self.bubbles.borrow();
        let Some(bubble) = bubbles.get(id) else {
            self.app().toast("Original message isn't loaded. Scroll up to find it.");
            return;
        };
        let root = bubble.root.clone();
        root.add_css_class("bubble-match");
        self.follow_bottom.set(false);
        self.scroll_into_view(&root);
        glib::timeout_add_local_once(std::time::Duration::from_millis(1500), move || root.remove_css_class("bubble-match"));
    }

    fn scroll_into_view(&self, root: &gtk::Widget) {
        // Bounds are relative to the message box, so this has to wait for a
        // layout pass after any highlight reflow.
        let root = root.clone();
        let messages = self.messages.clone();
        let adjustment = self.scroller.vadjustment();
        glib::idle_add_local_once(move || {
            if let Some(bounds) = root.compute_bounds(&messages) {
                let target = bounds.y() as f64 - adjustment.page_size() / 3.0;
                adjustment.set_value(target.clamp(0.0, (adjustment.upper() - adjustment.page_size()).max(0.0)));
            }
        });
    }

    pub(super) fn clear_search_highlight(&self) {
        for bubble in self.bubbles.borrow().values() {
            bubble.root.remove_css_class("bubble-match");
        }
    }

}

// --- small helpers ---

/// The in-chat search strip: an entry plus previous/next and a match counter.
/// It searches the bubbles already on screen rather than the archive, which is
/// what the Android chat does too — scrolling up loads more history and widens
/// the search with it. Searching the whole archive would mean a decrypt pass
/// over every stored row on every keystroke.
pub(super) fn build_search_bar(view: &Rc<ChatView>) -> (gtk::Revealer, gtk::SearchEntry) {
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
