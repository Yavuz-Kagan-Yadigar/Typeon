//! Reactions: picker, sending, list dialog, applying summaries.

use super::*;

impl ChatView {
    pub(super) fn apply_reactions(&self, id: &str, summary: &str) {
        let bubbles = self.bubbles.borrow();
        let Some(bubble) = bubbles.get(id) else { return };
        bubble.reactions.set_label(summary);
        bubble.reactions.set_visible(!summary.is_empty());
        bubble.entry.borrow_mut().reactions = summary.to_string();
    }

    pub(super) fn pick_reaction(self: &Rc<Self>, anchor: &gtk::Box, entry: &Entry) {
        let chooser = gtk::EmojiChooser::new();
        chooser.set_parent(anchor);
        chooser.connect_closed(|chooser| chooser.unparent());
        let view = self.clone();
        let id = entry.id.clone();
        chooser.connect_emoji_picked(move |_, emoji| view.send_reaction(&id, emoji));
        chooser.popup();
    }

    /// `emoji` empty removes my reaction.
    pub(super) fn send_reaction(self: &Rc<Self>, id: &str, emoji: &str) {
        let (direct, target) = match &self.conversation {
            Conversation::Direct { fingerprint, .. } => (true, fingerprint.clone()),
            Conversation::Group { group_id, .. } => (false, group_id.clone()),
        };
        let (view, id, emoji) = (self.clone(), id.to_string(), emoji.to_string());
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
    }

    /// Who reacted with what; "Remove my reaction" when one is mine.
    pub(super) fn show_reactions(self: &Rc<Self>, entry: &Entry) {
        // Takes the core lock: read off the GTK thread.
        let (view, id) = (self.clone(), entry.id.clone());
        let message_id = id.clone();
        crate::app::run_in_background(
            move || core::list_reactions(&message_id),
            move |rows| view.show_reaction_rows(&id, rows),
        );
    }

    fn show_reaction_rows(self: &Rc<Self>, id: &str, rows: Vec<core::ReactionEntry>) {
        let body = rows
            .iter()
            .map(|r| {
                let who = if r.is_me { "You".to_string() } else { self.app().identity_name(&r.identity_id) };
                let who = if who.is_empty() { r.identity_id.chars().take(8).collect() } else { who };
                format!("{}  {}", r.emoji, who)
            })
            .collect::<Vec<_>>()
            .join("\n");
        let Some(window) = self.app().window() else { return };
        let dialog = adw::MessageDialog::new(Some(&window), Some("Reactions"), Some(if body.is_empty() { "No reactions" } else { body.as_str() }));
        dialog.add_response("close", "Close");
        if rows.iter().any(|r| r.is_me) {
            dialog.add_response("remove", "Remove my reaction");
            dialog.set_response_appearance("remove", adw::ResponseAppearance::Destructive);
        }
        dialog.set_close_response("close");
        let (view, id) = (self.clone(), id.to_string());
        dialog.connect_response(Some("remove"), move |_, _| view.send_reaction(&id, ""));
        dialog.present();
    }

}
