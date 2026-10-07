//! Small shared widget builders.

use adw::prelude::*;

/// One row of a popover menu, styled to Material 3's menu metrics: a leading
/// icon, a left-aligned label and a 46px pill-shaped hit area.
///
/// The menus here are boxes of buttons rather than `GtkPopoverMenu` + `GMenu`
/// because every item is a plain closure — going through `GAction` would mean
/// registering and naming an action for each one, with nothing gained.
pub fn menu_item(icon_name: &str, label: &str) -> gtk::Button {
    let icon = gtk::Image::from_icon_name(icon_name);
    let text = gtk::Label::builder().label(label).xalign(0.0).hexpand(true).build();

    let content = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(12)
        .build();
    content.append(&icon);
    content.append(&text);

    let button = gtk::Button::builder().child(&content).build();
    button.add_css_class("flat");
    button
}

/// A popover holding `.m3-menu`-styled items, ready for `menu_item` children.
pub fn menu_popover() -> (gtk::Popover, gtk::Box) {
    let items = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(2)
        .build();
    items.add_css_class("m3-menu");
    let popover = gtk::Popover::builder().child(&items).build();
    // The default arrow is a small unstyled triangular nub the stylesheet's
    // rounded `popover > contents` card (see theme.rs) does not reach — it
    // read as a stray rectangle wedged between the menu button and the card.
    popover.set_has_arrow(false);
    (popover, items)
}

/// Wraps a widget for use as an `AdwMessageDialog` extra child.
///
/// A dialog drops its extra child straight against the body text and the
/// response buttons with no spacing of its own, which leaves an entry visually
/// jammed between the two — more so here, where the M3 sheet makes entries
/// tall and fully rounded.
pub fn dialog_field(child: &impl IsA<gtk::Widget>) -> gtk::Box {
    let holder = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(10)
        .margin_top(16)
        .margin_bottom(12)
        .margin_start(12)
        .margin_end(12)
        .build();
    holder.append(child);
    holder
}
