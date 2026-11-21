//! The shared whiteboard of one chat — the Android `WhiteboardPanel` +
//! `WhiteboardView` pair. All board state lives in the core (`whiteboard.rs`
//! there); this panel draws what the core has and hands it strokes and erases.
//! Nothing polls: other people's changes arrive as `"whiteboard"` events.
//!
//! Strokes live on the core's 1600x1000 virtual canvas; the view only scales
//! them, so every device shows the same picture.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::{Rc, Weak};
use std::time::Duration;

use adw::prelude::*;
use gtk::glib;

use crate::app::{run_in_background, App, Event};
use crate::core;

const WIDTH: f64 = 1600.0;
const HEIGHT: f64 = 1000.0;
const DEFAULT_PEN_WIDTH: u8 = 5;
const MAX_PEN_WIDTH: u8 = 40;
const MAX_PAGES: u32 = 20;
const MAX_UNDO: usize = 50;
/// Minimum distance between two stored points, in board units.
const MIN_STEP: f64 = 3.0;
const ERASER_RADIUS: f64 = 18.0;
/// Just past the core's 800 ms burst debounce and its 5 s digest delay.
const TICK_OPS_MS: u64 = 900;
const TICK_DIGEST_MS: u64 = 6_000;

#[derive(Clone)]
struct Stroke {
    /// Empty until the core has stored the stroke.
    id: Vec<u8>,
    shade: u8,
    author: u8,
    width: u8,
    points: Vec<(f64, f64)>,
}

/// One undoable step: strokes that are either on the board (`live`, with their
/// current `ids`) or erased. Undo and redo both just flip it.
struct Step {
    page: u8,
    strokes: Vec<Stroke>,
    ids: Vec<u8>,
    live: bool,
}

struct State {
    strokes: Vec<Stroke>,
    /// Drawn here, not echoed back by the core yet.
    pending: Vec<Stroke>,
    /// pending strokes erased while their add is still in flight,
    /// tagged with the page they were drawn on (a same-shaped stroke on a
    /// different page must not inherit this erase). The core does not know
    /// them yet — they cannot be erased by id until the add is acked, and
    /// `add_stroke`'s callback then finishes the job (and must not resurrect
    /// the stroke on screen meanwhile).
    erased_pending: Vec<(u8, Stroke)>,
    current: Vec<(f64, f64)>,
    drag_origin: (f64, f64),
    shade: u8,
    pen_width: u8,
    erasing: bool,
    page: u8,
    page_count: u32,
    unread: u32,
    me: usize,
    names: Vec<String>,
    undo: VecDeque<Step>,
    redo: VecDeque<Step>,
}

struct Inner {
    app: Rc<App>,
    peer: String,
    group_id: String,
    state: RefCell<State>,
    root: gtk::Revealer,
    /// The board lives in its own window; `root` is its content.
    window: gtk::Window,
    area: gtk::DrawingArea,
    legend: gtk::Label,
    page_label: gtk::Label,
    toggle: gtk::ToggleButton,
    pen: gtk::ToggleButton,
    eraser: gtk::ToggleButton,
    swatches: Vec<gtk::ToggleButton>,
    undo_button: gtk::Button,
    redo_button: gtk::Button,
    /// Bumped on every tick request so only the newest pair of timers fires.
    ticks: Cell<u64>,
}

pub struct Board {
    inner: Rc<Inner>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.window.destroy();
        // Whatever is still queued goes out before the chat is gone.
        std::thread::spawn(core::whiteboard_tick);
    }
}

/// Everyone gets one hue at equal angles round the wheel; the three shades of
/// a person share it. `author` out of range = no longer a participant (grey).
fn color_of(author: usize, participants: usize, shade: u8) -> (f64, f64, f64) {
    let lightness = match shade {
        0 => 0.75,
        2 => 0.35,
        _ => 0.55,
    };
    if author >= participants {
        return (lightness, lightness, lightness);
    }
    hsl(360.0 * author as f64 / participants as f64, 0.9, lightness)
}

fn hsl(h: f64, s: f64, l: f64) -> (f64, f64, f64) {
    let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
    let x = c * (1.0 - ((h / 60.0) % 2.0 - 1.0).abs());
    let m = l - c / 2.0;
    let (r, g, b) = match (h / 60.0) as u32 {
        0 => (c, x, 0.0),
        1 => (x, c, 0.0),
        2 => (0.0, c, x),
        3 => (0.0, x, c),
        4 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    (r + m, g + m, b + m)
}

fn css_hex((r, g, b): (f64, f64, f64)) -> String {
    format!("#{:02x}{:02x}{:02x}", (r * 255.0) as u8, (g * 255.0) as u8, (b * 255.0) as u8)
}

/// id(8) shade(1) author(1) width(1) count(u16 LE) points(u16 LE x,y).
fn parse_page(blob: &[u8]) -> Vec<Stroke> {
    let mut out = Vec::new();
    let mut at = 0;
    while blob.len() - at >= 13 {
        let id = blob[at..at + 8].to_vec();
        let (shade, author, width) = (blob[at + 8], blob[at + 9], blob[at + 10]);
        let count = u16::from_le_bytes([blob[at + 11], blob[at + 12]]) as usize;
        at += 13;
        if count == 0 || blob.len() - at < count * 4 {
            break;
        }
        let points = (0..count)
            .map(|i| {
                let p = at + i * 4;
                (
                    u16::from_le_bytes([blob[p], blob[p + 1]]) as f64,
                    u16::from_le_bytes([blob[p + 2], blob[p + 3]]) as f64,
                )
            })
            .collect();
        at += count * 4;
        out.push(Stroke { id, shade, author, width, points });
    }
    out
}

fn point_bytes(stroke: &Stroke) -> Vec<u8> {
    stroke
        .points
        .iter()
        .flat_map(|(x, y)| [(*x as u16).to_le_bytes(), (*y as u16).to_le_bytes()].concat())
        .collect()
}

fn segment_distance(p: (f64, f64), a: (f64, f64), b: (f64, f64)) -> f64 {
    let (dx, dy) = (b.0 - a.0, b.1 - a.1);
    let len2 = dx * dx + dy * dy;
    let t = if len2 == 0.0 { 0.0 } else { (((p.0 - a.0) * dx + (p.1 - a.1) * dy) / len2).clamp(0.0, 1.0) };
    ((p.0 - (a.0 + t * dx)).powi(2) + (p.1 - (a.1 + t * dy)).powi(2)).sqrt()
}

fn near(stroke: &Stroke, p: (f64, f64)) -> bool {
    let pts = &stroke.points;
    (0..pts.len()).any(|i| {
        let (a, b) = (pts[i], pts[(i + 1).min(pts.len() - 1)]);
        // Cheap bounding-box reject before the exact distance.
        let r = ERASER_RADIUS;
        if p.0 < a.0.min(b.0) - r || p.0 > a.0.max(b.0) + r || p.1 < a.1.min(b.1) - r || p.1 > a.1.max(b.1) + r {
            return false;
        }
        segment_distance(p, a, b) < r
    })
}

/// Strokes, one `cairo` path each, in board units (the caller scales).
fn paint_strokes(cr: &gtk::cairo::Context, strokes: &[&Stroke], participants: usize) {
    cr.set_line_cap(gtk::cairo::LineCap::Round);
    cr.set_line_join(gtk::cairo::LineJoin::Round);
    for s in strokes {
        let (r, g, b) = color_of(s.author as usize, participants, s.shade);
        cr.set_source_rgb(r, g, b);
        cr.set_line_width(if s.width == 0 { DEFAULT_PEN_WIDTH } else { s.width } as f64);
        let Some(first) = s.points.first() else { continue };
        cr.move_to(first.0, first.1);
        for p in &s.points[1..] {
            cr.line_to(p.0, p.1);
        }
        // A dot: a zero-length line still draws with a round cap.
        if s.points.len() == 1 {
            cr.line_to(first.0, first.1);
        }
        let _ = cr.stroke();
    }
}

/// Fit the board letterboxed in `w` x `h`: (scale, offset x, offset y).
fn layout(w: f64, h: f64) -> (f64, f64, f64) {
    let scale = (w / WIDTH).min(h / HEIGHT).max(0.0001);
    (scale, (w - WIDTH * scale) / 2.0, (h - HEIGHT * scale) / 2.0)
}

impl Board {
    pub fn new(app: &Rc<App>, peer: &str, group_id: &str) -> Self {
        let area = gtk::DrawingArea::builder().hexpand(true).content_height(320).build();
        area.add_css_class("card");
        let legend = gtk::Label::builder().xalign(0.0).wrap(true).use_markup(true).build();
        legend.add_css_class("caption");
        let page_label = gtk::Label::new(Some("1/1"));
        page_label.set_width_chars(6);

        let toggle = gtk::ToggleButton::builder()
            .icon_name("document-edit-symbolic")
            .tooltip_text("Whiteboard")
            .build();
        let pen = gtk::ToggleButton::builder().icon_name("document-edit-symbolic").tooltip_text("Pen").active(true).build();
        let eraser = gtk::ToggleButton::builder().icon_name("edit-clear-symbolic").tooltip_text("Eraser").build();
        eraser.set_group(Some(&pen));
        let mut swatches: Vec<gtk::ToggleButton> = Vec::new();
        for _ in 0..3 {
            let swatch = gtk::ToggleButton::builder().label("⬤").tooltip_text("Colour").build();
            if let Some(first) = swatches.first() {
                swatch.set_group(Some(first));
            }
            swatches.push(swatch);
        }
        swatches[1].set_active(true);
        let undo_button = gtk::Button::builder().icon_name("edit-undo-symbolic").tooltip_text("Undo").sensitive(false).build();
        let redo_button = gtk::Button::builder().icon_name("edit-redo-symbolic").tooltip_text("Redo").sensitive(false).build();
        let root = gtk::Revealer::builder()
            .transition_type(gtk::RevealerTransitionType::SlideDown)
            .reveal_child(false)
            .build();

        let window = gtk::Window::builder().title("Whiteboard").default_width(960).default_height(720).build();
        window.set_application(Some(&app.application));
        window.set_child(Some(&root));
        let inner = Rc::new(Inner {
            app: app.clone(),
            peer: peer.to_string(),
            group_id: group_id.to_string(),
            state: RefCell::new(State {
                strokes: Vec::new(),
                pending: Vec::new(),
                erased_pending: Vec::new(),
                current: Vec::new(),
                drag_origin: (0.0, 0.0),
                shade: 1,
                pen_width: DEFAULT_PEN_WIDTH,
                erasing: false,
                page: 0,
                page_count: 1,
                unread: 0,
                me: 0,
                names: Vec::new(),
                undo: VecDeque::new(),
                redo: VecDeque::new(),
            }),
            root,
            window,
            area,
            legend,
            page_label,
            toggle,
            pen,
            eraser,
            swatches,
            undo_button,
            redo_button,
            ticks: Cell::new(0),
        });
        inner.build_layout();
        inner.wire();
        inner.refresh_info();
        Board { inner }
    }

    pub fn toggle_button(&self) -> &gtk::ToggleButton {
        &self.inner.toggle
    }

    pub fn handle_event(&self, event: &Event) {
        if event.kind != "whiteboard" {
            return;
        }
        let me = &self.inner;
        let mine = if me.group_id.is_empty() {
            event.optional("group_id").is_none() && event.string("peer") == me.peer
        } else {
            event.optional("group_id").as_deref() == Some(me.group_id.as_str())
        };
        if !mine {
            return;
        }
        let mut changed_here = false;
        {
            let mut st = me.state.borrow_mut();
            if let Some(pages) = event.value.get("pages").and_then(|v| v.as_array()) {
                for p in pages.iter().filter_map(|p| p.as_u64()) {
                    // a remote (or core-bumped) page count past the UI
                    // cap must not grow `page_count` beyond it — the pager
                    // (and `1u32 << page` below) would go out of range.
                    let reached = u32::try_from(p).unwrap_or(0) + 1;
                    st.page_count = st.page_count.max(reached.min(MAX_PAGES));
                    changed_here |= p == st.page as u64;
                }
            }
            st.unread = event.number("unread") as u32;
        }
        me.update_unread();
        if me.root.reveals_child() && changed_here {
            me.load_page();
        } else {
            me.update_page_label();
        }
    }
}

impl Inner {
    fn build_layout(self: &Rc<Self>) {
        let column = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(6)
            .margin_top(6)
            .margin_bottom(6)
            .margin_start(12)
            .margin_end(12)
            .build();
        column.append(&self.legend);
        column.append(&self.area);

        let pages = gtk::Box::builder().orientation(gtk::Orientation::Horizontal).spacing(6).build();
        let prev = gtk::Button::builder().icon_name("go-previous-symbolic").tooltip_text("Previous page").build();
        let next = gtk::Button::builder().icon_name("go-next-symbolic").tooltip_text("Next page").build();
        let size = gtk::Scale::with_range(gtk::Orientation::Horizontal, 1.0, MAX_PEN_WIDTH as f64, 1.0);
        size.set_value(DEFAULT_PEN_WIDTH as f64);
        size.set_draw_value(false);
        size.set_hexpand(true);
        size.set_tooltip_text(Some("Pen size"));
        let pdf = gtk::Button::builder().label("PDF").tooltip_text("Save this page as PDF").build();
        pages.append(&prev);
        pages.append(&self.page_label);
        pages.append(&next);
        pages.append(&size);
        pages.append(&pdf);
        column.append(&pages);

        let tools = gtk::Box::builder().orientation(gtk::Orientation::Horizontal).spacing(6).build();
        tools.append(&self.pen);
        tools.append(&self.eraser);
        for swatch in &self.swatches {
            tools.append(swatch);
        }
        tools.append(&gtk::Box::builder().hexpand(true).build());
        tools.append(&self.undo_button);
        tools.append(&self.redo_button);
        column.append(&tools);
        self.root.set_child(Some(&column));

        for (button, delta) in [(&prev, -1), (&next, 1)] {
            let weak = Rc::downgrade(self);
            button.connect_clicked(move |_| {
                if let Some(me) = weak.upgrade() {
                    let target = me.state.borrow().page as i32 + delta;
                    me.go_to_page(target);
                }
            });
        }
        {
            let weak = Rc::downgrade(self);
            size.connect_value_changed(move |scale| {
                if let Some(me) = weak.upgrade() {
                    me.state.borrow_mut().pen_width = scale.value() as u8;
                }
            });
        }
        {
            let weak = Rc::downgrade(self);
            pdf.connect_clicked(move |button| {
                if let Some(me) = weak.upgrade() {
                    me.export_pdf(button);
                }
            });
        }
    }

    fn wire(self: &Rc<Self>) {
        let weak = Rc::downgrade(self);

        // Header toggle.
        {
            let weak = weak.clone();
            self.toggle.connect_toggled(move |button| {
                let Some(me) = weak.upgrade() else { return };
                me.root.set_reveal_child(button.is_active());
                if !button.is_active() {
                    me.window.set_visible(false);
                } else {
                    me.window.present();
                    let (peer, gid) = (me.peer.clone(), me.group_id.clone());
                    std::thread::spawn(move || core::whiteboard_open(&peer, &gid));
                    me.refresh_info();
                    me.load_page();
                }
            });
        }

        // Closing the window just hides it, like toggling the header button.
        {
            let toggle = self.toggle.clone();
            self.window.connect_close_request(move |_| {
                toggle.set_active(false);
                glib::Propagation::Stop
            });
        }

        // Tools.
        {
            let weak = weak.clone();
            self.eraser.connect_toggled(move |button| {
                if let Some(me) = weak.upgrade() {
                    me.state.borrow_mut().erasing = button.is_active();
                }
            });
        }
        for (shade, swatch) in self.swatches.iter().enumerate() {
            let weak = weak.clone();
            swatch.connect_clicked(move |_| {
                if let Some(me) = weak.upgrade() {
                    {
                        let mut st = me.state.borrow_mut();
                        st.shade = shade as u8;
                        st.erasing = false;
                    }
                    me.pen.set_active(true);
                }
            });
        }
        {
            let weak = weak.clone();
            self.undo_button.connect_clicked(move |_| {
                if let Some(me) = weak.upgrade() {
                    me.flip(true);
                }
            });
        }
        {
            let weak = weak.clone();
            self.redo_button.connect_clicked(move |_| {
                if let Some(me) = weak.upgrade() {
                    me.flip(false);
                }
            });
        }

        // Drawing.
        {
            let weak = weak.clone();
            self.area.set_draw_func(move |_, cr, w, h| {
                let Some(me) = weak.upgrade() else { return };
                let st = me.state.borrow();
                let (scale, ox, oy) = layout(w as f64, h as f64);
                cr.set_source_rgb(0.0, 0.0, 0.0);
                let _ = cr.paint();
                cr.translate(ox, oy);
                cr.scale(scale, scale);
                cr.rectangle(0.0, 0.0, WIDTH, HEIGHT);
                cr.clip();
                let participants = st.names.len().max(2);
                let all: Vec<&Stroke> = st.strokes.iter().chain(st.pending.iter()).collect();
                paint_strokes(cr, &all, participants);
                if !st.current.is_empty() && !st.erasing {
                    let live = Stroke {
                        id: Vec::new(),
                        shade: st.shade,
                        author: st.me as u8,
                        width: st.pen_width,
                        points: st.current.clone(),
                    };
                    paint_strokes(cr, &[&live], participants);
                }
            });
        }
        let drag = gtk::GestureDrag::new();
        drag.set_button(1);
        {
            let weak = weak.clone();
            drag.connect_drag_begin(move |_, x, y| {
                let Some(me) = weak.upgrade() else { return };
                {
                    let mut st = me.state.borrow_mut();
                    st.drag_origin = (x, y);
                    st.current.clear();
                }
                me.touch(x, y);
            });
        }
        {
            let weak = weak.clone();
            drag.connect_drag_update(move |_, dx, dy| {
                let Some(me) = weak.upgrade() else { return };
                let (ox, oy) = me.state.borrow().drag_origin;
                me.touch(ox + dx, oy + dy);
            });
        }
        {
            let weak = weak.clone();
            drag.connect_drag_end(move |_, _, _| {
                if let Some(me) = weak.upgrade() {
                    me.finish_stroke();
                }
            });
        }
        self.area.add_controller(drag);
    }

    /// View pixels → board units, then pen or eraser.
    fn touch(self: &Rc<Self>, vx: f64, vy: f64) {
        let (scale, ox, oy) = layout(self.area.width() as f64, self.area.height() as f64);
        let p = (((vx - ox) / scale).clamp(0.0, WIDTH), ((vy - oy) / scale).clamp(0.0, HEIGHT));
        let erasing = self.state.borrow().erasing;
        if erasing {
            self.erase_at(p);
            return;
        }
        {
            let mut st = self.state.borrow_mut();
            if let Some(last) = st.current.last() {
                if ((p.0 - last.0).powi(2) + (p.1 - last.1).powi(2)).sqrt() < MIN_STEP {
                    return;
                }
            }
            st.current.push(p);
        }
        self.area.queue_draw();
    }

    fn finish_stroke(self: &Rc<Self>) {
        let stroke = {
            let mut st = self.state.borrow_mut();
            if st.erasing || st.current.is_empty() {
                st.current.clear();
                return;
            }
            let s = Stroke {
                id: Vec::new(),
                shade: st.shade,
                author: st.me as u8,
                width: st.pen_width,
                points: std::mem::take(&mut st.current),
            };
            st.pending.push(s.clone());
            s
        };
        self.add_stroke(stroke);
        self.area.queue_draw();
    }

    fn remember(&self, step: Step) {
        {
            let mut st = self.state.borrow_mut();
            st.undo.push_back(step);
            if st.undo.len() > MAX_UNDO {
                st.undo.pop_front();
            }
            st.redo.clear();
        }
        self.style_history();
    }

    fn add_stroke(self: &Rc<Self>, stroke: Stroke) {
        let page = self.state.borrow().page;
        // The step is stored with empty ids and filled in when the core answers.
        self.remember(Step { page, strokes: vec![stroke.clone()], ids: Vec::new(), live: true });
        let (peer, gid) = (self.peer.clone(), self.group_id.clone());
        let bytes = point_bytes(&stroke);
        let (shade, width) = (stroke.shade, stroke.width);
        let me = self.clone();
        run_in_background(
            move || core::whiteboard_add_stroke(&peer, &gid, page, shade, width, &bytes),
            move |result| {
                let mut reload = false;
                {
                    let mut st = me.state.borrow_mut();
                    if let Some(at) = st.pending.iter().position(|p| p.points == stroke.points) {
                        st.pending.remove(at);
                    }
                    match &result {
                        Ok(ids) => {
                            // erased while the add was still in flight?
                            // Do not resurrect it — record the id in the
                            // erase step and send the erase now.
                            let erased = st
                                .erased_pending
                                .iter()
                                .any(|(entry_page, p)| {
                                    *entry_page == page && p.points == stroke.points
                                });
                            if erased {
                                st.erased_pending
                                    .retain(|(entry_page, p)| {
                                        !(*entry_page == page && p.points == stroke.points)
                                    });
                                if !ids.is_empty() {
                                    if let Some(step) = st.undo.iter_mut().rev().find(|s| {
                                        !s.live
                                            && s.ids.is_empty()
                                            && s.page == page
                                            && s.strokes
                                                .iter()
                                                .any(|added| added.points == stroke.points)
                                    }) {
                                        step.ids = ids.clone();
                                    }
                                    let (peer, gid) = (me.peer.clone(), me.group_id.clone());
                                    let ids = ids.clone();
                                    std::thread::spawn(move || {
                                        let _ = core::whiteboard_erase(&peer, &gid, &ids);
                                    });
                                }
                            } else if let Some(step) = st
                                .undo
                                .iter_mut()
                                .rev()
                                .find(|s| s.ids.is_empty() && s.live && s.page == page)
                            {
                                step.ids = ids.clone();
                            }
                            if !erased && st.page == page {
                                if ids.len() == 8 {
                                    // The call returned the new id: keep the stroke instead of
                                    // fetching a snapshot that could bring back a stroke erased
                                    // in the meantime.
                                    let mut kept = stroke.clone();
                                    kept.id = ids.clone();
                                    st.strokes.push(kept);
                                } else {
                                    reload = true;
                                }
                            }
                        }
                        Err(_) => {
                            st.undo.pop_back();
                        }
                    }
                }
                if let Err(error) = &result {
                    me.app.toast(&format!("Could not draw: {}", error));
                    me.style_history();
                }
                if reload {
                    me.load_page();
                }
                me.area.queue_draw();
            },
        );
        self.schedule_ticks();
    }

    fn erase_at(self: &Rc<Self>, p: (f64, f64)) {
        let (hit, pending_hit): (Vec<Stroke>, Vec<Stroke>) = {
            let mut st = self.state.borrow_mut();
            // pending strokes are drawn too, so "nothing under the
            // eraser" (the common mouse-move) means neither list has a hit.
            if !st
                .strokes
                .iter()
                .chain(st.pending.iter())
                .any(|s| near(s, p))
            {
                return;
            }
            let (hit, keep): (Vec<Stroke>, Vec<Stroke>) = st.strokes.drain(..).partition(|s| near(s, p));
            st.strokes = keep;
            // a pending stroke has no id yet (the add is still in
            // flight), so it cannot be erased by id now. Remember it and
            // finish the erase the moment the add is acked (`add_stroke`),
            // which also keeps the view from drawing the ack tombstone.
            let (pending_hit, keep): (Vec<Stroke>, Vec<Stroke>) =
                st.pending.drain(..).partition(|s| near(s, p));
            st.pending = keep;
            let this_page = st.page;
            for stroke in pending_hit.iter() {
                st.erased_pending.push((this_page, stroke.clone()));
            }
            (hit, pending_hit)
        };
        if hit.is_empty() && pending_hit.is_empty() {
            return;
        }
        let ids: Vec<u8> = hit.iter().flat_map(|s| s.id.clone()).collect();
        let page = self.state.borrow().page;
        // One step covers both kinds: flipping it restores every erased
        // stroke (a pending one goes back as a re-added copy with fresh ids,
        // like any erased stroke) — see `flip`.
        let mut all = hit;
        all.extend(pending_hit);
        self.remember(Step { page, strokes: all, ids: ids.clone(), live: false });
        // Live hits have ids to erase now; a pending-only erase catches up in
        // `add_stroke`'s ack. Sending an empty id list would be a
        // pointless core round trip.
        if !ids.is_empty() {
            let (peer, gid) = (self.peer.clone(), self.group_id.clone());
            std::thread::spawn(move || {
                let _ = core::whiteboard_erase(&peer, &gid, &ids);
            });
        }
        self.area.queue_draw();
        self.schedule_ticks();
    }

    /// Undo (`undo` = true) or redo: flips the newest step. An erased stroke
    /// cannot come back under its old id (every device remembers the erase),
    /// so it is drawn again as a new stroke — in my colour.
    fn flip(self: &Rc<Self>, undo: bool) {
        // A stroke whose add has not been answered has no id to erase yet:
        // undoing it now would send an empty erase and the stroke would come
        // back when the add returns. It can be undone a moment later.
        {
            let st = self.state.borrow();
            let back = if undo { st.undo.back() } else { st.redo.back() };
            if back.is_some_and(|step| step.live && step.ids.is_empty()) {
                return;
            }
        }
        let copy = {
            let mut st = self.state.borrow_mut();
            let popped = if undo { st.undo.pop_back() } else { st.redo.pop_back() };
            popped.map(|s| {
                let copy = Step { page: s.page, strokes: s.strokes.clone(), ids: s.ids.clone(), live: s.live };
                if undo { st.redo.push_back(s) } else { st.undo.push_back(s) };
                copy
            })
        };
        self.style_history();
        let Some(Step { page, strokes, ids, live }) = copy else { return };
        let (peer, gid) = (self.peer.clone(), self.group_id.clone());
        let me = self.clone();
        // a restored step that re-adds strokes cancels any erase-in-flight
        // for the same shapes — otherwise the still-un-acked add's callback
        // would "finish" the erase and wipe the stroke the user just restored.
        let restored_points = if live {
            Vec::new()
        } else {
            strokes.iter().map(|s| s.points.clone()).collect::<Vec<_>>()
        };
        // The step is identified by its ids: an undo/redo/draw that interleaved
        // with this request may have changed what sits at the back.
        let expect_ids = ids.clone();
        run_in_background(
            move || {
                if live {
                    let _ = core::whiteboard_erase(&peer, &gid, &ids);
                    Vec::new()
                } else {
                    strokes
                        .iter()
                        .flat_map(|s| {
                            core::whiteboard_add_stroke(&peer, &gid, page, s.shade, s.width, &point_bytes(s))
                                .unwrap_or_default()
                        })
                        .collect::<Vec<u8>>()
                }
            },
            move |new_ids| {
                {
                    let mut st = me.state.borrow_mut();
                    // the restore went out, so the erase remembered
                    // for those shapes must not fire on the ack.
                    if !restored_points.is_empty() {
                        st.erased_pending.retain(|(_, p)| {
                            !restored_points.iter().any(|pts| *pts == p.points)
                        });
                    }
                    // The step now sits at the back of the opposite stack.
                    let other = if undo { st.redo.back_mut() } else { st.undo.back_mut() };
                    if let Some(s) = other.filter(|s| s.ids == expect_ids) {
                        if !live {
                            s.ids = new_ids;
                        }
                        s.live = !live;
                    }
                }
                if me.state.borrow().page == page {
                    me.load_page();
                } else {
                    me.go_to_page(page as i32);
                }
            },
        );
        self.schedule_ticks();
    }

    fn schedule_ticks(self: &Rc<Self>) {
        let generation = self.ticks.get() + 1;
        self.ticks.set(generation);
        for ms in [TICK_OPS_MS, TICK_DIGEST_MS] {
            let weak: Weak<Inner> = Rc::downgrade(self);
            glib::timeout_add_local_once(Duration::from_millis(ms), move || {
                if let Some(me) = weak.upgrade() {
                    // A newer request restarted the timers; its own pair will do.
                    if me.ticks.get() == generation {
                        std::thread::spawn(core::whiteboard_tick);
                    }
                }
            });
        }
    }

    fn go_to_page(self: &Rc<Self>, target: i32) {
        if target < 0 || target as u32 >= MAX_PAGES {
            return;
        }
        {
            let mut st = self.state.borrow_mut();
            st.page = target as u8;
            st.page_count = st.page_count.max(target as u32 + 1);
            st.pending.clear();
            st.strokes.clear();
        }
        self.update_page_label();
        self.area.queue_draw();
        self.load_page();
    }

    fn load_page(self: &Rc<Self>) {
        let shown = self.state.borrow().page;
        let (peer, gid) = (self.peer.clone(), self.group_id.clone());
        let me = self.clone();
        run_in_background(
            move || {
                let blob = core::whiteboard_page(&peer, &gid, shown);
                core::whiteboard_mark_read(&peer, &gid, shown);
                parse_page(&blob)
            },
            move |strokes| {
                {
                    let mut st = me.state.borrow_mut();
                    if st.page != shown {
                        return;
                    }
                    st.strokes = strokes;
                    st.unread &= !(1u32 << shown);
                }
                me.update_unread();
                me.update_page_label();
                me.area.queue_draw();
            },
        );
    }

    fn refresh_info(self: &Rc<Self>) {
        let (peer, gid) = (self.peer.clone(), self.group_id.clone());
        let me = self.clone();
        run_in_background(
            move || core::whiteboard_info(&peer, &gid),
            move |info| {
                let Ok(info) = info else { return };
                {
                    let mut st = me.state.borrow_mut();
                    // see `handle_event` — the core can report pages
                    // past the UI cap; the pager stays inside it.
                    st.page_count = st
                        .page_count
                        .max(info.pages.min(MAX_PAGES))
                        .max(st.page as u32 + 1);
                    st.me = info.me.unwrap_or(0);
                    st.names = info.participants.iter().map(|p| p.name.clone()).collect();
                    st.unread = info.unread;
                }
                me.update_unread();
                me.update_page_label();
                me.style_tools();
                me.area.queue_draw();
            },
        );
    }

    // ---------------------------------------------------------------- chrome

    fn update_unread(&self) {
        let unseen = self.state.borrow().unread != 0;
        self.toggle
            .set_tooltip_text(Some(if unseen { "Whiteboard — new drawing" } else { "Whiteboard" }));
        if unseen {
            self.toggle.add_css_class("accent");
        } else {
            self.toggle.remove_css_class("accent");
        }
    }

    fn update_page_label(&self) {
        let st = self.state.borrow();
        let elsewhere = st.unread & !(1u32 << st.page) != 0;
        self.page_label.set_text(&format!(
            "{}/{}{}",
            st.page as u32 + 1,
            st.page_count,
            if elsewhere { " •" } else { "" }
        ));
    }

    fn style_history(&self) {
        let st = self.state.borrow();
        self.undo_button.set_sensitive(!st.undo.is_empty());
        self.redo_button.set_sensitive(!st.redo.is_empty());
    }

    /// Legend + swatch colours: who draws in which colour.
    fn style_tools(&self) {
        let st = self.state.borrow();
        let participants = st.names.len().max(2);
        let mut markup = String::new();
        for (index, name) in st.names.iter().enumerate() {
            for shade in 0..3 {
                markup.push_str(&format!(
                    "<span foreground=\"{}\">●</span>",
                    css_hex(color_of(index, participants, shade))
                ));
            }
            markup.push_str(&format!(" {}   ", glib::markup_escape_text(name)));
        }
        self.legend.set_markup(&markup);
        for (shade, swatch) in self.swatches.iter().enumerate() {
            if let Some(label) = swatch.child().and_downcast::<gtk::Label>() {
                label.set_markup(&format!(
                    "<span foreground=\"{}\">⬤</span>",
                    css_hex(color_of(st.me, participants, shade as u8))
                ));
            }
        }
    }

    fn export_pdf(self: &Rc<Self>, anchor: &gtk::Button) {
        let (strokes, participants, page) = {
            let st = self.state.borrow();
            (st.strokes.clone(), st.names.len().max(2), st.page)
        };
        let dialog = gtk::FileDialog::builder().modal(false)
            .title("Save whiteboard page")
            .initial_name(format!("whiteboard-{}.pdf", page as u32 + 1))
            .build();
        let window = anchor.root().and_downcast::<gtk::Window>();
        let me = self.clone();
        dialog.save(window.as_ref(), gtk::gio::Cancellable::NONE, move |result| {
            let Ok(file) = result else { return };
            let Some(path) = file.path() else { return };
            let ok = (|| -> Result<(), gtk::cairo::Error> {
                let surface = gtk::cairo::PdfSurface::new(WIDTH, HEIGHT, &path)?;
                // Cairo created the file world-readable; a whiteboard page is
                // private conversation content, so clamp it to owner-only as
                // soon as it exists. Best effort: FAT/exFAT cannot do chmod.
                let _ = crate::util::set_mode(&path, 0o600);
                let cr = gtk::cairo::Context::new(&surface)?;
                cr.set_source_rgb(0.0, 0.0, 0.0);
                cr.paint()?;
                let refs: Vec<&Stroke> = strokes.iter().collect();
                paint_strokes(&cr, &refs, participants);
                surface.finish();
                Ok(())
            })()
            .is_ok();
            if !ok {
                let _ = std::fs::remove_file(&path);
            }
            me.app.toast(if ok { "Page saved as PDF" } else { "Could not save the PDF" });
        });
    }
}
