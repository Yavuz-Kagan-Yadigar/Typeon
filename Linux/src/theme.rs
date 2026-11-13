//! Material 3 theming: tonal colour palette, shape scale, and the density and
//! text-size knobs that the Android Settings screen exposes.
//!
//! ## Colour
//!
//! Material 3 derives every colour role from a single seed by picking *tones* (fixed
//! perceptual lightness steps) out of a few hue families. Google's own
//! implementation does this in HCT (a CAM16-based space). Reimplementing HCT
//! here would be a lot of colour science for a chat client, so tones are
//! approximated in HSL: hue is preserved, chroma is scaled per family, and the
//! tone number is used as HSL lightness. That is not colorimetrically equal to
//! HCT (mid tones of a very saturated seed come out somewhat more vivid). It
//! still gives the part that matters here: one seed generates a consistent,
//! correctly ordered set of surfaces and accents that stay legible in both
//! light and dark.
//!
//! The generated roles are then mapped onto libadwaita's named colours, so
//! *every* stock widget (rows, dialogs, popovers, switches, the header bar)
//! picks them up, not only the widgets styled by hand below.
//!
//! ## Shape
//!
//! Material 3's shape scale (4 / 8 / 12 / 16 / 28), plus fully rounded "pill" geometry
//! for everything interactive.

use crate::prefs::Prefs;

/// Material 3's own baseline seed, used when the user has not picked an accent.
pub const DEFAULT_SEED: &str = "#6750A4";

// --- a small HSL colour model ---

fn hex_to_rgb(hex: &str) -> Option<(f64, f64, f64)> {
    let hex = hex.trim_start_matches('#');
    if hex.len() != 6 {
        return None;
    }
    let value = u32::from_str_radix(hex, 16).ok()?;
    Some((
        ((value >> 16) & 0xff) as f64 / 255.0,
        ((value >> 8) & 0xff) as f64 / 255.0,
        (value & 0xff) as f64 / 255.0,
    ))
}

fn rgb_to_hsl(r: f64, g: f64, b: f64) -> (f64, f64, f64) {
    let max = r.max(g).max(b);
    let min = r.min(g).min(b);
    let lightness = (max + min) / 2.0;
    if (max - min).abs() < f64::EPSILON {
        return (0.0, 0.0, lightness);
    }
    let delta = max - min;
    let saturation = if lightness > 0.5 {
        delta / (2.0 - max - min)
    } else {
        delta / (max + min)
    };
    let hue = if (max - r).abs() < f64::EPSILON {
        ((g - b) / delta) % 6.0
    } else if (max - g).abs() < f64::EPSILON {
        (b - r) / delta + 2.0
    } else {
        (r - g) / delta + 4.0
    };
    ((hue * 60.0 + 360.0) % 360.0, saturation, lightness)
}

fn hsl_to_hex(hue: f64, saturation: f64, lightness: f64) -> String {
    let saturation = saturation.clamp(0.0, 1.0);
    let lightness = lightness.clamp(0.0, 1.0);
    let c = (1.0 - (2.0 * lightness - 1.0).abs()) * saturation;
    let h = (((hue % 360.0) + 360.0) % 360.0) / 60.0;
    let x = c * (1.0 - (h % 2.0 - 1.0).abs());
    let (r, g, b) = match h as u32 {
        0 => (c, x, 0.0),
        1 => (x, c, 0.0),
        2 => (0.0, c, x),
        3 => (0.0, x, c),
        4 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    let m = lightness - c / 2.0;
    format!(
        "#{:02x}{:02x}{:02x}",
        ((r + m) * 255.0).round().clamp(0.0, 255.0) as u8,
        ((g + m) * 255.0).round().clamp(0.0, 255.0) as u8,
        ((b + m) * 255.0).round().clamp(0.0, 255.0) as u8
    )
}

/// The tonal families Material 3 derives from one seed.
struct Palette {
    hue: f64,
    chroma: f64,
}

impl Palette {
    fn from_seed(seed: &str) -> Self {
        let (r, g, b) = hex_to_rgb(seed)
            .or_else(|| hex_to_rgb(DEFAULT_SEED))
            .unwrap_or((0.40, 0.31, 0.64));
        let (hue, saturation, _) = rgb_to_hsl(r, g, b);
        Self {
            hue,
            // A washed-out seed still needs a visible accent and a neon one
            // should not shout; clamping keeps every seed usable.
            chroma: saturation.clamp(0.28, 0.72),
        }
    }

    fn primary(&self, tone: f64) -> String {
        hsl_to_hex(self.hue, self.chroma, tone / 100.0)
    }
    fn secondary(&self, tone: f64) -> String {
        hsl_to_hex(self.hue, self.chroma * 0.36, tone / 100.0)
    }
    fn tertiary(&self, tone: f64) -> String {
        hsl_to_hex(self.hue + 60.0, self.chroma * 0.50, tone / 100.0)
    }
        /// Near-grey, faintly tinted by the seed. Material 3 surfaces are never pure grey.
    fn neutral(&self, tone: f64) -> String {
        hsl_to_hex(self.hue, self.chroma * 0.05, tone / 100.0)
    }
    fn neutral_variant(&self, tone: f64) -> String {
        hsl_to_hex(self.hue, self.chroma * 0.11, tone / 100.0)
    }
    fn error(&self, tone: f64) -> String {
        hsl_to_hex(25.0, 0.70, tone / 100.0)
    }
}

/// Everything the stylesheet needs, read off the saved preferences.
pub struct Appearance {
    pub dark: bool,
    pub seed: String,
    pub background: Option<String>,
    pub foreground: Option<String>,
    pub text_scale: f64,
    pub base_font_pt: f64,
    pub font_family: Option<String>,
    pub wallpaper: Option<String>,
    /// CSS `font-family` for the active custom font (from `fontdb`); `None`
    /// means a built-in/system font is active.
    pub custom_font_family: Option<String>,
}

impl Appearance {
    pub fn from_prefs(prefs: &Prefs, dark: bool, base_font_pt: f64, custom_font_family: Option<String>) -> Self {
        Self {
            dark,
            seed: prefs
                .accent_color
                .clone()
                .unwrap_or_else(|| DEFAULT_SEED.to_string()),
            background: prefs.background_color.clone(),
            foreground: prefs.foreground_color.clone(),
            text_scale: prefs.text_scale,
            base_font_pt,
            font_family: prefs.font_family.clone(),
            wallpaper: prefs.chat_wallpaper.clone(),
            custom_font_family,
        }
    }
}

/// The colours currently in effect for the three user-editable roles, with the
/// palette's own choice filled in wherever the user has not overridden it.
/// Settings uses this so an untouched swatch shows what is actually on screen
/// rather than the colour button's arbitrary default.
pub fn effective_colors(appearance: &Appearance) -> (String, String, String) {
    let palette = Palette::from_seed(&appearance.seed);
    let dark = appearance.dark;
    (
        // The accent row edits the seed itself, so show the seed.
        appearance.seed.clone(),
        appearance
            .background
            .clone()
            .unwrap_or_else(|| palette.neutral(if dark { 6.0 } else { 98.0 })),
        appearance
            .foreground
            .clone()
            .unwrap_or_else(|| palette.neutral(if dark { 90.0 } else { 10.0 })),
    )
}

/// Builds the full stylesheet: Material 3 colour roles mapped onto libadwaita's named
/// colours, then the shape and metric rules on top.
pub fn stylesheet(appearance: &Appearance) -> String {
    let palette = Palette::from_seed(&appearance.seed);
    let dark = appearance.dark;

    let primary = palette.primary(if dark { 80.0 } else { 40.0 });
    let on_primary = palette.primary(if dark { 20.0 } else { 100.0 });
    let primary_container = palette.primary(if dark { 30.0 } else { 90.0 });
    let on_primary_container = palette.primary(if dark { 90.0 } else { 10.0 });
    let secondary_container = palette.secondary(if dark { 30.0 } else { 90.0 });
    let on_secondary_container = palette.secondary(if dark { 90.0 } else { 10.0 });
    let tertiary = palette.tertiary(if dark { 80.0 } else { 40.0 });
    let outline_variant = palette.neutral_variant(if dark { 30.0 } else { 80.0 });
    let error = palette.error(if dark { 80.0 } else { 40.0 });
    let on_error = palette.error(if dark { 20.0 } else { 100.0 });

    let surface = appearance
        .background
        .clone()
        .unwrap_or_else(|| palette.neutral(if dark { 6.0 } else { 98.0 }));
    let on_surface = appearance
        .foreground
        .clone()
        .unwrap_or_else(|| palette.neutral(if dark { 90.0 } else { 10.0 }));

    // Container tones. When the user picks their own background these are
    // derived *from it* — otherwise a custom colour would sit as an island in
    // a palette-coloured window.
    let (surface_lowest, surface_low, surface_container, surface_high) =
        match appearance.background.as_deref().and_then(hex_to_rgb) {
            Some((r, g, b)) => {
                let (hue, saturation, lightness) = rgb_to_hsl(r, g, b);
                                // Containers step towards the viewer: lighter on dark, darker
                                // on light, as Material 3's surface-container roles do.
                let step = if dark { 0.035 } else { -0.030 };
                (
                    hsl_to_hex(hue, saturation, lightness - step),
                    hsl_to_hex(hue, saturation, lightness + step),
                    hsl_to_hex(hue, saturation, lightness + step * 2.0),
                    hsl_to_hex(hue, saturation, lightness + step * 3.0),
                )
            }
            None => (
                palette.neutral(if dark { 4.0 } else { 100.0 }),
                palette.neutral(if dark { 10.0 } else { 96.0 }),
                palette.neutral(if dark { 12.0 } else { 94.0 }),
                palette.neutral(if dark { 17.0 } else { 92.0 }),
            ),
        };

    let font_pt = (appearance.base_font_pt * appearance.text_scale).clamp(6.0, 32.0);

    // Build the CSS font-family stack: custom font first (loaded at runtime),
    // then the user's chosen generic family, falling back to system default.
    // User-chosen values go inside CSS strings: escape `\` and `"`, drop newlines.
    let css_str = |v: &str| v.replace('\\', "\\\\").replace('"', "\\\"").replace(['\n', '\r'], " ");
    let custom_font_escaped = appearance.custom_font_family.as_deref().map(css_str);
    let font_family_css = match (&custom_font_escaped, &appearance.font_family) {
        (Some(custom), Some(generic)) => format!(
            "    font-family: \"{custom}\", {generic};\n"
        ),
        (Some(custom), None) => format!(
            "    font-family: \"{custom}\";\n"
        ),
        (None, Some(generic)) => format!(
            "    font-family: {generic};\n"
        ),
        (None, None) => String::new(),
    };
    // GTK resolves url() against the stylesheet's own location, which for a
    // string-loaded provider is nowhere — so the path has to be absolute and
    // fully qualified.
    let wallpaper = match &appearance.wallpaper {
        Some(path) => {
            let path = css_str(path);
            format!(
            // Braces are doubled ONCE, not twice: this inner `format!` emits the
            // final text, which the outer one then inserts verbatim without a
            // second round of brace processing.
            ".chat-messages {{\n    background-image: url(\"file://{path}\");\n    \
             background-size: cover;\n    background-position: center;\n}}\n"
            )
        }
        None => String::new(),
    };

    // Concave fillets and the matching outer corners at a bubble-width step,
    // in the even radii `chat::seam_radius` can return.
    let mut rd_css = String::new();
    let mut fillet_css = String::new();
    for r in (2..=12).step_by(2) {
        for (corner, prop, at) in [
            ("tl", "top-left", "left top"),
            ("tr", "top-right", "right top"),
            ("bl", "bottom-left", "left bottom"),
            ("br", "bottom-right", "right bottom"),
        ] {
            rd_css.push_str(&format!(".bubble.rd-{corner}-{r} {{ border-{prop}-radius: {r}px; }}\n"));
            fillet_css.push_str(&format!(
                ".fillet-{corner}-{r} {{ background-image: radial-gradient(circle at {at}, transparent {}px, currentColor {r}px); }}\n",
                r - 1
            ));
        }
    }
    // Screen-space shade steps (see chat.rs `update_shading`): white tint at the
    // top reaching well down the screen, black tint only near the bottom.
    // Bubbles take `background-color`; fillets use `color` (currentColor fill).
    for (role, base) in [("mine", "@m3_primary_container"), ("theirs", "@m3_surface_high")] {
        for n in 0..24 {
            let t = n as f64 / 23.0;
            let colour = if t < 0.65 {
                format!("mix({base}, white, {:.3})", 0.28 * (1.0 - t / 0.65))
            } else {
                format!("mix({base}, black, {:.3})", 0.45 * (t - 0.65) / 0.35)
            };
            fillet_css.push_str(&format!(".bubble-{role}.shade-{n} {{ background-color: {colour}; }}\n"));
            fillet_css.push_str(&format!(".fshade-{role}-{n} {{ color: {colour}; }}\n"));
        }
    }
    format!(
        r#"
/* ===================== Material 3 colour roles ===================== */
@define-color m3_primary {primary};
@define-color m3_on_primary {on_primary};
@define-color m3_primary_container {primary_container};
@define-color m3_on_primary_container {on_primary_container};
@define-color m3_secondary_container {secondary_container};
@define-color m3_on_secondary_container {on_secondary_container};
@define-color m3_tertiary {tertiary};
@define-color m3_surface {surface};
@define-color m3_on_surface {on_surface};
@define-color m3_surface_lowest {surface_lowest};
@define-color m3_surface_low {surface_low};
@define-color m3_surface_container {surface_container};
@define-color m3_surface_high {surface_high};
@define-color m3_outline_variant {outline_variant};
@define-color m3_error {error};
@define-color m3_on_error {on_error};

/* Two spellings on purpose. libadwaita <=1.6 resolves `@name`; 1.7+ converted
   its palette to CSS custom properties and reads `var(--name)`, so redefining
   only the old form left stock widgets (switches, checks, links) on the
   desktop's system accent while hand-styled ones followed the palette. Both
   are emitted so either vintage picks it up. */
:root {{
    --accent-color: {primary};
    --accent-bg-color: {primary};
    --accent-fg-color: {on_primary};
    --destructive-color: {error};
    --destructive-bg-color: {error};
    --destructive-fg-color: {on_error};
    --success-color: {tertiary};
    --window-bg-color: {surface};
    --window-fg-color: {on_surface};
    --view-bg-color: {surface_lowest};
    --view-fg-color: {on_surface};
    --headerbar-bg-color: {surface};
    --headerbar-fg-color: {on_surface};
    --sidebar-bg-color: {surface};
    --sidebar-fg-color: {on_surface};
    --secondary-sidebar-bg-color: {surface};
    --card-bg-color: {surface_low};
    --card-fg-color: {on_surface};
    --dialog-bg-color: {surface_high};
    --dialog-fg-color: {on_surface};
    --popover-bg-color: {surface_container};
    --popover-fg-color: {on_surface};
    --borders: {outline_variant};
}}

@define-color accent_color @m3_primary;
@define-color accent_bg_color @m3_primary;
@define-color accent_fg_color @m3_on_primary;
@define-color destructive_color @m3_error;
@define-color destructive_bg_color @m3_error;
@define-color destructive_fg_color @m3_on_error;
@define-color success_color @m3_tertiary;
@define-color window_bg_color @m3_surface;
@define-color window_fg_color @m3_on_surface;
@define-color view_bg_color @m3_surface_lowest;
@define-color view_fg_color @m3_on_surface;
@define-color headerbar_bg_color @m3_surface;
@define-color headerbar_fg_color @m3_on_surface;
@define-color sidebar_bg_color @m3_surface;
@define-color sidebar_fg_color @m3_on_surface;
@define-color secondary_sidebar_bg_color @m3_surface;
@define-color card_bg_color @m3_surface_low;
@define-color card_fg_color @m3_on_surface;
@define-color dialog_bg_color @m3_surface_high;
@define-color dialog_fg_color @m3_on_surface;
@define-color popover_bg_color @m3_surface_container;
@define-color popover_fg_color @m3_on_surface;
@define-color borders @m3_outline_variant;

/* ===================== type scale ===================== */
window {{
    font-size: {font_pt}pt;
{font_family_css}}}
{wallpaper}

/* ===================== shape: pill everything ===================== */
button {{
    border-radius: 9999px;
    border: none;
    box-shadow: none;
    min-height: 34px;
}}
button.text-button {{ padding-left: 20px; padding-right: 20px; }}
/* `.image-button` is not a class this app adds — GTK assigns it automatically
   to *any* button whose sole child is an icon, which includes the titlebar's
   own minimize/maximize/close controls. Forcing a min-size and zero padding
   onto every such button (an earlier version of this rule did) fought that
   widget's own compact sizing and warped its buttons on hover. Only
   `.circular`, which this app adds deliberately (the send button, in-bubble
   play/pause), gets the explicit centering treatment below; `.image-button`
   keeps just the rounding it already had. */
button.circular, button.image-button {{ border-radius: 9999px; }}
/* `padding: 0` matters here: without it, an icon-only button inherits enough
   asymmetric default padding (tuned for wider, non-circular buttons) to draw
   its icon visibly off-centre inside the circle — the composer's send button
   most noticeably, since it sits right at the end of a text row. */
button.circular {{
    min-width: 34px;
    min-height: 34px;
    padding: 0;
}}
button.pill {{ min-height: 46px; padding-left: 26px; padding-right: 26px; }}
button.suggested-action, button.destructive-action, button.opaque {{ box-shadow: none; }}

/* Surfaces have to be painted explicitly for the same reason the accent does
   (see the note on switches): redefining libadwaita's named colours no longer
   reaches its own widgets, so a custom background colour changed the chat
   bubbles but left the window chrome on the stock grey — which read as "the
   colour pickers do nothing". */
window, .background,
window > contents,
toolbarview, navigationview, navigationsplitview,
preferencespage, viewstack, stack, box, scrolledwindow, viewport {{
    background-color: transparent;
    color: @m3_on_surface;
}}
window, .background {{ background-color: @m3_surface; }}
/* The chat list sits on the background colour, not a grey sidebar tone. */
.sidebar-pane, .sidebar-pane > toolbarview, .navigation-sidebar {{ background-color: @m3_surface; }}
window.messagedialog, window.dialog, dialog, .dialog {{
    background-color: @m3_surface_high;
    color: @m3_on_surface;
}}
label, .title, .heading, .caption-heading {{ color: @m3_on_surface; }}
.dim-label, .subtitle, .caption {{ color: @m3_on_surface; opacity: 0.7; }}
/* This stylesheet is loaded at `STYLE_PROVIDER_PRIORITY_USER` (see settings.rs
   — deliberately above libadwaita's own accent provider), which means the
   blanket `label` rule above beats Adwaita's built-in `.success`/`.warning`/
   `.error` label colouring outright, regardless of that rule's higher
   selector specificity: provider priority is checked before specificity.
   The connection-status dot (`window.rs::status_indicator`) toggles exactly
   those three classes to signal Tor/peer state, and without rules of our
   own for them here it could never actually change colour — it just always
   rendered in the plain on-surface tone above, which reads as "always grey".*/
label.success {{ color: @m3_tertiary; }}
label.error {{ color: @m3_error; }}

headerbar {{
    background-color: @m3_surface;
    border: none;
    box-shadow: none;
    min-height: 54px;
}}
headerbar button {{ border-radius: 9999px; }}

entry, spinbutton, passwordentry, searchentry {{
    border-radius: 9999px;
    border: none;
    background-color: @m3_surface_container;
    box-shadow: none;
    min-height: 42px;
    padding-left: 14px;
    padding-right: 14px;
}}
entry:focus-within, spinbutton:focus-within,
passwordentry:focus-within, searchentry:focus-within {{
    box-shadow: inset 0 0 0 2px @m3_primary;
}}

/* The message composer's text box — a pill like every other text input
   (see `entry` above), not the 20px-corner rectangle a plain `.card` gives
   wider containers. `border-radius: 9999px` still does the right thing once
   it grows past one line: the radius clamps to half the box's actual height,
   so a taller multi-line composer becomes a rounded "stadium" rather than
   a pill stretched into an ellipse. */
.composer-input {{
    border-radius: 9999px;
    border: none;
    background-color: @m3_surface_container;
}}

/* Reply "island" (see `ChatView::reply_island`): while quoting, the quote and
   the composer bar sit on one tinted rounded surface. Only the colour
   changes, never the padding, so the composer keeps its size. */
.reply-island {{
    border-radius: 30px;
    transition: background-color 150ms ease-out;
}}
.reply-island.active {{
    background-color: @m3_outline_variant;
}}

/* Containers: corner-large, no hairlines. Material 3 separates them tonally. */
.card, .boxed-list, list.boxed-list {{
    border-radius: 20px;
    border: none;
    background-color: @m3_surface_low;
}}
list.boxed-list > row:first-child {{ border-top-left-radius: 20px; border-top-right-radius: 20px; }}
list.boxed-list > row:last-child {{ border-bottom-left-radius: 20px; border-bottom-right-radius: 20px; }}
list.boxed-list > row:not(:last-child) {{ border-bottom: none; }}
list, listview {{ background-color: transparent; }}

/* Navigation rows are pills, as in a Material 3 navigation drawer. */
.navigation-sidebar {{ padding: 6px 4px; background-color: transparent; }}
.navigation-sidebar > row {{
    border-radius: 9999px;
    margin: 2px 6px;
    min-height: 60px;
    padding-left: 10px;
    padding-right: 10px;
}}
.navigation-sidebar > row:hover {{
    background-color: @m3_secondary_container;
    color: @m3_on_secondary_container;
}}

/* No shadow: Windows draws popups on an opaque surface, so the shadow's
   margin showed up as a black rectangle around every menu. */
popover > contents {{
    border-radius: 20px;
    border: none;
    padding: 8px;
    background-color: @m3_surface_container;
    box-shadow: none;
}}
popover.background > contents, popover.menu > contents {{ box-shadow: none; }}
.m3-menu {{ min-width: 220px; }}
.m3-menu button {{
    border-radius: 9999px;
    min-height: 46px;
    padding-left: 14px;
    padding-right: 18px;
}}
.m3-menu button label {{ padding-left: 4px; }}

/* Pill response buttons need room the stock layout does not reserve: it
   assumes flat, full-width buttons divided by separators, so rounded ones
   ran into each other and off the dialog edge. */
.messagedialog .response-area,
.dialog-action-area {{
    padding: 10px;
    border-top: none;
}}
.messagedialog .response-area button,
.dialog-action-area button {{
    border-radius: 9999px;
    min-height: 42px;
    margin: 3px;
    padding-left: 18px;
    padding-right: 18px;
}}

/* libadwaita 1.6+ owns the accent colour itself (AdwStyleManager reads the
   desktop's system accent), and neither `@define-color accent_bg_color` nor
   the 1.7 `--accent-bg-color` custom property overrides it — verified: the
   window background followed our palette while switches stayed on the system
   accent. Since the seed here is an arbitrary colour, not one of the nine
   AdwAccentColor presets, the supported API cannot express it either. So the
   accented widgets are painted explicitly. */
switch {{ border-radius: 9999px; }}
/* `background-image: none` matters: libadwaita paints the track with a
   gradient built from its own accent, which otherwise sits on top of our
   background-color and shows through as the old colour. */
switch:checked {{ background-color: @m3_primary; background-image: none; }}
switch:checked > slider {{ background-color: @m3_on_primary; }}
check:checked, check:indeterminate,
radio:checked, radio:indeterminate {{
    background-color: @m3_primary;
    background-image: none;
    color: @m3_on_primary;
    border-color: @m3_primary;
}}
button.suggested-action {{ background-color: @m3_primary; background-image: none; color: @m3_on_primary; }}
button.destructive-action {{ background-color: @m3_error; background-image: none; color: @m3_on_error; }}
/* GTK has a `selection` node; `::selection` is a web-ism and is rejected. */
selection {{ background-color: @m3_primary; color: @m3_on_primary; }}
row:selected, row.activatable:selected {{
    background-color: @m3_secondary_container;
    color: @m3_on_secondary_container;
}}
/* Descendant selectors, not child: the exact node path under `scale`/
   `progressbar` differs between GTK versions, and a `>` chain that stops
   matching fails silently — the widget just keeps the system accent. */
progressbar progress,
scale highlight,
scale > trough > slider,
levelbar block.filled {{
    background-color: @m3_primary;
    background-image: none;
}}
spinner {{ color: @m3_primary; }}
link, button.link {{ color: @m3_primary; }}
.accent {{ color: @m3_primary; }}
progressbar > trough, progressbar > trough > progress,
scale > trough, scale > trough > highlight {{ border-radius: 9999px; }}
toast {{ border-radius: 9999px; }}
avatar {{ border-radius: 9999px; }}

/* ===================== chat bubbles ===================== */
/* Android draws a gradient pill, and the same look is wanted on Flatpak. The bubble colour is
   lighter at the top of the list and keeps the current colour at the bottom. GTK widgets only
   know their own bounds, so the gradient is drawn inside each bubble. */
.bubble {{ border-radius: 20px; }}
.bubble-mine {{
    background-color: @m3_primary_container;
    color: @m3_on_primary_container;
    border-bottom-right-radius: 6px;
}}
.bubble-theirs {{
    background-color: @m3_surface_high;
    color: @m3_on_surface;
    border-bottom-left-radius: 6px;
}}
.bubble-mine .dim-label {{ opacity: 0.85; }}
/* Consecutive bubbles from one sender read as a single block. The edges that touch get small
   radii. The seam classes below handle the corners at width steps. This is the same approach as
   the WhatsApp and Telegram group views, and it overrides the single tail rule of .bubble-mine
   and .bubble-theirs because it is more specific. */
/* Joined corners of a run of bubbles: small on the straight (aligned) side, square where a
   narrower bubble meets a wider one. */
.bubble.seam-tl {{ border-top-left-radius: 4px; }}
.bubble.seam-tr {{ border-top-right-radius: 4px; }}
.bubble.seam-bl {{ border-bottom-left-radius: 4px; }}
.bubble.seam-br {{ border-bottom-right-radius: 4px; }}
{rd_css}.bubble.sq-tl {{ border-top-left-radius: 0; }}
.bubble.sq-tr {{ border-top-right-radius: 0; }}
.bubble.sq-bl {{ border-bottom-left-radius: 0; }}
.bubble.sq-br {{ border-bottom-right-radius: 0; }}
/* Narrows the gap between bubbles of the same group (see `.chat-messages`). */
/* (GTK CSS rejects negative margins; the gap is set in chat.rs.) */
.bubble-row-continued {{ }}
/* Concave notch at a seam where the width changes (see `mark_group_seam`). GTK CSS has no
   ::before or ::after pseudo-elements, so the notch is a separate widget. Its colour matches the
   background. With a wallpaper set (see the `wallpaper` variable) it sits over the texture as a
   flat patch. This small limit is accepted as the cost of the cheap method. */
{fillet_css}/* Images and videos in a chat get rounded corners and a thin border, as on Android
   (ShapeableImageView strokeWidth). Before, only the corner radius was set. */
.attachment-preview {{
    border-radius: 14px;
    border: 1px solid @m3_outline_variant;
}}
/* Inline quote at the top of a bubble: darker rounded box, as on the phone. */
.quote-block {{
    background-color: alpha(black, 0.25);
    border-radius: 10px;
    padding: 4px 10px;
    opacity: 0.85;
}}
.sticker {{ border-radius: 8px; }}
/* Current in-chat search hit. */
.bubble-match {{ outline: 2px solid @m3_primary; outline-offset: 2px; }}
.msg-pop {{ animation: msg-pop 220ms cubic-bezier(0.2, 0.8, 0.2, 1); transform-origin: 0% 100%; }}
.msg-pop.msg-pop-mine {{ transform-origin: 100% 100%; }}
@keyframes msg-pop {{ from {{ opacity: 0; transform: translateY(12px) scale(0.85); }} to {{ opacity: 1; transform: none; }} }}
"#
    )
}
