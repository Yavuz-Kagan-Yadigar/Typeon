//! Material 3 theming: tonal colour palette, shape scale, and the density /
//! text-size knobs the Android Settings screen exposes.
//!
//! ## Colour
//!
//! M3 derives every colour role from a single seed by picking *tones* — fixed
//! perceptual lightness steps — out of a few hue families. Google's own
//! implementation does this in HCT (a CAM16-based space). Reimplementing HCT
//! here would be a lot of colour science for a chat client, so tones are
//! approximated in HSL: hue is preserved, chroma is scaled per family, and the
//! tone number is used as HSL lightness. That is not colorimetrically equal to
//! HCT — mid tones of a very saturated seed come out somewhat more vivid — but
//! it reproduces the part that matters here: one seed generating a consistent,
//! correctly-ordered set of surfaces and accents that stay legible in both
//! light and dark.
//!
//! The generated roles are then mapped onto libadwaita's named colours, so
//! *every* stock widget — rows, dialogs, popovers, switches, the header bar —
//! picks them up, not only the widgets styled by hand below.
//!
//! ## Shape
//!
//! M3's shape scale (4 / 8 / 12 / 16 / 28) plus fully-rounded "pill" geometry
//! for everything interactive.

use crate::prefs::Prefs;

/// M3's own baseline seed, used when the user has not picked an accent.
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

/// The tonal families M3 derives from one seed.
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
    /// Near-grey, faintly tinted by the seed — M3 surfaces are never pure grey.
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

/// Builds the full stylesheet: M3 colour roles mapped onto libadwaita's named
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
                // Containers step *towards* the viewer: lighter on dark, darker
                // on light, exactly as M3's surface-container roles do.
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
    --sidebar-bg-color: {surface_low};
    --sidebar-fg-color: {on_surface};
    --secondary-sidebar-bg-color: {surface_low};
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
@define-color sidebar_bg_color @m3_surface_low;
@define-color sidebar_fg_color @m3_on_surface;
@define-color secondary_sidebar_bg_color @m3_surface_low;
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

/* Containers: corner-large, no hairlines — M3 separates tonally. */
.card, .boxed-list, list.boxed-list {{
    border-radius: 20px;
    border: none;
    background-color: @m3_surface_low;
}}
list.boxed-list > row:first-child {{ border-top-left-radius: 20px; border-top-right-radius: 20px; }}
list.boxed-list > row:last-child {{ border-bottom-left-radius: 20px; border-bottom-right-radius: 20px; }}
list.boxed-list > row:not(:last-child) {{ border-bottom: none; }}
list, listview {{ background-color: transparent; }}

/* Navigation rows are pills, as in an M3 navigation drawer. */
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

popover > contents {{
    border-radius: 20px;
    border: none;
    padding: 8px;
    background-color: @m3_surface_container;
}}
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
/* Spec dışı, kullanıcı isteği ("androidde gradient pill var, flatpakda
   yok"): Android tarafı ekranın en üstündeki balonu daha açık, alttakini
   mevcut renginde gösterip aralarında KAYDIRMAYA bağlı bir gradyan çiziyor
   (bkz. Android MergedBubbleDecoration) — GTK4'te balonlar tek tek widget'lar
   olduğundan (RecyclerView'ın tek bir Canvas'a çizdiği dekorasyon gibi bir
   mekanizma yok) kaydırma konumuna göre HEPSİNİ yeniden boyayan bir eşdeğer,
   her scroll adımında tüm balon arka planlarını elle yeniden hesaplamayı
   gerektirirdi. Onun yerine burada HER balonun KENDİ içinde üstten alta
   doğru bir gradyan var — aynı görsel "düz değil, hafif katmanlı" hissini
   çok daha ucuza veriyor. */
.bubble {{ border-radius: 20px; }}
.bubble-mine {{
    background-image: linear-gradient(
        to bottom,
        alpha(@m3_on_primary_container, 0.08) 0%,
        alpha(@m3_on_primary_container, 0.0) 60%
    );
    background-color: @m3_primary_container;
    color: @m3_on_primary_container;
    border-bottom-right-radius: 6px;
}}
.bubble-theirs {{
    background-image: linear-gradient(
        to bottom,
        alpha(@m3_on_surface, 0.06) 0%,
        alpha(@m3_on_surface, 0.0) 60%
    );
    background-color: @m3_surface_high;
    color: @m3_on_surface;
    border-bottom-left-radius: 6px;
}}
.bubble-mine .dim-label {{ opacity: 0.85; }}
/* Spec dışı, kullanıcı isteği ("merging message bubles on linux? ... internal
   corner fillet is important as well, do it cheaper way" — bkz.
   `chat.rs` `BUBBLE_GROUP_WINDOW_MS`/`mark_group_seam` dosya başı notları):
   art arda aynı göndericiden gelen balonlar birbirine değen kenarlarda
   küçük bir yarıçapa düşer (WhatsApp/Telegram'ın kendi grup görünümüyle
   AYNI yaklaşım) — `.bubble-mine`/`.bubble-theirs`'in TEK köşeyi küçülten
   "kuyruk" kuralından DAHA ÖZGÜL olduğundan, o kuralı gerektiğinde
   sorunsuzca ezer. */
.bubble.continued-top {{ border-top-left-radius: 6px; border-top-right-radius: 6px; }}
.bubble.continued-bottom {{ border-bottom-left-radius: 6px; border-bottom-right-radius: 6px; }}
/* Aynı gruptaki balonlar arasındaki boşluğu daraltır — `.chat-messages`
   listesinin kendi (6px) `spacing`'inin üzerine binen negatif bir üst
   dolgu. */
.bubble-row-continued {{ margin-top: -4px; }}
/* Genişlik farkı olan bir dikişteki "iç bükey" çentik — bkz. `mark_group_seam`
   dosya başı notu (GTK CSS'te web'deki `::before`/`::after` sözde-öğe
   karşılığı olmadığından bu gerçek, ayrı bir widget). Arka planla AYNI ton:
   duvarkağıdı ayarlıysa (bkz. `wallpaper` değişkeni) o dokunun üzerine düz
   bir yama gibi oturur — bilinen, kabul edilmiş küçük bir sınır (ucuz
   yöntemin bedeli, bkz. dosya başı notu). */
.bubble-seam-notch {{ background-color: @m3_surface; border-radius: 9999px; }}
/* Spec dışı, kullanıcı isteği ("gönderilen resim/videolar kenarları
   yuvarlatılmış ve ince bir border ile görünsün" — Android `ShapeableImageView
   strokeWidth`): burada sadece köşe yarıçapı vardı, çerçeve YOKTU. */
.attachment-preview {{
    border-radius: 14px;
    border: 1px solid @m3_outline_variant;
}}
.sticker {{ border-radius: 8px; }}
/* Current in-chat search hit. */
.bubble-match {{ outline: 2px solid @m3_primary; outline-offset: 2px; }}
"#
    )
}
