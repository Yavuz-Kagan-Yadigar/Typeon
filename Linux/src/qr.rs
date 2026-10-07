//! Device-link QR rendering.
//!
//! The payload is raw CBOR, exactly the bytes `build_device_link_request`
//! returns. The Android side encodes/decodes the same QR as ISO-8859-1 text
//! (`QrBinaryCodec`) purely because ZXing's API is String-shaped; on the wire
//! that is byte-for-byte identical to the QR byte mode this writes, and ZXing
//! decodes byte mode as ISO-8859-1 when no ECI is present. So a code produced
//! here round-trips through `QrScanActivity` unchanged.

use gtk::prelude::*;

/// A square, theme-independent QR widget. Always painted dark-on-white with a
/// quiet zone: a scanner pointed at an inverted "dark mode" QR will not read
/// it, so this deliberately ignores the desktop theme.
pub fn qr_widget(data: &[u8]) -> Option<gtk::DrawingArea> {
    // Low EC: the payload is a fingerprint plus a multiaddr, and the code is
    // being read off a bright screen from a few centimetres away. Lower EC
    // means fewer, larger modules, which scans faster.
    let code = qrcode::QrCode::with_error_correction_level(data, qrcode::EcLevel::L).ok()?;
    let width = code.width();
    let modules: Vec<bool> = code
        .to_colors()
        .into_iter()
        .map(|color| color == qrcode::Color::Dark)
        .collect();
    if width == 0 || modules.len() < width * width {
        return None;
    }

    let area = gtk::DrawingArea::new();
    area.set_hexpand(true);
    area.set_vexpand(true);
    area.set_draw_func(move |_, context, allocated_width, allocated_height| {
        // Four modules of quiet zone is the spec minimum; without it many
        // scanners never lock on.
        const QUIET_MODULES: f64 = 4.0;
        let side = allocated_width.min(allocated_height) as f64;
        if side <= 0.0 {
            return;
        }
        let total_modules = width as f64 + QUIET_MODULES * 2.0;
        let module_size = side / total_modules;
        let origin_x = (allocated_width as f64 - side) / 2.0;
        let origin_y = (allocated_height as f64 - side) / 2.0;

        context.set_source_rgb(1.0, 1.0, 1.0);
        context.rectangle(origin_x, origin_y, side, side);
        let _ = context.fill();

        context.set_source_rgb(0.0, 0.0, 0.0);
        for y in 0..width {
            for x in 0..width {
                if !modules[y * width + x] {
                    continue;
                }
                context.rectangle(
                    origin_x + (x as f64 + QUIET_MODULES) * module_size,
                    origin_y + (y as f64 + QUIET_MODULES) * module_size,
                    // Round up so neighbouring modules meet instead of leaving
                    // hairline gaps at fractional scales.
                    module_size.ceil(),
                    module_size.ceil(),
                );
            }
        }
        let _ = context.fill();
    });
    Some(area)
}
