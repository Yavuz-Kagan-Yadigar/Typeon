//! JPEG XL encoding, sticker checks, GIF/PNG conversion and frame decoding.

use super::*;

/// Largest image the JPEG XL paths take, in pixels: 64 MP is 256 MB as RGBA,
/// and a received file names its own size.
pub const MAX_IMAGE_PIXELS: u64 = 24_000_000;

/// A "hi-res" image attachment: lossless JPEG XL of 8-bit RGBA pixels, row
/// after row, not premultiplied. With `has_alpha` false the alpha bytes are
/// dropped first, in place: `rgba` is the caller's buffer and is changed.
pub fn encode_jxl_lossless(rgba: &mut [u8], width: u32, height: u32, has_alpha: bool, out: &Path) -> Result<(), String> {
    std::fs::write(out, jxl_codestream(rgba, width, height, has_alpha)?).map_err(|e| e.to_string())
}

pub(super) fn jxl_codestream(rgba: &mut [u8], width: u32, height: u32, has_alpha: bool) -> Result<Vec<u8>, String> {
    use zune_core::{bit_depth::BitDepth, colorspace::ColorSpace, options::EncoderOptions};
    let pixels = width as u64 * height as u64;
    if width < 2 || height < 2 || pixels > MAX_IMAGE_PIXELS || rgba.len() as u64 != pixels * 4 {
        return Err("Bad image size".to_string());
    }
    let pixels = pixels as usize;
    let (data, colorspace): (&[u8], ColorSpace) = if has_alpha {
        (&*rgba, ColorSpace::RGBA)
    } else {
        for i in 0..pixels {
            rgba.copy_within(i * 4..i * 4 + 3, i * 3);
        }
        (&rgba[..pixels * 3], ColorSpace::RGB)
    };
    let options = EncoderOptions::new(width as usize, height as usize, colorspace, BitDepth::Eight);
    let mut encoded = Vec::new();
    zune_jpegxl::JxlSimpleEncoder::new(data, options)
        .encode(&mut encoded)
        .map_err(|e| format!("JPEG XL: {e:?}"))?;
    Ok(encoded)
}

/// Most frames an animated image keeps; all frames together stay within
/// `MAX_IMAGE_PIXELS` too.
pub const MAX_ANIMATION_FRAMES: usize = 300;

/// LSB-first bit writer: the JPEG XL codestream and GIF's LZW codes both
/// pack bits this way.
#[derive(Default)]
pub(super) struct Bits { out: Vec<u8>, acc: u64, n: u32 }

impl Bits {
    pub(super) fn put(&mut self, nbits: u32, value: u64) {
        self.acc |= value << self.n;
        self.n += nbits;
        while self.n >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.n -= 8;
        }
    }
    pub(super) fn pad(&mut self) {
        if self.n > 0 {
            self.out.push(self.acc as u8);
            (self.acc, self.n) = (0, 0);
        }
    }
}

/// The image header zune-jpegxl writes (8-bit sRGB, RGB or RGBA), with
/// `animated` adding an animation of 1000 ticks per second, looping forever.
pub(super) fn jxl_image_header(width: u32, height: u32, alpha: bool, animated: bool) -> Vec<u8> {
    let mut b = Bits::default();
    b.put(16, 0x0AFF);
    b.put(1, 0); // not small
    let size = |b: &mut Bits, v: u32| {
        let v = u64::from(v - 1);
        let (sel, bits) = if v < 1 << 9 { (0, 9) } else if v < 1 << 13 { (1, 13) } else if v < 1 << 18 { (2, 18) } else { (3, 30) };
        b.put(2, sel);
        b.put(bits, v);
    };
    size(&mut b, height);
    b.put(3, 0); // no ratio: width follows
    size(&mut b, width);
    b.put(1, 0); // metadata not all_default
    b.put(1, u64::from(animated)); // extra_fields
    if animated {
        b.put(3, 0); // orientation 1
        b.put(1, 0); // no intrinsic size
        b.put(1, 0); // no preview
        b.put(1, 1); // animation:
        b.put(2, 1); // tps_numerator 1000
        b.put(2, 0); // tps_denominator 1
        b.put(2, 0); // num_loops 0 = forever
        b.put(1, 0); // no timecodes
    }
    b.put(1, 0); // integer samples
    b.put(2, 0); // 8 bits
    b.put(1, 1); // 16-bit buffers suffice
    if alpha {
        b.put(2, 1); // one extra channel
        b.put(1, 1); // default: 8-bit alpha
    } else {
        b.put(2, 0);
    }
    b.put(1, 0); // not XYB
    b.put(1, 1); // sRGB
    if animated {
        b.put(1, 1); // tone mapping all_default
    }
    b.put(2, 0); // no extensions
    b.put(1, 1); // default transform data
    b.pad();
    b.out
}

/// zune-jpegxl's frame header (one modular pass, kReplace) and its TOC.
/// `duration` (ticks) only in an animated image; a frame that is not the
/// last one is not kept as a reference.
pub(super) fn jxl_frame_header(alpha: bool, duration: Option<u32>, is_last: bool, toc: &[u64]) -> Vec<u8> {
    let mut b = Bits::default();
    b.put(1, 0); // not all_default
    b.put(2, 0); // regular frame
    b.put(1, 1); // modular
    b.put(2, 0); // no flags
    b.put(1, 0); // not YCbCr
    b.put(2, 0); // no upsampling
    if alpha {
        b.put(2, 0);
    }
    b.put(2, 1); // group size 256
    b.put(2, 0); // one pass
    b.put(1, 0); // no crop
    b.put(2, 0); // kReplace
    if alpha {
        b.put(2, 0);
    }
    if let Some(d) = duration {
        match d {
            0 => b.put(2, 0),
            1 => b.put(2, 1),
            2..=255 => { b.put(2, 2); b.put(8, u64::from(d)); }
            _ => { b.put(2, 3); b.put(32, u64::from(d)); }
        }
    }
    b.put(1, u64::from(is_last));
    if !is_last {
        b.put(2, 0); // save_as_reference 0
    }
    b.put(2, 0); // no name
    b.put(1, 0); // restoration filter not all_default
    b.put(1, 0); // no gaborish
    b.put(2, 0); // no EPF
    b.put(2, 0); // no LF extensions
    b.put(2, 0); // no FH extensions
    b.put(1, 0); // no TOC permutation
    b.pad();
    for &size in toc {
        if size < 1 << 10 {
            b.put(2, 0); b.put(10, size);
        } else if size - 1024 < 1 << 14 {
            b.put(2, 1); b.put(14, size - 1024);
        } else if size - 17408 < 1 << 22 {
            b.put(2, 2); b.put(22, size - 17408);
        } else {
            b.put(2, 3); b.put(30, size - 4211712);
        }
    }
    b.pad();
    b.out
}

/// an animated image as a lossless animated JPEG XL, no metadata.
/// `frames`: RGBA bytes each (as `encode_jxl_lossless`, changed in place),
/// `delays_ms` one per frame. zune-jpegxl writes single frames only: each is
/// encoded alone and its frame data is re-framed under an animated header.
/// The headers zune wrote are compared bit for bit with ours first, so a
/// zune update that changes them is an error, not a broken file.
pub fn encode_jxl_animated(frames: &mut [Vec<u8>], width: u32, height: u32, delays_ms: &[u32], has_alpha: bool, out: &Path) -> Result<(), String> {
    let pixels = width as u64 * height as u64;
    if frames.is_empty() || frames.len() > MAX_ANIMATION_FRAMES || frames.len() != delays_ms.len()
        || pixels * frames.len() as u64 > MAX_IMAGE_PIXELS
    {
        return Err("Too many frames or too large".to_string());
    }
    let plain_image = jxl_image_header(width, height, has_alpha, false);
    let plain_frame = jxl_frame_header(has_alpha, None, true, &[]);
    let (gx, gy) = ((width as u64).div_ceil(256), (height as u64).div_ceil(256));
    let toc_len = (if gx * gy == 1 { 1 } else { 2 + (width as u64).div_ceil(2048) * (height as u64).div_ceil(2048) + gx * gy }) as usize;
    let mut encoded = jxl_image_header(width, height, has_alpha, true);
    let count = frames.len();
    for (i, frame) in frames.iter_mut().enumerate() {
        let single = jxl_codestream(frame, width, height, has_alpha)?;
        let toc_at = plain_image.len() + plain_frame.len();
        if !single.starts_with(&plain_image) || single.get(plain_image.len()..toc_at) != Some(&plain_frame[..]) {
            return Err("JPEG XL: unexpected encoder header".to_string());
        }
        // Read the TOC back (same codes as `jxl_frame_header` writes).
        let (mut pos, mut toc) = (toc_at * 8, Vec::with_capacity(toc_len));
        let mut read = |n: usize| -> Option<u64> {
            let mut v = 0u64;
            for k in 0..n {
                let bit = (single.get((pos + k) / 8)? >> ((pos + k) % 8)) & 1;
                v |= u64::from(bit) << k;
            }
            pos += n;
            Some(v)
        };
        for _ in 0..toc_len {
            let size = match read(2) {
                Some(0) => read(10),
                Some(1) => read(14).map(|v| v + 1024),
                Some(2) => read(22).map(|v| v + 17408),
                Some(_) => read(30).map(|v| v + 4211712),
                None => None,
            };
            toc.push(size.ok_or("JPEG XL: short frame")?);
        }
        let data = &single[pos.div_ceil(8)..];
        if toc.iter().sum::<u64>() != data.len() as u64 {
            return Err("JPEG XL: unexpected encoder output".to_string());
        }
        let is_last = i + 1 == count;
        // Duration 0 would make the frame a hidden layer of the next one.
        encoded.extend(jxl_frame_header(has_alpha, Some(delays_ms[i].max(1)), is_last, &toc));
        encoded.extend_from_slice(data);
    }
    std::fs::write(out, encoded).map_err(|e| e.to_string())
}

/// A sticker: lossy JPEG XL (libjxl, quality 85), still or animated.
/// `frames` and `delays_ms` as `encode_jxl_animated` (one frame = a still;
/// the frames are changed in place when `has_alpha` is false).
pub fn encode_jxl_sticker(frames: &mut [Vec<u8>], width: u32, height: u32, delays_ms: &[u32], has_alpha: bool, out: &Path) -> Result<(), String> {
    use jpegxl_rs::encode::{Animation, EncoderFrame, ImageInfo};
    let pixels = width as u64 * height as u64;
    if width < 2 || height < 2 || frames.is_empty() || frames.len() > MAX_ANIMATION_FRAMES
        || (frames.len() > 1 && frames.len() != delays_ms.len())
        || pixels * frames.len() as u64 > MAX_IMAGE_PIXELS
        || frames.iter().any(|f| f.len() as u64 != pixels * 4)
    {
        return Err("Bad image size".to_string());
    }
    let animated = frames.len() > 1;
    // Effort 3: the default 7 took ~0.7 s per sticker on a phone; 3 is several
    // times faster for slightly larger files.
    let mut encoder = jpegxl_rs::encoder_builder().jpeg_quality(85.0).speed(jpegxl_rs::encode::EncoderSpeed::Falcon).has_alpha(has_alpha).build().map_err(|e| format!("JPEG XL: {e}"))?;
    let info = ImageInfo::builder().width(width).height(height).has_alpha(has_alpha)
        .maybe_animation(animated.then(|| Animation::builder().tps_numerator(1000).build()))
        .build();
    let mut session = encoder.session(&info).map_err(|e| format!("JPEG XL: {e}"))?;
    let channels = if has_alpha { 4 } else { 3 };
    let (frames_len, mut encoded) = (frames.len(), Vec::new());
    for (i, rgba) in frames.iter_mut().enumerate() {
        if !has_alpha {
            for p in 0..pixels as usize {
                rgba.copy_within(p * 4..p * 4 + 3, p * 3);
            }
        }
        let mut frame = EncoderFrame::new(&rgba[..pixels as usize * channels]).num_channels(channels as u32);
        if animated {
            // Duration 0 would make the frame a hidden layer of the next one.
            frame = frame.duration(delays_ms[i].max(1));
        }
        session.add_frame(&frame).map_err(|e| format!("JPEG XL: {e}"))?;
        // Encode each frame as it comes: libjxl would otherwise hold every
        // frame (as floats) until `finish`.
        if i + 1 < frames_len {
            encoded.extend(session.take_output().map_err(|e| format!("JPEG XL: {e}"))?);
        }
    }
    encoded.extend(session.finish().map_err(|e| format!("JPEG XL: {e}"))?);
    std::fs::write(out, encoded).map_err(|e| e.to_string())
}

/// Longest side of a sticker, in pixels.
pub const STICKER_MAX_SIDE: u32 = 600;
/// Largest sticker file. Lossless 600 px stills are well under; long
/// animations can pass it and are refused.
pub const MAX_STICKER_BYTES: u64 = 4 << 20;

/// A sticker file as it must be: a JPEG XL of at most `STICKER_MAX_SIDE`
/// pixels a side and `MAX_STICKER_BYTES`. Ok(animated).
pub fn sticker_check(src: &Path) -> Result<bool, String> {
    if std::fs::metadata(src).map_err(|e| e.to_string())?.len() > MAX_STICKER_BYTES {
        return Err("Sticker too large".to_string());
    }
    let image = jxl_oxide::JxlImage::builder().open(src).map_err(|e| format!("JPEG XL: {e}"))?;
    if image.width() > STICKER_MAX_SIDE || image.height() > STICKER_MAX_SIDE {
        return Err("Sticker larger than 600 px".to_string());
    }
    Ok(image.image_header().metadata.animation.is_some())
}

/// Whether a JPEG XL file says it is animated, from its headers only (the
/// first 64 KiB; a longer ICC profile reads as "not animated").
pub fn jxl_is_animated(src: &Path) -> bool {
    jxl_head_of(src).map_or(false, |(_, _, animated)| animated)
}

/// (width, height, animated) from the first 64 KiB of a JPEG XL file.
pub(super) fn jxl_head_of(src: &Path) -> Option<(u32, u32, bool)> {
    let mut head = Vec::new();
    File::open(src).and_then(|f| f.take(64 << 10).read_to_end(&mut head)).ok()?;
    jxl_head(&head)
}

/// (width, height, animated) from the start of a JPEG XL file, headers only.
/// None when they do not fit in `head`.
pub fn jxl_head(head: &[u8]) -> Option<(u32, u32, bool)> {
    use jxl_oxide::{InitializeResult, JxlImage};
    let mut image = JxlImage::builder().build_uninit();
    image.feed_bytes(head).ok()?;
    match image.try_init() {
        Ok(InitializeResult::Initialized(i)) => Some((i.width(), i.height(), i.image_header().metadata.animation.is_some())),
        _ => None,
    }
}

/// Largest JPEG XL file decoded: `open` reads the whole file into the
/// decoder before any size check.
pub(super) const MAX_JXL_DECODE_BYTES: u64 = 256 << 20;

/// The checks before a JPEG XL decode: file size, and the pixel count from
/// the headers, so a huge image is refused before `open` reads it all.
pub(super) fn jxl_decode_allowed(src: &Path) -> Result<(), String> {
    if std::fs::metadata(src).map_err(|e| e.to_string())?.len() > MAX_JXL_DECODE_BYTES {
        return Err("Image too large".to_string());
    }
    if let Some((w, h, _)) = jxl_head_of(src) {
        if w as u64 * h as u64 > MAX_IMAGE_PIXELS {
            return Err("Image too large".to_string());
        }
    }
    Ok(())
}

/// GIF LZW image data of palette indices (8-bit minimum code size), as
/// sub-blocks. Code width and table reset follow gifenc.
pub(super) fn gif_lzw(indices: &[u8], out: &mut Vec<u8>) {
    const CLEAR: u64 = 256;
    out.push(8);
    let mut dict: std::collections::HashMap<(u16, u8), u16> = std::collections::HashMap::new();
    let (mut next, mut size) = (258u16, 9u32);
    let mut b = Bits::default();
    b.put(size, CLEAR);
    let mut cur: Option<u16> = None;
    for &px in indices {
        let Some(c) = cur else {
            cur = Some(u16::from(px));
            continue;
        };
        if let Some(&code) = dict.get(&(c, px)) {
            cur = Some(code);
            continue;
        }
        b.put(size, u64::from(c));
        if next < 4096 {
            if u32::from(next) == 1 << size {
                size += 1;
            }
            dict.insert((c, px), next);
            next += 1;
        } else {
            b.put(size, CLEAR);
            dict.clear();
            (next, size) = (258, 9);
        }
        cur = Some(u16::from(px));
    }
    if let Some(c) = cur {
        b.put(size, u64::from(c));
    }
    b.put(size, 257); // end of information
    b.pad();
    for block in b.out.chunks(255) {
        out.push(block.len() as u8);
        out.extend_from_slice(block);
    }
    out.push(0);
}

/// See `jxl_to_gif`.
pub const GIF_MAX_FRAMES: usize = 100;

/// Median-cut palette of up to 255 colours from a sample of the opaque pixels.
pub(super) fn median_cut_palette(pixels: &[[u8; 3]], opaque: &[bool]) -> Vec<[u8; 3]> {
    let step = (pixels.len() / 16384).max(1);
    let mut sample: Vec<[u8; 3]> = pixels.iter().zip(opaque).step_by(step).filter(|x| *x.1).map(|x| *x.0).collect();
    if sample.is_empty() {
        return vec![[0; 3]];
    }
    let spread = |s: &[[u8; 3]]| -> (u8, usize) {
        (0..3).map(|c| {
            let (lo, hi) = s.iter().fold((255u8, 0u8), |(l, h), p| (l.min(p[c]), h.max(p[c])));
            (hi - lo, c)
        }).max().unwrap()
    };
    // (lo, hi, spread): a box's spread is computed once, when it is made.
    let mut boxes = vec![(0, sample.len(), spread(&sample))];
    while boxes.len() < 255 {
        let Some(bi) = (0..boxes.len()).filter(|&i| boxes[i].1 - boxes[i].0 > 1 && boxes[i].2.0 > 0)
            .max_by_key(|&i| boxes[i].2.0) else { break };
        let (lo, hi, (_, c)) = boxes[bi];
        sample[lo..hi].sort_unstable_by_key(|p| p[c]);
        let mid = (lo + hi) / 2;
        boxes[bi] = (lo, mid, spread(&sample[lo..mid]));
        boxes.push((mid, hi, spread(&sample[mid..hi])));
    }
    boxes.iter().map(|&(lo, hi, _)| {
        let n = (hi - lo) as u32;
        [0, 1, 2].map(|c| (sample[lo..hi].iter().map(|p| u32::from(p[c])).sum::<u32>() / n) as u8)
    }).collect()
}

/// a received animated JPEG XL as an animated GIF for the viewers
/// (neither Android nor GTK plays JPEG XL). Each frame gets its own median-cut
/// local palette (255 colours + index 255 transparent; alpha below half is
/// transparent). ponytail: no dithering; palette from ~16k sampled pixels, pixels
/// map through a 15-bit nearest-colour cache.
/// At most `GIF_MAX_FRAMES` frames are written (evenly picked, each kept frame
/// lasting the frames it stands for): the per-frame palette work is the cost.
pub fn jxl_to_gif(src: &Path, out: &Path) -> Result<(), String> {
    use jxl_oxide::{AllocTracker, EnumColourEncoding, JxlImage, RenderingIntent};
    jxl_decode_allowed(src)?;
    let mut image = JxlImage::builder()
        .alloc_tracker(AllocTracker::with_limit(512 << 20))
        .open(src)
        .map_err(|e| format!("JPEG XL: {e}"))?;
    image.request_color_encoding(EnumColourEncoding::srgb(RenderingIntent::Relative));
    let (width, height) = (image.width(), image.height());
    let frames = image.num_loaded_keyframes();
    if width > u16::MAX as u32 || height > u16::MAX as u32 || frames > MAX_ANIMATION_FRAMES
        || width as u64 * height as u64 * frames as u64 > MAX_IMAGE_PIXELS
    {
        return Err("Image too large".to_string());
    }
    if frames == 0 {
        return Err("JPEG XL: no frame".to_string());
    }
    // Ticks to centiseconds; a still image gets no delay.
    let (tps_num, tps_den) = image.image_header().metadata.animation.as_ref()
        .map_or((1, 0), |a| (u64::from(a.tps_numerator).max(1), u64::from(a.tps_denominator)));
    const TRANSPARENT: u8 = 255;
    let mut gif = b"GIF89a".to_vec();
    gif.extend_from_slice(&(width as u16).to_le_bytes());
    gif.extend_from_slice(&(height as u16).to_le_bytes());
    gif.extend_from_slice(&[0, 0, 0]); // no global table: every frame has its own
    gif.extend_from_slice(b"\x21\xFF\x0BNETSCAPE2.0\x03\x01\0\0\0"); // loop forever
    let mut row = Vec::new();
    let mut indices = Vec::with_capacity(width as usize * height as usize);
    let mut pixels: Vec<[u8; 3]> = Vec::with_capacity(width as usize * height as usize);
    let mut opaque: Vec<bool> = Vec::with_capacity(width as usize * height as usize);
    let out_frames = frames.min(GIF_MAX_FRAMES);
    for j in 0..out_frames {
        let k = j * frames / out_frames;
        let span = ((j + 1) * frames / out_frames - k) as u64;
        let render = image.render_frame(k).map_err(|e| format!("JPEG XL: {e}"))?;
        let mut stream = render.stream();
        let ch = stream.channels() as usize;
        if !(1..=4).contains(&ch) || (stream.width(), stream.height()) != (width, height) {
            return Err("JPEG XL: unexpected frame layout".to_string());
        }
        let has_alpha = ch == 2 || ch == 4;
        row.resize(width as usize * ch, 0);
        pixels.clear();
        opaque.clear();
        for _ in 0..height {
            let mut filled = 0;
            while filled < row.len() {
                let n = stream.write_to_buffer(&mut row[filled..]);
                if n == 0 {
                    return Err("JPEG XL: frame ended early".to_string());
                }
                filled += n;
            }
            for p in row.chunks(ch) {
                pixels.push(if ch >= 3 { [p[0], p[1], p[2]] } else { [p[0]; 3] });
                opaque.push(!(has_alpha && p[ch - 1] < 128));
            }
        }
        let palette = median_cut_palette(&pixels, &opaque);
        let mut cache = vec![u8::MAX; 1 << 15]; // 5 bits a channel; 255 = unfilled (never a real index)
        indices.clear();
        for (p, &o) in pixels.iter().zip(&opaque) {
            indices.push(if !o {
                TRANSPARENT
            } else {
                let key = (usize::from(p[0] >> 3) << 10) | (usize::from(p[1] >> 3) << 5) | usize::from(p[2] >> 3);
                if cache[key] == u8::MAX {
                    cache[key] = (0..palette.len()).min_by_key(|&i| {
                        (0..3).map(|c| (i32::from(palette[i][c]) - i32::from(p[c])).pow(2)).sum::<i32>()
                    }).unwrap_or(0) as u8;
                }
                cache[key]
            });
        }
        // u128: `tps_den` and the duration come from the file, their product
        // overflowed u64.
        let delay = (u128::from(render.duration()) * u128::from(span) * u128::from(tps_den) * 100 / u128::from(tps_num))
            .min(u16::MAX as u128) as u16;
        // Disposal 2 (clear) under transparency, else 1 (keep).
        let packed = if has_alpha { 2 << 2 | 1 } else { 1 << 2 };
        gif.extend_from_slice(&[0x21, 0xF9, 4, packed]);
        gif.extend_from_slice(&delay.to_le_bytes());
        gif.extend_from_slice(&[TRANSPARENT, 0, 0x2C, 0, 0, 0, 0]);
        gif.extend_from_slice(&(width as u16).to_le_bytes());
        gif.extend_from_slice(&(height as u16).to_le_bytes());
        gif.push(0x87); // local table of 256 colours
        for i in 0..256 {
            gif.extend_from_slice(&palette.get(i).copied().unwrap_or([0; 3]));
        }
        gif_lzw(&indices, &mut gif);
    }
    gif.push(0x3B);
    std::fs::write(out, gif).map_err(|e| e.to_string())
}

/// `conv(src, out)` unless `out` exists; written to a temp name and renamed, so
/// a half-written `out` is never reused. `out` named by content hash = one
/// conversion for identical files.
pub fn convert_cached(src: &Path, out: &Path, conv: fn(&Path, &Path) -> Result<(), String>) -> Result<(), String> {
    if out.exists() {
        return Ok(());
    }
    let tmp = out.with_file_name(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let r = conv(src, &tmp).and_then(|()| std::fs::rename(&tmp, out).map_err(|e| e.to_string()));
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r
}

/// A received JPEG XL as PNG: no Android version decodes JPEG XL, and the
/// Linux viewer takes the common formats only. The file is the sender's: its
/// size is checked before the frame is rendered, and the decoder's
/// allocations are capped.
/// The frames of an animated JPEG XL as straight RGBA plus each frame's
/// duration in ms, at most `GIF_MAX_FRAMES` (evenly picked, like `jxl_to_gif`).
/// For a player that stops after a few loops (the desktop sticker bubble).
pub fn jxl_frames_rgba(src: &Path) -> Result<(u32, u32, Vec<(Vec<u8>, u32)>), String> {
    use jxl_oxide::{AllocTracker, EnumColourEncoding, JxlImage, RenderingIntent};
    jxl_decode_allowed(src)?;
    let mut image = JxlImage::builder()
        .alloc_tracker(AllocTracker::with_limit(512 << 20))
        .open(src)
        .map_err(|e| format!("JPEG XL: {e}"))?;
    image.request_color_encoding(EnumColourEncoding::srgb(RenderingIntent::Relative));
    let (width, height) = (image.width(), image.height());
    let frames = image.num_loaded_keyframes();
    if frames == 0 || frames > MAX_ANIMATION_FRAMES || width as u64 * height as u64 * frames as u64 > MAX_IMAGE_PIXELS {
        return Err("Image too large".to_string());
    }
    let (tps_num, tps_den) = image.image_header().metadata.animation.as_ref()
        .map_or((1, 0), |a| (u64::from(a.tps_numerator).max(1), u64::from(a.tps_denominator)));
    let out_frames = frames.min(GIF_MAX_FRAMES);
    let mut out = Vec::with_capacity(out_frames);
    let mut row = Vec::new();
    for j in 0..out_frames {
        let k = j * frames / out_frames;
        let span = ((j + 1) * frames / out_frames - k) as u64;
        let render = image.render_frame(k).map_err(|e| format!("JPEG XL: {e}"))?;
        let mut stream = render.stream();
        let ch = stream.channels() as usize;
        if !(1..=4).contains(&ch) || (stream.width(), stream.height()) != (width, height) {
            return Err("JPEG XL: unexpected frame layout".to_string());
        }
        row.resize(width as usize * ch, 0);
        let mut rgba = Vec::with_capacity(width as usize * height as usize * 4);
        for _ in 0..height {
            let mut filled = 0;
            while filled < row.len() {
                let n = stream.write_to_buffer(&mut row[filled..]);
                if n == 0 {
                    return Err("JPEG XL: frame ended early".to_string());
                }
                filled += n;
            }
            for p in row.chunks(ch) {
                let (r, g, b) = if ch >= 3 { (p[0], p[1], p[2]) } else { (p[0], p[0], p[0]) };
                let a = if ch == 2 || ch == 4 { p[ch - 1] } else { 255 };
                rgba.extend_from_slice(&[r, g, b, a]);
            }
        }
        let ms = (u128::from(render.duration()) * u128::from(span) * u128::from(tps_den) * 1000 / u128::from(tps_num))
            .min(u32::MAX as u128) as u32;
        out.push((rgba, ms));
    }
    Ok((width, height, out))
}

pub fn jxl_to_png(src: &Path, out: &Path) -> Result<(), String> {
    use jxl_oxide::{AllocTracker, EnumColourEncoding, JxlImage, PixelFormat, RenderingIntent};
    jxl_decode_allowed(src)?;
    let mut image = JxlImage::builder()
        .alloc_tracker(AllocTracker::with_limit(512 << 20))
        .open(src)
        .map_err(|e| format!("JPEG XL: {e}"))?;
    // The PNG carries no colour profile: render in sRGB.
    image.request_color_encoding(EnumColourEncoding::srgb(RenderingIntent::Relative));
    if image.width() as u64 * image.height() as u64 > MAX_IMAGE_PIXELS {
        return Err("Image too large".to_string());
    }
    let color = match image.pixel_format() {
        PixelFormat::Gray => png::ColorType::Grayscale,
        PixelFormat::Graya => png::ColorType::GrayscaleAlpha,
        PixelFormat::Rgb => png::ColorType::Rgb,
        PixelFormat::Rgba => png::ColorType::Rgba,
        _ => return Err("Unsupported JPEG XL colour format".to_string()),
    };
    if image.num_loaded_keyframes() == 0 {
        return Err("JPEG XL: no frame".to_string());
    }
    let render = image.render_frame(0).map_err(|e| format!("JPEG XL: {e}"))?;
    let mut stream = render.stream();
    let (width, height) = (stream.width(), stream.height());
    if stream.channels() as usize != color.samples() {
        return Err("JPEG XL: unexpected channel count".to_string());
    }
    let mut encoder = png::Encoder::new(std::io::BufWriter::new(File::create(out).map_err(|e| e.to_string())?), width, height);
    encoder.set_color(color);
    encoder.set_depth(png::BitDepth::Eight);
    // The default level spent ~4/5 of a hi-res open on zlib (13.8 MP: 1.86 s
    // against 0.08 s on a desktop); the file is ~50 % larger.
    encoder.set_compression(png::Compression::Fast);
    let mut writer = encoder.write_header().map_err(|e| e.to_string())?;
    // Row by row: no second full-size buffer next to the rendered frame.
    let mut rows = writer.stream_writer().map_err(|e| e.to_string())?;
    let mut row = vec![0u8; width as usize * color.samples()];
    for _ in 0..height {
        let mut filled = 0;
        while filled < row.len() {
            let n = stream.write_to_buffer(&mut row[filled..]);
            if n == 0 {
                return Err("JPEG XL: frame ended early".to_string());
            }
            filled += n;
        }
        rows.write_all(&row).map_err(|e| e.to_string())?;
    }
    rows.finish().map_err(|e| e.to_string())
}
