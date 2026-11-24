//! Metadata stripping (JPEG, PNG, JPEG XL, WebP) and EXIF orientation.

use super::*;

/// The byte ranges of the metadata segments of a JPEG file: every APPn segment
/// except the JFIF APP0, the ICC profile (APP2) and Adobe APP14, and every COM
/// segment (EXIF with the GPS position, XMP, IPTC, ...). The image data is
/// outside them. The EXIF orientation of the photo, if it is not the upright
/// one, is returned too: the caller puts that one tag back
/// (`orientation_segment`), or a photo taken rotated is shown as the sensor
/// stored it.
/// None for a file that is not a JPEG and on any doubt about its structure:
/// the caller then refuses to send it (fail closed, the EXIF may hold GPS).
pub(super) fn jpeg_metadata_ranges(file: &mut File) -> Option<(Vec<(u64, u64)>, Option<u8>)> {
    {
        let len = file.metadata().ok()?.len();
        let mut head = [0u8; 4];
        file.seek(SeekFrom::Start(0)).ok()?;
        if read_full(file, &mut head[..2]).ok()? != 2 || head[..2] != [0xFF, 0xD8] {
            return None;
        }
        let mut ranges = Vec::new();
        let mut orientation = None;
        let mut at: u64 = 2;
        // ponytail: 4096 segments; a real file has a few dozen.
        for _ in 0..4096 {
            file.seek(SeekFrom::Start(at)).ok()?;
            if read_full(file, &mut head).ok()? != 4 || head[0] != 0xFF {
                return None;
            }
            let marker = head[1];
            // Start of scan: the header is over, the rest is image data up to
            // the end-of-image marker. What follows it (a motion-photo video,
            // a second "multi-picture" JPEG with its own EXIF) is dropped.
            if marker == 0xDA {
                let eoi = jpeg_image_end(file, at, &mut ranges)?;
                if eoi < len {
                    ranges.push((eoi, len));
                }
                return Some((ranges, orientation));
            }
            // Only segments that carry a length are expected before the scan.
            let known = matches!(marker, 0xC0..=0xCF | 0xDB..=0xDF | 0xE0..=0xEF | 0xFE) && marker != 0xC8;
            let size = u16::from_be_bytes([head[2], head[3]]) as u64;
            let end = at.checked_add(2 + size)?;
            if !known || size < 2 || end > len {
                return None;
            }
            // Allow-list: of the APPn segments only a JFIF
            // APP0, an ICC APP2 and an Adobe APP14 stay; every other APPn
            // (EXIF, XMP, IPTC, MPF, maker blocks, JFXX thumbnails, JUMBF/C2PA)
            // and every COM goes.
            if matches!(marker, 0xE0..=0xEF | 0xFE) {
                let mut tag = [0u8; 12];
                let want = (size as usize - 2).min(tag.len());
                if read_full(file, &mut tag[..want]).ok()? != want {
                    return None;
                }
                let tag = &tag[..want];
                let keep = match marker {
                    // Only a JFIF APP0 without a thumbnail (length 16): the thumbnail can show the uncropped original.
                    0xE0 => tag.starts_with(b"JFIF\0") && size == 16,
                    0xE2 => tag.starts_with(b"ICC_PROFILE\0"),
                    0xEE => tag.starts_with(b"Adobe"),
                    _ => false,
                };
                if !keep {
                    ranges.push((at, end));
                }
                file.seek(SeekFrom::Start(at + 4)).ok()?;
            }
            if marker == 0xE1 && orientation.is_none() {
                let mut body = vec![0u8; size as usize - 2];
                if read_full(file, &mut body).ok()? != body.len() {
                    return None;
                }
                orientation = exif_orientation(&body);
            }
            at = end;
        }
        None
    }
}

/// The offset just past the end-of-image marker, scanning from the start-of-
/// scan segment at `sos`: entropy-coded data, and between progressive scans
/// further marker segments with a length. APPn and COM segments met between
/// scans go into `ranges` too.
pub(super) fn jpeg_image_end(file: &mut File, sos: u64, ranges: &mut Vec<(u64, u64)>) -> Option<u64> {
    let mut reader = std::io::BufReader::with_capacity(1 << 16, &mut *file);
    reader.seek(SeekFrom::Start(sos + 1)).ok()?;
    let mut at = sos + 1;
    let mut byte = [0u8; 1];
    let mut next = |reader: &mut std::io::BufReader<&mut File>, at: &mut u64| -> Option<u8> {
        reader.read_exact(&mut byte).ok()?;
        *at += 1;
        Some(byte[0])
    };
    // At a marker (0xFF already read): its code, then the segment if it has one.
    let mut marker_segment = true;
    loop {
        if marker_segment {
            // The 0xFF before the code.
            let start = at - 1;
            let code = next(&mut reader, &mut at)?;
            let mut len = [0u8; 2];
            len[0] = next(&mut reader, &mut at)?;
            len[1] = next(&mut reader, &mut at)?;
            let size = u16::from_be_bytes(len) as i64;
            if size < 2 || code == 0xD9 {
                return None;
            }
            reader.seek_relative(size - 2).ok()?;
            at += size as u64 - 2;
            if matches!(code, 0xE0..=0xEF | 0xFE) {
                ranges.push((start, at));
            }
            marker_segment = false;
        }
        if next(&mut reader, &mut at)? != 0xFF {
            continue;
        }
        let mut code = next(&mut reader, &mut at)?;
        while code == 0xFF {
            code = next(&mut reader, &mut at)?;
        }
        match code {
            0x00 | 0xD0..=0xD7 => {}
            0xD9 => return Some(at),
            _ => {
                // Back over the code: the segment branch reads it again.
                reader.seek_relative(-2).ok()?;
                at -= 2;
                next(&mut reader, &mut at)?;
                marker_segment = true;
            }
        }
    }
}

/// PNG ancillary chunks outside a short allow-list (text, time, `eXIf` with
/// the GPS position, private chunks), and anything after `IEND`. Image
/// chunks and the colour profile stay. None for a file that is not a PNG, and on any doubt.
pub(super) fn png_metadata_ranges(file: &mut File) -> Option<Vec<(u64, u64)>> {
    {
        let len = file.metadata().ok()?.len();
        let mut head = [0u8; 8];
        file.seek(SeekFrom::Start(0)).ok()?;
        if read_full(file, &mut head).ok()? != 8 || head != *b"\x89PNG\r\n\x1a\n" {
            return None;
        }
        let mut ranges = Vec::new();
        let mut at = 8u64;
        // ponytail: 1 << 16 chunks; real files have tens (APNG: frames x2).
        for _ in 0..1 << 16 {
            file.seek(SeekFrom::Start(at)).ok()?;
            if read_full(file, &mut head).ok()? != 8 {
                return None;
            }
            let end = at.checked_add(12 + u32::from_be_bytes(head[..4].try_into().ok()?) as u64)?;
            if end > len {
                return None;
            }
            match &head[4..8] {
                b"IEND" => {
                    if end < len {
                        ranges.push((end, len));
                    }
                    return Some(ranges);
                }
                // Allow-list: critical chunks (upper-case first
                // letter) and the ancillary chunks of image, colour and
                // animation stay; text, time, EXIF and every private or
                // unknown ancillary chunk (C2PA `caBX`, editor data) go.
                kind if kind[0].is_ascii_lowercase()
                    && !matches!(kind, b"tRNS" | b"gAMA" | b"cHRM" | b"sRGB" | b"iCCP" | b"sBIT" | b"pHYs" | b"bKGD" | b"acTL" | b"fcTL" | b"fdAT") =>
                {
                    ranges.push((at, end))
                }
                _ => {}
            }
            at = end;
        }
        None
    }
}

/// Every JPEG XL container box except the codestream and the frame/header
/// boxes (`ftyp`, `jxll`, `jxlc`, `jxlp`, `jxli`): so EXIF, XMP, JUMBF and
/// `brob` (Brotli-compressed) boxes go, and so does `jbrd`, the JPEG
/// reconstruction data that holds the source JPEG's other APP markers and
/// comments (IPTC, COM). Without it the image still decodes, only not back to
/// the exact JPEG bytes. A bare codestream has no metadata. None for other
/// files, and on any doubt.
pub(super) fn jxl_metadata_ranges(file: &mut File) -> Option<Vec<(u64, u64)>> {
    {
        let len = file.metadata().ok()?.len();
        let mut head = [0u8; 12];
        file.seek(SeekFrom::Start(0)).ok()?;
        let got = read_full(file, &mut head).ok()?;
        if got >= 2 && head[..2] == [0xFF, 0x0A] {
            return Some(Vec::new());
        }
        if got != 12 || head != *b"\0\0\0\x0CJXL \r\n\x87\n" {
            return None;
        }
        let mut ranges = Vec::new();
        let mut at = 12u64;
        // ponytail: 1 << 16 boxes; real files have a handful (jxlp parts at most).
        for _ in 0..1 << 16 {
            if at == len {
                return Some(ranges);
            }
            let mut h = [0u8; 16];
            file.seek(SeekFrom::Start(at)).ok()?;
            if read_full(file, &mut h[..8]).ok()? != 8 {
                return None;
            }
            let (header, size) = match u32::from_be_bytes(h[..4].try_into().ok()?) {
                1 => {
                    if read_full(file, &mut h[8..]).ok()? != 8 {
                        return None;
                    }
                    (16, u64::from_be_bytes(h[8..].try_into().ok()?))
                }
                0 => (8, len - at),
                s => (8, s as u64),
            };
            let end = at.checked_add(size)?;
            if size < header || end > len {
                return None;
            }
            // Allow-list, like the other formats: only the boxes that carry the image stay.
            let dropped = !matches!(&h[4..8], b"ftyp" | b"jxll" | b"jxlc" | b"jxlp" | b"jxli");
            if dropped {
                ranges.push((at, end));
            }
            at = end;
        }
        None
    }
}

/// WebP chunks other than image, alpha, animation and ICC (`EXIF`, `XMP `,
/// unknown ones), and anything after the RIFF data.
/// The second value is the patched start of the file that replaces the same
/// number of bytes: the RIFF size less the dropped chunks, and in a leading
/// `VP8X` chunk the EXIF/XMP flags cleared (a decoder may refuse a file whose
/// size or flags do not match). Empty when nothing is dropped, and for a RIFF
/// file that is not a WebP. None on any doubt about the structure.
pub(super) fn webp_metadata_ranges(file: &mut File) -> Option<(Vec<(u64, u64)>, Vec<u8>)> {
    let len = file.metadata().ok()?.len();
    let mut head = [0u8; 21];
    file.seek(SeekFrom::Start(0)).ok()?;
    let got = read_full(file, &mut head).ok()?;
    if got < 12 || &head[..4] != b"RIFF" {
        return None;
    }
    if &head[8..12] != b"WEBP" {
        return Some((Vec::new(), Vec::new()));
    }
    let riff_size = u32::from_le_bytes(head[4..8].try_into().ok()?);
    let riff_end = 8 + riff_size as u64;
    if riff_end < 12 || riff_end > len {
        return None;
    }
    let mut ranges = Vec::new();
    let mut dropped: u64 = 0;
    let mut vp8x = false;
    let mut at = 12u64;
    // ponytail: 1 << 16 chunks; real files have a handful (animations: one per frame).
    for _ in 0..1 << 16 {
        if at == riff_end {
            if riff_end < len {
                ranges.push((riff_end, len));
            }
            if dropped == 0 {
                return Some((ranges, Vec::new()));
            }
            // `dropped` is part of `riff_size`, so this cannot underflow.
            let mut patched = head[..if vp8x { 21 } else { 12 }].to_vec();
            patched[4..8].copy_from_slice(&(riff_size - dropped as u32).to_le_bytes());
            if vp8x {
                // Bit 3: EXIF present, bit 2: XMP present.
                patched[20] &= !0x0C;
            }
            return Some((ranges, patched));
        }
        let mut h = [0u8; 8];
        file.seek(SeekFrom::Start(at)).ok()?;
        if read_full(file, &mut h).ok()? != 8 {
            return None;
        }
        let size = u32::from_le_bytes(h[4..8].try_into().ok()?) as u64;
        // Chunks are padded to an even size.
        let end = at.checked_add(8 + size + (size & 1))?;
        if end > riff_end {
            return None;
        }
        match &h[..4] {
            b"VP8X" if at == 12 && size >= 10 && got == 21 => vp8x = true,
            // Allow-list: image, alpha, animation and colour
            // profile; EXIF, XMP and every unknown chunk go.
            b"VP8 " | b"VP8L" | b"VP8X" | b"ALPH" | b"ANIM" | b"ANMF" | b"ICCP" => {}
            _ => {
                ranges.push((at, end));
                dropped += end - at;
            }
        }
        at = end;
    }
    None
}

/// The orientation (2..=8, not the upright 1) in the body of an EXIF APP1
/// segment: tag 0x0112 of the first image directory.
pub(super) fn exif_orientation(body: &[u8]) -> Option<u8> {
    let tiff = body.strip_prefix(b"Exif\0\0")?;
    let big_endian = match tiff.get(..4)? {
        b"MM\0*" => true,
        b"II*\0" => false,
        _ => return None,
    };
    let u16_at = |at: usize| -> Option<u16> {
        let b: [u8; 2] = tiff.get(at..at.checked_add(2)?)?.try_into().ok()?;
        Some(if big_endian { u16::from_be_bytes(b) } else { u16::from_le_bytes(b) })
    };
    let dir_bytes: [u8; 4] = tiff.get(4..8)?.try_into().ok()?;
    let dir = (if big_endian { u32::from_be_bytes(dir_bytes) } else { u32::from_le_bytes(dir_bytes) }) as usize;
    for i in 0..u16_at(dir)? as usize {
        let entry = dir.checked_add(2 + 12 * i)?;
        if u16_at(entry)? == 0x0112 {
            let value = u16_at(entry.checked_add(8)?)?;
            return (2..=8).contains(&value).then_some(value as u8);
        }
    }
    None
}

/// An EXIF APP1 segment that holds the orientation and nothing else.
pub(super) fn orientation_segment(orientation: u8) -> [u8; 36] {
    let mut segment = *b"\xFF\xE1\0\x22Exif\0\0MM\0*\0\0\0\x08\0\x01\x01\x12\0\x03\0\0\0\x01\0\0\0\0\0\0\0\0";
    segment[29] = orientation;
    segment
}

/// Reads a file without the given ranges (sorted, not overlapping).
pub(super) struct SkipRanges {
    pub(super) file: File,
    pub(super) pos: u64,
    pub(super) ranges: std::collections::VecDeque<(u64, u64)>,
}

impl Read for SkipRanges {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut max = buf.len();
        while let Some(&(start, end)) = self.ranges.front() {
            if self.pos < start {
                max = max.min((start - self.pos) as usize);
                break;
            }
            self.file.seek(SeekFrom::Start(end))?;
            self.pos = end;
            self.ranges.pop_front();
        }
        let n = self.file.read(&mut buf[..max])?;
        self.pos += n as u64;
        Ok(n)
    }
}
