use super::*;

#[test]
fn jpeg_trailer_and_png_text_are_dropped() {
    let path = std::env::temp_dir().join(format!("typeon-meta-{}", std::process::id()));
    // SOI, APP0, SOS, entropy data with a stuffed byte and a restart
    // marker, a DHT between scans, a second SOS, EOI, then a trailer.
    let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0, 0, 7, b'J', b'F', b'I', b'F', 0, 0xFF, 0xDA, 0, 3, 9, 0x11, 0xFF, 0x00, 0x22, 0xFF, 0xD3, 0x33];
    jpeg.extend_from_slice(&[0xFF, 0xC4, 0, 3, 7, 0xFF, 0xDA, 0, 3, 9, 0x44, 0xFF, 0xD9]);
    let eoi = jpeg.len() as u64;
    jpeg.extend_from_slice(b"MOTIONPHOTO");
    std::fs::write(&path, &jpeg).unwrap();
    let (ranges, _) = jpeg_metadata_ranges(&mut File::open(&path).unwrap()).unwrap();
    assert_eq!(ranges, vec![(eoi, jpeg.len() as u64)]);

    let chunk = |kind: &[u8; 4], body: &[u8]| {
        let mut c = (body.len() as u32).to_be_bytes().to_vec();
        c.extend_from_slice(kind);
        c.extend_from_slice(body);
        c.extend_from_slice(&[0; 4]);
        c
    };
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend(chunk(b"IHDR", &[0; 13]));
    let text_at = png.len() as u64;
    png.extend(chunk(b"tEXt", b"GPS"));
    let text_end = png.len() as u64;
    png.extend(chunk(b"pHYs", &[0; 9]));
    let private_at = png.len() as u64;
    png.extend(chunk(b"caBX", b"c2pa"));
    let private_end = png.len() as u64;
    png.extend(chunk(b"IDAT", &[1, 2]));
    png.extend(chunk(b"IEND", &[]));
    std::fs::write(&path, &png).unwrap();
    assert_eq!(png_metadata_ranges(&mut File::open(&path).unwrap()), Some(vec![(text_at, text_end), (private_at, private_end)]));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn jxl_exif_and_xml_boxes_are_dropped() {
    let path = std::env::temp_dir().join(format!("typeon-jxl-{}", std::process::id()));
    let boxed = |kind: &[u8; 4], body: &[u8]| {
        let mut b = (body.len() as u32 + 8).to_be_bytes().to_vec();
        b.extend_from_slice(kind);
        b.extend_from_slice(body);
        b
    };
    let mut jxl = b"\0\0\0\x0CJXL \r\n\x87\n".to_vec();
    jxl.extend(boxed(b"ftyp", b"jxl \0\0\0\0jxl "));
    let exif_at = jxl.len() as u64;
    jxl.extend(boxed(b"Exif", b"\0\0\0\0GPS!"));
    jxl.extend(boxed(b"xml ", b"<x/>"));
    jxl.extend(boxed(b"jbrd", b"IPTC"));
    let xml_end = jxl.len() as u64;
    jxl.extend(boxed(b"jxlc", &[0xFF, 0x0A, 1, 2]));
    std::fs::write(&path, &jxl).unwrap();
    assert_eq!(jxl_metadata_ranges(&mut File::open(&path).unwrap()), Some(vec![(exif_at, exif_at + 16), (exif_at + 16, exif_at + 28), (exif_at + 28, xml_end)]));

    std::fs::write(&path, [0xFF, 0x0A, 1, 2, 3]).unwrap();
    assert_eq!(jxl_metadata_ranges(&mut File::open(&path).unwrap()), Some(vec![]));

    jxl.truncate(jxl.len() - 2);
    std::fs::write(&path, &jxl).unwrap();
    assert_eq!(jxl_metadata_ranges(&mut File::open(&path).unwrap()), None);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn webp_exif_and_xmp_chunks_are_dropped() {
    let path = std::env::temp_dir().join(format!("typeon-webp-{}", std::process::id()));
    let chunk = |kind: &[u8; 4], body: &[u8]| {
        let mut c = kind.to_vec();
        c.extend_from_slice(&(body.len() as u32).to_le_bytes());
        c.extend_from_slice(body);
        if body.len() % 2 == 1 {
            c.push(0);
        }
        c
    };
    let mut body = b"WEBP".to_vec();
    body.extend(chunk(b"VP8X", &[0x0C, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    body.extend(chunk(b"VP8L", &[1, 2, 3, 4]));
    let exif_at = 8 + body.len() as u64;
    body.extend(chunk(b"EXIF", b"GPS"));
    body.extend(chunk(b"XMP ", b"<x/>"));
    let mut webp = b"RIFF".to_vec();
    webp.extend_from_slice(&(body.len() as u32).to_le_bytes());
    webp.extend(body);
    std::fs::write(&path, &webp).unwrap();
    let (ranges, patched) = webp_metadata_ranges(&mut File::open(&path).unwrap()).unwrap();
    // EXIF: 8 + 3 + 1 pad, XMP: 8 + 4.
    assert_eq!(ranges, vec![(exif_at, exif_at + 12), (exif_at + 12, exif_at + 24)]);
    assert_eq!(u32::from_le_bytes(patched[4..8].try_into().unwrap()) as u64, exif_at - 8);
    assert_eq!(patched[20], 0);
    // A RIFF that is not a WebP is left alone; a cut WebP is refused.
    std::fs::write(&path, b"RIFF\x04\0\0\0WAVE").unwrap();
    assert_eq!(webp_metadata_ranges(&mut File::open(&path).unwrap()), Some((vec![], vec![])));
    std::fs::write(&path, &webp[..webp.len() - 2]).unwrap();
    assert_eq!(webp_metadata_ranges(&mut File::open(&path).unwrap()), None);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn plain_chunks_read_back_give_the_file_hash() {
    let base = std::env::temp_dir().join(format!("typeon-att-{}", std::process::id()));
    let (src, enc) = (base.with_extension("src"), base.with_extension("enc"));
    std::fs::write(&src, vec![7u8; 40]).unwrap();
    let key = [1u8; 32];
    let (total, sha) = encrypt_file_to_disk_with(&src, &enc, &key, 16).unwrap();
    let mut hasher = Sha256::new();
    for i in 0..total_chunks_with(total, 16) {
        hasher.update(read_plain_chunk_with(&enc, i, &key, 16).unwrap());
    }
    assert_eq!(hex::encode(hasher.finalize()), sha);
    assert!(read_plain_chunk_with(&enc, 0, &[2u8; 32], 16).is_err());
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&enc);
}

#[test]
fn chunk_hashes_cover_each_chunk_group() {
    assert_eq!((chunks_per_hash(0), chunk_hashes_len(0)), (1, 0));
    assert_eq!((chunks_per_hash(4096), chunk_hashes_len(4096)), (1, 4096 * 32));
    // 4 GiB at 256 KiB: groups of 4 chunks, 4096 entries.
    assert_eq!((chunks_per_hash(16384), chunk_hashes_len(16384)), (4, 4096 * 32));
    assert_eq!(chunk_hashes_len(4097), 2049 * 32);
    let base = std::env::temp_dir().join(format!("typeon-hashes-{}", std::process::id()));
    let (src, enc) = (base.with_extension("src"), base.with_extension("enc"));
    std::fs::write(&src, vec![7u8; 40]).unwrap();
    let (total, _) = encrypt_file_to_disk_with(&src, &enc, &[1u8; 32], 16).unwrap();
    let n = total_chunks_with(total, 16);
    let hashes = chunk_hashes_of(&enc, n, 16).unwrap();
    assert_eq!(hashes.len(), chunk_hashes_len(n));
    // One chunk per entry here: each entry is the hash of that chunk's ciphertext.
    for i in 0..n {
        let ct = read_chunk_from_disk_with(&enc, i, 16).unwrap().unwrap();
        assert_eq!(&hashes[i as usize * 32..][..32], Sha256::digest(&ct).as_slice());
    }
    // Another file key gives other chunks: they do not match.
    let other = base.with_extension("enc2");
    encrypt_file_to_disk_with(&src, &other, &[2u8; 32], 16).unwrap();
    assert_ne!(chunk_hashes_of(&other, n, 16).unwrap(), hashes);
    for p in [&src, &enc, &other] {
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn hi_res_jpeg_xl_opens_as_the_same_pixels() {
    let base = std::env::temp_dir().join(format!("typeon-jxl-{}", std::process::id()));
    let (jxl, out) = (base.with_extension("jxl"), base.with_extension("png"));
    let (w, h) = (7u32, 5u32);
    let rgba: Vec<u8> = (0..w * h * 4).map(|i| (i * 37 % 251) as u8).collect();
    for has_alpha in [true, false] {
        encode_jxl_lossless(&mut rgba.clone(), w, h, has_alpha, &jxl).unwrap();
        jxl_to_png(&jxl, &out).unwrap();
        let mut reader = png::Decoder::new(std::io::BufReader::new(File::open(&out).unwrap())).read_info().unwrap();
        let mut got = vec![0u8; reader.output_buffer_size().unwrap()];
        reader.next_frame(&mut got).unwrap();
        let want: Vec<u8> = if has_alpha {
            rgba.clone()
        } else {
            rgba.chunks(4).flat_map(|p| p[..3].to_vec()).collect()
        };
        assert_eq!(got, want, "alpha={has_alpha}");
    }
    assert!(encode_jxl_lossless(&mut vec![0; 4], 1, 1, true, &jxl).is_err(), "1x1");
    assert!(encode_jxl_lossless(&mut vec![0; 8], 2, 2, true, &jxl).is_err(), "short buffer");
    let _ = std::fs::remove_file(&jxl);
    let _ = std::fs::remove_file(&out);
}

#[test]
fn same_animation_one_gif_and_first_frame_png() {
    let dir = std::env::temp_dir().join(format!("typeon-animdedupe-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (w, h) = (9u32, 6u32);
    let frames: Vec<Vec<u8>> = (0..2u32).map(|f| (0..w * h * 4).map(|i| ((i + f * 5) * 31 % 251) as u8).collect()).collect();
    let (a, b) = (dir.join("a.jxl"), dir.join("b.jxl"));
    encode_jxl_animated(&mut frames.clone(), w, h, &[40, 40], true, &a).unwrap();
    std::fs::copy(&a, &b).unwrap();
    let gif = dir.join("anim-abc.gif");
    convert_cached(&a, &gif, jxl_to_gif).unwrap();
    let t = std::fs::metadata(&gif).unwrap().modified().unwrap();
    convert_cached(&b, &gif, jxl_to_gif).unwrap();
    assert_eq!(std::fs::metadata(&gif).unwrap().modified().unwrap(), t);
    let png = dir.join("first-abc.png");
    convert_cached(&a, &png, jxl_to_png).unwrap();
    let dec = png::Decoder::new(std::io::BufReader::new(File::open(&png).unwrap())).read_info().unwrap();
    assert_eq!((dec.info().width, dec.info().height), (w, h));
    let n = std::fs::read_dir(&dir).unwrap().count();
    assert_eq!(n, 4, "a, b, one gif, one png: no temp left");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn animated_jpeg_xl_keeps_every_frame_and_delay() {
    use jxl_oxide::JxlImage;
    let base = std::env::temp_dir().join(format!("typeon-anim-{}", std::process::id()));
    let (jxl, gif) = (base.with_extension("jxl"), base.with_extension("gif"));
    // 300 wide: two groups, so the multi-entry TOC path runs too; 600x400
    // runs the GIF LZW table resets.
    for (w, h, has_alpha) in [(7u32, 5u32, true), (300, 3, false), (600, 400, true)] {
        let frames: Vec<Vec<u8>> = (0..3u32).map(|f| (0..w * h * 4).map(|i| ((i + f * 11) * 37 % 251) as u8).collect()).collect();
        encode_jxl_animated(&mut frames.clone(), w, h, &[40, 300, 1000], has_alpha, &jxl).unwrap();
        let image = JxlImage::builder().open(&jxl).unwrap();
        assert_eq!(image.num_loaded_keyframes(), 3);
        for (k, want_ms) in [40u32, 300, 1000].into_iter().enumerate() {
            let render = image.render_frame(k).unwrap();
            assert_eq!(render.duration(), want_ms);
            let mut stream = render.stream();
            let mut got = vec![0u8; (w * h) as usize * stream.channels() as usize];
            stream.write_to_buffer(&mut got);
            let want: Vec<u8> = if has_alpha { frames[k].clone() } else { frames[k].chunks(4).flat_map(|p| p[..3].to_vec()).collect() };
            assert_eq!(got, want, "frame {k} {w}x{h}");
        }
        jxl_to_gif(&jxl, &gif).unwrap();
        let out = std::fs::read(&gif).unwrap();
        assert!(out.starts_with(b"GIF89a") && out.ends_with(&[0x3B]));
        assert_eq!(sticker_check(&jxl), Ok(true), "{w}x{h} is a sticker");
    }
    // Smooth gradient: first frame's local palette must be rich, not a 6x7x6 cube.
    let (w, h) = (256u32, 64u32);
    let grad: Vec<u8> = (0..w * h).flat_map(|i| { let x = (i % w) as u8; [x, x / 2 + 40, 255 - x, 255] }).collect();
    encode_jxl_animated(&mut vec![grad.clone(), grad.clone()], w, h, &[40, 40], false, &jxl).unwrap();
    jxl_to_gif(&jxl, &gif).unwrap();
    let g = std::fs::read(&gif).unwrap();
    let d = 13 + 19 + 8; // header, loop ext, GCE
    assert_eq!(g[d], 0x2C);
    assert_eq!(g[d + 9], 0x87);
    let pal: Vec<[u8; 3]> = g[d + 10..d + 10 + 768].chunks(3).map(|c| [c[0], c[1], c[2]]).collect();
    let distinct: std::collections::HashSet<_> = pal.iter().collect();
    assert!(distinct.len() > 64, "{} palette colours", distinct.len());
    // Every pixel is close to some palette colour (red channel spans 0..255).
    let err: u32 = (0..w).map(|x| pal.iter().map(|p| (i32::from(p[0]) - x as i32).unsigned_abs()).min().unwrap()).sum();
    assert!(err / w < 6, "mean red error {}", err / w);
    // More frames than `GIF_MAX_FRAMES`: capped, total duration kept.
    let many = 150;
    let tiny: Vec<Vec<u8>> = (0..many).map(|f| vec![f as u8; 2 * 2 * 4]).collect();
    encode_jxl_animated(&mut tiny.clone(), 2, 2, &vec![20; many], false, &jxl).unwrap();
    jxl_to_gif(&jxl, &gif).unwrap();
    let g = std::fs::read(&gif).unwrap();
    let (mut at, mut count, mut total_cs) = (13 + 19, 0usize, 0u32);
    while g[at] == 0x21 {
        total_cs += u32::from(u16::from_le_bytes([g[at + 4], g[at + 5]]));
        at += 8 + 10 + 768 + 1; // GCE, descriptor, local table, LZW code size
        while g[at] != 0 {
            at += 1 + g[at] as usize;
        }
        at += 1;
        count += 1;
    }
    assert_eq!(g[at], 0x3B);
    assert_eq!((count, total_cs), (GIF_MAX_FRAMES, 150 * 2));
    encode_jxl_lossless(&mut vec![9; 600 * 2 * 4], 600, 2, true, &jxl).unwrap();
    assert_eq!(sticker_check(&jxl), Ok(false), "still sticker");
    encode_jxl_lossless(&mut vec![9; 601 * 2 * 4], 601, 2, true, &jxl).unwrap();
    assert!(sticker_check(&jxl).is_err(), "601 px is too wide");
    std::fs::write(&jxl, b"not a jxl").unwrap();
    assert!(sticker_check(&jxl).is_err(), "not a JPEG XL");
    assert!(encode_jxl_animated(&mut [vec![0; 16]], 2, 2, &[], true, &jxl).is_err(), "delay count");
    let _ = std::fs::remove_file(&jxl);
    let _ = std::fs::remove_file(&gif);
}

#[test]
fn lossy_sticker_keeps_frames_and_is_smaller() {
    use jxl_oxide::JxlImage;
    let base = std::env::temp_dir().join(format!("typeon-lossy-{}", std::process::id()));
    let (lossy, lossless) = (base.with_extension("jxl"), base.with_extension("ll.jxl"));
    let (w, h) = (512u32, 512u32);
    // Noisy gradient: lossless cannot shrink the noise, lossy can.
    let mut seed = 1u32;
    let frames: Vec<Vec<u8>> = (0..3u32).map(|f| (0..w * h * 4).map(|i| {
        seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
        if i % 4 == 3 { 255 } else { ((i / 4 % w + f * 20) / 3 + (seed >> 28)) as u8 }
    }).collect()).collect();
    for has_alpha in [true, false] {
        encode_jxl_sticker(&mut frames[..1].to_vec(), w, h, &[], has_alpha, &lossy).unwrap();
        encode_jxl_lossless(&mut frames[0].clone(), w, h, has_alpha, &lossless).unwrap();
        let (a, b) = (std::fs::metadata(&lossy).unwrap().len(), std::fs::metadata(&lossless).unwrap().len());
        println!("still alpha={has_alpha}: lossy {a} B, lossless {b} B");
        assert!(a * 2 < b, "lossy {a} vs lossless {b}");
        assert_eq!(sticker_check(&lossy), Ok(false));
        let image = JxlImage::builder().open(&lossy).unwrap();
        assert_eq!((image.width(), image.height()), (w, h));
        image.render_frame(0).unwrap();
    }
    encode_jxl_sticker(&mut frames.clone(), w, h, &[40, 300, 1000], true, &lossy).unwrap();
    encode_jxl_animated(&mut frames.clone(), w, h, &[40, 300, 1000], true, &lossless).unwrap();
    let (a, b) = (std::fs::metadata(&lossy).unwrap().len(), std::fs::metadata(&lossless).unwrap().len());
    println!("animated: lossy {a} B, lossless {b} B");
    assert!(a * 2 < b, "lossy {a} vs lossless {b}");
    assert_eq!(sticker_check(&lossy), Ok(true));
    let image = JxlImage::builder().open(&lossy).unwrap();
    assert_eq!(image.num_loaded_keyframes(), 3);
    for (k, want_ms) in [40u32, 300, 1000].into_iter().enumerate() {
        assert_eq!(image.render_frame(k).unwrap().duration(), want_ms);
    }
    assert!(encode_jxl_sticker(&mut frames.clone(), w, h, &[40], true, &lossy).is_err(), "delay count");
    let _ = std::fs::remove_file(&lossy);
    let _ = std::fs::remove_file(&lossless);
}

#[test]
fn exif_is_cut_from_a_jpeg_and_a_doubtful_jpeg_is_refused() {
    let base = std::env::temp_dir().join(format!("typeon-jpg-{}", std::process::id()));
    let (src, enc) = (base.with_extension("src"), base.with_extension("enc"));
    let key = [1u8; 32];
    let sent = |bytes: &[u8]| -> Vec<u8> {
        std::fs::write(&src, bytes).unwrap();
        let (total, _) = encrypt_file_to_disk_with(&src, &enc, &key, 16).unwrap();
        let out: Vec<u8> = (0..total_chunks_with(total, 16)).flat_map(|i| read_plain_chunk_with(&enc, i, &key, 16).unwrap()).collect();
        assert_eq!(out.len() as u64, total);
        out
    };
    let soi = [0xFF, 0xD8];
    let jfif = [0xFF, 0xE0, 0, 7, b'J', b'F', b'I', b'F', 0];
    let exif = [0xFF, 0xE1, 0, 6, b'E', b'x', b'i', b'f'];
    let icc = [&[0xFF, 0xE2, 0, 14][..], b"ICC_PROFILE\0"].concat();
    let iptc = [0xFF, 0xED, 0, 4, b'P', b'S'];
    // a maker APPn (GoPro APP6) and a comment are cut too.
    let maker = [0xFF, 0xE6, 0, 7, b'G', b'o', b'P', b'r', b'o'];
    let com = [0xFF, 0xFE, 0, 4, b'h', b'i'];
    // An APP1 segment between scans is metadata too: cut as well.
    let scan = [0xFF, 0xDA, 0, 2, 1, 2, 0xFF, 0xD9];
    let scan_app1 = [0xFF, 0xDA, 0, 2, 1, 2, 0xFF, 0xE1, 0, 2, 0xFF, 0xD9];
    let photo = [&soi[..], &jfif, &exif, &icc, &iptc, &maker, &com, &scan_app1].concat();
    assert_eq!(sent(&photo), [&soi[..], &jfif, &icc, &scan].concat());
    // A rotated photo keeps its orientation, and only that.
    let rotated = b"\xFF\xE1\0\x32Exif\0\0II*\0\x08\0\0\0\x02\0\x0F\x01\x02\0\x01\0\0\0A\0\0\0\x12\x01\x03\0\x01\0\0\0\x06\0\0\0\0\0\0\0GPS!";
    assert_eq!(rotated.len(), 2 + 0x32);
    let photo = [&soi[..], &jfif, &rotated[..], &exif, &scan].concat();
    assert_eq!(sent(&photo), [&soi[..], &orientation_segment(6), &jfif, &scan].concat());
    assert_eq!(exif_orientation(&orientation_segment(6)[4..]), Some(6));
    // A segment longer than the file, or no start-of-scan: refused.
    for doubtful in [[&soi[..], &exif, &[0xFF, 0xE1, 0xFF, 0xFF, 1]].concat(), [&soi[..], &exif].concat()] {
        std::fs::write(&src, &doubtful).unwrap();
        assert!(encrypt_file_to_disk_with(&src, &enc, &key, 16).is_err());
    }
    // Not a JPEG: unchanged.
    let other = [&[0x89, b'P', b'N', b'G'][..], &exif].concat();
    assert_eq!(sent(&other), other);
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&enc);
}
