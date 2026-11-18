//! On-device QR decoding of camera frames (D-0110, D-0116): what the camera sees is
//! attacker-chosen. Never panics, never reads past the buffer, only bounded UTF-8 text comes out.
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_camera::qr;

fuzz_target!(|data: &[u8]| {
    // The first four bytes choose the shape: width and height up to 255, a stride of up to 15
    // extra bytes, and a whole upscale factor of 1 to 8 (so frames up to 2,040 a side reach the
    // scaling path and finder-dense patterns repeat). The rest are the pixels, so lengths that
    // do not fit are exercised too.
    let Some((shape, pixels)) = data.split_first_chunk::<4>() else { return };
    let (w, h) = (usize::from(shape[0]), usize::from(shape[1]));
    let stride = w + usize::from(shape[2] & 0x0F);
    let factor = usize::from(shape[3] & 0x07) + 1;
    if factor == 1 {
        for text in qr::decode_grey(w, h, stride, pixels) {
            assert!(text.len() < 8 * 1024);
        }
        return;
    }
    if w == 0 || h == 0 || stride.checked_mul(h).is_none_or(|n| pixels.len() < n) {
        return;
    }
    let (bw, bh) = (w * factor, h * factor);
    let mut big = vec![0u8; bw * bh];
    for y in 0..bh {
        for x in 0..bw {
            big[y * bw + x] = pixels[(y / factor) * stride + x / factor];
        }
    }
    for text in qr::decode_grey(bw, bh, bw, &big) {
        assert!(text.len() < 8 * 1024);
    }
});
