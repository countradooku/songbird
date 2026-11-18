//! On-device QR decoding of camera frames (D-0110): what the camera sees is attacker-chosen.
//! Never panics, never reads past the buffer, only bounded UTF-8 text comes out.
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_camera::qr;

fuzz_target!(|data: &[u8]| {
    // The first four bytes choose the shape (up to 255×255, a stride of up to 15 extra
    // bytes); the rest are the pixels, so lengths that do not fit are exercised too.
    let Some((shape, pixels)) = data.split_first_chunk::<4>() else { return };
    let width = usize::from(shape[0]);
    let height = usize::from(shape[1]);
    let stride = width + usize::from(shape[2] & 0x0F);
    for text in qr::decode_grey(width, height, stride, pixels) {
        assert!(text.len() < 8 * 1024);
    }
});
