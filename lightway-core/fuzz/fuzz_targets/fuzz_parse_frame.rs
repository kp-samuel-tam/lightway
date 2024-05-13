#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut b = bytes::BytesMut::from(data);
    lightway_core::fuzz_frame_parse(&mut b);
});
