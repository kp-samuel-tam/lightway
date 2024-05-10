#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut buf = bytes::BytesMut::from(data);
    loop {
        match lightway_core::Header::try_from_wire(&mut buf) {
            Ok(h) => {
                let mut buf = bytes::BytesMut::new();
                h.append_to_wire(&mut buf);
            }
            Err(lightway_core::FromWireError::InsufficientData) => break,
            Err(_) => {}
        }
    }
});
