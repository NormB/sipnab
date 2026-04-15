#![no_main]
use libfuzzer_sys::fuzz_target;
use sipnab::capture::websocket::unwrap_websocket_frame;

fuzz_target!(|data: &[u8]| {
    let _ = unwrap_websocket_frame(data);
});
