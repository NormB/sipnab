//! Fuzz the WebSocket frame unwrapper (SIP-over-WS transport). Arbitrary
//! bytes must be unwrapped to a payload or rejected without panicking or
//! over-reading on a malformed length/mask field.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sipnab::capture::websocket::unwrap_websocket_frame;

fuzz_target!(|data: &[u8]| {
    let _ = unwrap_websocket_frame(data);
});
