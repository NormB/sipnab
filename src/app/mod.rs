//! Application layer (WS2): the testable seams between the CLI binary and
//! the library — companion-server startup, batch running, and bootstrap
//! planning. `main.rs` should only parse arguments, build a plan, and
//! dispatch into this module.

pub mod servers;
