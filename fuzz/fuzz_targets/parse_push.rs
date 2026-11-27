#![no_main]
//! Raw client bytes into the ref-command parser, the refusal builder and the advertisement rewrite.
//! Run from the repository root: cargo +nightly fuzz run parse_push -- -max_total_time=60
//! (or `RUSTC_BOOTSTRAP=1 cargo fuzz run ...` on stable when nightly is older than rust-version).
use libfuzzer_sys::fuzz_target;
use pushgate::pkt;

fuzz_target!(|data: &[u8]| {
    if let Ok(req) = pkt::parse_push(data) {
        assert!(req.pack_offset <= data.len());
        let reasons = vec![Some("x".to_string()); req.commands.len()];
        let _ = pkt::rejection(&req.caps, &req.commands, &reasons, "x");
    }
    let _ = pkt::add_capability(data, "no-thin");
});
