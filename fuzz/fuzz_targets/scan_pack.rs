#![no_main]
//! Raw bytes into the pack entry-header scanner (run before `git index-pack`). Small limits keep
//! each run bounded: no entry inflates past 64 KiB.
//! Run from the repository root: cargo +nightly fuzz run scan_pack -- -max_total_time=60
use libfuzzer_sys::fuzz_target;
use pushgate::scan::{ScanLimits, check};

fuzz_target!(|data: &[u8]| {
    let lim = ScanLimits {
        oid_len: if data.first().is_some_and(|b| b & 1 == 1) { 32 } else { 20 },
        max_delta: 1 << 16,
        max_object: 1 << 16,
        deadline: None,
    };
    let _ = check(data, lim);
});
