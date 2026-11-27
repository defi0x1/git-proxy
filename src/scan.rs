//! A bounded scan of a pack's entry headers, run before `git index-pack` so a small push cannot
//! make the proxy materialise huge objects. It reads each entry's type and size, inflates each
//! zlib stream no further than its declared size (to find where the next entry starts), and for
//! deltas reads the declared result size from the start of the delta data.

use std::io::{BufRead, Read};
use std::time::Instant;

/// Refusal text when pack inspection runs past its deadline.
pub(crate) const TIMED_OUT: &str = "pack inspection took too long (over 30 s); push less at once";

/// Bounds for [`check`].
#[derive(Debug, Clone, Copy)]
pub struct ScanLimits {
    /// Object id length in bytes (20 for SHA-1, 32 for SHA-256), for `REF_DELTA` entries.
    pub oid_len: usize,
    /// Largest delta (data and declared result size).
    pub max_delta: u64,
    /// Largest whole (non-delta) object.
    pub max_object: u64,
    /// Give up (refuse) past this instant.
    pub deadline: Option<Instant>,
}

fn corrupt(what: &str) -> String {
    format!("pack is corrupt ({what})")
}

fn byte(r: &mut impl Read) -> Result<u8, String> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b)
        .map_err(|_| corrupt("truncated entry header"))?;
    Ok(b[0])
}

/// A delta header varint (7 bits per byte, little-endian) from `buf`; `None` if short or too long.
fn delta_varint(buf: &[u8]) -> Option<(u64, &[u8])> {
    let mut v = 0u64;
    for (i, &b) in buf.iter().enumerate().take(10) {
        let shift = 7 * i as u32;
        let part = u64::from(b & 0x7f);
        if shift >= 64 || (part << shift) >> shift != part {
            return None;
        }
        v |= part << shift;
        if b & 0x80 == 0 {
            return Some((v, &buf[i + 1..]));
        }
    }
    None
}

/// Checks every entry of the pack read from `r` against `lim`; returns the entry count, or the
/// refusal text. Reads no further than the last entry (the trailing checksum is left unread).
pub fn check<R: BufRead>(mut r: R, lim: ScanLimits) -> Result<u32, String> {
    let late = || lim.deadline.is_some_and(|d| Instant::now() >= d);
    let mut head = [0u8; 12];
    if r.read_exact(&mut head[..4]).is_err() || &head[..4] != b"PACK" {
        return Err("data after the ref commands is not a pack".into());
    }
    r.read_exact(&mut head[4..])
        .map_err(|_| corrupt("short pack header"))?;
    let version = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
    if version != 2 && version != 3 {
        return Err(corrupt("unsupported pack version"));
    }
    let count = u32::from_be_bytes([head[8], head[9], head[10], head[11]]);
    let mut buf = [0u8; 8192];
    for _ in 0..count {
        if late() {
            return Err(TIMED_OUT.into());
        }
        let mut b = byte(&mut r)?;
        let kind = (b >> 4) & 7;
        let mut size = u64::from(b & 0x0f);
        let mut shift = 4u32;
        while b & 0x80 != 0 {
            b = byte(&mut r)?;
            let part = u64::from(b & 0x7f);
            if shift >= 64 || (part << shift) >> shift != part {
                return Err(corrupt("object size overflows"));
            }
            size |= part << shift;
            shift += 7;
        }
        let delta = match kind {
            1..=4 => false,
            6 => {
                // Base offset: big-endian 7-bit groups; a u64 needs at most 10.
                let mut n = 0;
                while byte(&mut r)? & 0x80 != 0 {
                    n += 1;
                    if n >= 10 {
                        return Err(corrupt("delta base offset overflows"));
                    }
                }
                true
            }
            7 => {
                let mut oid = [0u8; 64];
                let oid = oid
                    .get_mut(..lim.oid_len)
                    .ok_or_else(|| corrupt("bad object id length"))?;
                r.read_exact(oid)
                    .map_err(|_| corrupt("truncated delta base"))?;
                true
            }
            _ => return Err(corrupt("unknown object type")),
        };
        let limit = if delta { lim.max_delta } else { lim.max_object };
        if size > limit {
            return Err(format!(
                "an object in the pack is {size} bytes, over the {limit} byte limit"
            ));
        }

        // Inflate no further than the declared size; keep the first bytes of a delta.
        let mut z = flate2::bufread::ZlibDecoder::new(&mut r);
        let mut first = [0u8; 20];
        let mut total = 0u64;
        loop {
            if late() {
                return Err(TIMED_OUT.into());
            }
            let n = z
                .read(&mut buf)
                .map_err(|_| corrupt("bad compressed data"))?;
            if n == 0 {
                break;
            }
            if let Some(dst) = first.get_mut(total as usize..) {
                let k = dst.len().min(n);
                dst[..k].copy_from_slice(&buf[..k]);
            }
            total += n as u64;
            if total > size {
                return Err(corrupt("object inflates past its declared size"));
            }
        }
        if total != size {
            return Err(corrupt("object is shorter than its declared size"));
        }
        if delta {
            let kept = &first[..first.len().min(total as usize)];
            let result = delta_varint(kept)
                .and_then(|(_, rest)| delta_varint(rest))
                .map(|(v, _)| v)
                .ok_or_else(|| corrupt("bad delta header"))?;
            if result > lim.max_delta {
                return Err(format!(
                    "a delta in the pack expands to {result} bytes, over the {} byte limit",
                    lim.max_delta
                ));
            }
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::io::Write;

    const LIM: ScanLimits = ScanLimits {
        oid_len: 20,
        max_delta: 100,
        max_object: 1000,
        deadline: None,
    };

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(data).unwrap();
        z.finish().unwrap()
    }

    fn pack(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let mut p = b"PACK\0\0\0\x02".to_vec();
        p.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        for (h, d) in entries {
            p.extend_from_slice(h);
            p.extend(zlib(d));
        }
        p.extend_from_slice(&[0; 20]);
        p
    }

    #[test]
    fn accepts_small_and_refuses_big() {
        let blob = (vec![0x35], b"hello".to_vec()); // blob, size 5
        assert_eq!(check(&pack(std::slice::from_ref(&blob))[..], LIM), Ok(1));
        // REF_DELTA, 4 bytes of delta data declaring a 5 -> 200 byte result.
        let delta = (
            [vec![0x74], vec![0xab; 20]].concat(),
            vec![5, 0xc8, 0x01, 0x00],
        );
        let e = check(&pack(&[blob, delta])[..], LIM).unwrap_err();
        assert!(e.contains("expands to 200 bytes"), "{e}");
        // A blob declaring 2000 bytes (0xb0 0x7d: 0 | 125 << 4).
        let e = check(&pack(&[(vec![0xb0, 0x7d], vec![0; 2000])])[..], LIM).unwrap_err();
        assert!(e.contains("2000 bytes"), "{e}");
        // Declared size smaller than the data.
        let e = check(&pack(&[(vec![0x33], b"hello".to_vec())])[..], LIM).unwrap_err();
        assert!(e.contains("corrupt"), "{e}");
        assert!(check(&b"PACX"[..], LIM).is_err());
        assert!(check(&b"PACK\0\0\0\x02\0\0\0\x05\x35"[..], LIM).is_err());
    }
}
