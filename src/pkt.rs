//! pkt-line framing, the receive-pack request header (ref commands), and the two rewrites the
//! proxy needs: adding a capability to the ref advertisement and building a report-status refusal.
//!
//! Everything here reads raw client bytes, so it never panics on any input (fuzzed and proptested).

/// Largest pkt-line, including the 4-byte length.
pub const MAX_PKT: usize = 65520;
/// Largest payload of one pkt-line.
pub const MAX_PKT_DATA: usize = MAX_PKT - 4;
/// The flush-pkt.
pub const FLUSH: &[u8] = b"0000";

/// One pkt-line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pkt<'a> {
    /// `0000`
    Flush,
    /// `0001`
    Delim,
    /// `0002`
    ResponseEnd,
    /// A data line, without its length prefix.
    Data(&'a [u8]),
}

/// Why a request header or advertisement could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// The input ends inside a pkt-line.
    #[error("request ends inside a pkt-line")]
    Truncated,
    /// A pkt-line length is not four hex digits, or is a reserved value.
    #[error("bad pkt-line length")]
    BadLength,
    /// A pkt-line payload is over [`MAX_PKT_DATA`] bytes.
    #[error("pkt-line payload over {MAX_PKT_DATA} bytes")]
    TooLong,
    /// A ref command line is malformed; the text says how.
    #[error("bad ref command: {0}")]
    BadCommand(&'static str),
    /// A signed push (`push-cert`), which the proxy does not support.
    #[error("signed pushes (push-cert) are not supported")]
    PushCert,
}

fn hex_value(b: u8) -> Option<usize> {
    match b {
        b'0'..=b'9' => Some(usize::from(b - b'0')),
        b'a'..=b'f' => Some(usize::from(b - b'a' + 10)),
        b'A'..=b'F' => Some(usize::from(b - b'A' + 10)),
        _ => None,
    }
}

/// Reads one pkt-line from the start of `buf`; returns it and the number of bytes it took.
pub fn read_pkt(buf: &[u8]) -> Result<(Pkt<'_>, usize), ParseError> {
    let Some(prefix) = buf.get(..4) else {
        return Err(ParseError::Truncated);
    };
    let mut len = 0usize;
    for &b in prefix {
        len = len * 16 + hex_value(b).ok_or(ParseError::BadLength)?;
    }
    match len {
        0 => Ok((Pkt::Flush, 4)),
        1 => Ok((Pkt::Delim, 4)),
        2 => Ok((Pkt::ResponseEnd, 4)),
        3 => Err(ParseError::BadLength),
        n if n > MAX_PKT => Err(ParseError::BadLength),
        n => buf
            .get(4..n)
            .map(|d| (Pkt::Data(d), n))
            .ok_or(ParseError::Truncated),
    }
}

/// Frames `data` as one pkt-line.
pub fn encode(data: &[u8]) -> Result<Vec<u8>, ParseError> {
    if data.len() > MAX_PKT_DATA {
        return Err(ParseError::TooLong);
    }
    let mut out = format!("{:04x}", data.len() + 4).into_bytes();
    out.extend_from_slice(data);
    Ok(out)
}

/// Appends `data` as one pkt-line, cutting it at [`MAX_PKT_DATA`]. Only for lines the proxy
/// builds itself, which are far shorter.
fn push_pkt(out: &mut Vec<u8>, data: &[u8]) {
    let data = &data[..data.len().min(MAX_PKT_DATA)];
    out.extend_from_slice(format!("{:04x}", data.len() + 4).as_bytes());
    out.extend_from_slice(data);
}

/// One ref update: `<old> <new> <ref>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    /// The ref's current value as the client sees it (hex); all zeros for a create.
    pub old: String,
    /// The value to set (hex); all zeros for a delete.
    pub new: String,
    /// The full ref name, for example `refs/heads/main`.
    pub refname: String,
}

fn is_zero(oid: &str) -> bool {
    oid.bytes().all(|b| b == b'0')
}

impl Command {
    /// The new value is the zero id.
    pub fn is_delete(&self) -> bool {
        is_zero(&self.new)
    }

    /// The old value is the zero id.
    pub fn is_create(&self) -> bool {
        is_zero(&self.old)
    }
}

/// The start of a git-receive-pack request body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PushRequest {
    /// The ref updates, in order.
    pub commands: Vec<Command>,
    /// Capabilities sent after the first command, for example `report-status`.
    pub caps: Vec<String>,
    /// `shallow <oid>` lines sent before the commands.
    pub shallow: Vec<String>,
    /// Push options (`git push -o`), if any were sent.
    pub push_options: Vec<String>,
    /// Offset of the pack (or the end of input) after the commands and push options.
    pub pack_offset: usize,
}

impl PushRequest {
    /// The client asked for capability `cap`.
    pub fn has_cap(&self, cap: &str) -> bool {
        self.caps.iter().any(|c| c == cap)
    }
}

fn valid_oid(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn valid_ref(s: &str) -> bool {
    s.starts_with("refs/") && s.len() < 1024 && s.bytes().all(|b| b > 0x20 && b != 0x7f)
}

fn strip_lf(d: &[u8]) -> &[u8] {
    d.strip_suffix(b"\n").unwrap_or(d)
}

/// Parses the start of a git-receive-pack request body:
/// `[shallow <oid>]* <old> <new> <ref>\0<caps> (<old> <new> <ref>)* flush [push-option* flush] PACK...`
///
/// A body of just a flush-pkt (git's auth probe before a large push) gives zero commands.
pub fn parse_push(buf: &[u8]) -> Result<PushRequest, ParseError> {
    let mut req = PushRequest::default();
    let mut pos = 0;
    loop {
        let (pkt, n) = read_pkt(buf.get(pos..).unwrap_or_default())?;
        pos += n;
        let data = match pkt {
            Pkt::Flush => break,
            Pkt::Data(d) => d,
            Pkt::Delim | Pkt::ResponseEnd => {
                return Err(ParseError::BadCommand("unexpected special packet"));
            }
        };
        let line = strip_lf(data);
        if line.starts_with(b"push-cert") {
            return Err(ParseError::PushCert);
        }
        if let Some(oid) = line.strip_prefix(b"shallow ") {
            let oid =
                std::str::from_utf8(oid).map_err(|_| ParseError::BadCommand("shallow oid"))?;
            if !valid_oid(oid) || !req.commands.is_empty() {
                return Err(ParseError::BadCommand("bad shallow line"));
            }
            req.shallow.push(oid.to_string());
            continue;
        }
        let (cmd, caps) = match line.iter().position(|&b| b == 0) {
            Some(i) => (&line[..i], Some(&line[i + 1..])),
            None => (line, None),
        };
        if let Some(caps) = caps {
            if !req.commands.is_empty() {
                return Err(ParseError::BadCommand(
                    "capabilities after the first command",
                ));
            }
            let caps = std::str::from_utf8(caps)
                .map_err(|_| ParseError::BadCommand("capabilities not utf-8"))?;
            req.caps = caps
                .split(' ')
                .filter(|c| !c.is_empty())
                .map(str::to_string)
                .collect();
        }
        let cmd = std::str::from_utf8(cmd).map_err(|_| ParseError::BadCommand("not utf-8"))?;
        let mut parts = cmd.splitn(3, ' ');
        let (Some(old), Some(new), Some(refname)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(ParseError::BadCommand("expected `old new ref`"));
        };
        if !valid_oid(old) || !valid_oid(new) || old.len() != new.len() {
            return Err(ParseError::BadCommand("bad object id"));
        }
        if !valid_ref(refname) {
            return Err(ParseError::BadCommand("bad ref name"));
        }
        req.commands.push(Command {
            old: old.into(),
            new: new.into(),
            refname: refname.into(),
        });
    }
    if req.has_cap("push-options") {
        loop {
            let (pkt, n) = read_pkt(buf.get(pos..).unwrap_or_default())?;
            pos += n;
            match pkt {
                Pkt::Flush => break,
                Pkt::Data(d) => req
                    .push_options
                    .push(String::from_utf8_lossy(strip_lf(d)).into_owned()),
                Pkt::Delim | Pkt::ResponseEnd => {
                    return Err(ParseError::BadCommand("unexpected packet in push options"));
                }
            }
        }
    }
    req.pack_offset = pos;
    Ok(req)
}

/// Adds `cap` to the capability list on the first ref line of a smart-HTTP ref advertisement
/// (`# service=...` pkt, flush, first ref with `\0caps`). Leaves it alone if already there.
pub fn add_capability(adv: &[u8], cap: &str) -> Result<Vec<u8>, ParseError> {
    let mut out = Vec::with_capacity(adv.len() + cap.len() + 1);
    let mut pos = 0;
    let mut done = false;
    while pos < adv.len() {
        let (pkt, n) = read_pkt(&adv[pos..])?;
        let raw = &adv[pos..pos + n];
        pos += n;
        let Pkt::Data(d) = pkt else {
            out.extend_from_slice(raw);
            continue;
        };
        let body = strip_lf(d);
        match body.iter().position(|&b| b == 0) {
            Some(nul) if !done => {
                let caps = &body[nul + 1..];
                let mut line = body.to_vec();
                if !caps.split(|&b| b == b' ').any(|c| c == cap.as_bytes()) {
                    if !caps.is_empty() {
                        line.push(b' ');
                    }
                    line.extend_from_slice(cap.as_bytes());
                }
                line.push(b'\n');
                out.extend(encode(&line)?);
                done = true;
            }
            _ => out.extend_from_slice(raw),
        }
    }
    Ok(out)
}

/// Longest reason put in one `ng` line.
const MAX_REASON: usize = 1000;

fn clean(s: &str) -> String {
    let mut s = s.replace(['\n', '\r', '\0'], " ");
    if s.len() > MAX_REASON {
        let mut end = MAX_REASON;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
    s
}

/// Builds a receive-pack response that refuses every command, so `git push` prints
/// `! [remote rejected] <ref> (<reason>)` for each ref. `reasons[i]` is the reason for
/// `commands[i]`; a ref without one was refused because another ref in the same push was.
/// With no commands, the summary goes into the unpack status instead.
pub fn rejection(
    caps: &[String],
    commands: &[Command],
    reasons: &[Option<String>],
    summary: &str,
) -> Vec<u8> {
    let summary = clean(summary);
    let mut inner = Vec::new();
    if commands.is_empty() {
        push_pkt(&mut inner, format!("unpack {summary}\n").as_bytes());
    } else {
        push_pkt(&mut inner, b"unpack ok\n");
        for (i, c) in commands.iter().enumerate() {
            let reason = reasons
                .get(i)
                .and_then(Option::as_deref)
                .unwrap_or("another ref in this push was refused");
            let line = format!("ng {} {}\n", clean(&c.refname), clean(reason));
            push_pkt(&mut inner, line.as_bytes());
        }
    }
    inner.extend_from_slice(FLUSH);

    let has = |c: &str| caps.iter().any(|x| x == c);
    let chunk = if has("side-band-64k") {
        MAX_PKT_DATA - 1
    } else if has("side-band") {
        1000 - 5
    } else {
        return inner;
    };
    let mut out = Vec::new();
    let mut msg = vec![2u8];
    msg.extend_from_slice(format!("git-proxy: push refused: {summary}\n").as_bytes());
    push_pkt(&mut out, &msg);
    for part in inner.chunks(chunk) {
        let mut p = Vec::with_capacity(part.len() + 1);
        p.push(1u8);
        p.extend_from_slice(part);
        push_pkt(&mut out, &p);
    }
    out.extend_from_slice(FLUSH);
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use proptest::prelude::*;

    const A: &str = "1111111111111111111111111111111111111111";
    const B: &str = "2222222222222222222222222222222222222222";

    fn request(
        cmds: &[(String, String, String)],
        caps: &str,
        opts: &[String],
        pack: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, (o, n, r)) in cmds.iter().enumerate() {
            let line = if i == 0 {
                format!("{o} {n} {r}\0{caps}\n")
            } else {
                format!("{o} {n} {r}\n")
            };
            out.extend(encode(line.as_bytes()).unwrap());
        }
        out.extend_from_slice(FLUSH);
        if !opts.is_empty() {
            for o in opts {
                out.extend(encode(format!("{o}\n").as_bytes()).unwrap());
            }
            out.extend_from_slice(FLUSH);
        }
        out.extend_from_slice(pack);
        out
    }

    #[test]
    fn parses_a_real_shaped_request() {
        let body = request(
            &[(A.into(), B.into(), "refs/heads/agent/t1".into())],
            "report-status side-band-64k agent=git/2.56",
            &[],
            b"PACKxyz",
        );
        let req = parse_push(&body).unwrap();
        assert_eq!(req.commands[0].refname, "refs/heads/agent/t1");
        assert!(req.has_cap("side-band-64k"));
        assert_eq!(&body[req.pack_offset..], b"PACKxyz");
    }

    #[test]
    fn probe_is_empty() {
        let req = parse_push(b"0000").unwrap();
        assert!(req.commands.is_empty());
        assert_eq!(req.pack_offset, 4);
    }

    #[test]
    fn push_cert_is_refused() {
        let mut body = encode(b"push-cert\0report-status\n").unwrap();
        body.extend_from_slice(FLUSH);
        assert_eq!(parse_push(&body), Err(ParseError::PushCert));
    }

    #[test]
    fn adds_no_thin() {
        let mut adv = encode(b"# service=git-receive-pack\n").unwrap();
        adv.extend_from_slice(FLUSH);
        adv.extend(
            encode(format!("{A} refs/heads/main\0report-status delete-refs\n").as_bytes()).unwrap(),
        );
        adv.extend_from_slice(FLUSH);
        let out = add_capability(&adv, "no-thin").unwrap();
        let text = String::from_utf8_lossy(&out);
        assert!(
            text.contains("report-status delete-refs no-thin\n"),
            "{text}"
        );
        assert_eq!(add_capability(&out, "no-thin").unwrap(), out);
    }

    #[test]
    fn rejection_names_each_ref() {
        let cmds = [
            Command {
                old: A.into(),
                new: B.into(),
                refname: "refs/heads/main".into(),
            },
            Command {
                old: A.into(),
                new: B.into(),
                refname: "refs/heads/agent/t1".into(),
            },
        ];
        let out = rejection(&[], &cmds, &[Some("no\nmain".into())], "no main");
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("ng refs/heads/main no main\n"), "{text}");
        assert!(
            text.contains("ng refs/heads/agent/t1 another ref in this push was refused\n"),
            "{text}"
        );
    }

    fn oid() -> impl Strategy<Value = String> {
        "[0-9a-f]{40}"
    }
    fn refname() -> impl Strategy<Value = String> {
        "refs/(heads|tags)/[a-z0-9/_.-]{1,40}"
    }

    proptest! {
        // The parser sees raw client bytes: it must never panic.
        #[test]
        fn never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = parse_push(&bytes);
            let _ = add_capability(&bytes, "no-thin");
        }

        // Valid-looking framing with junk inside must not panic either.
        #[test]
        fn never_panics_framed(lines in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..80), 0..6)) {
            let mut body = Vec::new();
            for l in &lines { body.extend(encode(l).unwrap()); }
            body.extend_from_slice(FLUSH);
            if let Ok(req) = parse_push(&body) {
                let reasons = vec![Some("x".to_string()); req.commands.len()];
                let _ = rejection(&req.caps, &req.commands, &reasons, "x");
            }
        }

        #[test]
        fn roundtrip(cmds in proptest::collection::vec((oid(), oid(), refname()), 1..5),
                     opts in proptest::collection::vec("[a-z=]{1,10}", 0..3),
                     pack in proptest::collection::vec(any::<u8>(), 0..64)) {
            let caps = if opts.is_empty() { "report-status" } else { "report-status push-options" };
            let body = request(&cmds, caps, &opts, &pack);
            let req = parse_push(&body).unwrap();
            prop_assert_eq!(req.commands.len(), cmds.len());
            for (c, (o, n, r)) in req.commands.iter().zip(&cmds) {
                prop_assert_eq!((&c.old, &c.new, &c.refname), (o, n, r));
            }
            prop_assert_eq!(&req.push_options, &opts);
            prop_assert_eq!(&body[req.pack_offset..], &pack[..]);
        }

        // Every prefix of a valid request is an error or a correct parse, never a panic.
        #[test]
        fn truncation(cmds in proptest::collection::vec((oid(), oid(), refname()), 1..3), cut in 0usize..400) {
            let body = request(&cmds, "report-status", &[], b"");
            let cut = cut.min(body.len());
            let _ = parse_push(&body[..cut]);
        }
    }
}
