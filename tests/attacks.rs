//! Crafted pushes that once got past the checks or stalled the proxy, kept as regression tests.
//! Each names one bypass or denial of service. Helpers are a trimmed copy of `tests/push.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pushgate::{
    Binding, Credential, Decision, FakeUpstream, GitProxy, Limits, Policy, PushEvent, pkt,
};

const USER: &str = "x-access-token";
const PASS: &str = "s3cret-installation-token";
const SECRET: &str = "per-session-secret-t1";
const ZERO: &str = "0000000000000000000000000000000000000000";

struct Env {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    up: FakeUpstream,
    events: Arc<Mutex<Vec<PushEvent>>>,
    proxy_port: u16,
    rt: tokio::runtime::Runtime,
}

impl Env {
    fn new() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        std::fs::create_dir_all(dir.join("up")).unwrap();
        std::fs::create_dir_all(dir.join("proxy-tmp")).unwrap();
        let bare = dir.join("up/repo.git");
        ok(git(
            &dir,
            &["init", "--bare", "-q", "-b", "main", bare.to_str().unwrap()],
        ));
        let seed = dir.join("seed");
        ok(git(&dir, &["init", "-q", "-b", "main", "seed"]));
        write(&seed, "README.md", b"hello\n");
        write(&seed, ".github/workflows/ci.yml", b"on: push\njobs: {}\n");
        commit(&seed, "seed");
        ok(git(&seed, &["push", "-q", bare.to_str().unwrap(), "main"]));

        let limits = Limits::default();
        let policy = Policy::new(["refs/heads/agent/*"]);
        let cred = Credential::basic(USER, PASS).unwrap();
        let up = FakeUpstream::new(dir.join("up"), cred.clone());
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let (up_l, px_l) = rt.block_on(async {
            (
                tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(),
                tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(),
            )
        });
        let up_port = up_l.local_addr().unwrap().port();
        let proxy_port = px_l.local_addr().unwrap().port();
        let upstream = format!("http://127.0.0.1:{up_port}/repo.git");
        let resolve = Arc::new(move |secret: &str| {
            (secret == SECRET).then(|| Binding {
                policy: policy.clone(),
                upstream: upstream.clone(),
                credential: cred.clone(),
                limits,
            })
        });
        let events = Arc::new(Mutex::new(Vec::new()));
        let ev = events.clone();
        let audit = Arc::new(move |e: &PushEvent| ev.lock().unwrap().push(e.clone()));
        let proxy = GitProxy::new(resolve, audit, dir.join("proxy-tmp")).unwrap();
        let up_router: axum::Router = up.router();
        rt.spawn(async move { axum::serve(up_l, up_router).await });
        let px_router: axum::Router = proxy.router();
        rt.spawn(async move { axum::serve(px_l, px_router).await });
        Env {
            _tmp: tmp,
            dir,
            up,
            events,
            proxy_port,
            rt,
        }
    }

    fn proxy_url(&self) -> String {
        format!("http://127.0.0.1:{}/git/{SECRET}/repo.git", self.proxy_port)
    }

    fn client(&self) -> PathBuf {
        let w = self.dir.join("w");
        ok(git(&self.dir, &["clone", "-q", &self.proxy_url(), "w"]));
        ok(git(&w, &["checkout", "-q", "-b", "agent/t1"]));
        w
    }

    fn upstream_ref(&self, r: &str) -> Option<String> {
        let o = git(
            &self.dir.join("up/repo.git"),
            &["rev-parse", "--verify", "-q", r],
        );
        o.status
            .success()
            .then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
    }

    fn last_decision(&self) -> Option<Decision> {
        self.events
            .lock()
            .unwrap()
            .last()
            .map(|e| e.decision.clone())
    }

    /// POSTs a receive-pack body; returns (response text, elapsed), or `None` on timeout.
    fn post_receive_pack(&self, body: Vec<u8>, timeout: Duration) -> Option<(String, Duration)> {
        let url = format!("{}/git-receive-pack", self.proxy_url());
        self.rt.block_on(async move {
            let t = Instant::now();
            let resp = reqwest::Client::new()
                .post(url)
                .header("content-type", "application/x-git-receive-pack-request")
                .timeout(timeout)
                .body(body)
                .send()
                .await
                .ok()?;
            let text = String::from_utf8_lossy(&resp.bytes().await.ok()?).to_string();
            Some((text, t.elapsed()))
        })
    }
}

fn git(dir: &Path, args: &[&str]) -> Output {
    git_cmd(dir, args).output().unwrap()
}

fn git_cmd(dir: &Path, args: &[&str]) -> Command {
    let mut c = Command::new("git");
    c.current_dir(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "/usr/bin/false")
        .env("HOME", dir)
        .env("GIT_AUTHOR_NAME", "w")
        .env("GIT_AUTHOR_EMAIL", "w@example.invalid")
        .env("GIT_COMMITTER_NAME", "w")
        .env("GIT_COMMITTER_EMAIL", "w@example.invalid");
    c
}

/// Runs git with `input` on stdin; returns trimmed stdout.
fn git_in(dir: &Path, args: &[&str], input: &[u8]) -> String {
    let mut child = git_cmd(dir, args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let o = ok(child.wait_with_output().unwrap());
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

fn ok(o: Output) -> Output {
    assert!(
        o.status.success(),
        "git failed:\n{}\n{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    o
}

fn out(o: Output) -> String {
    String::from_utf8_lossy(&ok(o).stdout).trim().to_string()
}

fn write(repo: &Path, path: &str, data: &[u8]) {
    let p = repo.join(path);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, data).unwrap();
}

fn commit(repo: &Path, msg: &str) {
    ok(git(repo, &["add", "-A"]));
    ok(git(repo, &["commit", "-q", "-m", msg]));
}

fn head(repo: &Path) -> String {
    out(git(repo, &["rev-parse", "HEAD"]))
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// A raw tree entry (`<mode> <name>\0<20-byte oid>`), mode spelled as given.
fn tree_entry(mode: &str, name: &str, oid: &str) -> Vec<u8> {
    let mut e = format!("{mode} {name}\0").into_bytes();
    e.extend(unhex(oid));
    e
}

fn pack(repo: &Path, new: &str, old: Option<&str>) -> Vec<u8> {
    let mut po = git_cmd(repo, &["pack-objects", "--stdout", "--revs", "-q"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let revs = match old {
        Some(o) => format!("{new}\n^{o}\n"),
        None => format!("{new}\n"),
    };
    po.stdin.take().unwrap().write_all(revs.as_bytes()).unwrap();
    po.wait_with_output().unwrap().stdout
}

fn push_body(old: &str, new: &str, pack: &[u8]) -> Vec<u8> {
    let mut body =
        pkt::encode(format!("{old} {new} refs/heads/agent/t1\0report-status\n").as_bytes())
            .unwrap();
    body.extend_from_slice(pkt::FLUSH);
    body.extend_from_slice(pack);
    body
}

// --- Bypass or stall 1 ---------------------------------------------------------------------------

/// An ancestry walk that treats every `parent ` line in the commit header as a parent is wrong.
/// Git (and fsck) only count `parent` lines directly after `tree`; a `parent <old>` header placed
/// after `committer` is a free extra header that fsck accepts. Read naively, a commit that does
/// not descend from the branch tip passes as a fast-forward, and the upstream (no branch
/// protection) takes the force push.
#[test]
fn extra_parent_header_does_not_hide_a_force_push() {
    let env = Env::new();
    let w = env.client();
    write(&w, "x.txt", b"accepted work\n");
    commit(&w, "one");
    ok(git(&w, &["push", "-q", "origin", "agent/t1"]));
    let one = head(&w);

    // A rewrite: real parent is main (not `one`), with `parent <one>` hidden after committer.
    let main = out(git(&w, &["rev-parse", "origin/main"]));
    write(&w, "x.txt", b"rewritten history\n");
    ok(git(&w, &["add", "-A"]));
    let tree = out(git(&w, &["write-tree"]));
    let raw = format!(
        "tree {tree}\nparent {main}\nauthor w <w@example.invalid> 1700000000 +0000\n\
         committer w <w@example.invalid> 1700000000 +0000\nparent {one}\n\nrewrite\n"
    );
    // Without --literally: hash-object runs fsck checks, so this object is fsck-clean.
    let forged = git_in(
        &w,
        &["hash-object", "-t", "commit", "-w", "--stdin"],
        raw.as_bytes(),
    );
    let real_parents = out(git(&w, &["rev-list", "--parents", "-n1", &forged]));
    assert_eq!(
        real_parents,
        format!("{forged} {main}"),
        "git sees only main"
    );

    let o = git(
        &w,
        &[
            "push",
            "-f",
            "origin",
            &format!("{forged}:refs/heads/agent/t1"),
        ],
    );
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(
        env.upstream_ref("refs/heads/agent/t1"),
        Some(one),
        "force push reached upstream (git exit ok={}, proxy decision {:?}):\n{err}",
        o.status.success(),
        env.last_decision()
    );
}

// --- Bypass or stall 2 ---------------------------------------------------------------------------

/// The tree walk recognises a directory only by the exact mode string `40000`. Git parses modes
/// as octal, so `040000` (a zero-padded mode, only an fsck *warning*) is a directory to git but
/// would be a file to the walk, which would never look inside it. Non-canonical modes are
/// refused instead, so a new workflow under a `.github` entry spelled that way cannot pass.
#[test]
fn zero_padded_tree_mode_does_not_hide_a_workflow_change() {
    let env = Env::new();
    let w = env.client();
    let evil = git_in(
        &w,
        &["hash-object", "-w", "--stdin"],
        b"on: push\njobs: {evil: {runs-on: ubuntu-latest, steps: [{run: env}]}}\n",
    );
    let ci = out(git(&w, &["rev-parse", "HEAD:.github/workflows/ci.yml"]));
    let readme = out(git(&w, &["rev-parse", "HEAD:README.md"]));
    let workflows = git_in(
        &w,
        &["mktree"],
        format!("100644 blob {ci}\tci.yml\n100644 blob {evil}\tevil.yml\n").as_bytes(),
    );
    let github = git_in(
        &w,
        &["mktree"],
        format!("040000 tree {workflows}\tworkflows\n").as_bytes(),
    );
    let mut root = tree_entry("040000", ".github", &github); // zero-padded
    root.extend(tree_entry("100644", "README.md", &readme));
    let root = git_in(
        &w,
        &["hash-object", "-t", "tree", "-w", "--literally", "--stdin"],
        &root,
    );
    let parent = head(&w);
    let c = out(git(
        &w,
        &["commit-tree", &root, "-p", &parent, "-m", "add workflow"],
    ));
    // Git itself reads the padded entry as a directory holding the new workflow.
    let listing = out(git(&w, &["ls-tree", "-r", "--name-only", &c]));
    assert!(listing.contains(".github/workflows/evil.yml"), "{listing}");

    let before = env.up.pushes();
    let o = git(&w, &["push", "origin", &format!("{c}:refs/heads/agent/t1")]);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        // Refused at the padded entry itself (non-canonical modes are refused, naming the path).
        !o.status.success() && err.contains("tree entry .github has a non-canonical mode 040000"),
        "workflow change was forwarded (upstream agent/t1 = {:?}):\n{err}",
        env.upstream_ref("refs/heads/agent/t1")
    );
    assert_eq!(env.up.pushes(), before, "upstream was contacted");
}

// --- Bypass or stall 3 ---------------------------------------------------------------------------

/// A tree that lists the same subtree under many names, nested, has fan-out^depth paths while the
/// pack holds only `depth` small trees. A walk that dedupes by (tree, path) instead of by tree
/// does one cat-file round trip per path. Here a ~3 KB pack (10 names, 7 levels: 10^7 paths)
/// must still be answered within seconds.
#[test]
fn tree_bomb_is_answered_quickly() {
    let env = Env::new();
    let w = env.client();
    let mut sub = git_in(&w, &["hash-object", "-w", "--stdin"], b"x\n");
    let mut kind = "blob";
    let mut mode = "100644";
    for _ in 0..7 {
        let listing: String = (0..10)
            .map(|i| format!("{mode} {kind} {sub}\te{i}\n"))
            .collect();
        sub = git_in(&w, &["mktree"], listing.as_bytes());
        kind = "tree";
        mode = "040000";
    }
    let root = git_in(
        &w,
        &["mktree"],
        format!("040000 tree {sub}\tbomb\n").as_bytes(),
    );
    let parent = head(&w);
    let c = out(git(
        &w,
        &["commit-tree", &root, "-p", &parent, "-m", "bomb"],
    ));
    let p = pack(&w, &c, Some(&parent));
    assert!(p.len() < 8 << 10, "pack is {} bytes", p.len());

    let answer = env.post_receive_pack(push_body(ZERO, &c, &p), Duration::from_secs(5));
    assert!(
        answer.is_some(),
        "a {} byte push kept the proxy busy for over 5 s",
        p.len()
    );
}

// --- Bypass or stall 4 ---------------------------------------------------------------------------

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut msg = data.to_vec();
    let bits = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_be_bytes());
    for block in msg.chunks(64) {
        let mut wv = [0u32; 80];
        for i in 0..16 {
            wv[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..80 {
            wv[i] = (wv[i - 3] ^ wv[i - 8] ^ wv[i - 14] ^ wv[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, &wi) in wv.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 20];
    for (i, x) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&x.to_be_bytes());
    }
    out
}

/// zlib with stored (uncompressed) blocks.
fn zlib_stored(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78, 0x01];
    let chunks: Vec<&[u8]> = data.chunks(65535).collect();
    for (i, ch) in chunks.iter().enumerate() {
        out.push(u8::from(i + 1 == chunks.len()));
        let len = ch.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(ch);
    }
    let (mut a, mut b) = (1u32, 0u32);
    for &x in data {
        a = (a + u32::from(x)) % 65521;
        b = (b + a) % 65521;
    }
    out.extend_from_slice(&((b << 16) | a).to_be_bytes());
    out
}

fn varint(mut n: u64) -> Vec<u8> {
    let mut v = Vec::new();
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            v.push(b);
            return v;
        }
        v.push(b | 0x80);
    }
}

/// OFS_DELTA negative offset encoding.
fn ofs(mut off: u64) -> Vec<u8> {
    let mut enc = vec![(off & 0x7f) as u8];
    off >>= 7;
    while off > 0 {
        off -= 1;
        enc.push(0x80 | (off & 0x7f) as u8);
        off >>= 7;
    }
    enc.reverse();
    enc
}

fn obj_header(kind: u8, size: u64) -> Vec<u8> {
    let mut first = (kind << 4) | (size & 0x0f) as u8;
    let mut rest = size >> 4;
    let mut v = Vec::new();
    while rest > 0 {
        v.push(first | 0x80);
        first = (rest & 0x7f) as u8;
        rest >>= 7;
    }
    v.push(first);
    v
}

/// A delta of one-byte "copy 64 KiB" instructions expands ~65000x, so a ~80 KB push would make
/// `git index-pack` allocate and hash a 1 GiB blob (100 MB of body: terabytes, across all cores)
/// before a blob size check after indexing could refuse it. The scan of the pack entry headers
/// (object and delta result sizes) runs before index-pack and answers at once.
#[test]
fn delta_bomb_is_refused_before_it_is_inflated() {
    const RESULT: u64 = 1 << 30;
    let env = Env::new();
    let _w = env.client();
    let base = vec![0u8; 1 << 16];
    let mut delta = varint(base.len() as u64);
    delta.extend(varint(RESULT));
    delta.extend(std::iter::repeat_n(0x80u8, (RESULT >> 16) as usize)); // copy 0..0x10000
    let mut p = b"PACK".to_vec();
    p.extend_from_slice(&2u32.to_be_bytes());
    p.extend_from_slice(&2u32.to_be_bytes());
    let base_at = p.len();
    p.extend(obj_header(3, base.len() as u64)); // blob
    p.extend(zlib_stored(&base));
    let delta_at = p.len();
    p.extend(obj_header(6, delta.len() as u64)); // OFS_DELTA
    p.extend(ofs((delta_at - base_at) as u64));
    p.extend(zlib_stored(&delta));
    let trailer = sha1(&p);
    p.extend_from_slice(&trailer);
    assert!(p.len() < 100 << 10, "pack is {} bytes", p.len());

    let new = "1234567890123456789012345678901234567890";
    let (answer, took) = env
        .post_receive_pack(push_body(ZERO, new, &p), Duration::from_secs(120))
        .expect("no answer");
    assert!(answer.contains("ng refs/heads/agent/t1"), "{answer}");
    assert!(
        took < Duration::from_secs(1),
        "a {} byte push took {took:?} to refuse ({answer:?}): the proxy inflated a {RESULT} byte \
         object before applying the {} byte limit",
        p.len(),
        Limits::default().max_blob
    );
}

// --- Known gap -----------------------------------------------------------------------------------

/// KNOWN GAP. The proxy only reads objects that are in the pack. A denied directory re-pointed
/// at a tree the server already has adds nothing under it to the pack, so the change is not
/// seen. Here `.github/workflows` becomes a copy of the existing `.github` tree. Forwarded.
/// Mitigation: give the token no `workflows` permission.
#[test]
fn gap_repointing_a_denied_path_at_an_existing_tree_is_not_seen() {
    let env = Env::new();
    let w = env.client();
    let github = out(git(&w, &["rev-parse", "HEAD:.github"]));
    let readme = out(git(&w, &["rev-parse", "HEAD:README.md"]));
    let new_github = git_in(
        &w,
        &["mktree"],
        format!("040000 tree {github}\tworkflows\n").as_bytes(),
    );
    let root = git_in(
        &w,
        &["mktree"],
        format!("040000 tree {new_github}\t.github\n100644 blob {readme}\tREADME.md\n").as_bytes(),
    );
    let parent = head(&w);
    let c = out(git(
        &w,
        &["commit-tree", &root, "-p", &parent, "-m", "re-point"],
    ));
    ok(git(
        &w,
        &["push", "-q", "origin", &format!("{c}:refs/heads/agent/t1")],
    ));
    assert_eq!(env.upstream_ref("refs/heads/agent/t1"), Some(c));
}
