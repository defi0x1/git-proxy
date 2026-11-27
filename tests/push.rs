//! Real `git` against a local upstream (`git http-backend`) through the proxy.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use git_proxy::{
    Binding, Credential, Decision, FakeUpstream, GitProxy, Limits, Policy, PushEvent, pkt,
};

const USER: &str = "x-access-token";
const PASS: &str = "s3cret-installation-token";
const SECRET: &str = "per-session-secret-t1";
const MB: usize = 1024 * 1024;

struct Env {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    up: FakeUpstream,
    events: Arc<Mutex<Vec<PushEvent>>>,
    up_port: u16,
    proxy_port: u16,
    rt: tokio::runtime::Runtime,
}

impl Env {
    fn new(tweak: impl FnOnce(&mut Limits, &mut Policy)) -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        std::fs::create_dir_all(dir.join("up")).unwrap();
        std::fs::create_dir_all(dir.join("proxy-tmp")).unwrap();
        let bare = dir.join("up/repo.git");
        ok(git(
            &dir,
            &["init", "--bare", "-q", "-b", "main", bare.to_str().unwrap()],
        ));
        ok(git(
            &bare,
            &["config", "receive.advertisePushOptions", "true"],
        ));

        // Seed: main with a workflow, plus a branch outside the allowed refs.
        let seed = dir.join("seed");
        ok(git(&dir, &["init", "-q", "-b", "main", "seed"]));
        write(&seed, "README.md", b"hello\n");
        write(&seed, ".github/workflows/ci.yml", b"on: push\njobs: {}\n");
        commit(&seed, "seed");
        ok(git(&seed, &["checkout", "-q", "-b", "feature/other"]));
        write(&seed, "other.txt", b"other\n");
        commit(&seed, "other branch");
        ok(git(
            &seed,
            &[
                "push",
                "-q",
                bare.to_str().unwrap(),
                "main",
                "feature/other",
            ],
        ));

        let mut limits = Limits {
            max_body: 200 * MB as u64,
            max_blob: 5 * MB as u64,
            max_drain: 64 * MB as u64,
        };
        let mut policy = Policy::new(["refs/heads/agent/*"]);
        tweak(&mut limits, &mut policy);
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
            up_port,
            proxy_port,
            rt,
        }
    }

    fn proxy_url(&self) -> String {
        format!("http://127.0.0.1:{}/git/{SECRET}/repo.git", self.proxy_port)
    }

    fn direct_url(&self) -> String {
        format!("http://{USER}:{PASS}@127.0.0.1:{}/repo.git", self.up_port)
    }

    /// Clone through the proxy and start branch agent/t1.
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

    fn last_event(&self) -> PushEvent {
        self.events
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("no push event")
    }

    /// The push must fail with `reason` in git's output and never reach upstream.
    fn assert_refused(&self, w: &Path, args: &[&str], reason: &str) -> String {
        let before = self.up.pushes();
        let main = self.upstream_ref("refs/heads/main");
        let t1 = self.upstream_ref("refs/heads/agent/t1");
        let o = git(w, args);
        let err = String::from_utf8_lossy(&o.stderr).to_string();
        assert!(!o.status.success(), "push should fail: {err}");
        assert!(err.contains(reason), "expected {reason:?} in:\n{err}");
        assert!(
            err.contains("[remote rejected]") || err.contains("remote unpack failed"),
            "{err}"
        );
        assert_eq!(self.up.pushes(), before, "upstream was contacted");
        assert_eq!(self.upstream_ref("refs/heads/main"), main);
        assert_eq!(self.upstream_ref("refs/heads/agent/t1"), t1);
        match self.last_event().decision {
            Decision::Refused(r) => {
                assert!(err.contains(&r), "audit reason {r:?} not in git output")
            }
            Decision::Allowed => panic!("audit says allowed"),
        }
        err
    }

    /// POSTs a hand-made receive-pack body to the proxy; returns the response body.
    fn post_receive_pack(&self, body: Vec<u8>) -> String {
        let url = format!("{}/git-receive-pack", self.proxy_url());
        self.rt.block_on(async move {
            let resp = reqwest::Client::new()
                .post(url)
                .header("content-type", "application/x-git-receive-pack-request")
                .body(body)
                .send()
                .await
                .unwrap();
            String::from_utf8_lossy(&resp.bytes().await.unwrap()).to_string()
        })
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        // Proxy temp data must be gone after every push.
        let left = std::fs::read_dir(self.dir.join("proxy-tmp"))
            .map(|d| d.count())
            .unwrap_or(0);
        if !std::thread::panicking() {
            assert_eq!(left, 0, "proxy left temp data");
        }
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

fn ok(o: Output) -> Output {
    assert!(
        o.status.success(),
        "git failed:\n{}\n{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    o
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
    String::from_utf8_lossy(&ok(git(repo, &["rev-parse", "HEAD"])).stdout)
        .trim()
        .to_string()
}

/// `git pack-objects` for `new ^old` in `repo`.
fn pack(repo: &Path, new: &str, old: &str, thin: bool) -> Vec<u8> {
    let mut args = vec!["pack-objects", "--stdout", "--revs", "-q"];
    if thin {
        args.push("--thin");
    }
    let mut po = git_cmd(repo, &args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    po.stdin
        .take()
        .unwrap()
        .write_all(format!("{new}\n^{old}\n").as_bytes())
        .unwrap();
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

/// Incompressible bytes (xorshift), so pack size matches file size.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2).wrapping_add(1);
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(len);
    out
}

#[test]
fn clone_and_fetch_through_proxy() {
    let env = Env::new(|_, _| {});
    let w = env.client();
    assert!(w.join(".github/workflows/ci.yml").exists());
    // Upstream moves on; the client fetches through the proxy.
    let seed = env.dir.join("seed");
    ok(git(&seed, &["checkout", "-q", "main"]));
    write(&seed, "news.txt", b"news\n");
    commit(&seed, "news");
    ok(git(
        &seed,
        &[
            "push",
            "-q",
            env.dir.join("up/repo.git").to_str().unwrap(),
            "main",
        ],
    ));
    ok(git(&w, &["fetch", "-q", "origin"]));
    let fetched = String::from_utf8_lossy(&ok(git(&w, &["rev-parse", "origin/main"])).stdout)
        .trim()
        .to_string();
    assert_eq!(Some(fetched), env.upstream_ref("refs/heads/main"));
    // The client holds only the secret, never the credential.
    let url =
        String::from_utf8_lossy(&ok(git(&w, &["remote", "get-url", "origin"])).stdout).to_string();
    assert!(!url.contains(PASS));
    assert!(
        env.events.lock().unwrap().is_empty(),
        "fetches are not push decisions"
    );
}

#[test]
fn unknown_secret_is_forbidden() {
    let env = Env::new(|_, _| {});
    let url = format!(
        "http://127.0.0.1:{}/git/not-a-secret/repo.git",
        env.proxy_port
    );
    let o = git(&env.dir, &["ls-remote", &url]);
    assert!(!o.status.success());
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("403"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
}

#[test]
fn upstream_requires_the_credential() {
    let env = Env::new(|_, _| {});
    let url = format!("http://127.0.0.1:{}/repo.git", env.up_port);
    let o = git(&env.dir, &["ls-remote", &url]);
    assert!(
        !o.status.success(),
        "upstream must refuse a client without the credential"
    );
    ok(git(&env.dir, &["ls-remote", &env.direct_url()]));
}

#[test]
fn allowed_push_to_own_branch_create_then_fast_forward() {
    let env = Env::new(|_, _| {});
    let w = env.client();
    write(&w, "src/a.txt", &noise(300_000, 1)); // big enough that the next push deltas against it
    write(&w, ".github/CODEOWNERS", b"* @someone\n"); // .github but not workflows: allowed
    commit(&w, "one");
    ok(git(&w, &["push", "-q", "origin", "agent/t1"]));
    assert_eq!(env.upstream_ref("refs/heads/agent/t1"), Some(head(&w)));

    let mut data = noise(300_000, 1);
    data[1000] ^= 0xff;
    write(&w, "src/a.txt", &data);
    commit(&w, "two");
    ok(git(&w, &["push", "-q", "origin", "agent/t1"]));
    assert_eq!(env.upstream_ref("refs/heads/agent/t1"), Some(head(&w)));
    let events = env.events.lock().unwrap().clone();
    assert_eq!(events.len(), 2, "{events:?}");
    for e in &events {
        assert_eq!(e.refs, ["refs/heads/agent/t1"]);
        assert_eq!(e.decision, Decision::Allowed);
        assert!(e.bytes > 0);
    }
}

#[test]
fn refuses_main() {
    let env = Env::new(|_, _| {});
    let w = env.client();
    ok(git(&w, &["checkout", "-q", "main"]));
    write(&w, "x.txt", b"x\n");
    commit(&w, "to main");
    env.assert_refused(
        &w,
        &["push", "origin", "main"],
        "refs/heads/main is not an allowed ref",
    );
}

#[test]
fn refuses_a_branch_outside_the_patterns() {
    let env = Env::new(|_, _| {});
    let w = env.client();
    ok(git(
        &w,
        &[
            "checkout",
            "-q",
            "-B",
            "feature/other",
            "origin/feature/other",
        ],
    ));
    write(&w, "x.txt", b"x\n");
    commit(&w, "fast-forward on someone else's branch");
    env.assert_refused(
        &w,
        &["push", "origin", "feature/other"],
        "refs/heads/feature/other is not an allowed ref",
    );
}

#[test]
fn refuses_force_push() {
    let env = Env::new(|_, _| {});
    let w = env.client();
    write(&w, "x.txt", b"x\n");
    commit(&w, "one");
    ok(git(&w, &["push", "-q", "origin", "agent/t1"]));
    write(&w, "x.txt", b"rewritten\n");
    ok(git(
        &w,
        &["commit", "-q", "-a", "--amend", "-m", "one, rewritten"],
    ));
    env.assert_refused(
        &w,
        &["push", "-f", "origin", "agent/t1"],
        "not a fast-forward",
    );
}

#[test]
fn refuses_force_push_backwards() {
    // Reset to an older commit: the pack is empty, so ancestry cannot be shown.
    let env = Env::new(|_, _| {});
    let w = env.client();
    write(&w, "x.txt", b"1\n");
    commit(&w, "one");
    write(&w, "x.txt", b"2\n");
    commit(&w, "two");
    ok(git(&w, &["push", "-q", "origin", "agent/t1"]));
    ok(git(&w, &["reset", "-q", "--hard", "HEAD~1"]));
    env.assert_refused(&w, &["push", "-f", "origin", "agent/t1"], "cannot prove");
}

#[test]
fn refuses_delete() {
    let env = Env::new(|_, _| {});
    let w = env.client();
    write(&w, "x.txt", b"x\n");
    commit(&w, "one");
    ok(git(&w, &["push", "-q", "origin", "agent/t1"]));
    env.assert_refused(
        &w,
        &["push", "origin", ":agent/t1"],
        "deleting a ref is not allowed",
    );
}

#[test]
fn refuses_tag() {
    let env = Env::new(|_, _| {});
    let w = env.client();
    ok(git(&w, &["tag", "v1"]));
    env.assert_refused(&w, &["push", "origin", "v1"], "tags may not be pushed");
}

#[test]
fn refuses_multi_ref_with_one_bad_ref() {
    let env = Env::new(|_, _| {});
    let w = env.client();
    write(&w, "x.txt", b"x\n");
    commit(&w, "agent work");
    ok(git(&w, &["checkout", "-q", "main"]));
    write(&w, "y.txt", b"y\n");
    commit(&w, "main work");
    let err = env.assert_refused(
        &w,
        &["push", "origin", "agent/t1", "main"],
        "refs/heads/main is not an allowed ref",
    );
    assert!(
        err.contains("another ref in this push was refused"),
        "{err}"
    );
    assert_eq!(env.upstream_ref("refs/heads/agent/t1"), None);
    assert_eq!(env.last_event().refs.len(), 2);
}

#[test]
fn refuses_workflow_change() {
    let env = Env::new(|_, _| {});
    let w = env.client();
    write(
        &w,
        ".github/workflows/x.yml",
        b"on: push\njobs: {evil: {runs-on: ubuntu-latest}}\n",
    );
    commit(&w, "add workflow");
    env.assert_refused(
        &w,
        &["push", "origin", "agent/t1"],
        "changes under .github/workflows are not allowed (.github/workflows/x.yml)",
    );
}

#[test]
fn refuses_workflow_change_in_an_earlier_commit() {
    // Changed then restored: the tip is clean but history carries it.
    let env = Env::new(|_, _| {});
    let w = env.client();
    write(
        &w,
        ".github/workflows/ci.yml",
        b"on: push\njobs: {changed: {}}\n",
    );
    commit(&w, "edit workflow");
    ok(git(
        &w,
        &["checkout", "-q", "HEAD~1", "--", ".github/workflows/ci.yml"],
    ));
    commit(&w, "restore workflow");
    env.assert_refused(
        &w,
        &["push", "origin", "agent/t1"],
        "changes under .github/workflows are not allowed",
    );
}

#[test]
fn refuses_workflow_replace() {
    let env = Env::new(|_, _| {});
    let w = env.client();
    write(&w, ".github/workflows/other.yml", b"on: push\n");
    ok(git(&w, &["rm", "-q", ".github/workflows/ci.yml"]));
    commit(&w, "drop ci, add other");
    env.assert_refused(
        &w,
        &["push", "origin", "agent/t1"],
        "(.github/workflows/other.yml)",
    );
}

#[test]
fn gap_removing_the_whole_workflows_dir_is_not_seen() {
    // KNOWN GAP. Deleting the last workflow file removes the `workflows` entry from the .github
    // tree. The pack holds the new .github tree but not the parent's, so the proxy cannot tell a
    // workflows dir was there. Forwarded. Mitigation: give the token no `workflows` permission.
    let env = Env::new(|_, _| {});
    let w = env.client();
    ok(git(&w, &["rm", "-q", ".github/workflows/ci.yml"]));
    write(&w, ".github/keep", b"k\n");
    commit(&w, "drop ci");
    ok(git(&w, &["push", "-q", "origin", "agent/t1"]));
    assert_eq!(env.upstream_ref("refs/heads/agent/t1"), Some(head(&w)));
}

#[test]
fn refuses_oversize_blob() {
    let env = Env::new(|_, _| {});
    let w = env.client();
    write(&w, "data/big.bin", &noise(6 * MB, 7));
    commit(&w, "big file");
    env.assert_refused(
        &w,
        &["push", "origin", "agent/t1"],
        "file data/big.bin is 6291456 bytes, over the 5242880 byte limit",
    );
}

#[test]
fn refuses_oversize_push() {
    let env = Env::new(|l, _| l.max_body = 2 * MB as u64);
    let w = env.client();
    for i in 0..4 {
        write(&w, &format!("f{i}.bin"), &noise(MB, i + 10));
    }
    commit(&w, "4 MB of small files");
    env.assert_refused(
        &w,
        &["push", "origin", "agent/t1"],
        "over the 2097152 byte limit",
    );
}

#[test]
fn cuts_a_push_past_the_drain_limit() {
    let env = Env::new(|l, _| {
        l.max_body = MB as u64;
        l.max_drain = MB as u64;
    });
    let w = env.client();
    for i in 0..4 {
        write(&w, &format!("f{i}.bin"), &noise(MB, i + 20));
    }
    commit(&w, "4 MB");
    let before = env.up.pushes();
    let o = git(&w, &["push", "origin", "agent/t1"]);
    assert!(!o.status.success());
    assert_eq!(env.up.pushes(), before);
    assert_eq!(env.upstream_ref("refs/heads/agent/t1"), None);
    assert!(
        matches!(env.last_event().decision, Decision::Refused(r) if r.contains("connection cut"))
    );
}

#[test]
fn refuses_push_options() {
    let env = Env::new(|_, _| {});
    let w = env.client();
    write(&w, "x.txt", b"x\n");
    commit(&w, "one");
    env.assert_refused(
        &w,
        &["push", "-o", "ci.skip", "origin", "agent/t1"],
        "push options are not allowed",
    );
}

#[test]
fn advertises_no_thin_and_refuses_a_thin_pack() {
    // Without no-thin, an update deltas against objects only the server has, and index-pack
    // cannot resolve them. The proxy advertises no-thin; a client that ignores it is refused.
    let env = Env::new(|_, _| {});
    let w = env.client();
    let data = noise(300_000, 3);
    write(&w, "a.bin", &data);
    commit(&w, "one");
    ok(git(&w, &["push", "-q", "origin", "agent/t1"]));
    let one = head(&w);
    let mut d2 = data.clone();
    d2[10] ^= 1;
    write(&w, "a.bin", &d2);
    commit(&w, "two");
    let two = head(&w);

    let before = env.up.pushes();
    let thin = pack(&w, &two, &one, true);
    let answer = env.post_receive_pack(push_body(&one, &two, &thin));
    assert!(
        answer.contains("ng refs/heads/agent/t1 pack is not self-contained"),
        "{answer}"
    );
    assert_eq!(env.up.pushes(), before);
    assert_eq!(env.upstream_ref("refs/heads/agent/t1"), Some(one));

    // A real git push of the same change works, because the client honours no-thin.
    ok(git(&w, &["push", "-q", "origin", "agent/t1"]));
    assert_eq!(env.upstream_ref("refs/heads/agent/t1"), Some(two));
}

#[test]
fn stale_old_is_refused_by_upstream_compare_and_swap() {
    // The proxy does not check that `old` is the current tip; receive-pack does, atomically.
    let env = Env::new(|_, _| {});
    let w = env.client();
    write(&w, "x.txt", b"x\n");
    commit(&w, "one");
    ok(git(&w, &["push", "-q", "origin", "agent/t1"]));
    let w2 = env.dir.join("w2");
    ok(git(
        &env.dir,
        &["clone", "-q", "-b", "agent/t1", &env.proxy_url(), "w2"],
    ));
    write(&w2, "y.txt", b"y\n");
    commit(&w2, "from w2");
    ok(git(&w2, &["push", "-q", "origin", "agent/t1"]));
    // w still has "one" as the tip. git itself would refuse ("fetch first"), so send a
    // hand-made request: by ancestry it is a fast-forward, so the proxy passes it; upstream
    // refuses because "one" is no longer the tip.
    let one = head(&w);
    write(&w, "z.txt", b"z\n");
    commit(&w, "from w");
    let new = head(&w);
    let tip_w2 = env.upstream_ref("refs/heads/agent/t1");
    let answer = env.post_receive_pack(push_body(&one, &new, &pack(&w, &new, &one, false)));
    assert!(answer.contains("ng refs/heads/agent/t1"), "{answer}");
    assert_eq!(env.upstream_ref("refs/heads/agent/t1"), tip_w2);
    assert_eq!(env.last_event().decision, Decision::Allowed);
}

#[test]
fn allows_any_ref_matching_a_pattern() {
    let env = Env::new(|_, _| {});
    let w = env.client();
    ok(git(&w, &["checkout", "-q", "-b", "agent/fix/deep-name"]));
    write(&w, "x.txt", b"x\n");
    commit(&w, "one");
    ok(git(&w, &["push", "-q", "origin", "agent/fix/deep-name"]));
    assert_eq!(
        env.upstream_ref("refs/heads/agent/fix/deep-name"),
        Some(head(&w))
    );
}

#[test]
fn refuses_two_allowed_refs_in_one_push() {
    let env = Env::new(|_, _| {});
    let w = env.client();
    write(&w, "x.txt", b"x\n");
    commit(&w, "one");
    ok(git(&w, &["branch", "agent/t2"]));
    env.assert_refused(
        &w,
        &["push", "origin", "agent/t1", "agent/t2"],
        "one ref per push",
    );
}

#[test]
fn refuses_changes_under_a_configured_path() {
    let env = Env::new(|_, p| {
        p.deny_paths.push("deploy/secrets".into());
        p.deny_paths.push("/Cargo.lock/".into()); // slashes are ignored; a file works too
    });
    let w = env.client();
    write(&w, "deploy/secrets/prod/key.txt", b"k\n");
    commit(&w, "add a secret");
    env.assert_refused(
        &w,
        &["push", "origin", "agent/t1"],
        "changes under deploy/secrets are not allowed (deploy/secrets/prod/key.txt)",
    );
    ok(git(&w, &["reset", "-q", "--hard", "origin/main"]));
    write(&w, "Cargo.lock", b"# changed\n");
    write(&w, "deploy/readme.txt", b"next to secrets: allowed\n");
    commit(&w, "lock file");
    env.assert_refused(
        &w,
        &["push", "origin", "agent/t1"],
        "changes under Cargo.lock are not allowed (Cargo.lock)",
    );
    // The default rule is still there.
    ok(git(&w, &["reset", "-q", "--hard", "origin/main"]));
    write(
        &w,
        ".github/workflows/ci.yml",
        b"on: [push, pull_request]\n",
    );
    commit(&w, "edit ci");
    env.assert_refused(
        &w,
        &["push", "origin", "agent/t1"],
        "changes under .github/workflows are not allowed (.github/workflows/ci.yml)",
    );
}

#[test]
fn allows_delete_and_tags_when_the_policy_says_so() {
    let env = Env::new(|_, p| {
        p.allow_deletes = true;
        p.allow_tags = true;
        p.allow_refs.push("refs/tags/agent-*".into());
    });
    let w = env.client();
    write(&w, "x.txt", b"x\n");
    commit(&w, "one");
    ok(git(&w, &["push", "-q", "origin", "agent/t1"]));
    ok(git(&w, &["push", "-q", "origin", ":agent/t1"]));
    assert_eq!(env.upstream_ref("refs/heads/agent/t1"), None);
    assert_eq!(env.last_event().decision, Decision::Allowed);

    ok(git(&w, &["tag", "agent-v1"]));
    ok(git(&w, &["push", "-q", "origin", "agent-v1"]));
    assert_eq!(env.upstream_ref("refs/tags/agent-v1"), Some(head(&w)));
    // A tag outside the patterns is still refused, and so is a branch delete outside them.
    ok(git(&w, &["tag", "v1"]));
    env.assert_refused(
        &w,
        &["push", "origin", "v1"],
        "refs/tags/v1 is not an allowed ref",
    );
    env.assert_refused(
        &w,
        &["push", "origin", ":main"],
        "refs/heads/main is not an allowed ref",
    );
}

/// Overhead on a ~50 MB push: direct to upstream vs through the proxy.
/// Run: cargo test --release --test push -- --ignored --nocapture overhead
#[test]
#[ignore]
fn overhead_50mb() {
    let runs = 5;
    let mut direct = Vec::new();
    let mut proxied = Vec::new();
    for r in 0..runs {
        for via_proxy in [false, true] {
            let env = Env::new(|_, _| {});
            let w = env.client();
            for i in 0..50 {
                write(
                    &w,
                    &format!("data/f{i:02}.bin"),
                    &noise(MB, (r * 100 + i) as u64 + 1),
                );
            }
            commit(&w, "50 MB");
            let url = if via_proxy {
                env.proxy_url()
            } else {
                env.direct_url()
            };
            let t = Instant::now();
            ok(git(&w, &["push", "-q", &url, "agent/t1"]));
            let el = t.elapsed();
            assert_eq!(env.upstream_ref("refs/heads/agent/t1"), Some(head(&w)));
            eprintln!(
                "run {r}: {} {el:?}",
                if via_proxy { "proxy" } else { "direct" }
            );
            if via_proxy {
                proxied.push(el)
            } else {
                direct.push(el)
            }
        }
    }
    let med = |v: &mut Vec<Duration>| {
        v.sort();
        v[v.len() / 2]
    };
    let (d, p) = (med(&mut direct), med(&mut proxied));
    eprintln!(
        "median direct {d:?}, proxy {p:?}, overhead {:?}",
        p.saturating_sub(d)
    );
}
