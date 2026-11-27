//! The proxy service: `/git/{secret}/repo.git/{info/refs, git-upload-pack, git-receive-pack}`.

use std::fmt;
use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine;
use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::pack::{self, InspectError, PackSource};
use crate::pkt;
use crate::policy::{self, Policy};

/// Bytes of the request start kept in memory for the ref commands. Longer command lists are refused.
const HEAD_MAX: usize = 1 << 20;
/// Largest receive-pack ref advertisement read to add `no-thin`.
const MAX_ADVERTISEMENT: usize = 16 << 20;
/// Read size when streaming the spooled push upstream.
const FORWARD_CHUNK: usize = 64 << 10;

/// The `Authorization` header value the proxy adds upstream. Never printed.
#[derive(Clone)]
pub struct Credential(HeaderValue);

/// The credential is not a valid header value.
#[derive(Debug, thiserror::Error)]
#[error("credential is not a valid HTTP header value")]
pub struct CredentialError;

impl Credential {
    /// `Basic base64(user:pass)`, for example `x-access-token` and an installation token.
    pub fn basic(user: &str, pass: &str) -> Result<Self, CredentialError> {
        let enc = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        Self::from_header(&format!("Basic {enc}"))
    }

    /// A full `Authorization` header value.
    pub fn from_header(value: &str) -> Result<Self, CredentialError> {
        let mut v = HeaderValue::from_str(value).map_err(|_| CredentialError)?;
        v.set_sensitive(true);
        Ok(Credential(v))
    }

    pub(crate) fn header(&self) -> &HeaderValue {
        &self.0
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credential(..)")
    }
}

/// Size limits for one push.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest receive-pack request body (commands and pack) accepted.
    pub max_body: u64,
    /// Largest file (full blob size) in a push.
    pub max_blob: u64,
    /// Bytes past `max_body` read and thrown away so git can read the refusal. Past
    /// `max_body + max_drain` the request fails with 413 and the connection is cut.
    pub max_drain: u64,
}

impl Default for Limits {
    /// 100 MiB body, 5 MiB file, 64 MiB drain.
    fn default() -> Self {
        Limits {
            max_body: 100 << 20,
            max_blob: 5 << 20,
            max_drain: 64 << 20,
        }
    }
}

/// What a secret grants: pushes allowed by `policy` to one upstream repository.
#[derive(Debug, Clone)]
pub struct Binding {
    /// The upstream repository URL, for example `https://github.com/o/r.git`. The proxy appends
    /// `/info/refs`, `/git-upload-pack` and `/git-receive-pack`.
    pub upstream: String,
    /// Added to every upstream request. The client's own `Authorization` is dropped.
    pub credential: Credential,
    /// What the client may push.
    pub policy: Policy,
    /// Size limits for each push.
    pub limits: Limits,
}

/// Resolves the secret in the URL to its binding; `None` answers 403. Called on every request,
/// on the async runtime, so it must not block (an in-memory map lookup).
pub type Resolve = Arc<dyn Fn(&str) -> Option<Binding> + Send + Sync>;

/// Called once per push decision (pushes with at least one ref command, or that could not be read).
/// Must not block.
pub type AuditHook = Arc<dyn Fn(&PushEvent) + Send + Sync>;

/// Whether a push was forwarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Forwarded upstream. The upstream can still refuse it (for example a stale old value).
    Allowed,
    /// Refused by the proxy; upstream was not contacted. The reason is what git printed.
    Refused(String),
}

/// One push decision, for the audit log. Holds no secret or credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushEvent {
    /// The refs the push tried to update (empty if the commands could not be read).
    pub refs: Vec<String>,
    /// Forwarded or refused, and why.
    pub decision: Decision,
    /// Request body bytes received.
    pub bytes: u64,
}

/// The proxy could not be built.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// The HTTP client for the upstream could not be built.
    #[error("http client: {0}")]
    Client(#[from] reqwest::Error),
}

/// The Git proxy. Build it once and serve [`GitProxy::router`], or merge it into your own router.
#[derive(Clone)]
pub struct GitProxy {
    inner: Arc<Inner>,
}

struct Inner {
    resolve: Resolve,
    audit: AuditHook,
    tmp_dir: PathBuf,
    client: reqwest::Client,
}

impl GitProxy {
    /// `tmp_dir` holds spooled push bodies (unnamed files, gone when closed) and the temp
    /// repositories used for pack inspection (deleted after every push). It must exist.
    pub fn new(resolve: Resolve, audit: AuditHook, tmp_dir: PathBuf) -> Result<Self, ProxyError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .build()?;
        Ok(GitProxy {
            inner: Arc::new(Inner {
                resolve,
                audit,
                tmp_dir,
                client,
            }),
        })
    }

    /// The routes, at the root: `/git/{secret}/repo.git/info/refs` (GET),
    /// `/git/{secret}/repo.git/git-upload-pack` and `/git/{secret}/repo.git/git-receive-pack`
    /// (POST). Request paths hold the secret: do not log them.
    pub fn router<S: Clone + Send + Sync + 'static>(self) -> Router<S> {
        Router::new()
            .route("/git/{secret}/repo.git/info/refs", get(info_refs))
            .route("/git/{secret}/repo.git/git-upload-pack", post(upload_pack))
            .route(
                "/git/{secret}/repo.git/git-receive-pack",
                post(receive_pack),
            )
            .layer(DefaultBodyLimit::disable())
            .with_state(self.inner)
    }
}

fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, "unknown or expired git secret\n").into_response()
}

fn bad_gateway(e: impl fmt::Display) -> Response {
    (StatusCode::BAD_GATEWAY, format!("upstream: {e}\n")).into_response()
}

fn endpoint(b: &Binding, rest: &str) -> String {
    format!("{}/{rest}", b.upstream.trim_end_matches('/'))
}

/// Request headers passed upstream, plus the binding's credential.
fn upstream_headers(h: &HeaderMap, b: &Binding, with_encoding: bool) -> HeaderMap {
    let mut out = HeaderMap::new();
    let mut pass = vec![
        header::CONTENT_TYPE,
        header::ACCEPT,
        header::USER_AGENT,
        HeaderName::from_static("git-protocol"),
    ];
    if with_encoding {
        pass.push(header::CONTENT_ENCODING);
    }
    for name in pass {
        if let Some(v) = h.get(&name) {
            out.insert(name, v.clone());
        }
    }
    out.insert(header::AUTHORIZATION, b.credential.header().clone());
    out
}

fn response(status: StatusCode, upstream: &HeaderMap, body: Body) -> Response {
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    for name in [
        header::CONTENT_TYPE,
        header::CACHE_CONTROL,
        header::EXPIRES,
        header::PRAGMA,
    ] {
        if let Some(v) = upstream.get(&name) {
            resp.headers_mut().insert(name, v.clone());
        }
    }
    resp
}

/// Streams an upstream response back. An upstream auth failure is the proxy's problem, not the
/// client's, so it becomes 502 (a 401 would make git ask the client for a password).
fn streamed(resp: reqwest::Response) -> Response {
    let status = resp.status();
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        return bad_gateway(format!("refused the proxy's credential ({status})"));
    }
    let headers = resp.headers().clone();
    response(status, &headers, Body::from_stream(resp.bytes_stream()))
}

async fn info_refs(
    State(st): State<Arc<Inner>>,
    Path(secret): Path<String>,
    Query(q): Query<Vec<(String, String)>>,
    headers: HeaderMap,
) -> Response {
    let Some(b) = (st.resolve)(&secret) else {
        return forbidden();
    };
    let service = q
        .iter()
        .find(|(k, _)| k == "service")
        .map_or("", |(_, v)| v.as_str());
    if service != "git-upload-pack" && service != "git-receive-pack" {
        return (StatusCode::FORBIDDEN, "only smart HTTP is supported\n").into_response();
    }
    let url = endpoint(&b, &format!("info/refs?service={service}"));
    let resp = match st
        .client
        .get(url)
        .headers(upstream_headers(&headers, &b, false))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return bad_gateway(e),
    };
    if service != "git-receive-pack" || resp.status() != StatusCode::OK {
        return streamed(resp);
    }
    // Ask the client for a self-contained pack, so the proxy can inspect it.
    let up_headers = resp.headers().clone();
    let mut resp = resp;
    let mut adv = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(c)) if adv.len() + c.len() <= MAX_ADVERTISEMENT => adv.extend_from_slice(&c),
            Ok(Some(_)) => return bad_gateway("ref advertisement too large"),
            Ok(None) => break,
            Err(e) => return bad_gateway(e),
        }
    }
    match pkt::add_capability(&adv, "no-thin") {
        Ok(adv) => response(StatusCode::OK, &up_headers, Body::from(adv)),
        Err(e) => bad_gateway(format!("bad ref advertisement: {e}")),
    }
}

async fn upload_pack(
    State(st): State<Arc<Inner>>,
    Path(secret): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(b) = (st.resolve)(&secret) else {
        return forbidden();
    };
    let body = reqwest::Body::wrap_stream(body.into_data_stream());
    match st
        .client
        .post(endpoint(&b, "git-upload-pack"))
        .headers(upstream_headers(&headers, &b, true))
        .body(body)
        .send()
        .await
    {
        Ok(r) => streamed(r),
        Err(e) => bad_gateway(e),
    }
}

/// A push body on disk. The file is unnamed, so it is gone once closed, on every path.
struct Spooled {
    file: File,
    /// The first `HEAD_MAX` bytes, for the ref commands.
    head: Vec<u8>,
    /// Bytes received.
    total: u64,
    /// Bytes in the file (at most `max_body`).
    kept: u64,
}

#[derive(Debug, thiserror::Error)]
enum SpoolError {
    #[error("spool: {0}")]
    Io(#[from] io::Error),
    #[error("reading the push: {0}")]
    Body(#[from] axum::Error),
    #[error("push is over {0} bytes; connection cut")]
    TooLarge(u64),
}

async fn spool(body: Body, dir: PathBuf, limits: Limits) -> Result<Spooled, SpoolError> {
    let std_file = tokio::task::spawn_blocking(move || tempfile::tempfile_in(dir))
        .await
        .map_err(io::Error::other)??;
    let mut file = tokio::fs::File::from_std(std_file);
    let hard = limits.max_body.saturating_add(limits.max_drain);
    let (mut head, mut total, mut kept) = (Vec::new(), 0u64, 0u64);
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        total += chunk.len() as u64;
        if total > hard {
            return Err(SpoolError::TooLarge(hard));
        }
        let room = usize::try_from(limits.max_body - kept).unwrap_or(usize::MAX);
        let part = &chunk[..room.min(chunk.len())];
        if !part.is_empty() {
            file.write_all(part).await?;
            kept += part.len() as u64;
        }
        let head_room = HEAD_MAX.saturating_sub(head.len()).min(chunk.len());
        head.extend_from_slice(&chunk[..head_room]);
    }
    file.flush().await?;
    Ok(Spooled {
        file: file.into_std().await,
        head,
        total,
        kept,
    })
}

fn report(
    caps: &[String],
    cmds: &[pkt::Command],
    reasons: &[Option<String>],
    summary: &str,
) -> Response {
    (
        [
            (
                header::CONTENT_TYPE,
                "application/x-git-receive-pack-result",
            ),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        pkt::rejection(caps, cmds, reasons, summary),
    )
        .into_response()
}

impl Inner {
    fn decide(&self, refs: Vec<String>, decision: Decision, bytes: u64) {
        match &decision {
            Decision::Allowed => tracing::info!(?refs, bytes, "git push forwarded"),
            Decision::Refused(reason) => {
                tracing::info!(?refs, bytes, %reason, "git push refused");
            }
        }
        (self.audit)(&PushEvent {
            refs,
            decision,
            bytes,
        });
    }
}

async fn receive_pack(
    State(st): State<Arc<Inner>>,
    Path(secret): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(b) = (st.resolve)(&secret) else {
        return forbidden();
    };
    let refuse = |refs: Vec<String>, reason: String, bytes: u64| {
        st.decide(refs, Decision::Refused(reason), bytes);
    };

    if headers
        .get(header::CONTENT_ENCODING)
        .is_some_and(|v| v != "identity")
    {
        // git never compresses push bodies; refuse rather than inspect blind.
        let reason = "compressed push body is not supported".to_string();
        refuse(vec![], reason.clone(), 0);
        return (StatusCode::UNSUPPORTED_MEDIA_TYPE, reason).into_response();
    }

    let spooled = match spool(body, st.tmp_dir.clone(), b.limits).await {
        Ok(s) => s,
        Err(e @ SpoolError::TooLarge(_)) => {
            refuse(
                vec![],
                e.to_string(),
                b.limits.max_body.saturating_add(b.limits.max_drain),
            );
            return (StatusCode::PAYLOAD_TOO_LARGE, e.to_string()).into_response();
        }
        Err(e @ SpoolError::Body(_)) => {
            return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
        }
        Err(e @ SpoolError::Io(_)) => {
            tracing::error!(error = %e, "git push spool failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "proxy could not store the push\n",
            )
                .into_response();
        }
    };
    let total = spooled.total;

    let req = match pkt::parse_push(&spooled.head) {
        Ok(r) => r,
        Err(pkt::ParseError::Truncated) if spooled.head.len() >= HEAD_MAX => {
            let s = format!("ref commands are over {HEAD_MAX} bytes");
            refuse(vec![], s.clone(), total);
            return report(&[], &[], &[], &s);
        }
        Err(e) => {
            let s = format!("cannot read the push: {e}");
            refuse(vec![], s.clone(), total);
            return report(&[], &[], &[], &s);
        }
    };
    let refs: Vec<String> = req.commands.iter().map(|c| c.refname.clone()).collect();

    if total > b.limits.max_body {
        let s = format!(
            "push is {total} bytes, over the {} byte limit",
            b.limits.max_body
        );
        refuse(refs, s.clone(), total);
        return report(
            &req.caps,
            &req.commands,
            &vec![Some(s.clone()); req.commands.len()],
            &s,
        );
    }

    let mut file = spooled.file;
    if let Some(cmd) = req.commands.first() {
        if let Some((reasons, summary)) = policy::check_commands(&b.policy, &req) {
            refuse(refs, summary.clone(), total);
            return report(&req.caps, &req.commands, &reasons, &summary);
        }
        // Exactly one command now, for an allowed ref.
        let cmd = cmd.clone();
        let deny_paths = b.policy.deny_paths.clone();
        let offset = req.pack_offset as u64;
        let len = spooled.kept.saturating_sub(offset);
        let (max_blob, max_body, tmp) = (b.limits.max_blob, b.limits.max_body, st.tmp_dir.clone());
        let joined = tokio::task::spawn_blocking(move || {
            if cmd.is_delete() {
                // An allowed delete carries no pack: nothing to inspect.
                return (file, Ok(pack::Inspection::default()));
            }
            let src = PackSource {
                file: &mut file,
                offset,
                len,
            };
            let r = pack::inspect(src, &cmd, &deny_paths, max_blob, max_body, &tmp);
            (file, r)
        })
        .await;
        file = match joined {
            Ok((f, Ok(found))) => {
                tracing::debug!(
                    objects = found.objects,
                    commits = found.commits,
                    "pack inspected"
                );
                f
            }
            other => {
                let s = match other {
                    Ok((_, Err(InspectError::Refused(s)))) => s,
                    Ok((_, Err(InspectError::Internal(e)))) => {
                        tracing::error!(error = %e, "pack inspection failed");
                        format!("proxy could not inspect the pack: {e}")
                    }
                    Ok((_, Ok(_))) | Err(_) => {
                        tracing::error!("pack inspection task failed");
                        "proxy could not inspect the pack".to_string()
                    }
                };
                refuse(refs, s.clone(), total);
                return report(&req.caps, &req.commands, &[Some(s.clone())], &s);
            }
        };
        st.decide(refs, Decision::Allowed, total);
    }
    // With no commands (git's auth probe) there is nothing to decide; pass it on.

    // Forward the exact bytes received.
    let mut file = tokio::fs::File::from_std(file);
    if let Err(e) = file.seek(io::SeekFrom::Start(0)).await {
        tracing::error!(error = %e, "spool seek failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "proxy could not read the push\n",
        )
            .into_response();
    }
    let stream = futures_util::stream::try_unfold(file, |mut f| async move {
        let mut buf = vec![0u8; FORWARD_CHUNK];
        let n = f.read(&mut buf).await?;
        if n == 0 {
            return Ok::<_, io::Error>(None);
        }
        buf.truncate(n);
        Ok(Some((Bytes::from(buf), f)))
    });
    match st
        .client
        .post(endpoint(&b, "git-receive-pack"))
        .headers(upstream_headers(&headers, &b, false))
        .header(header::CONTENT_LENGTH, spooled.kept)
        .body(reqwest::Body::wrap_stream(stream))
        .send()
        .await
    {
        Ok(r) => streamed(r),
        Err(e) => bad_gateway(e),
    }
}
