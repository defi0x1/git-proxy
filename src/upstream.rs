//! A stand-in for GitHub: `git http-backend` (CGI) over a directory of bare repositories, behind a
//! fixed credential. The tests and the example push through the proxy to it.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use crate::Credential;

/// Largest CGI header block read from `git http-backend`.
const MAX_CGI_HEADER: usize = 64 << 10;
const CHUNK: usize = 64 << 10;

/// Serves the bare repositories under a root directory with `git http-backend`.
#[derive(Clone)]
pub struct FakeUpstream {
    inner: Arc<Inner>,
}

struct Inner {
    root: PathBuf,
    credential: Credential,
    pushes: AtomicUsize,
}

impl FakeUpstream {
    /// Serves `<repo_root>/<name>.git` at `/<name>.git/...`. Every request must carry `credential`.
    pub fn new(repo_root: PathBuf, credential: Credential) -> Self {
        FakeUpstream {
            inner: Arc::new(Inner {
                root: repo_root,
                credential,
                pushes: AtomicUsize::new(0),
            }),
        }
    }

    /// Receive-pack requests that carried more than a flush-pkt (that is, ref commands).
    /// Tests use it to prove a refused push never reached the upstream.
    pub fn pushes(&self) -> usize {
        self.inner.pushes.load(Ordering::SeqCst)
    }

    /// The CGI as a fallback route: mount it with `nest` (paths are taken after the prefix).
    pub fn router<S: Clone + Send + Sync + 'static>(&self) -> Router<S> {
        Router::new()
            .fallback(cgi)
            .layer(DefaultBodyLimit::disable())
            .with_state(self.inner.clone())
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn internal(e: impl std::fmt::Display) -> Response {
    tracing::error!(error = %e, "fake upstream");
    (StatusCode::INTERNAL_SERVER_ERROR, "fake upstream error\n").into_response()
}

async fn cgi(
    State(st): State<Arc<Inner>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if headers.get(header::AUTHORIZATION) != Some(st.credential.header()) {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"upstream\"")],
            "credential required\n",
        )
            .into_response();
    }
    let h = |n: &str| {
        headers
            .get(n)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    let mut cmd = Command::new("git");
    cmd.arg("http-backend")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_PROJECT_ROOT", &st.root)
        .env("GIT_HTTP_EXPORT_ALL", "1")
        .env("REMOTE_USER", "pushgate")
        .env("REMOTE_ADDR", "127.0.0.1")
        .env("REQUEST_METHOD", method.as_str())
        .env("PATH_INFO", uri.path())
        .env("QUERY_STRING", uri.query().unwrap_or(""))
        .env("CONTENT_TYPE", h("content-type"))
        .env("HTTP_CONTENT_ENCODING", h("content-encoding"))
        .env("GIT_PROTOCOL", h("git-protocol"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let length = h("content-length");
    if !length.is_empty() {
        cmd.env("CONTENT_LENGTH", length);
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return internal(e),
    };
    let (Some(mut stdin), Some(mut stdout)) = (child.stdin.take(), child.stdout.take()) else {
        return internal("http-backend pipes missing");
    };

    let is_push = method == Method::POST && uri.path().ends_with("/git-receive-pack");
    let inner = st.clone();
    tokio::spawn(async move {
        let mut stream = body.into_data_stream();
        let (mut total, mut counted) = (0usize, false);
        while let Some(Ok(chunk)) = stream.next().await {
            total += chunk.len();
            if is_push && total > 4 && !counted {
                inner.pushes.fetch_add(1, Ordering::SeqCst);
                counted = true;
            }
            if stdin.write_all(&chunk).await.is_err() {
                break;
            }
        }
        // Dropping stdin closes it, so http-backend sees the end of the body.
    });

    // CGI output: headers, a blank line, the body.
    let mut out = Vec::new();
    let (head_end, sep) = loop {
        let crlf = find(&out, b"\r\n\r\n").map(|i| (i, 4));
        let lf = find(&out, b"\n\n").map(|i| (i, 2));
        match (crlf, lf) {
            (Some(a), Some(b)) => break if b.0 < a.0 { b } else { a },
            (Some(x), None) | (None, Some(x)) => break x,
            (None, None) => {}
        }
        if out.len() > MAX_CGI_HEADER {
            return internal("CGI header too long");
        }
        let mut buf = vec![0u8; CHUNK];
        match stdout.read(&mut buf).await {
            Ok(0) => return internal("CGI output ended in its headers"),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) => return internal(e),
        }
    };
    tokio::spawn(async move {
        let _ = child.wait().await;
    });

    let mut resp = Response::new(Body::empty());
    for line in String::from_utf8_lossy(&out[..head_end]).lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let v = v.trim();
        if k.eq_ignore_ascii_case("status") {
            let code = v.split(' ').next().and_then(|c| c.parse().ok());
            *resp.status_mut() = code
                .and_then(|c| StatusCode::from_u16(c).ok())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        } else if let (Ok(k), Ok(v)) = (
            header::HeaderName::try_from(k.trim()),
            header::HeaderValue::try_from(v),
        ) {
            resp.headers_mut().append(k, v);
        }
    }
    let first = Bytes::copy_from_slice(&out[head_end + sep..]);
    let rest = futures_util::stream::try_unfold(stdout, |mut s| async move {
        let mut buf = vec![0u8; CHUNK];
        let n = s.read(&mut buf).await?;
        if n == 0 {
            return Ok::<_, std::io::Error>(None);
        }
        buf.truncate(n);
        Ok(Some((Bytes::from(buf), s)))
    });
    *resp.body_mut() =
        Body::from_stream(futures_util::stream::once(async { Ok(first) }).chain(rest));
    resp
}

/// A repository operation failed.
#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    #[error("running git: {0}")]
    Io(#[from] std::io::Error),
    #[error("git {args} failed: {stderr}")]
    Git { args: String, stderr: String },
}

/// Runs git in `repo` with a fixed identity and no user config; returns trimmed stdout.
async fn git(repo: &Path, args: &[&str]) -> Result<String, RepoError> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "pushgate")
        .env("GIT_AUTHOR_EMAIL", "pushgate@localhost")
        .env("GIT_COMMITTER_NAME", "pushgate")
        .env("GIT_COMMITTER_EMAIL", "pushgate@localhost")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .output()
        .await?;
    if !out.status.success() {
        return Err(RepoError::Git {
            args: args.join(" "),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Creates a bare repository at `path` with one empty commit on `main`.
pub async fn create_bare_repo(path: &Path) -> Result<(), RepoError> {
    tokio::fs::create_dir_all(path).await?;
    git(path, &["init", "--bare", "-q", "-b", "main", "."]).await?;
    // `git mktree` with no input writes the empty tree.
    let tree = git(path, &["mktree"]).await?;
    let commit = git(path, &["commit-tree", &tree, "-m", "Initial commit"]).await?;
    git(path, &["update-ref", "refs/heads/main", &commit, ""]).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[tokio::test]
    async fn creates_main_with_one_commit() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo.git");
        create_bare_repo(&repo).await.unwrap();
        let count = git(&repo, &["rev-list", "--count", "main"]).await.unwrap();
        assert_eq!(count, "1");
        assert!(
            create_bare_repo(&repo).await.is_err(),
            "main already exists"
        );
    }
}
