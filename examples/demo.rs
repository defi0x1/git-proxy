//! Starts a fake upstream (`git http-backend` behind a token) and git-proxy in front of it, then
//! pushes through the proxy with plain `git`: one push the policy allows, two it refuses.
//!
//! Run: cargo run --example demo

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use git_proxy::{
    Binding, Credential, Decision, FakeUpstream, GitProxy, Limits, Policy, PushEvent,
    create_bare_repo,
};

type Error = Box<dyn std::error::Error>;

/// Runs git in `dir` with no user config; prints the command and what git printed.
fn git(dir: &Path, args: &[&str]) -> Result<bool, Error> {
    println!("$ git {}", args.join(" "));
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_NAME", "agent")
        .env("GIT_AUTHOR_EMAIL", "agent@example.invalid")
        .env("GIT_COMMITTER_NAME", "agent")
        .env("GIT_COMMITTER_EMAIL", "agent@example.invalid")
        .output()?;
    for text in [&out.stdout, &out.stderr] {
        for line in String::from_utf8_lossy(text).lines() {
            println!("  {line}");
        }
    }
    Ok(out.status.success())
}

fn main() -> Result<(), Error> {
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path();
    let rt = tokio::runtime::Runtime::new()?;

    // The upstream only accepts the real token. Only the proxy knows it.
    let token = Credential::basic("x-access-token", "real-token-the-client-never-sees")?;
    rt.block_on(create_bare_repo(&dir.join("up/repo.git")))?;
    let upstream = FakeUpstream::new(dir.join("up"), token.clone());

    let (up_listener, proxy_listener) = rt.block_on(async {
        let a = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let b = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        Ok::<_, std::io::Error>((a, b))
    })?;
    let binding = Binding {
        upstream: format!("http://{}/repo.git", up_listener.local_addr()?),
        credential: token,
        policy: Policy::new(["refs/heads/agent/*"]),
        limits: Limits::default(),
    };
    // The client holds this throwaway secret, nothing else.
    let secret = "throwaway-secret";
    let resolve = Arc::new(move |s: &str| (s == secret).then(|| binding.clone()));
    let audit = Arc::new(|e: &PushEvent| match &e.decision {
        Decision::Allowed => println!("  [git-proxy] allowed {:?}", e.refs),
        Decision::Refused(why) => println!("  [git-proxy] refused {:?}: {why}", e.refs),
    });
    std::fs::create_dir(dir.join("spool"))?;
    let proxy = GitProxy::new(resolve, audit, dir.join("spool"))?;
    let url = format!(
        "http://{}/git/{secret}/repo.git",
        proxy_listener.local_addr()?
    );
    let up_router: axum::Router = upstream.router();
    let proxy_router: axum::Router = proxy.router();
    rt.spawn(async move { axum::serve(up_listener, up_router).await });
    rt.spawn(async move { axum::serve(proxy_listener, proxy_router).await });

    println!("== clone through the proxy, work on an agent branch");
    git(dir, &["clone", "-q", &url, "client"])?;
    let client = dir.join("client");
    git(&client, &["checkout", "-q", "-b", "agent/fix-typo"])?;
    std::fs::write(client.join("README.md"), "hello\n")?;
    git(&client, &["add", "README.md"])?;
    git(&client, &["commit", "-q", "-m", "add readme"])?;

    println!("\n== allowed: push to refs/heads/agent/fix-typo");
    git(&client, &["push", "origin", "agent/fix-typo"])?;

    println!("\n== refused: push the same commit to main");
    git(&client, &["push", "origin", "agent/fix-typo:main"])?;

    println!("\n== refused: change a workflow on the agent branch");
    std::fs::create_dir_all(client.join(".github/workflows"))?;
    std::fs::write(client.join(".github/workflows/ci.yml"), "on: push\n")?;
    git(&client, &["add", "."])?;
    git(&client, &["commit", "-q", "-m", "add workflow"])?;
    git(&client, &["push", "origin", "agent/fix-typo"])?;

    println!("\n== what the upstream has");
    git(&dir.join("up/repo.git"), &["branch", "--list"])?;
    Ok(())
}
