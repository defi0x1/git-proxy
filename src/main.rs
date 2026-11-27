//! `git-proxy`: run the proxy for one upstream repository.

use std::io::Read;
use std::process::ExitCode;
use std::sync::Arc;

use git_proxy::{Binding, Credential, Decision, GitProxy, Limits, Policy, PushEvent};

const HELP: &str = "\
git-proxy: let a client push to a Git repository without holding its token.

USAGE:
    git-proxy --upstream <URL> --allow-ref <PATTERN>... [OPTIONS]

OPTIONS:
    --upstream <URL>       Repository to forward to, e.g. https://github.com/owner/repo.git
    --allow-ref <PATTERN>  Ref the client may push, e.g. 'refs/heads/agent/*' (repeatable)
    --token-env <NAME>     Environment variable holding the real token [default: GH_TOKEN]
    --listen <ADDR>        Address to listen on [default: 127.0.0.1:7777]
    --deny-path <PATH>     Path no push may change, added to .github/workflows (repeatable)
    --allow-tags           Allow tags that match --allow-ref
    --allow-deletes        Allow deleting refs that match --allow-ref
    --secret-env <NAME>    Take the client secret from this variable instead of a random one
    -h, --help             Print this help
";

#[derive(Debug)]
struct Args {
    upstream: String,
    policy: Policy,
    token_env: String,
    listen: String,
    secret_env: Option<String>,
}

fn parse(mut it: impl Iterator<Item = String>) -> Result<Args, String> {
    let (mut upstream, mut token_env, mut listen, mut secret_env) = (
        None,
        "GH_TOKEN".to_string(),
        "127.0.0.1:7777".to_string(),
        None,
    );
    let mut policy = Policy::new(Vec::<String>::new());
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or(format!("{flag} needs a value"));
        match flag.as_str() {
            "-h" | "--help" => return Err(String::new()),
            "--upstream" => upstream = Some(value()?),
            "--allow-ref" => policy.allow_refs.push(value()?),
            "--token-env" => token_env = value()?,
            "--listen" => listen = value()?,
            "--deny-path" => policy.deny_paths.push(value()?),
            "--secret-env" => secret_env = Some(value()?),
            "--allow-tags" => policy.allow_tags = true,
            "--allow-deletes" => policy.allow_deletes = true,
            _ => return Err(format!("unknown argument {flag}")),
        }
    }
    let upstream = upstream.ok_or("--upstream is required")?;
    if policy.allow_refs.is_empty() {
        return Err("at least one --allow-ref is required".into());
    }
    Ok(Args {
        upstream,
        policy,
        token_env,
        listen,
        secret_env,
    })
}

/// 128 random bits, hex.
fn random_secret() -> std::io::Result<String> {
    let mut b = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Compares in time that depends only on the lengths, so the secret cannot be guessed byte by
/// byte from response times.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

fn audit(e: &PushEvent) {
    let refs = e.refs.join(" ");
    match &e.decision {
        Decision::Allowed => eprintln!("allowed  {refs} ({} bytes)", e.bytes),
        Decision::Refused(why) => eprintln!("refused  {refs}: {why}"),
    }
}

async fn run(args: Args) -> Result<(), String> {
    let token = std::env::var(&args.token_env)
        .map_err(|_| format!("set {} to the upstream token", args.token_env))?;
    let credential = Credential::basic("x-access-token", &token).map_err(|e| e.to_string())?;
    let secret = match &args.secret_env {
        Some(name) => std::env::var(name).map_err(|_| format!("{name} is not set"))?,
        None => random_secret().map_err(|e| format!("random secret: {e}"))?,
    };
    let binding = Binding {
        upstream: args.upstream,
        credential,
        policy: args.policy,
        limits: Limits::default(),
    };
    let listener = tokio::net::TcpListener::bind(&args.listen)
        .await
        .map_err(|e| format!("listen on {}: {e}", args.listen))?;
    // The only thing the client gets: a URL holding the throwaway secret.
    println!("http://{}/git/{secret}/repo.git", args.listen);
    eprintln!("git-proxy: forwarding to {}", binding.upstream);
    let resolve = Arc::new(move |s: &str| same(s, &secret).then(|| binding.clone()));
    let tmp = tempfile::tempdir().map_err(|e| format!("temp dir: {e}"))?;
    let proxy = GitProxy::new(resolve, Arc::new(audit), tmp.path().to_path_buf())
        .map_err(|e| e.to_string())?;
    axum::serve(listener, proxy.router::<()>())
        .await
        .map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = match parse(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) if e.is_empty() => {
            print!("{HELP}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("error: {e}\n\n{HELP}");
            return ExitCode::from(2);
        }
    };
    match run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Result<Args, String> {
        parse(s.split_whitespace().map(String::from))
    }

    #[test]
    fn parses_flags() {
        let a = args(
            "--upstream https://example.com/r.git --allow-ref refs/heads/a/* --allow-ref refs/tags/v* \
             --deny-path secrets --allow-tags --listen 0.0.0.0:9000 --token-env T --secret-env S",
        )
        .unwrap();
        assert_eq!(a.upstream, "https://example.com/r.git");
        assert_eq!(a.policy.allow_refs, ["refs/heads/a/*", "refs/tags/v*"]);
        assert_eq!(a.policy.deny_paths, [".github/workflows", "secrets"]);
        assert!(a.policy.allow_tags && !a.policy.allow_deletes);
        assert_eq!(
            (a.listen.as_str(), a.token_env.as_str()),
            ("0.0.0.0:9000", "T")
        );
        assert_eq!(a.secret_env.as_deref(), Some("S"));
    }

    #[test]
    fn defaults_and_errors() {
        let a = args("--upstream u --allow-ref r").unwrap();
        assert_eq!(
            (a.listen.as_str(), a.token_env.as_str()),
            ("127.0.0.1:7777", "GH_TOKEN")
        );
        assert!(a.secret_env.is_none());
        assert!(args("--allow-ref r").unwrap_err().contains("--upstream"));
        assert!(args("--upstream u").unwrap_err().contains("--allow-ref"));
        assert!(args("--upstream").unwrap_err().contains("needs a value"));
        assert!(
            args("--upstream u --allow-ref r --bogus")
                .unwrap_err()
                .contains("--bogus")
        );
        assert_eq!(args("-h").err().as_deref(), Some(""));
    }

    #[test]
    fn compares_secrets() {
        assert!(same("abc", "abc"));
        assert!(!same("abc", "abd"));
        assert!(!same("abc", "abcd"));
        assert!(same("", ""));
    }
}
