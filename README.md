# pushgate

Let an AI coding agent, a CI job or a contractor push to your GitHub repository **without giving
it a token**. pushgate is a small Git smart-HTTP proxy: the client only holds a throwaway secret
in its remote URL, pushgate holds the real token, checks every push, and forwards only the pushes
your policy allows.

<p align="center">
  <img src="docs/how-it-works.svg" alt="The client holds a throwaway secret and pushes to pushgate. pushgate holds the real token and runs four checks on every push: ref policy, fast-forward only, denied paths, size limits. Only pushes that pass are forwarded to GitHub, byte for byte, with the token added. Refused pushes go back to the client with a reason." width="900">
</p>

> **Status: early.** Tested and fuzzed, but not yet widely reviewed.
> Review it before you rely on it, and keep GitHub branch protection on as well.

## Quickstart (30 seconds)

Needs Rust and `git` on the machine that runs the proxy.

```sh
cargo install --git https://github.com/defi0x1/pushgate
export GH_TOKEN=...   # a token that can push to the repository; only pushgate sees it
pushgate --upstream https://github.com/you/repo.git --allow-ref 'refs/heads/agent/*'
```

pushgate prints the one URL the client gets:

```text
http://127.0.0.1:7799/git/0d538ff7920f4f54d1bd43ba5f18341f/repo.git
pushgate: forwarding to https://github.com/defi0x1/pushgate.git
```

Give the client that URL (`git clone <url>` or `git remote set-url origin <url>`) and nothing
else. Clone and fetch work as usual. This is a real session against GitHub, with
`--listen 127.0.0.1:7799`:

```text
$ git push origin agent/smoke-test
remote:
remote: Create a pull request for 'agent/smoke-test' on GitHub by visiting:
remote:      https://github.com/defi0x1/pushgate/pull/new/agent/smoke-test
remote:
To http://127.0.0.1:7799/git/0d538ff7920f4f54d1bd43ba5f18341f/repo.git
 * [new branch]      agent/smoke-test -> agent/smoke-test

$ git push origin agent/smoke-test:main
remote: pushgate: push refused: refs/heads/main is not an allowed ref
To http://127.0.0.1:7799/git/0d538ff7920f4f54d1bd43ba5f18341f/repo.git
 ! [remote rejected] agent/smoke-test -> main (refs/heads/main is not an allowed ref)
error: failed to push some refs to 'http://127.0.0.1:7799/git/0d538ff7920f4f54d1bd43ba5f18341f/repo.git'

$ git push origin agent/smoke-test        # after editing .github/workflows/ci.yml
remote: pushgate: push refused: changes under .github/workflows are not allowed (.github/workflows/ci.yml)
To http://127.0.0.1:7799/git/0d538ff7920f4f54d1bd43ba5f18341f/repo.git
 ! [remote rejected] agent/smoke-test -> agent/smoke-test (changes under .github/workflows are not allowed (.github/workflows/ci.yml))
error: failed to push some refs to 'http://127.0.0.1:7799/git/0d538ff7920f4f54d1bd43ba5f18341f/repo.git'
```

And pushgate's own log of the same session:

```text
allowed  refs/heads/agent/smoke-test (880 bytes)
refused  refs/heads/main: refs/heads/main is not an allowed ref
refused  refs/heads/agent/smoke-test: changes under .github/workflows are not allowed (.github/workflows/ci.yml)
```

Other options: `pushgate --help`. To try it without GitHub or a token, run the demo below.

## Without it / with it

| | Without pushgate | With pushgate |
|---|---|---|
| What the client holds | a token that can push anywhere the token can | a throwaway secret, valid only at this proxy |
| Push to `main` | goes through unless branch protection stops it | refused before GitHub sees it |
| Force push, delete a branch, push a tag | allowed by the token | refused (deletes and tags can be allowed per policy) |
| Edit `.github/workflows` (runs with your secrets) | allowed if the token has `workflows` scope | refused, naming the file |
| A huge file, a huge push, a pack bomb | reaches GitHub | refused by size limits; bombs are caught from the pack headers before anything is unpacked |
| Token leaks into a log, a prompt, a transcript | an attacker gets the token | the secret only works through pushgate, under the same policy; restart pushgate to change it |

## What is refused, and what git prints

Every refusal reaches the client as a normal git error (`! [remote rejected] <ref> (<reason>)`),
and GitHub is never contacted. The texts below are the reasons exactly as pushgate writes them.

| Push | Reason shown to the client |
|---|---|
| a ref that matches no `--allow-ref` pattern | `refs/heads/main is not an allowed ref` |
| a tag (unless `--allow-tags`) | `tags may not be pushed` |
| a delete (unless `--allow-deletes`) | `deleting a ref is not allowed` |
| a force push | `not a fast-forward: <old> is not an ancestor of <new> (force push is not allowed)` |
| a branch reset to an older commit | `cannot prove <old> -> <new> is a fast-forward: the push carries no objects` |
| a change at or under a denied path | `changes under .github/workflows are not allowed (.github/workflows/x.yml)` |
| a file over the size limit (5 MiB) | `file data/big.bin is 6291456 bytes, over the 5242880 byte limit` |
| a push over the body limit (100 MiB) | `push is <n> bytes, over the 104857600 byte limit` |
| a delta that would expand past the file limit | `a delta in the pack expands to <n> bytes, over the 5242880 byte limit` |
| two or more refs in one push | `one ref per push` |
| push options (`git push -o`) | `push options are not allowed` |
| a thin or corrupt pack | `pack is not self-contained or is corrupt (<git's error>)` |
| a tree entry with a non-canonical mode | `tree entry .github has a non-canonical mode 040000` |
| a pack that takes over 30 s to inspect | `pack inspection took too long (over 30 s); push less at once` |
| a wrong secret in the URL | HTTP 403 `unknown or expired git secret` |

A push far past the body limit (over 164 MiB by default) is cut off with HTTP 413 instead of
being read to the end.

## How it works

For each `git push`, pushgate:

1. spools the request body to an unnamed temp file (gone when closed, on every path);
2. reads the ref commands and applies the ref policy;
3. scans the pack entry headers for object and delta sizes, without inflating anything big;
4. indexes the pack into an empty temp repository with `git index-pack`, walks only the objects
   in the pack, and checks fast-forward, denied paths and file sizes;
5. forwards the exact bytes it received to the upstream with the token in `Authorization`.

It advertises `no-thin` to the client, so the pack can be checked on its own. Fetches and clones
are streamed through with the token added and are not filtered.

## Demo, no GitHub needed

```sh
cargo run --example demo
```

It starts a fake upstream (`git http-backend` that only accepts the real token) and pushgate in
front of it, then pushes with plain `git`. Real output:

```text
== clone through the proxy, work on an agent branch
$ git clone -q http://127.0.0.1:56209/git/throwaway-secret/repo.git client
$ git checkout -q -b agent/fix-typo
$ git add README.md
$ git commit -q -m add readme

== allowed: push to refs/heads/agent/fix-typo
$ git push origin agent/fix-typo
  [pushgate] allowed ["refs/heads/agent/fix-typo"]
  To http://127.0.0.1:56209/git/throwaway-secret/repo.git
   * [new branch]      agent/fix-typo -> agent/fix-typo

== refused: push the same commit to main
$ git push origin agent/fix-typo:main
  [pushgate] refused ["refs/heads/main"]: refs/heads/main is not an allowed ref
  remote: pushgate: push refused: refs/heads/main is not an allowed ref
  To http://127.0.0.1:56209/git/throwaway-secret/repo.git
   ! [remote rejected] agent/fix-typo -> main (refs/heads/main is not an allowed ref)
  error: failed to push some refs to 'http://127.0.0.1:56209/git/throwaway-secret/repo.git'

== refused: change a workflow on the agent branch
$ git add .
$ git commit -q -m add workflow
$ git push origin agent/fix-typo
  [pushgate] refused ["refs/heads/agent/fix-typo"]: changes under .github/workflows are not allowed (.github/workflows/ci.yml)
  remote: pushgate: push refused: changes under .github/workflows are not allowed (.github/workflows/ci.yml)
  To http://127.0.0.1:56209/git/throwaway-secret/repo.git
   ! [remote rejected] agent/fix-typo -> agent/fix-typo (changes under .github/workflows are not allowed (.github/workflows/ci.yml))
  error: failed to push some refs to 'http://127.0.0.1:56209/git/throwaway-secret/repo.git'

== what the upstream has
$ git branch --list
    agent/fix-typo
  * main
```

## As a library

The CLI serves one upstream and one secret. To serve many clients (one secret each, each with its
own repository and policy), use the crate. It needs `tokio` and `axum` alongside it.

```rust
use std::sync::Arc;

use pushgate::{Binding, Credential, GitProxy, Limits, Policy, PushEvent};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let token = std::env::var("GH_TOKEN")?;
    let binding = Binding {
        upstream: "https://github.com/you/repo.git".into(),
        credential: Credential::basic("x-access-token", &token)?,
        policy: Policy::new(["refs/heads/agent/*"]),
        limits: Limits::default(),
    };
    // Map each client's secret to what it may do; here, one client.
    let resolve = Arc::new(move |secret: &str| (secret == "s3cret").then(|| binding.clone()));
    let audit = Arc::new(|event: &PushEvent| println!("{event:?}"));
    let proxy = GitProxy::new(resolve, audit, std::env::temp_dir())?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:7777").await?;
    axum::serve(listener, proxy.router::<()>()).await?;
    Ok(())
}
```

`Policy` has four fields: `allow_refs` (patterns where `*` matches anything, `/` included),
`allow_tags`, `allow_deletes`, and `deny_paths` (`.github/workflows` by default; a directory or a
file). `Limits` sets the body, file and drain sizes. `GitProxy::router` is an `axum::Router`, so
you can merge it into your own server.

## Limits

Two known gaps, both covered by tests that show the push going through
(`gap_removing_the_whole_workflows_dir_is_not_seen` in `tests/push.rs`,
`gap_repointing_a_denied_path_at_an_existing_tree_is_not_seen` in `tests/attacks.rs`):

- **Deleting the whole `.github/workflows` directory is not seen.** Removing the last file drops
  the `workflows` entry from the `.github` tree. The pack holds the new `.github` tree but not the
  old one, so pushgate cannot tell the directory was there.
- **A denied path re-pointed at an object that already exists is not seen.** pushgate only reads
  objects that are in the pack. If a commit points `.github/workflows` (or any denied path) at a
  tree or file the server already has, nothing new under that path is in the pack.

For both, give the token no `workflows` permission, so GitHub refuses workflow changes too.

Also keep in mind:

- The secret grants **read access** to the whole repository (clone and fetch go through
  unfiltered), and push access within the policy. Treat it as you would a deploy key.
- One ref per push. `git push origin a b` is refused; push them one at a time.
- The CLI listens on plain HTTP. Keep it on localhost or a private network, or put TLS in front.
- The CLI makes a new random secret every start, unless you pass `--secret-env`.
- GitHub branch protection is still worth having. pushgate is a second layer, not a replacement.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT)
at your option.
