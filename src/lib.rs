//! A Git smart-HTTP proxy that lets a client push without holding a token.
//!
//! The client (an AI coding agent, a CI job, a contractor) only knows a throwaway secret in its
//! remote URL, `http://127.0.0.1:7777/git/{secret}/repo.git`. The proxy holds the real token. For
//! every push it reads the ref commands, applies a [`Policy`] (allowed refs, no tags, no deletes,
//! no force pushes), scans the pack (size limits, denied paths such as `.github/workflows`), and
//! only then forwards the exact bytes upstream with the token added. Fetches and clones pass
//! through.
//!
//! Build a [`GitProxy`] with a [`Resolve`] closure (secret to [`Binding`]) and an [`AuditHook`],
//! then serve [`GitProxy::router`] (an `axum::Router`) or merge it into your own router.
//!
//! [`FakeUpstream`] serves bare repositories with `git http-backend`, for tests and demos.

#![warn(missing_docs)]

mod pack;
pub mod pkt;
mod policy;
mod proxy;
pub mod scan;
mod upstream;

pub use policy::Policy;
pub use proxy::{
    AuditHook, Binding, Credential, CredentialError, Decision, GitProxy, Limits, ProxyError,
    PushEvent, Resolve,
};
pub use upstream::{FakeUpstream, RepoError, create_bare_repo};
