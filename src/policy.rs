//! The ref policy, and the checks that need only the ref commands (no pack).

use crate::pkt::PushRequest;

/// What a client may push.
///
/// ```
/// let policy = pushgate::Policy::new(["refs/heads/agent/*"]);
/// assert!(policy.ref_allowed("refs/heads/agent/fix-1"));
/// assert!(!policy.ref_allowed("refs/heads/main"));
/// assert_eq!(policy.deny_paths, [".github/workflows"]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// Ref patterns the client may update, for example `refs/heads/agent/*`. `*` matches any
    /// run of characters, `/` included. A ref matching none of them is refused.
    pub allow_refs: Vec<String>,
    /// Allow pushing tags (`refs/tags/...`) that match `allow_refs`. Off by default.
    pub allow_tags: bool,
    /// Allow deleting refs that match `allow_refs`. Off by default.
    pub allow_deletes: bool,
    /// Paths (a directory or a file) no pushed commit may change, for example
    /// `.github/workflows`. A change at or under one is refused.
    pub deny_paths: Vec<String>,
}

impl Policy {
    /// Allows `allow_refs`; no tags, no deletes, nothing under `.github/workflows`.
    pub fn new<I, S>(allow_refs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Policy {
            allow_refs: allow_refs.into_iter().map(Into::into).collect(),
            allow_tags: false,
            allow_deletes: false,
            deny_paths: vec![".github/workflows".into()],
        }
    }

    /// Whether `refname` matches one of `allow_refs`.
    pub fn ref_allowed(&self, refname: &str) -> bool {
        self.allow_refs.iter().any(|p| glob(p, refname))
    }
}

/// `*` matches any run of characters (including `/`); everything else matches itself.
fn glob(pattern: &str, s: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or_default();
    let Some(mut rest) = s.strip_prefix(first) else {
        return false;
    };
    let parts: Vec<&str> = parts.collect();
    let Some((last, middle)) = parts.split_last() else {
        return rest.is_empty(); // no `*`: exact match
    };
    for part in middle {
        match rest.find(part) {
            Some(i) => rest = &rest[i + part.len()..],
            None => return false,
        }
    }
    rest.ends_with(last)
}

/// A refused command list: one reason per command (`None` means "refused because another ref
/// was"), and a summary.
pub(crate) type Refusal = (Vec<Option<String>>, String);

/// Returns `None` when the commands pass.
pub(crate) fn check_commands(policy: &Policy, req: &PushRequest) -> Option<Refusal> {
    if req.has_cap("push-options") || !req.push_options.is_empty() {
        let r = "push options are not allowed".to_string();
        return Some((vec![Some(r.clone()); req.commands.len()], r));
    }
    let mut reasons: Vec<Option<String>> = req
        .commands
        .iter()
        .map(|c| {
            if c.refname.starts_with("refs/tags/") && !policy.allow_tags {
                Some("tags may not be pushed".into())
            } else if !policy.ref_allowed(&c.refname) {
                Some(format!("{} is not an allowed ref", c.refname))
            } else if c.is_delete() && !policy.allow_deletes {
                Some("deleting a ref is not allowed".into())
            } else {
                None
            }
        })
        .collect();
    // Several allowed refs in one push: refuse rather than reason about each pack walk.
    if reasons.len() > 1 && reasons.iter().all(Option::is_none) {
        reasons[1] = Some("one ref per push".into());
    }
    let first = reasons.iter().flatten().next()?.clone();
    Some((reasons, first))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        assert!(glob("refs/heads/main", "refs/heads/main"));
        assert!(!glob("refs/heads/main", "refs/heads/main2"));
        assert!(glob("refs/heads/agent/*", "refs/heads/agent/a"));
        assert!(glob("refs/heads/agent/*", "refs/heads/agent/a/b"));
        assert!(!glob("refs/heads/agent/*", "refs/heads/agent"));
        assert!(!glob("refs/heads/agent/*", "refs/heads/main"));
        assert!(glob("refs/heads/*/wip", "refs/heads/x/wip"));
        assert!(!glob("refs/heads/*/wip", "refs/heads/x/wip2"));
        assert!(glob("*", "anything"));
        assert!(glob("a*b*c", "abc"));
        assert!(!glob("a*b*c", "acb"));
        assert!(!glob("ab*ba", "aba")); // prefix and suffix may not overlap
    }
}
