//! Inspects a pushed pack without a repository: index it into an empty temp repository
//! (`git index-pack --stdin`), then read only the objects that are in the pack. Objects the client
//! left out are ones it believes the server already has; they cannot be read and count as unchanged.
//!
//! Everything here is blocking (child processes and pipes). Call it from `spawn_blocking`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command as Proc, Stdio};
use std::time::{Duration, Instant};

use crate::pkt::Command;
use crate::scan::{self, ScanLimits, TIMED_OUT};

/// Wall-clock limit for inspecting one pack.
const INSPECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Most tree entries read while inspecting one pack.
const MAX_TREE_ENTRIES: usize = 200_000;
/// The modes git writes in trees. Anything else (such as a zero-padded `040000`) is refused.
const CANONICAL_MODES: [&str; 5] = ["100644", "100755", "120000", "40000", "160000"];

/// Why a pack was not accepted.
#[derive(Debug, thiserror::Error)]
pub(crate) enum InspectError {
    /// A policy refusal; the text is shown to the pusher.
    #[error("{0}")]
    Refused(String),
    /// The proxy could not run the inspection. The push is refused (fail closed).
    #[error("{0}")]
    Internal(String),
}

impl From<io::Error> for InspectError {
    fn from(e: io::Error) -> Self {
        InspectError::Internal(e.to_string())
    }
}

fn refused<T>(reason: String) -> Result<T, InspectError> {
    Err(InspectError::Refused(reason))
}

/// What an accepted pack held.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Inspection {
    pub objects: usize,
    pub commits: usize,
}

/// The pack part of a spooled push body.
pub(crate) struct PackSource<'a> {
    pub file: &'a mut File,
    pub offset: u64,
    pub len: u64,
}

/// `git` with no system or global config, a minimal environment, run in `dir`.
pub(crate) fn git(dir: &Path) -> Proc {
    let mut c = Proc::new("git");
    c.arg("-C")
        .arg(dir)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("LC_ALL", "C");
    c
}

fn short(oid: &str) -> &str {
    &oid[..oid.len().min(10)]
}

/// A long-running `git cat-file --batch` over the temp repository.
struct Odb {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Odb {
    fn open(dir: &Path) -> io::Result<Odb> {
        let mut child = git(dir)
            .args(["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::other("cat-file pipes missing"));
        };
        Ok(Odb {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        })
    }

    /// The object's type and content, or `None` if it is not in the pack.
    fn get(&mut self, oid: &str) -> io::Result<Option<(String, Vec<u8>)>> {
        writeln!(self.stdin, "{oid}")?;
        self.stdin.flush()?;
        let mut header = String::new();
        self.stdout.read_line(&mut header)?;
        let parts: Vec<&str> = header.split_whitespace().collect();
        let [_, kind, size] = parts[..] else {
            return Ok(None); // "<oid> missing"
        };
        let size: usize = size
            .parse()
            .map_err(|_| io::Error::other("cat-file: bad size"))?;
        let mut data = vec![0; size + 1];
        self.stdout.read_exact(&mut data)?;
        data.pop(); // trailing LF
        Ok(Some((kind.to_string(), data)))
    }
}

impl Drop for Odb {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Entries of a raw tree object: (mode, name, hex oid).
fn parse_tree(data: &[u8], oid_len: usize) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let Some(sp) = rest.iter().position(|&b| b == b' ') else {
            break;
        };
        let Some(nul) = rest[sp..].iter().position(|&b| b == 0).map(|n| sp + n) else {
            break;
        };
        let Some(raw) = rest.get(nul + 1..nul + 1 + oid_len) else {
            break;
        };
        let mode = String::from_utf8_lossy(&rest[..sp]).into_owned();
        let name = String::from_utf8_lossy(&rest[sp + 1..nul]).into_owned();
        let oid = raw.iter().map(|b| format!("{b:02x}")).collect();
        out.push((mode, name, oid));
        rest = &rest[nul + 1 + oid_len..];
    }
    out
}

/// Feeds the pack to `git index-pack --stdin` in `dir`; kills it at `deadline`.
fn index_pack(
    dir: &Path,
    pack: &mut PackSource<'_>,
    deadline: Instant,
) -> Result<(), InspectError> {
    let mut child = git(dir)
        .args(["index-pack", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let (Some(mut stdin), Some(mut stderr)) = (child.stdin.take(), child.stderr.take()) else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(InspectError::Internal("index-pack pipes missing".into()));
    };
    if let Err(e) = pack.file.seek(SeekFrom::Start(pack.offset)) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e.into());
    }
    let src = Read::take(&mut *pack.file, pack.len);
    // Write stdin and read stderr on their own threads so neither pipe can block the wait.
    // Killing the child ends both.
    let (status, err) = std::thread::scope(|s| {
        s.spawn(move || {
            let mut src = src;
            // index-pack may exit early on a bad pack; a broken pipe is expected then.
            let _ = io::copy(&mut src, &mut stdin);
        });
        let reader = s.spawn(move || {
            let mut v = Vec::new();
            let _ = stderr.read_to_end(&mut v);
            v
        });
        let status = loop {
            match child.try_wait() {
                Ok(Some(st)) => break Ok(st),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Ok(None) => break Err(InspectError::Refused(TIMED_OUT.into())),
                Err(e) => break Err(e.into()),
            }
        };
        if status.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        (status, reader.join().unwrap_or_default())
    });
    if status?.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&err);
    let line = err
        .lines()
        .find(|l| l.starts_with("fatal"))
        .unwrap_or(err.trim());
    refused(format!(
        "pack is not self-contained or is corrupt ({})",
        line.trim()
    ))
}

/// Checks the pack for one allowed ref update. Temp data goes under `tmp_root` and is deleted
/// before this returns.
pub(crate) fn inspect(
    mut pack: PackSource<'_>,
    cmd: &Command,
    deny_paths: &[String],
    max_blob: u64,
    max_object: u64,
    tmp_root: &Path,
) -> Result<Inspection, InspectError> {
    let deadline = Instant::now() + INSPECT_TIMEOUT;
    let late = || {
        if Instant::now() >= deadline {
            refused(TIMED_OUT.into())
        } else {
            Ok(())
        }
    };
    if pack.len == 0 {
        // The new tip is an object the server already has.
        if cmd.is_create() || cmd.old == cmd.new {
            return Ok(Inspection {
                objects: 0,
                commits: 0,
            });
        }
        return refused(format!(
            "cannot prove {} -> {} is a fast-forward: the push carries no objects",
            short(&cmd.old),
            short(&cmd.new)
        ));
    }
    let sha256 = cmd.new.len() == 64;
    let oid_len = if sha256 { 32 } else { 20 };

    // Entry sizes and delta result sizes, before index-pack materialises anything. A whole object
    // over `max_blob` (up to `max_object`) is left to the check after index-pack, which can name
    // its path; a delta cannot expand past `max_blob`.
    pack.file.seek(SeekFrom::Start(pack.offset))?;
    let reader = BufReader::new(Read::take(&mut *pack.file, pack.len));
    let lim = ScanLimits {
        oid_len,
        max_delta: max_blob,
        max_object: max_object.max(max_blob),
        deadline: Some(deadline),
    };
    scan::check(reader, lim).map_err(InspectError::Refused)?;

    let tmp = tempfile::Builder::new()
        .prefix("push-")
        .tempdir_in(tmp_root)?;
    let dir = tmp.path();
    let mut init = git(dir);
    init.args(["init", "--bare", "-q"]);
    if sha256 {
        init.arg("--object-format=sha256");
    }
    if !init.arg(".").status()?.success() {
        return Err(InspectError::Internal("git init failed".into()));
    }

    // index-pack resolves every delta from the pack alone. A thin pack (deltas against objects
    // the server has) fails here; the proxy advertises no-thin so git does not send one.
    index_pack(dir, &mut pack, deadline)?;

    // Every object in the pack, with its full (undeltified) size.
    let out = git(dir)
        .args([
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname) %(objecttype) %(objectsize)",
        ])
        .stderr(Stdio::null())
        .output()?;
    if !out.status.success() {
        return Err(InspectError::Internal(
            "cat-file --batch-all-objects failed".into(),
        ));
    }
    let mut objects: HashMap<String, (String, u64)> = HashMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let [oid, kind, size] = line.split(' ').collect::<Vec<_>>()[..] {
            objects.insert(oid.into(), (kind.into(), size.parse().unwrap_or(u64::MAX)));
        }
    }

    let mut odb = Odb::open(dir)?;

    // Commits reachable from the new tip inside the pack. Parents outside the pack are the
    // boundary the client assumed the server has.
    let mut commits: Vec<String> = Vec::new(); // root trees
    let mut found_old = false;
    let mut seen = HashSet::new();
    let mut queue = VecDeque::from([cmd.new.clone()]);
    while let Some(c) = queue.pop_front() {
        late()?;
        if c == cmd.old {
            found_old = true;
            continue;
        }
        if objects.get(&c).is_none_or(|(t, _)| t != "commit") || !seen.insert(c.clone()) {
            continue;
        }
        let Some((_, data)) = odb.get(&c)? else {
            return Err(InspectError::Internal(format!(
                "commit {} unreadable",
                short(&c)
            )));
        };
        // As git reads it: `tree` first, then the `parent` lines right after it. A `parent`
        // header anywhere later is not a parent.
        let text = String::from_utf8_lossy(&data);
        let mut lines = text.split('\n');
        let Some(tree) = lines.next().and_then(|l| l.strip_prefix("tree ")) else {
            return refused(format!("commit {} has no tree line first", short(&c)));
        };
        commits.push(tree.to_string());
        for line in lines {
            let Some(p) = line.strip_prefix("parent ") else {
                break;
            };
            queue.push_back(p.to_string());
        }
    }

    if !cmd.is_create() && cmd.new != cmd.old {
        if !objects.contains_key(&cmd.new) {
            return refused(format!(
                "cannot prove {} -> {} is a fast-forward: new tip is not in the pack",
                short(&cmd.old),
                short(&cmd.new)
            ));
        }
        if !found_old {
            return refused(format!(
                "not a fast-forward: {} is not an ancestor of {} (force push is not allowed)",
                short(&cmd.old),
                short(&cmd.new)
            ));
        }
    }

    // Walk only trees that are in the pack, each tree once (by oid, whatever path it is under).
    let mut trees: HashMap<String, Vec<(String, String, String)>> = HashMap::new();
    let mut blob_paths: HashMap<String, String> = HashMap::new();
    let mut budget = MAX_TREE_ENTRIES;
    for root in &commits {
        let mut stack = vec![(root.clone(), String::new())];
        while let Some((tree, prefix)) = stack.pop() {
            if !objects.contains_key(&tree) || trees.contains_key(&tree) {
                continue;
            }
            late()?;
            let Some((_, data)) = odb.get(&tree)? else {
                return Err(InspectError::Internal(format!(
                    "tree {} unreadable",
                    short(&tree)
                )));
            };
            let entries = parse_tree(&data, oid_len);
            budget = match budget.checked_sub(entries.len()) {
                Some(b) => b,
                None => {
                    return refused(format!(
                        "the push has more than {MAX_TREE_ENTRIES} tree entries to inspect"
                    ));
                }
            };
            for (mode, name, oid) in &entries {
                let path = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}/{name}")
                };
                if !CANONICAL_MODES.contains(&mode.as_str()) {
                    return refused(format!("tree entry {path} has a non-canonical mode {mode}"));
                }
                if !objects.contains_key(oid) {
                    continue; // unchanged: the server already has it
                }
                if mode == "40000" {
                    stack.push((oid.clone(), path));
                } else {
                    blob_paths.entry(oid.clone()).or_insert(path);
                }
            }
            trees.insert(tree, entries);
        }
    }

    // Anything in the pack at or under a denied path is a change there.
    let find = |tree: &str, name: &str| {
        trees
            .get(tree)?
            .iter()
            .find(|(_, n, _)| n == name)
            .map(|(m, _, o)| (m.as_str() == "40000", o.clone()))
    };
    for denied in deny_paths {
        let parts: Vec<&str> = denied.split('/').filter(|p| !p.is_empty()).collect();
        let Some((last, dirs)) = parts.split_last() else {
            continue;
        };
        let denied = parts.join("/");
        for root in &commits {
            // Walk down the directories; a directory not in the pack is unchanged.
            let mut tree = Some(root.clone());
            for dir in dirs {
                tree = match tree.as_deref().and_then(|t| find(t, dir)) {
                    Some((true, oid)) => Some(oid),
                    _ => None,
                };
            }
            let Some((is_tree, oid)) = tree.as_deref().and_then(|t| find(t, last)) else {
                continue;
            };
            if !objects.contains_key(&oid) {
                continue;
            }
            // Name a changed file if there is one; a changed tree with no new file is a
            // delete or rename.
            let mut path = denied.clone();
            let mut stack = vec![(oid, path.clone())];
            let mut seen = HashSet::new();
            'walk: while let Some((tree, prefix)) = stack.pop() {
                if !is_tree || !seen.insert(tree.clone()) {
                    continue;
                }
                for (mode, name, oid) in trees.get(&tree).into_iter().flatten() {
                    if !objects.contains_key(oid) {
                        continue;
                    }
                    if mode == "40000" {
                        stack.push((oid.clone(), format!("{prefix}/{name}")));
                    } else {
                        path = format!("{prefix}/{name}");
                        break 'walk;
                    }
                }
            }
            return refused(format!("changes under {denied} are not allowed ({path})"));
        }
    }

    for (oid, (kind, size)) in &objects {
        if kind == "blob" && *size > max_blob {
            let path = blob_paths
                .get(oid)
                .map_or("(not in any pushed tree)", String::as_str);
            return refused(format!(
                "file {path} is {size} bytes, over the {max_blob} byte limit"
            ));
        }
    }

    Ok(Inspection {
        objects: objects.len(),
        commits: commits.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_parser_stops_on_junk() {
        let mut t = b"100644 a.txt\0".to_vec();
        t.extend_from_slice(&[0xab; 20]);
        t.extend_from_slice(b"40000 dir\0short");
        let entries = parse_tree(&t, 20);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1, "a.txt");
        assert_eq!(entries[0].2, "ab".repeat(20));
        assert!(parse_tree(b"\0\0 \0", 20).is_empty());
    }

    #[test]
    fn canonical_modes() {
        assert!(CANONICAL_MODES.contains(&"40000"));
        assert!(!CANONICAL_MODES.contains(&"040000"));
        assert!(!CANONICAL_MODES.contains(&"100664"));
    }
}
