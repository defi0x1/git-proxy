# Contributing

Issues and pull requests are welcome. For anything bigger than a small fix, open an issue first
so we can agree on the shape before you write the code.

Before you open a pull request, run what CI runs:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check        # if you added or changed a dependency
```

The tests need `git` on your `PATH`; they start a local `git http-backend` and push through the
proxy with real git.

A change to a check (ref policy, pack inspection, size limits) should come with a test that
pushes something the check must refuse, in `tests/push.rs` or `tests/attacks.rs`. Parser changes
can also be fuzzed:

```sh
cd fuzz
cargo +nightly fuzz run parse_push -- -max_total_time=60
cargo +nightly fuzz run scan_pack -- -max_total_time=60
```

Commit subjects are short and lowercase with a type prefix, for example
`fix: refuse a tree entry with a padded mode`.

Unless you say otherwise, your contribution is licensed as MIT OR Apache-2.0, like the rest of
the project.

Found a way past a check? Please do not open a public issue; see [SECURITY.md](SECURITY.md).
