# Security policy

git-proxy is a security boundary: a push it forwards is a push the client was meant to be able
to make. A push that gets past a check, a way to read the upstream token, or a small request that
keeps the proxy busy or out of memory is a vulnerability.

## Reporting

Please report privately through GitHub: the **Security** tab of this repository, then
**Report a vulnerability**. Do not open a public issue.

Include the push that gets through (a script or the raw request body is ideal), what you
expected the proxy to do, and the version or commit you tested.

You should hear back within a week. Once a fix is out we will credit you in the release notes
unless you prefer not to be named.

## Known gaps

The gaps listed under "Limits" in the [README](README.md#limits) are known and accepted for now.
They are not vulnerabilities, but ideas for closing them are welcome as issues.

## Supported versions

Only the latest commit on `main` is supported while the project is at 0.x.
