# Security Policy

## ⚠️ dvmcp is intentionally vulnerable

`dvmcp` (the training server in this repository) contains **deliberately
insecure code**: command injection, path traversal, SSRF, missing
authentication, tool poisoning, a rug pull, a prompt-injection chain, and a
secret-leaking resource. This is by design — it is a practice target, like
DVWA or WebGoat.

**Do not report dvmcp's planted vulnerabilities as security bugs.** They are
documented in [`docs/challenges/`](docs/challenges/) and are the whole point of
the project.

## Rules for running it safely

- **Never expose dvmcp to a network you do not fully control.** It binds to
  `127.0.0.1` by default and refuses to start on a non-loopback address unless
  you pass `--i-know-this-is-dangerous`.
- The Docker setup publishes the port to **host loopback only**
  (`127.0.0.1:8731`). Do not change this to `0.0.0.0`.
- Run it in the provided container (non-root, read-only filesystem, dropped
  capabilities, lab files in tmpfs) when you can.
- Every "secret" in the project is a **fake canary** (prefixed `dvmcp_canary_`
  or inside a `DVMCP{...}` flag). There are no real credentials anywhere.
- The command-injection challenge only runs a genuine shell when
  `DVMCP_REAL_EXEC=1` is set (the container sets it); otherwise it uses a
  contained simulator. Either way it can only reach a canary file in the lab
  directory.

## Reporting a real vulnerability

If you find a vulnerability in the **scanner (`mcpscan`)**, the **harness**, or
the **safety controls** (for example, a way to make dvmcp bind off-loopback
without the override, or a scanner crash on hostile input), please report it
privately:

- Open a GitHub **Security Advisory** on this repository (preferred), or
- Email the maintainer (see the GitHub profile) with "mcp-range security" in
  the subject.

Please include steps to reproduce. Since this is a personal open-source
project, expect a best-effort response rather than a formal SLA.

## Responsible use

This project is for defensive security education and tooling. Use the
techniques it teaches only against systems you own or are authorized to test.
