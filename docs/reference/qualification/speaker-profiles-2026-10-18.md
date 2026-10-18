# Speaker profile qualification — 2026-10-18 UTC

Both Compose profiles passed on Linux/amd64 using the same locally built
controller image, `sha256:9a22c93f4a9e18461e1de281ed780ca7cafe658538b425e0a87c44bc1fa166df`.
This identifies the local qualification artifact; it is not a published registry
digest. The 108-file Docker input manifest has SHA-256
`88015e7e99dd0f299285a9d6359e7dbe5cd3f531098626e94d00febf5875fffd`.

The build used the pinned
`rust:1.99.1-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a`
builder. Cargo used three jobs; the actual builder, Cargo, Rust and C compiler
processes were observed on CPUs 32–63. The declared Rust 1.88 minimum has a
separate CI gate. All owned build and runtime resources were cleaned afterward;
the local image and raw successful/failed receipts were retained.

Speaker pins:

- rustbgpd 0.77.0:
  `ghcr.io/lance0/rustbgpd:0.77.0@sha256:6dbfa42c47aa1d063f119f3eff9524aac4585665c0a9c79167ec8d20244bc6c2`.
- GoBGP 4.10.0, independently qualified image:
  `jauderho/gobgp@sha256:42b8d0017237e388c55936efe1f23632365b24a31751f6e8815f93e12c4d18c2`.

## Results

| Check | rustbgpd | GoBGP |
| --- | --- | --- |
| Actual UID/GID 999 controller and speaker | Passed | Passed |
| Private management | Owner-only directory 0700/socket 0600 | Shared namespace, loopback RPC only; no profiling/metrics listener |
| Credentials login and protected operational health | Passed | Passed |
| IPv4 discard and IPv6 policing at 8 Mbps, UDP ports 53/123, TTL 60 | Exact complete local inventories | Exact complete accepted local RIBs |
| Withdrawal, original actor/reason audit and raw absence | Passed; other-family control preserved | Passed; other-family control preserved |
| Inventory reload, playbook/correlation/alerting saves and backups | Passed | Passed |
| Recreated speaker/controller and persisted configuration | Passed | Passed, including namespace-owner recreation |
| Active rule after recreation | Same persisted ID, absolute expiry and exact rule; withdrawal/audit passed | Same persisted ID, absolute expiry and exact rule; withdrawal/audit passed |

The three Compose model/seeding checks passed with the built image, including
mutual-profile rejection before startup and preservation of existing edits.
Configuration tests passed 75 cases with all features and 75 with no default
features plus test utilities. Formatting, both strict Clippy configurations and
the GoBGP-only binary check passed. The shipped rustbgpd configuration passed the
pinned release's `--check --strict` with networking disabled. The dual-family
peer-restart case also passed against released rustbgpd 0.76.0 and 0.77.0.

## Scope and retained failures

The profile runs used preloaded images, an existing published dashboard and an
outbound-isolated network with ephemeral loopback HTTP. They exercised actual
authenticated API requests and local speaker state. Documentation peers remained
Idle; these runs do not establish router forwarding, browser behavior or a cold
quickstart timing guarantee. Rust read-back is retained local intent; GoBGP
read-back is its accepted local RIB.

Earlier failed runs were preserved and diagnosed: Docker copy-up reset private
empty-volume modes, saved correlation settings were ignored at startup, and
private harness assumptions about nginx ingress, numeric CLI spelling and an
`id` utility needed correction. Go now verifies all four kernel UID/GID fields.
The peer restart fixture also exposed Docker reallocating an automatically
published RPC port; reserving the existing fixture port preserves the client
endpoint. No failed oracle was weakened to obtain a passing result.
