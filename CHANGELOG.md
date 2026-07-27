# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

During `0.x`, breaking database schema changes may land in minor releases. Each one is
flagged **BREAKING** here with the migration or reinstall steps required.

## [Unreleased]

## [0.1.0-alpha.2] — 2026-07-27

Discovery and device inventory.

### Added
- **ExecutionEngine** — the single path through which every command in the
  application runs. No shell, argv arrays only, an allowlist of absolute-path
  binaries, a hard timeout per run, and the whole *process group* killed on
  expiry so children of `traceroute` and continuous `ping` cannot be orphaned.
  Concurrency is bounded and the permit is released in a `finally`, because one
  leaked permit is permanent. Discovery has its own separate, lower budget.
- **Output sanitising** — ANSI and control characters stripped (including
  carriage returns, which let later output overwrite earlier output), credential-
  shaped lines masked, and a byte-measured size cap that cuts on a character
  boundary.
- **Discovery** — nmap host and port scanning, parsed with `defusedxml`. Targets
  are validated against the allowlist and the host cap *before* nmap is invoked;
  an oversized or out-of-scope range never becomes a process. Scans run as
  background tasks with a polled status, so a reverse proxy cannot time out a
  scan that is working.
- **Device inventory** — sortable, searchable device list, device detail with
  open ports, and operator-editable name, type, and notes that a rescan never
  overwrites.
- Device identity is MAC-first with address fallback, so a DHCP lease change
  keeps one device rather than creating a second. A device first seen across a
  router adopts its MAC when later scanned from its own segment instead of
  duplicating, and a removed device that reappears is restored rather than
  re-created alongside its own history.
- Device removal is a soft delete. History survives, and the device page and
  list exclude it.

### Security
- Discovered hostnames are rendered escaped everywhere, and any URL built from
  device data is scheme-checked so a hostname of `javascript:…` cannot become a
  clickable link.
- XML entity expansion and external entity resolution are refused.

### Fixed
- Secret masking stopped at the first whitespace, so `Authorization: Bearer
  <token>` masked only the word `Bearer` and wrote the token itself into stored
  output. Patterns now consume the rest of the line.

## [0.1.0-alpha.1] — 2026-07-27

First release with a usable interface. Still a prerelease: there is no discovery,
no diagnostics, and no device inventory yet.

### Added
- Local username and password authentication with Argon2id hashing, signed-cookie
  sessions, absolute and idle expiry enforced server-side, and session replacement
  on login so a planted session cannot be adopted.
- Per-account lockout with exponential backoff and a per-IP login rate limit.
  Failure messages are identical whether or not the account exists, and the
  password hash is verified even for unknown usernames so response timing does
  not disclose which accounts are real.
- Forced rotation of the generated bootstrap password before the rest of the
  application is reachable — that value is printed to container logs, so leaving
  it in place would make the exposure permanent.
- Settings page for allowed CIDR ranges, scan host cap, concurrency limits,
  retention, and strict SSH host key verification. Allowed ranges must be private
  (RFC 1918 or CGNAT); loopback, link-local, multicast, and public space are
  rejected, as is any range that would let the app reach cloud metadata.
- Dashboard shell and a server-rendered UI with no build step. HTMX is vendored
  into the image rather than loaded from a CDN.
- CSRF protection on every state-changing request, enforced as middleware so a
  route added later cannot silently skip it.
- Content-Security-Policy with no `unsafe-inline`, plus `nosniff`, `DENY` framing,
  `no-referrer`, and HSTS when the proxy reports TLS.

### Fixed
- `/healthz` answered 405 to HEAD, which uptime monitors read as an outage.

## [0.1.0-alpha.0] — 2026-07-26

Delivery pipeline and container foundation. No usable application.

### Added
- Project scaffold, Apache-2.0 license, and public repository.
- Container build with non-root runtime user and file capabilities on `nmap`, `ping`,
  and `traceroute`, so raw sockets work without running as root. `NMAP_PRIVILEGED=1`
  is set because nmap gates SYN and ARP scans on `geteuid()` rather than on its own
  capabilities, and refuses them otherwise even when `CAP_NET_RAW` is present.
- First-run bootstrap: generates session and encryption keys, applies migrations, and
  creates an initial admin account with a random password printed once to the logs.
- Compose files for the published image, local source builds, and an optional
  host-networked Caddy TLS proxy.
- CI covering lint, tests, a multi-arch image build, and a container smoke test that
  asserts capabilities, the non-root UID, loopback-only binding, and SQLite pragmas.
- Release pipeline publishing signed multi-arch images with SBOM and provenance.

[Unreleased]: https://github.com/jjee33/netops-console/compare/v0.1.0-alpha.2...HEAD
[0.1.0-alpha.2]: https://github.com/jjee33/netops-console/compare/v0.1.0-alpha.1...v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/jjee33/netops-console/compare/v0.1.0-alpha.0...v0.1.0-alpha.1
[0.1.0-alpha.0]: https://github.com/jjee33/netops-console/releases/tag/v0.1.0-alpha.0
