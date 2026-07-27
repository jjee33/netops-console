# NetOps Console

Self-hosted network operations console for homelabs and small offices. Discovers what is on your LAN, runs diagnostics against it, and executes a fixed set of allowlisted commands — with every action written to an audit log.

That is the goal. Discovery and inventory work today; diagnostics, actions and the audit log are still being built. See below.

[![CI](https://github.com/jjee33/netops-console/actions/workflows/ci.yml/badge.svg)](https://github.com/jjee33/netops-console/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Image](https://img.shields.io/badge/ghcr.io-netops--console-blue?logo=docker)](https://github.com/jjee33/netops-console/pkgs/container/netops-console)

> **Status: pre-release (`v0.1.0-alpha.2`).** Usable but incomplete — see the table below for what actually works today. The schema may change between alpha tags without a migration path. Watch the repo for the v0.1.0 release.

---

## What works today

| | |
|---|---|
| **Authentication** | Local account with Argon2id, session expiry, per-account lockout and per-IP rate limiting, forced rotation of the generated first-run password |
| **Scope control** | Private IPv4 ranges you configure. Nothing outside them can be scanned or contacted, and loopback, link-local, multicast and public space are refused outright |
| **Discovery** | nmap host and port scanning of a chosen subnet, producing an inventory with IP, MAC, vendor, hostname and open ports. Safely re-runnable — a second scan of the same range creates no duplicates |
| **Inventory** | Sortable, searchable device list; device detail with open ports; your own name, type and notes, which a rescan never overwrites. Removal is a soft delete, so history survives |

## Not built yet

Planned for v0.1, in this order: **diagnostics** (ping, traceroute, DNS, TCP and
HTTP checks from the device page), **actions** (allowlisted commands you define,
run locally or over SSH, with typed parameter schemas), and the **audit log**
that records every one of them with the acting user, client IP, redacted
parameters, timing and output.

Until those land this is an inventory tool, not the console described above.

## What it deliberately does not do

Not a monitoring platform. No topology maps, no SNMP graphing, no alerting, no multi-tenancy, no agents. v0.1 is single-site, single-admin, IPv4, manual-trigger. That scope is a design decision, not a backlog — see [ROADMAP](#roadmap).

## Security posture — read before installing

This is **privileged infrastructure software**. It holds credentials and runs commands. Treat a compromise of this application as a compromise of your management plane.

It is designed to run on a trusted management network, behind a reverse proxy that terminates TLS, and **never exposed directly to the internet**. The container binds `127.0.0.1` by default specifically so that a misconfiguration cannot silently publish an admin panel to your LAN.

Design choices that follow from that, and which are in place now: a non-root container with all capabilities dropped except `CAP_NET_RAW`, a read-only root filesystem, no free-form command input anywhere in the UI, and a single choke point through which every command execution passes — no shell, argv arrays only, allowlisted binaries, hard timeouts, and process-group kills.

Still to come with the features that need them: credentials encrypted at rest, and strict SSH host key verification with an explicit human trust step.

Full threat model and vulnerability reporting: [SECURITY.md](SECURITY.md).

## Quickstart

Requires Docker Engine with the Compose v2 plugin, on a Linux host.

```bash
curl -O https://raw.githubusercontent.com/jjee33/netops-console/main/compose.yaml
docker compose up -d
docker compose logs app | grep -A3 'Initial admin'
```

The first start generates its own session and encryption keys, applies the database schema, and creates an `admin` account with a random password printed once to the container logs. You are required to change it at first login.

> **Back up `crypto_key` immediately, and store it somewhere other than where you store the database.** It encrypts every stored credential. Lose it and they are unrecoverable; leak it alongside a database copy and they are all compromised. See [docs/BACKUP_RESTORE.md](docs/BACKUP_RESTORE.md).

The app listens on `127.0.0.1:8000` and is not reachable from your LAN until you put a TLS proxy in front of it. A working example is included:

```bash
curl -O https://raw.githubusercontent.com/jjee33/netops-console/main/compose.caddy.yaml
docker compose -f compose.yaml -f compose.caddy.yaml up -d
```

Full instructions, including why the proxy must use host networking: [docs/INSTALL.md](docs/INSTALL.md).

## Why host networking

Layer 2 discovery needs to see the real LAN. Under Docker's default bridge networking, MAC addresses are hidden behind NAT and ARP-based discovery returns nothing useful — vendor and MAC columns come back mysteriously empty rather than failing loudly. `network_mode: host` is the pragmatic default; macvlan is a documented alternative if you want more isolation. Bridge mode degrades you to IP-only discovery.

## Upgrading

```bash
docker compose pull && docker compose up -d
```

Migrations apply automatically at startup. Back up first. During `0.x`, breaking schema changes may land between minor versions; each is called out in [CHANGELOG.md](CHANGELOG.md). See [docs/UPGRADING.md](docs/UPGRADING.md).

## Verifying the image

Release images are multi-architecture (`linux/amd64`, `linux/arm64`), carry an SBOM and build provenance, and are signed with cosign keyless signing:

```bash
cosign verify ghcr.io/jjee33/netops-console:v0.1.0 \
  --certificate-identity-regexp '^https://github\.com/jjee33/netops-console/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Only semver tags get `latest`. Builds from `main` are tagged `main` and `sha-<commit>` and are not release candidates.

## Documentation

| Document | Contents |
|---|---|
| [docs/INSTALL.md](docs/INSTALL.md) | Full install, reverse proxy setup, capability verification |
| [docs/MANUAL_VERIFICATION.md](docs/MANUAL_VERIFICATION.md) | Checks that need a real network, which CI cannot perform |
| [docs/UPGRADING.md](docs/UPGRADING.md) | Upgrade and rollback |
| [docs/BACKUP_RESTORE.md](docs/BACKUP_RESTORE.md) | Consistent SQLite backup, key backup, restore drill |
| [docs/ACTION_DEFINITIONS.md](docs/ACTION_DEFINITIONS.md) | Writing safe action definitions |
| [docs/SUDOERS_EXAMPLE.md](docs/SUDOERS_EXAMPLE.md) | Narrow sudoers and SSH `ForceCommand` hardening |
| [SECURITY.md](SECURITY.md) | Threat model and vulnerability reporting |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup and project rules |

## Roadmap

Deferred to post-v0.1, in rough order of likelihood: live output streaming, scheduled discovery, IPv6, RBAC with multiple roles, and Wake-on-LAN. Explicitly out of scope: SNMP monitoring and graphing, topology mapping, multi-site or MSP multi-tenancy, Kubernetes, and AI diagnostics.

## License

Apache-2.0 — see [LICENSE](LICENSE). The container image bundles third-party tools under their own licenses; see [NOTICE](NOTICE).
