# NetOps Console

Self-hosted network operations console for homelabs and small offices. Discovers what is on your LAN, runs diagnostics against it, and executes a fixed set of allowlisted commands — with every action written to an audit log.

[![CI](https://github.com/jjee33/netops-console/actions/workflows/ci.yml/badge.svg)](https://github.com/jjee33/netops-console/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Image](https://img.shields.io/badge/ghcr.io-netops--console-blue?logo=docker)](https://github.com/jjee33/netops-console/pkgs/container/netops-console)

> **Status: pre-release (v0.1.0-alpha).** Not yet ready for use. The schema may change between alpha tags without a migration path. Watch the repo for the v0.1.0 release.

---

## What it does

- **Discovery** — nmap-backed scans of subnets you configure, producing an inventory with IP, MAC, vendor, hostname, and open ports. Re-runnable without creating duplicates.
- **Diagnostics** — ping, bounded continuous ping, traceroute, DNS, reverse DNS, TCP port test, limited service scan, ARP, and HTTP(S) check, all from the device page.
- **Actions** — you define allowlisted commands (local or over SSH) with typed parameter schemas. The browser sends an action ID and parameters, never a command string.
- **Audit** — every diagnostic, action, and discovery run is recorded with the acting user, client IP, parameters (secrets redacted), timing, exit code, and output. Deleting a device does not erase its history.

## What it deliberately does not do

Not a monitoring platform. No topology maps, no SNMP graphing, no alerting, no multi-tenancy, no agents. v0.1 is single-site, single-admin, IPv4, manual-trigger. That scope is a design decision, not a backlog — see [ROADMAP](#roadmap).

## Security posture — read before installing

This is **privileged infrastructure software**. It holds credentials and runs commands. Treat a compromise of this application as a compromise of your management plane.

It is designed to run on a trusted management network, behind a reverse proxy that terminates TLS, and **never exposed directly to the internet**. The container binds `127.0.0.1` by default specifically so that a misconfiguration cannot silently publish an admin panel to your LAN.

Design choices that follow from that: non-root container with all capabilities dropped except `CAP_NET_RAW`, read-only root filesystem, credentials encrypted at rest, strict SSH host key verification with an explicit human trust step, no free-form command input anywhere in the UI, and a single choke point through which every command execution passes.

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
