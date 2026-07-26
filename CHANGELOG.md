# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

During `0.x`, breaking database schema changes may land in minor releases. Each one is
flagged **BREAKING** here with the migration or reinstall steps required.

## [Unreleased]

### Added
- Project scaffold, Apache-2.0 license, and public repository.
- Container build with non-root runtime user and file capabilities on `nmap`, `ping`,
  and `traceroute`, so raw sockets work without running as root.
- First-run bootstrap: generates session and encryption keys, applies migrations, and
  creates an initial admin account with a random password printed once to the logs.
- Compose files for the published image, local source builds, and an optional
  host-networked Caddy TLS proxy.
- CI covering lint, tests, a multi-arch image build, and a container smoke test that
  asserts capabilities, the non-root UID, loopback-only binding, and SQLite pragmas.
- Release pipeline publishing signed multi-arch images with SBOM and provenance.

[Unreleased]: https://github.com/jjee33/netops-console/commits/main
