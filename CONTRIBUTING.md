# Contributing

Thanks for looking. This is a single-maintainer project with a deliberately narrow scope, so please open an issue to discuss anything larger than a bug fix before writing code — it saves you from building something that gets declined on scope grounds.

## Scope

v0.1 is single-site, single-admin, IPv4, manual-trigger. Features listed as out of scope in the README are not "not yet" — they are decisions. Monitoring, graphing, topology, multi-tenancy, and agents are all no.

## Development setup

Requires Python 3.12 and Docker Engine with the Compose v2 plugin.

```bash
git clone git@github.com:jjee33/netops-console.git
cd netops-console
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
```

Run the checks the CI runs:

```bash
make lint   # ruff, mypy, hadolint
make test   # pytest
```

Run the app against a locally built image:

```bash
make dev    # docker compose -f compose.yaml -f compose.dev.yaml up -d --build
make logs
```

## Rules that are not negotiable

These exist because this application executes commands and holds credentials. A PR that breaks one of them will be declined regardless of what else it does.

1. **All command execution goes through `app/core/execution.py`.** Nothing else in the codebase may call `subprocess`, `os.system`, `asyncio.create_subprocess_*`, or open an SSH session. The engine owns concurrency limits, timeouts, process-group kills, output caps, redaction, and audit writes; a second call site silently opts out of all of it. Ruff's `S603`/`S607` are enabled globally and may only be silenced per-line in that one module, with a comment explaining why.
2. **Never `shell=True`. Never string-concatenate a command.** Local execution uses argv arrays where each parameter is exactly one element.
3. **SSH parameters must have a regex allowlist.** Argv provides no protection on the SSH path — `sshd` hands the command to the remote login shell. A new SSH action definition without a `pattern` on every parameter is a security bug.
4. **Never render command output with `|safe`.** It is untrusted input from an untrusted host.
5. **Every state-changing route is POST and requires a CSRF token.** With HTMX it is easy to add a route that appears to work while skipping the token; add a test.
6. **Single worker.** Do not add `--workers`, Gunicorn, or a second replica. The concurrency semaphore is in-process, and multiplying it silently voids every cap.
7. **No new destination without validation.** Anything that takes an IP, CIDR, hostname, or URL goes through `app/core/validation.py`, including re-validating a hostname after DNS resolution.

## Tests

Priority is validators, redaction, crypto, the execution engine, and parsers — the places where a bug is a vulnerability rather than an annoyance. Please include:

- A test for the failure case, not only the success case.
- For anything touching parameters: an injection attempt (`; id`, `$(id)`, backticks, newline, space) asserting rejection.
- For anything touching output: an assertion that a hostile payload appears escaped in the rendered HTML.

Tests marked `@pytest.mark.smoke` need real network tools with working capabilities and are skipped by default.

## What CI cannot check

CI verifies capabilities, the non-root UID, unprivileged `nmap`/`ping`/`traceroute` against loopback, fresh-volume writability, SQLite pragmas, loopback-only binding, and CSRF enforcement. It runs on a single isolated runner, so it **cannot** verify:

- Real Layer 2 discovery, MAC address population, or vendor lookup
- Reverse proxy reachability against a host-networked container
- Behaviour against actual network equipment

If your change touches discovery, networking, or the container's network mode, test it on a real LAN and say so in the PR. Empty MAC and vendor columns are the specific failure mode here, and it fails silently rather than erroring.

## Commits and PRs

Conventional-ish commit subjects (`feat:`, `fix:`, `docs:`, `ci:`, `refactor:`, `test:`) in the imperative mood. Keep PRs focused. Update `CHANGELOG.md` under `[Unreleased]` for anything user-visible.

## Releasing (maintainer only)

1. Update the version in `pyproject.toml` and move `[Unreleased]` entries into a dated section in `CHANGELOG.md`.
2. Commit, then tag: `git tag -a v0.1.0 -m 'v0.1.0' && git push --tags`.
3. `release.yml` builds `linux/amd64` and `linux/arm64` on native runners, pushes by digest, merges the manifest, attaches SBOM and provenance, signs with cosign, and creates the GitHub release. The workflow fails if the tag and `pyproject.toml` version disagree.
4. Pre-release tags (`v0.1.0-alpha.1`) publish that exact tag only — no `latest`, no floating `0.1` or `0` tags.
