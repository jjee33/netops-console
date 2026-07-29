# Security Policy

## Reporting a vulnerability

Report privately through GitHub Security Advisories:
**https://github.com/jjee33/netops-console/security/advisories/new**

Please do not open a public issue for a security problem.

This is a single-maintainer project. Expect an acknowledgement within 7 days and a fix or a plan within 30 days for issues rated High or Critical. If you receive no response within 14 days, escalate by opening a public issue that says only that you sent a private report and got no reply — no details.

Supported versions: the latest release only. There are no backported security fixes during `0.x`.

## Threat model

Understanding this is a prerequisite for deploying the application safely. Several controls below are only sufficient *because* of the assumptions in the first section. If an assumption does not hold for your deployment, the security model is insufficient and you should not deploy until you have compensated for it.

### Assumptions

1. The application is **privileged infrastructure software**. It stores credentials and executes commands. A compromise of this app is equivalent to a compromise of your management plane.
2. It runs on a **trusted management network**, behind a reverse proxy terminating TLS, and is **never exposed directly to the internet**.
3. There is **one trusted administrator**. There is no RBAC in v0.1 — every authenticated user is fully privileged. The audit log records the acting user for future-proofing, not for privilege separation.
4. Targets are on **admin-configured private IPv4 ranges**. IPv6 is out of scope for v0.1.
5. The application runs as **a single process with a single worker**. Concurrency limits are enforced in-process, so running multiple workers or replicas silently voids every cap.

### In scope

| Threat | Control |
|---|---|
| Command injection, local execution | No shell, ever. `asyncio.create_subprocess_exec` with argv arrays; each parameter is exactly one argv element. |
| Command injection, SSH execution | Argv is **not** a boundary here — `sshd` runs the command through the remote user's login shell. Controlled instead by per-parameter regex allowlists or fixed choices, **mandatory and enforced when the action is saved** so an unsafe definition cannot be stored; `shlex.quote` on every substitution; and a documented `ForceCommand` pattern that moves enforcement to the target host. A pattern that matches everything is refused. |
| Arbitrary command execution from the browser | The frontend sends an action ID and parameters. It cannot send a command string. Built-in diagnostics use hardcoded argv builders and are not admin-editable. |
| SSRF | Every destination is parsed with `ipaddress`, must fall inside admin-configured CIDRs, and hostnames are re-validated *after* DNS resolution. Loopback, link-local (including `169.254.169.254`), multicast, and public ranges are rejected. HTTP checks do not follow redirects. |
| Excessive scan ranges | Prefix size capped (default ~1024 hosts), per-scan timeout, and a concurrent-scan limit. |
| Runaway processes | Hard per-action timeout; the engine kills the whole **process group**, so children of traceroute and continuous ping die with the parent. |
| Credential exposure | Fernet-encrypted at rest with a key that lives outside the database and outside the image. Decrypted in memory only at connection time. No route returns a secret; the UI shows a name, username and fingerprint. Parameters flagged `secret` are masked before an execution record is written. |
| SSH MITM | Strict host key verification against a database-backed trust store. A credential is never offered to a device whose key is unknown — the connection is refused during key exchange, before authentication. First contact requires an explicit human trust action recording who trusted which fingerprint and when, and the trust route re-reads the key from the device rather than believing the submitted form. A changed key fails the connection; it is never silently re-trusted. |
| XSS from command output | All command output is untrusted. Autoescaped, rendered in `<pre>`, ANSI and control characters stripped, size-capped. A restrictive CSP is set, and device hostnames rendered into links are scheme-validated to reject `javascript:`. |
| CSRF | Synchronizer token required on every state-changing request. |
| Credential brute force | Per-account lockout with backoff plus a per-IP rate limit. Failure messages never reveal whether a username exists. |
| Privilege escalation on the host | The container runs non-root with all capabilities dropped except `CAP_NET_RAW`. Local actions needing root require an operator-installed sudoers entry for one exact absolute-path command — never a wildcard, never a shell. |
| Audit tampering by deletion | Devices are soft-deleted. Audit rows survive with denormalized label snapshots. |

### Out of scope

These are **not** defended against, by design. Do not report them as vulnerabilities:

- **A malicious authenticated administrator.** The admin can define actions that run commands. That is the product. There is no privilege separation to escalate through.
- **Anyone with host `docker` group membership or root on the Docker host.** Both are root-equivalent and can read the master key.
- **Internet exposure.** If you publish this to the internet, findings that depend on that are configuration failures, not vulnerabilities.
- **A compromised target host.** If an SSH target is already owned, this app's credentials for it are already owned.
- **Denial of service against yourself** by configuring a huge scan or an aggressive timeout on your own network.
- **DNS rebinding / TOCTOU between validation and connection.** Acknowledged and mitigated only by short timeouts and private-range enforcement, not eliminated.
- **Any deployment running more than one worker or replica**, which voids the concurrency controls.

## Operator responsibilities

Controls that are yours, not the application's:

1. **Terminate TLS in front of it.** The app speaks plain HTTP on loopback deliberately.
2. **Back up `crypto_key` separately from the database.** Storing them together defeats the encryption. Losing it destroys every stored credential.
3. **Keep `--workers 1`.** It is not a performance knob; it is a safety property.
4. **Restrict SSH keys on the target** with an `authorized_keys` `command="..."` entry. It is the only control listed anywhere here that still protects a device if this application is compromised. See [docs/SUDOERS_EXAMPLE.md](docs/SUDOERS_EXAMPLE.md).
5. **Do not put an SSH user in the `docker` group** unless you accept that the credential is a root credential on that host.
6. **Keep the image current.** It bundles nmap and OpenSSL. Releases are scanned weekly, but only you can pull.
7. **The initial admin password is printed to the container logs.** This is deliberate — it is the only channel available before an account exists, and anyone who can read those logs already has Docker access, which is root-equivalent on the host. It does mean the password transits your logging pipeline, so if you ship container logs to a third party, change the password promptly and consider setting `NETOPS_ADMIN_PASSWORD` instead. It is a one-time value and the account is forced to rotate it at first login.
