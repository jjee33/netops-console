# Elevated actions: sudoers and ForceCommand

> Actions land in Phase 4 and Phase 5. This document describes the host-side configuration they will expect. The patterns below apply whether or not you use this application.

Some actions need privileges the SSH user does not have. Granting them is your decision and happens on the target host, not in this application — which is the point. This app cannot grant itself anything.

## Narrow sudoers entries

```
# /etc/sudoers.d/netops — one exact command per line
netops ALL=(root) NOPASSWD: /usr/bin/systemctl restart docker
netops ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx
netops ALL=(root) NOPASSWD: /usr/sbin/dmidecode
```

Install with `visudo -c -f /etc/sudoers.d/netops` to validate before it takes effect. A syntax error in a sudoers file can lock you out of `sudo` entirely.

### Rules

**One exact absolute path per line.** Not a directory, not a pattern.

**Never a wildcard.** `systemctl restart *` allows `systemctl restart` on any unit, including one the attacker just wrote. It is an escalation to root, not a convenience.

**Never `NOPASSWD: ALL`.** That is a root shell with extra steps.

**Never a shell or interpreter.** `/bin/bash`, `/usr/bin/python3`, `/usr/bin/find`, `/usr/bin/vi`, `/usr/bin/awk`, and `less` all execute arbitrary commands by design. So does anything with an escape-to-shell feature. Consult GTFOBins before adding a binary you have not thought about.

**Watch for arguments that are secretly shells.** `systemctl` can start a transient unit. `apt` runs maintainer scripts. Some of these cannot be made safe with sudoers alone.

## ForceCommand: the control that survives a compromise

Sudoers limits what the SSH user can escalate to. It does nothing about what the SSH user can run as itself. If this application is compromised, its credential is used with whatever the target allows.

Restricting the key on the target closes that:

```
# ~/.ssh/authorized_keys on the target
command="/usr/local/bin/netops-wrapper",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,restrict ssh-ed25519 AAAA... netops@console
```

With a wrapper that allowlists commands itself:

```bash
#!/usr/bin/env bash
# /usr/local/bin/netops-wrapper — the target decides what it will run.
set -euo pipefail

case "${SSH_ORIGINAL_COMMAND:-}" in
  "uptime")                       exec /usr/bin/uptime ;;
  "df -h")                        exec /bin/df -h ;;
  "ip route show")                exec /usr/sbin/ip route show ;;
  "systemctl restart docker")     exec /usr/bin/sudo /usr/bin/systemctl restart docker ;;
  *)
    logger -t netops-wrapper "rejected: ${SSH_ORIGINAL_COMMAND:-<none>}"
    echo "command not permitted" >&2
    exit 126
    ;;
esac
```

Exact string matches, no interpolation of `SSH_ORIGINAL_COMMAND` into another command, and a log line for every rejection. `restrict` disables all forwarding and PTY allocation; the explicit `no-*` options are redundant on modern OpenSSH but harmless on older versions.

This is the recommended production pattern. It is the only control listed anywhere in this project that still protects the target if the console itself is fully compromised.

## Verifying

```bash
# As the netops user on the target:
sudo -l                                   # exactly the lines you granted
ssh -i netops_key netops@target 'id'      # rejected by the wrapper
ssh -i netops_key netops@target 'uptime'  # permitted
```

If `sudo -l` shows more than you intended, fix it before assigning the credential.
