# Action definitions

> **Not yet implemented.** Actions land in Phase 4 (local) and Phase 5 (SSH). This document is the design contract they are being built against, published early because the security reasoning is what matters and it should not be invented at implementation time.

An *action* is an allowlisted command an administrator defines once and then runs against devices. The browser only ever sends an action ID and a set of parameters; it cannot send a command string. The server resolves what actually runs.

## Shape

```json
{
  "name": "Show routing table",
  "description": "Display the host routing table.",
  "execution_type": "local",
  "argv_template": ["/usr/sbin/ip", "route", "show"],
  "param_schema": {},
  "timeout_seconds": 10,
  "confirmation_required": false,
  "elevated_required": false,
  "applicable_tags": []
}
```

| Field | Meaning |
|---|---|
| `execution_type` | `local` runs in the container; `ssh` runs on the target device |
| `argv_template` | Command tokens; `{name}` placeholders are substituted from parameters |
| `param_schema` | Type, range, and pattern constraints per parameter |
| `timeout_seconds` | Hard cap; the engine kills the process group on expiry |
| `confirmation_required` | Requires an explicit confirm step in the UI |
| `elevated_required` | Needs a sudoers entry — see [SUDOERS_EXAMPLE.md](SUDOERS_EXAMPLE.md) |
| `applicable_tags` | Restricts which devices it can target; empty means all |

## Local actions: argv is a real boundary

Local actions run through `asyncio.create_subprocess_exec` with an argv array and no shell. Each parameter becomes exactly one argv element, so shell metacharacters are inert — a parameter of `; rm -rf /` is passed to the program as a literal string, because there is no shell to interpret it.

Use absolute paths. Relative paths depend on `PATH` and are a substitution target.

## SSH actions: argv is NOT a boundary

This is the part that is easy to get wrong, and getting it wrong is a remote code execution bug on the target host.

An SSH "exec" request transmits a **single command string** to the remote `sshd`, which runs it through the target user's **login shell**. It does not matter how carefully the string was assembled locally: metacharacters are interpreted on the far end.

```json
{
  "name": "Restart Docker container",
  "description": "Restart a named container. NOTE: requires the SSH user to be in the docker group, which is root-equivalent on the target.",
  "execution_type": "ssh",
  "argv_template": ["docker", "restart", "{container}"],
  "param_schema": {
    "container": {
      "type": "string",
      "pattern": "^[a-zA-Z0-9_.-]{1,64}$",
      "required": true
    }
  },
  "timeout_seconds": 30,
  "confirmation_required": true,
  "applicable_tags": ["docker-host"]
}
```

Safety here comes from two things, in this order:

1. **The `pattern`**, which rejects `;`, `$`, backticks, spaces, and newlines outright. This is mandatory for every SSH parameter, not advisory.
2. **`shlex.quote` on every substituted value** when the template is joined into a command string.

Neither is sufficient alone, and neither is as strong as the target-side control below.

## The strongest control lives on the target

Restrict the key itself in the target's `authorized_keys`:

```
command="/usr/local/bin/netops-wrapper",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding ssh-ed25519 AAAA... netops
```

The wrapper inspects `SSH_ORIGINAL_COMMAND` against its own allowlist and refuses anything else. This is the only control that still holds if **this application** is compromised, which is why it is the recommended production pattern rather than a footnote.

## Credentials that are more powerful than they look

Some actions imply far more privilege than the command suggests. Say so in the description.

- **Anything using `docker` on the target** requires the SSH user to be in the `docker` group. That group is root-equivalent — it can mount the host filesystem into a container. Treat the credential as a root credential.
- **`sudo systemctl restart <unit>`** with a wildcard in sudoers is trivially escalatable. One exact unit per line.
- **Any action taking a file path** is a path traversal target unless the path comes from an allowlist.

## Writing a safe action

1. Prefer no parameters at all. A static command has no injection surface.
2. If you need a parameter, use the narrowest pattern that works — an enum of allowed values beats a regex, and a regex beats a length limit.
3. Use absolute paths for local actions.
4. Set the shortest timeout that is realistic.
5. Set `confirmation_required` for anything that changes state.
6. Say in the description what privilege the action actually needs.
7. Test it with `; id`, `$(id)`, a backtick, a space, and a newline. All five must be rejected before the command runs.
