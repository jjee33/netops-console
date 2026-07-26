<!-- Keep this short. Delete anything that does not apply. -->

## What and why

## Checklist

- [ ] `make lint` and `make test` pass
- [ ] `CHANGELOG.md` updated under `[Unreleased]` if this is user-visible

If this PR touches command execution, credentials, validation, or output rendering:

- [ ] No new call site outside `app/core/execution.py` runs a subprocess or opens an SSH session
- [ ] Every new parameter is validated, and SSH parameters have a regex `pattern`
- [ ] Command output is rendered escaped — no `|safe`
- [ ] New state-changing routes are POST and require a CSRF token
- [ ] Tests cover the rejection case, not only the happy path

If this PR touches discovery, networking, or the container's network mode:

- [ ] Tested on a real LAN, not only in CI — MAC and vendor columns populate
- [ ] Describe what you tested against:
