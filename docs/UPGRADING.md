# Upgrading

```bash
docker compose exec app python -m app.cli backup /data/backup.db   # back up first
docker compose pull
docker compose up -d
docker compose logs app | tail -20
```

Migrations apply automatically at startup, before the server accepts connections. If a migration fails, the application does not start and your data is left as it was — read the traceback in the logs rather than retrying blindly.

## Version policy

Semantic versioning, with one caveat that matters during `0.x`:

- **`0.x` minor releases may change the database schema in breaking ways.** Each such change is marked **BREAKING** in [CHANGELOG.md](../CHANGELOG.md) with what it requires. Read it before upgrading.
- Patch releases never break the schema.
- `latest` always points at the most recent stable release, never at a prerelease or the tip of `main`.

Pin a version if you would rather upgrade deliberately:

```bash
NETOPS_VERSION=v0.1.0 docker compose up -d
```

## Rolling back

Downgrading the image alone is not enough if the newer version applied a migration — the older code will not understand the newer schema. Roll back by restoring the database from the backup you took before upgrading:

```bash
docker compose down
# restore the database per docs/BACKUP_RESTORE.md
NETOPS_VERSION=v0.1.0 docker compose up -d
```

This is why the first line of the upgrade procedure is a backup.

### Rolling back one migration without a restore

If you have kept writing to the database since upgrading and would rather not
lose that, you can step the schema back with the **newer** image, then start the
older one. Every migration in this project ships a downgrade, and CI checks that
they reverse cleanly.

```bash
docker compose exec app python -m app.cli backup /data/pre-rollback.db   # always
docker compose exec app alembic downgrade <revision the older version expects>
docker compose down
NETOPS_VERSION=<older tag> docker compose up -d
```

The older image cannot do this itself: it does not contain the newer
migration's downgrade step. A downgrade drops whatever that migration added;
the changelog entry for each migration says what that is. Restoring a backup is
still the simplest rollback and the one to prefer.

### Revision reference

| Version | Head revision | Adds |
|---|---|---|
| `0.1.0-alpha.5` | `36c5a90d852f` | — |
| `0.1.0-alpha.6` | `4cdd051ae46a` | `discovery_observation`, `change_event`, `discovery_run.scanned_ports`. Additive; downgrading to `36c5a90d852f` drops per-host scan history and the change log and touches nothing else |
| `0.1.0-alpha.7` | `4cdd051ae46a` | No schema changes from alpha.6 |

`verify-backup` reports the revision a backup is at, and whether this version
can run it.

## After upgrading

Worth a quick pass, particularly across a minor version:

- Log in.
- Run one discovery scan and confirm devices still populate with MAC and vendor data.
  Its report (Discovery → History → the run number) should list hosts; scans
  from before an upgrade that introduced per-host history say so instead.
- Run one diagnostic from a device page.
- If you use SSH actions, run one and confirm the stored credential still decrypts.

## Upgrading across several versions

Migrations are cumulative and are applied in order, so jumping from `v0.1.0` to `v0.4.0` in a single step works. Read every intervening **BREAKING** note in the changelog first, not just the one for the version you are moving to.
