# Backup and restore

There are **two** things to back up, and keeping them in the same place defeats the point of encrypting credentials at rest.

| What | Where | Why separately |
|---|---|---|
| Database | `/data/netops.db` | Holds devices, audit history, and credential *ciphertext* |
| Encryption key | `/data/secrets/crypto_key` | Decrypts that ciphertext |

One stolen archive containing both gives an attacker every stored SSH key and password. Store the key in a password manager, an offline copy, or a separate encrypted vault — not next to the database dumps.

## Backing up the database

**Never `cp` the database file while the app is running.** In WAL mode the `.db` file is only part of the state; a plain copy can capture a torn write that will not open. Use `VACUUM INTO`, which produces a consistent snapshot from a live database:

```bash
docker compose exec app python -m app.cli backup /data/backup.db
docker compose cp app:/data/backup.db ./netops-$(date +%F).db
docker compose exec app rm /data/backup.db
```

The CLI refuses to overwrite an existing file, so it cannot silently replace your only backup.

Verify what you took:

```bash
sqlite3 netops-$(date +%F).db 'PRAGMA integrity_check; SELECT count(*) FROM device;'
```

An untested backup is a guess. Do the restore drill below at least once.

## Backing up the key

```bash
docker compose exec app cat /data/secrets/crypto_key
```

Copy the value into your password manager. It is a single base64 line. Label it with the instance it belongs to — a key from a different install decrypts nothing.

## Restoring

```bash
docker compose down
docker volume rm netops-console_netops-data
docker volume create netops-console_netops-data

# Restore the database
docker run --rm -v netops-console_netops-data:/data -v "$PWD":/backup alpine \
  sh -c 'cp /backup/netops-2026-07-26.db /data/netops.db && chown 10001:10001 /data/netops.db'

# Restore the key
docker run --rm -i -v netops-console_netops-data:/data alpine \
  sh -c 'mkdir -p /data/secrets && cat > /data/secrets/crypto_key \
         && chmod 600 /data/secrets/crypto_key && chown -R 10001:10001 /data/secrets' \
  < ./crypto_key.txt

docker compose up -d
```

Migrations run automatically on start, so a backup from an older version is upgraded in place. Confirm afterwards that a stored credential still decrypts — open a device with an assigned credential and run an SSH action. If the key is wrong, decryption fails cleanly rather than producing garbage.

Restoring the database without the matching key leaves you with intact devices and audit history but unusable credentials, which have to be re-entered.

## Restore drill

Do this once, before you need it:

1. Take a backup of both artefacts.
2. `docker compose down -v` — deliberately destroy everything.
3. Restore using the steps above.
4. Log in and confirm an SSH action still runs against a device.

If step 4 fails, your backup procedure has a gap, and finding that out now is the entire point.

## Key rotation

Rotating `crypto_key` means decrypting every stored credential with the old key and re-encrypting with the new one, in a single transaction. There is no automated rotation command in v0.1. Until there is, rotate by re-entering credentials against a fresh key:

1. Back up the database.
2. Note which credentials exist (names and usernames are visible in the UI; the secrets are not).
3. Stop the app, replace `crypto_key`, start it.
4. Re-enter each credential.

Rotate if you have reason to believe the key was exposed — for example, it was committed somewhere, sent over chat, or lived on a machine that was compromised.

## What is not backed up

- `secret_key` — only signs session cookies. Losing it logs everyone out and nothing more.
- Container logs, including the initial admin password. If you lose it before first login: `docker compose exec app python -m app.cli reset-password`.
