#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# NetOps Console container entrypoint.
#
# Every step here is idempotent — this runs on every start, not just the first.
# Order matters: keys must exist before the app can decrypt anything, the schema
# must be current before the admin bootstrap can touch the user table, and the
# server must be the last thing started so it inherits PID 1's signal handling.
# ---------------------------------------------------------------------------
set -euo pipefail

log()  { printf '%s [entrypoint] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
fail() { log "ERROR: $*" >&2; exit 1; }

SECRET_KEY_FILE="${NETOPS_SECRET_KEY_FILE:-/data/secrets/secret_key}"
CRYPTO_KEY_FILE="${NETOPS_CRYPTO_KEY_FILE:-/data/secrets/crypto_key}"
DB_PATH="${NETOPS_DB_PATH:-/data/netops.db}"
DATA_DIR="$(dirname "$DB_PATH")"

# ---------------------------------------------------------------------------
# 1. Writable data directory
# ---------------------------------------------------------------------------
check_writable() {
  [ -d "$DATA_DIR" ] || fail "data directory $DATA_DIR does not exist"
  if ! touch "$DATA_DIR/.write-test" 2>/dev/null; then
    fail "$DATA_DIR is not writable by uid $(id -u).
       A named volume takes its ownership from the image's mount point. If you
       mounted a host directory instead, chown it: chown -R 10001:10001 <dir>"
  fi
  rm -f "$DATA_DIR/.write-test"
}

# ---------------------------------------------------------------------------
# 2. Keys
#
# Generated on first start so that `docker compose up` works with no manual
# setup. Provide them via *_KEY_FILE (Docker secrets) to manage them yourself.
# ---------------------------------------------------------------------------
generated_crypto_key=0

ensure_key() {
  local path="$1" kind="$2" dir
  dir="$(dirname "$path")"

  if [ -s "$path" ]; then
    log "using existing $kind key at $path"
    return 0
  fi

  if [ -e "$path" ]; then
    fail "$kind key at $path exists but is empty — refusing to overwrite it.
       If this is a broken first start, delete the file and restart. If it was
       ever populated, restore it from backup instead: a new crypto key cannot
       decrypt existing credentials."
  fi

  mkdir -p "$dir"
  chmod 0700 "$dir" 2>/dev/null || true

  # Fernet keys are 32 random bytes, urlsafe-base64 encoded.
  ( umask 0077; python -c \
      "import base64,os,sys; sys.stdout.write(base64.urlsafe_b64encode(os.urandom(32)).decode())" \
      > "$path" )
  chmod 0600 "$path"
  log "generated a new $kind key at $path"

  # Not `[ ... ] && x=1` — under `set -e` a false test would exit the script.
  if [ "$kind" = "credential-encryption" ]; then
    generated_crypto_key=1
  fi
  return 0
}

warn_about_crypto_key() {
  cat <<'EOF'

  ┌────────────────────────────────────────────────────────────────────────┐
  │  A NEW CREDENTIAL-ENCRYPTION KEY WAS GENERATED. BACK IT UP NOW.        │
  │                                                                        │
  │  This key encrypts every SSH key and password this instance stores.    │
  │                                                                        │
  │    Lose it   →  every stored credential is permanently unrecoverable.  │
  │    Leak it   →  every stored credential is compromised.                │
  │                                                                        │
  │  Copy it out of the volume and store it SEPARATELY from your database  │
  │  backups. Keeping both in one place defeats the encryption entirely.   │
  │                                                                        │
  │    docker compose exec app cat /data/secrets/crypto_key                │
  └────────────────────────────────────────────────────────────────────────┘

EOF
}

# ---------------------------------------------------------------------------
# 3. Schema
#
# Runs on every start, which is what makes upgrades `pull` + `up -d`. Safe only
# because this image runs exactly one worker — see the note in section 5.
# ---------------------------------------------------------------------------
apply_migrations() {
  log "applying database migrations"
  alembic upgrade head || fail "migrations failed — the app was not started.
       Your data is untouched. Restore from backup before retrying if you were
       mid-upgrade, and please report this with the traceback above."
  log "schema is up to date"
}

# ---------------------------------------------------------------------------
# 4. Initial admin
#
# Creates an account only when the user table is empty, with a random password
# printed once. A fixed default password on a publicly distributed, privileged
# tool is not a shortcut — it is a vulnerability.
# ---------------------------------------------------------------------------
bootstrap_admin() {
  python -m app.cli bootstrap-admin
}

# ---------------------------------------------------------------------------
# 5. Serve
# ---------------------------------------------------------------------------
validate_config() {
  local workers="${NETOPS_WORKERS:-1}"
  if [ "$workers" != "1" ]; then
    fail "NETOPS_WORKERS is set to '$workers'. This application enforces its
       concurrency limits, scan caps, and execution timeouts with in-process
       state. Every additional worker gets its own copy, silently multiplying
       every cap by N and adding SQLite write contention. This is a safety
       property, not a performance setting. Refusing to start."
  fi
}

serve() {
  local host="${NETOPS_BIND_HOST:-127.0.0.1}"
  local port="${NETOPS_BIND_PORT:-8000}"
  local log_level="${NETOPS_LOG_LEVEL:-info}"
  local forwarded="${NETOPS_FORWARDED_ALLOW_IPS:-127.0.0.1}"

  if [ "$host" = "0.0.0.0" ]; then
    log "WARNING: binding 0.0.0.0. Under host networking there is no port"
    log "         mapping, so this publishes an HTTP admin panel on every"
    log "         interface, bypassing your TLS proxy. Bind 127.0.0.1 unless"
    log "         you are certain you want this."
  fi

  log "starting on ${host}:${port} (1 worker)"
  exec uvicorn app.main:create_app --factory \
    --host "$host" \
    --port "$port" \
    --workers 1 \
    --log-level "$log_level" \
    --proxy-headers \
    --forwarded-allow-ips "$forwarded" \
    --no-server-header
}

# ---------------------------------------------------------------------------
main() {
  case "${1:-serve}" in
    serve)
      # Validate before touching the database, so a misconfigured start fails
      # without having half-applied a migration.
      validate_config
      check_writable
      ensure_key "$SECRET_KEY_FILE" "session-signing"
      ensure_key "$CRYPTO_KEY_FILE" "credential-encryption"
      export NETOPS_SECRET_KEY_FILE="$SECRET_KEY_FILE"
      export NETOPS_CRYPTO_KEY_FILE="$CRYPTO_KEY_FILE"
      apply_migrations
      bootstrap_admin
      if [ "$generated_crypto_key" -eq 1 ]; then
        warn_about_crypto_key
      fi
      serve
      ;;
    migrate)
      check_writable
      apply_migrations
      ;;
    backup)
      python -m app.cli backup "${2:-/data/backup.db}"
      ;;
    *)
      # Escape hatch for `docker compose run app <cmd>` — getcap, bash, pytest.
      exec "$@"
      ;;
  esac
}

main "$@"
