# Manual verification

CI covers a great deal — capabilities, the non-root user, unprivileged raw
sockets, fresh-volume startup, loopback-only binding, SQLite pragmas, CSRF,
security headers, and every parser and validation path. What it cannot cover is
anything that needs a real network, because it runs on one isolated host with no
neighbours.

This is the list of things you have to check yourself. Each one has a silent
failure mode: the application keeps working and simply returns less, which is
much harder to notice than an error.

## Before you start

```bash
docker compose -f compose.yaml -f compose.dev.yaml up -d --build
docker compose logs app | grep -A5 'Initial admin'
```

Substitute your own ranges for `192.168.1.0/24` below.

---

## 1. Layer 2 discovery — the big one

**Why it matters.** Under bridge networking, MAC addresses are hidden behind
NAT. The scan still succeeds, the device list still populates, and the MAC and
vendor columns are simply empty. Nothing errors.

1. Set your allowed ranges in **Settings**.
2. Run a scan of a subnet the container is directly attached to.
3. Open **Devices**.

**Pass:** MAC and vendor columns are populated for devices on the same segment.

**Fail:** every MAC is blank → the container is not seeing the LAN. Confirm
`network_mode: host` is in effect, and check `docker compose exec app ip addr`
shows your real interfaces rather than an `eth0@if…` bridge pair.

Devices *across a router* legitimately have no MAC. That is expected, not a
failure — compare a device on your own segment with one that is routed.

## 2. Raw sockets actually work

```bash
docker compose exec app netops-getcap /usr/bin/nmap /usr/bin/ping /usr/bin/traceroute
docker compose exec app nmap -sS -p 22 -Pn <a real host on your LAN>
```

**Pass:** all three report `cap_net_raw=ep`, and the SYN scan returns a result.

**Fail:** *"You requested a scan type which requires root privileges"* means
`NMAP_PRIVILEGED` is not set — nmap checks `geteuid()` rather than its own
capabilities. The image sets it; check you have not overridden the environment.

Note that `nmap -sn`, `ping`, and `traceroute` all succeed *without* a raw
socket, so none of them proves anything here. Only the SYN scan does.

## 3. Multiple VLANs

If you run several segments, scan each one and compare:

- Devices on the segment the container is attached to → MAC and vendor present.
- Devices on other VLANs → reachable, but no MAC. This is correct behaviour.

If a VLAN is entirely unreachable, that is routing or firewall, not this
application. Confirm with `docker compose exec app ping -c1 <gateway of that VLAN>`.

## 4. Re-scan produces no duplicates

Run the same scan twice, then check the device count on the dashboard. It must
not change. Then check **Discovery → History**: the second run should report
found > 0 and new = 0.

Also worth doing once: rename a device, add notes, rescan, and confirm your name
and notes survived. Discovery must never overwrite something you typed.

## 5. Reverse proxy reachability

```bash
docker compose -f compose.yaml -f compose.caddy.yaml up -d
curl -kI https://netops.lan/
ss -ltn | grep 8000
```

**Pass:** the proxy answers, and the listener is on `127.0.0.1:8000`.

**Fail — 502 with connection refused:** the proxy is on a bridge network and
cannot reach the app's loopback. Give it `network_mode: host` or run it natively.

**Fail — listener on `0.0.0.0:8000`:** the admin panel is exposed to your whole
LAN over plain HTTP, bypassing TLS. Fix before going further.

## 6. Timeouts leave no orphans

Start a scan of a range large enough to hit the 300-second cap, or temporarily
lower it, and let it time out. Then:

```bash
docker compose exec app ps -eo pid,comm
```

**Pass:** no lingering `nmap` processes.

**Fail:** orphaned processes mean the engine killed the child but not the
process group, which leaks sockets and file descriptors over time.

## 7. Fresh-volume install

```bash
docker compose down -v
docker compose up -d
docker compose logs app | grep -A5 'Initial admin'
```

**Pass:** new database, newly generated keys, a new random admin password, and a
working login. No `EACCES`.

This is the exact path every public user takes on first run, and it is the one
most likely to rot silently as the project changes. Worth repeating each release.

## 8. Restart does not rotate credentials

```bash
docker compose restart app
docker compose logs --tail 40 app
```

**Pass:** *"using existing credential-encryption key"* and *"an account already
exists"*. Your password still works.

**Fail:** a new admin password printed on every restart means the bootstrap is
not idempotent, and any credential already stored is now undecryptable.

## 9. Backup and restore drill

Do this once, properly, before you rely on it:

```bash
docker compose exec app python -m app.cli backup /data/backup.db
docker compose cp app:/data/backup.db ./netops-backup.db
docker compose exec app cat /data/secrets/crypto_key    # store separately
docker compose down -v
# restore per docs/BACKUP_RESTORE.md, then confirm you can log in
```

An untested backup is a guess. See [BACKUP_RESTORE.md](BACKUP_RESTORE.md).

---

## Reporting what you find

If something here fails, the details worth capturing are: the output of
`docker compose logs app`, whether `network_mode: host` is set, and the result of
the `netops-getcap` command in section 2. Those three answer most questions.
