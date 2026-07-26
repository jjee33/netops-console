# Installation

## Requirements

- A Linux host with Docker Engine and the Compose v2 plugin
- A trusted management network. This application must not be exposed to the internet.
- Root on the Docker host is not required to run it, but installing Docker is. Note that membership in the `docker` group is root-equivalent on the host.

## Install

```bash
mkdir -p ~/netops-console && cd ~/netops-console
curl -O https://raw.githubusercontent.com/jjee33/netops-console/main/compose.yaml
docker compose up -d
```

Read the initial admin password out of the logs. It is printed exactly once:

```bash
docker compose logs app | grep -A5 'Initial admin'
```

First start also generates two keys into the data volume:

| Key | Purpose | If lost |
|---|---|---|
| `/data/secrets/secret_key` | Signs session cookies | Everyone is logged out. Harmless. |
| `/data/secrets/crypto_key` | Encrypts stored credentials | **Every stored SSH key and password is unrecoverable.** |

**Back up `crypto_key` now**, and put it somewhere other than where your database backups live — storing both together means one stolen backup yields both the ciphertext and the key:

```bash
docker compose exec app cat /data/secrets/crypto_key
```

To manage the keys yourself instead, set `NETOPS_SECRET_KEY_FILE` and `NETOPS_CRYPTO_KEY_FILE` to paths supplied via Docker secrets. Nothing is generated when those are set.

## Put TLS in front of it

The app binds `127.0.0.1:8000` and is unreachable from your LAN until you proxy it. That is deliberate: under host networking there is no port mapping, so binding `0.0.0.0` would publish a plain-HTTP admin panel on every interface of the host.

The included Caddy config is the shortest path:

```bash
curl -O https://raw.githubusercontent.com/jjee33/netops-console/main/compose.caddy.yaml
mkdir -p docker && curl -o docker/Caddyfile \
  https://raw.githubusercontent.com/jjee33/netops-console/main/docker/Caddyfile
NETOPS_HOSTNAME=netops.lan docker compose -f compose.yaml -f compose.caddy.yaml up -d
```

### If you use your own proxy

The one thing that catches people: **a proxy container on the default bridge network cannot reach the app.** The app is on `127.0.0.1` inside the *host* network namespace; a bridged container's `127.0.0.1` is a different loopback entirely. The symptom is a 502 with connection refused, which looks like the app is down when it is running perfectly.

Two working options:

1. Run the proxy natively on the host (systemd nginx, Caddy, HAProxy).
2. Give the proxy container `network_mode: host`, as `compose.caddy.yaml` does.

Whichever you choose, set `NETOPS_FORWARDED_ALLOW_IPS` to the proxy's address. If it is wrong, every client IP in your audit log is wrong. Do not set it to `*`.

## Configure subnets

Log in, change the admin password when prompted, then go to **Settings** and set the private IPv4 ranges this instance may touch. Discovery, diagnostics, and actions targeting anything outside those ranges are rejected.

## Verify the install

These are worth running once. Each has a silent failure mode.

| Check | Command | Expected |
|---|---|---|
| File capabilities | `docker compose exec app netops-getcap /usr/bin/nmap /usr/bin/ping /usr/bin/traceroute` | `cap_net_raw=ep` on all three |
| Raw sockets really work | `docker compose exec app nmap -sS -p 22 -Pn 127.0.0.1` | A result, not "requires root privileges" |
| Unprivileged scan | `docker compose exec app nmap -sn 192.168.1.0/24` | Hosts found, MAC addresses populated |
| Running non-root | `docker compose exec app id -u` | `10001` |
| Not LAN-exposed | `ss -ltn \| grep 8000` | `127.0.0.1:8000`, never `0.0.0.0:8000` |
| Key permissions | `docker compose exec app stat -c %a /data/secrets/crypto_key` | `600` |
| Proxy reachable | `curl -kI https://netops.lan/` | `200` |

**Empty MAC and vendor columns after a scan** is the signature of bridge networking. It does not error — the scan succeeds and returns less. Confirm `network_mode: host` is in effect.

**"You requested a scan type which requires root privileges"** means `NMAP_PRIVILEGED` is not set. nmap decides whether it may use raw sockets by checking `geteuid()` rather than checking its own capabilities, so it refuses SYN and ARP scans as a non-root user even when `CAP_NET_RAW` is present and working. The image sets `NMAP_PRIVILEGED=1` for this reason. If you override the environment wholesale, keep it. It grants nothing — a genuinely missing capability still fails with `EPERM`.

Note that the first three checks in the table above can all pass with no raw socket at all: `nmap -sn` against loopback degrades to a TCP connect scan, `ping` uses an ICMP datagram socket because Docker sets `net.ipv4.ping_group_range` permissively, and `traceroute` defaults to UDP probes. The SYN scan is the one that actually proves it.

## Things that will break this install

Each of these looks like an improvement and is not:

**`security_opt: no-new-privileges:true`** — the single most likely well-intentioned change to break the container. `no_new_privs` blocks file capabilities at `execve`, so `nmap`, `ping`, and `traceroute` all lose `CAP_NET_RAW` and fail with "operation not permitted."

**Raising `NETOPS_WORKERS`** — concurrency limits, scan caps, and execution timeouts are enforced with in-process state. Each additional worker gets its own copy, multiplying every limit by N and adding SQLite write contention. The container refuses to start if you set this above 1.

**Adding `NET_ADMIN` to `cap_add`** — unnecessary, and under host networking it grants the container the ability to reconfigure the host's interfaces and firewall rules. `CAP_NET_RAW` alone covers every operation this app performs.

**Switching to bridge networking** — degrades you to IP-only discovery, silently.

**Binding `0.0.0.0`** — publishes an HTTP admin panel to your whole LAN, bypassing TLS.

## Alternatives to host networking

If host networking is too broad for you, `macvlan` gives the container its own MAC and IP on the LAN while keeping namespace isolation:

```yaml
networks:
  lan:
    driver: macvlan
    driver_opts:
      parent: eth0        # your physical interface
    ipam:
      config:
        - subnet: 192.168.1.0/24
          gateway: 192.168.1.1
```

Two caveats: the Docker host itself cannot reach a macvlan container without an extra host-side macvlan interface, and your reverse proxy needs to be somewhere that can reach it.

Bridge networking is not a supported configuration for discovery.

## Verifying the image

Release images are signed with cosign keyless signing:

```bash
cosign verify ghcr.io/jjee33/netops-console:v0.1.0 \
  --certificate-identity-regexp '^https://github\.com/jjee33/netops-console/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Inspect the SBOM and confirm both architectures are present:

```bash
docker buildx imagetools inspect ghcr.io/jjee33/netops-console:v0.1.0
```

Only stable releases carry `latest`. Tags named `main` or `sha-*` are development builds and are not release candidates.

## Uninstall

```bash
docker compose down -v     # -v also deletes the database and both keys
```
