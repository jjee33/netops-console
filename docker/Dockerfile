# syntax=docker/dockerfile:1.9
# ---------------------------------------------------------------------------
# NetOps Console
#
# Runs as a non-root user with all capabilities dropped except CAP_NET_RAW.
# The single most common way to get this wrong is documented at the setcap
# block below — read it before changing anything in this file.
# ---------------------------------------------------------------------------

ARG PYTHON_VERSION=3.13
ARG DEBIAN_SUITE=trixie

# ---------------------------------------------------------------------------
# Stage 1 — build wheels
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim-${DEBIAN_SUITE} AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Build toolchain for packages without prebuilt wheels on every arch
# (argon2-cffi, cryptography, asyncssh, uvloop, httptools).
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      libffi-dev \
      pkg-config \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Dependency layer first so source edits do not invalidate the wheel cache.
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY app ./app

RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip setuptools wheel \
 && /opt/venv/bin/pip install .

# ---------------------------------------------------------------------------
# Stage 2 — runtime
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim-${DEBIAN_SUITE} AS runtime

LABEL org.opencontainers.image.title="NetOps Console" \
      org.opencontainers.image.description="Self-hosted network discovery, diagnostics, and audited command execution." \
      org.opencontainers.image.source="https://github.com/jjee33/netops-console" \
      org.opencontainers.image.documentation="https://github.com/jjee33/netops-console/blob/main/docs/INSTALL.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Joshua Gann"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH="/opt/venv/bin:${PATH}" \
    NETOPS_BIND_HOST=127.0.0.1 \
    NETOPS_BIND_PORT=8000 \
    NETOPS_DB_PATH=/data/netops.db \
    NETOPS_WORKERS=1

# Network tooling. libcap2-bin is deliberately RETAINED rather than purged after
# setcap: `getcap` is how an operator verifies the capability plumbing actually
# worked (it is a release-gate check), and keeping `setcap` costs nothing in
# terms of risk because the container drops CAP_SETFCAP — a process inside it
# cannot grant file capabilities to anything.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap \
      iputils-ping \
      traceroute \
      bind9-dnsutils \
      iproute2 \
      libcap2-bin \
      ca-certificates \
      tini \
 && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# File capabilities — the trap this project exists downstream of.
#
# `cap_add: [NET_RAW]` in compose adds the capability to the container's
# BOUNDING set only. When the container runs as a non-root user, execve grants
# no permitted or effective capabilities unless the binary itself carries FILE
# capabilities, and Docker does not set ambient capabilities. Without the setcap
# below, nmap fails with "operation not permitted" while the capability looks
# granted. BOTH pieces are required: cap_add in compose AND setcap here.
#
# The +ep effective bit is what makes the capability usable by an unprivileged
# process. Resolve symlinks first — Debian ships traceroute behind an
# alternatives symlink, and setcap on a symlink fails.
#
# CAP_NET_RAW ONLY, deliberately. The recipe circulating for unprivileged nmap
# is `cap_net_raw,cap_net_admin,cap_net_bind_service+eip`, and copying it here
# would break this image outright. A binary whose file-permitted set contains a
# capability missing from the process bounding set, with the effective bit set,
# fails execve with EPERM — the "capability-dumb binary" safety check in
# capabilities(7). This container drops ALL and adds back only NET_RAW, so
# net_admin in the file caps would make nmap refuse to start at all.
#
# Widening cap_add to match would be worse: under network_mode: host,
# CAP_NET_ADMIN lets the container reconfigure the HOST's interfaces and
# firewall. CAP_NET_RAW alone covers everything this app needs — SYN scans,
# ARP-based host discovery, MAC and vendor resolution, ping, and traceroute.
# ---------------------------------------------------------------------------
# pipefail so the verification greps below cannot pass on a failed getcap.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN set -eux; \
    for tool in nmap ping traceroute; do \
      target="$(readlink -f "/usr/bin/$tool")"; \
      setcap cap_net_raw+ep "$target"; \
      getcap "$target" | grep -q cap_net_raw; \
    done

# `getcap /usr/bin/traceroute` prints nothing because Debian ships it behind an
# alternatives symlink and capabilities live on the target, not the link. This
# wrapper makes the operator-facing check work on the path people actually type.
# The single quotes are the point — this is script text being written to a
# file, not shell to expand at build time.
# hadolint ignore=SC2016
RUN printf '%s\n' \
      '#!/bin/sh' \
      '# Report file capabilities, resolving symlinks first.' \
      'for f in "$@"; do /sbin/getcap "$(readlink -f "$f")"; done' \
    > /usr/local/bin/netops-getcap \
 && chmod 0755 /usr/local/bin/netops-getcap

SHELL ["/bin/sh", "-c"]

# ---------------------------------------------------------------------------
# Non-root user. /data must be created AND chowned in the image: a fresh named
# volume inherits ownership from the mount point as it exists in the image, so
# skipping this makes first start fail with EACCES that reads like a code bug.
# ---------------------------------------------------------------------------
RUN groupadd --gid 10001 netops \
 && useradd --uid 10001 --gid 10001 --home-dir /app --no-create-home --shell /usr/sbin/nologin netops \
 && mkdir -p /data /data/secrets /app \
 && chown -R 10001:10001 /data /app \
 && chmod 0700 /data/secrets

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=10001:10001 app ./app
COPY --chown=10001:10001 migrations ./migrations
COPY --chown=10001:10001 alembic.ini ./alembic.ini
COPY --chown=10001:10001 docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

USER 10001:10001

VOLUME ["/data"]

# There is no EXPOSE: under network_mode: host it is meaningless, and the app
# binds loopback by design. Publishing it is the reverse proxy's job.

# tini reaps orphaned processes. The execution engine kills process groups on
# timeout, but a PID 1 that does not reap leaves zombies behind over time.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["serve"]
