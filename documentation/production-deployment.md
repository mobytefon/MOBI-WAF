# Production deployment (Ubuntu, rootless Docker)

A checklist for running this fork on Ubuntu Server with rootless Docker, one or several nodes. It collects what a lab deployment on two Ubuntu 24.04 nodes (2 vCPU, 3 GB RAM) ran into. For several nodes whose analytics are read from one dashboard, follow [Centralised analytics](clickhouse-cluster.md) as well.

## Hosts

- **Rootless Docker** for the user that runs the stack, with lingering on (`loginctl enable-linger <user>`) so the stack survives logout and reboots.
- **Ports 80 and 443** for a non-root user: `net.ipv4.ip_unprivileged_port_start=80` in `/etc/sysctl.d/` (rootless Docker cannot publish ports below it).
- **Clock in sync** (`timedatectl` shows *System clock synchronized: yes*): analytics, alerts and certificates all depend on it, and across nodes the central dashboard mixes their timestamps.
- **Memory to run**: the stack uses about 600 MB at rest (web about 350 MB, ClickHouse about 150 MB, Caddy about 50 MB) plus what the traffic needs. 2 GB of RAM is a floor; give ClickHouse more for long retention or heavy traffic.
- **Memory to build: none on the servers.** Do not build the images on small production hosts (next section).

## Build once, ship the images

The web image runs `next build`, whose type check alone peaks at about 4 GB, next to about 2 GB for the rest of the build. On a 3 GB server with 4 GB of swap the kernel's OOM killer stops it (`Out of memory: Killed process … (node)` in `journalctl -k`; the build log only says `SIGKILL` / exit code 137). Never skip the type check to get around this: build on a host with 8 GB of RAM or more (or 8 GB including swap), or in CI, and copy the images to every server.

On the build host, from a clean checkout:

```bash
docker compose build web caddy l4-port-manager
```

Then for each server:

```bash
docker save ghcr.io/ingres-si/ingressi-web:latest ghcr.io/ingres-si/ingressi-caddy:latest ghcr.io/ingres-si/ingressi-l4-port-manager:latest | gzip -1 | ssh <server> 'gunzip | docker load'
```

(or push them to a private registry). Check that every server reports the same image IDs (`docker images | grep ingressi`).

**Never run `docker compose pull` (or `up --pull always`) for `web`, `caddy` or `l4-port-manager`.** These services keep upstream's image names (`ghcr.io/ingres-si/…`); a pull replaces this fork's build with upstream's images, which lack its features (the Caddy `mlcheck` plugin, centralised analytics). Pull only the third-party images, by name:

```bash
docker compose pull clickhouse docker-socket-proxy
```

and start the stack without building or pulling:

```bash
docker compose up -d --no-build --pull never
```

## Copying the source

Each server needs a copy of the repository (the compose files and the configuration under `docker/` that they mount). Copy it from git, not from a Windows working tree: with `core.autocrlf` on, the working tree has CRLF line endings, which break the shell scripts and configuration files the containers read. `git archive` gives the repository's LF files:

```bash
git archive --format=tar.gz -o mobi-waf.tgz HEAD
```

## .env on each server

Start from `.env.example` (`chmod 600 .env`), then set at least:

| Variable | Value |
|---|---|
| `SESSION_SECRET` | `openssl rand -hex 32`, different on each server |
| `ADMIN_PASSWORD` | 12 characters or more, mixed classes |
| `BASE_URL` | the address users open the dashboard at |
| `CADDY_LOGS_DIR` | an absolute directory in the user's home, e.g. `/home/<user>/caddy-logs` |
| `DOCKER_SOCKET` | `/run/user/<uid>/docker.sock` (`id -u` gives the uid) |
| `CLICKHOUSE_PASSWORD` | `openssl rand -hex 24`; the same on every node with centralised analytics |
| `CLICKHOUSE_IMAGE` | with centralised analytics: the same pinned tag on every node |

`docker compose config --quiet` checks the result before the first start.

## After the first start

- **Turn the access log on** (Analytics settings, *Logging*, or `PUT /api/v1/settings/logging` with `{"enabled": true, "format": "json"}`). It is off by default; until it is on, Caddy writes no `access.log` and traffic analytics stay empty.
- Check that `docker logs ingressi-web` shows *ClickHouse analytics initialized*, *Log parser started* and *WAF log parser started*, and that `curl -s localhost:3000/api/health` answers 200.

## Firewall

With rootless Docker the published ports are sockets of the `rootlesskit` process, so ufw filters them like any other service (with rootful Docker they bypass ufw). For example, on a node of a centralised-analytics cluster whose central node is `10.0.0.11`:

```bash
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443
ufw allow from <admin network> to any port 3000 proto tcp
ufw allow from 10.0.0.11 to any port 9000 proto tcp
ufw enable
```

Allow SSH before `ufw enable`. Port 3000 (the dashboard) should only be reachable from the administrators' network.

## Workstations behind an HTTP proxy

Command-line tools on a workstation that has `HTTP_PROXY` set send requests for the servers' private addresses to the proxy, which cannot reach them: requests time out or the proxy answers 503, while the browser (which uses the system's bypass list) works. Add the servers' network to `NO_PROXY`, e.g. `NO_PROXY=localhost,127.0.0.1,192.168.0.0/16,10.0.0.0/8`, or use `curl --noproxy '*'`.
