# Argus Sentinel ML

Argus Sentinel is a small machine-learning classifier that scores each HTTP request the WAF inspects as **clean** or **attack**. It runs after the OWASP Core Rule Set, as an extra opinion: it can flag or block a request the CRS let through, and it never lets through a request the CRS blocked.

- The Caddy image includes the **`mlcheck`** WAF action ([mobytefon/coraza-mlcheck](https://github.com/mobytefon/coraza-mlcheck)).
- The model runs in the **`argus-sidecar`** container ([mobytefon/argus-sidecar](https://github.com/mobytefon/argus-sidecar), ONNX Runtime on the CPU). Caddy reaches it over a unix socket in the shared `argus-run` volume. The sidecar has no network at all.
- `mlcheck` sends the method, the request URI, the `User-Agent`, `Referer` and `Cookie` headers and the first 4 KiB of the body. `Authorization` and every other header stay in Caddy.
- When the sidecar is down, slow or busy, the request goes on without an ML verdict (fail open) and the CRS decides alone.

Nothing changes until you add the rules below to the WAF custom directives.

## Setting it up

1. Put the model in a directory of its own on the server, as the user that runs Docker. The released bundle is in the `model/` directory of [mobytefon/argus-sidecar](https://github.com/mobytefon/argus-sidecar/tree/main/model): `model.onnx`, `tokenizer.json`, `config.json`, `preprocess.py` and `inference_cpu.py`.

   ```sh
   git clone --depth 1 --branch v0.2.1 https://github.com/mobytefon/argus-sidecar.git /tmp/argus-sidecar
   mkdir -p ~/argus-model
   cp /tmp/argus-sidecar/model/{model.onnx,tokenizer.json,config.json,preprocess.py,inference_cpu.py} ~/argus-model/
   # Rootful Docker only (Docker Desktop, WSL with Docker Desktop): make it readable by everyone
   chmod 0755 ~/argus-model && chmod 0644 ~/argus-model/*
   ```

   The two `.py` files are run by the sidecar: only use files from a source you trust. Under rootless Docker the directory may stay private (`0700`); see [Users, socket and rootless Docker](#users-socket-and-rootless-docker).

2. In `.env`, set `ARGUS_MODEL_DIR` to that directory's absolute path (`ARGUS_MODEL_DIR=/home/<user>/argus-model`), and add `docker-compose.argus.yml` to `COMPOSE_FILE` (for example `COMPOSE_FILE=docker-compose.yml:docker-compose.argus.yml`, with any other overlays you use).

3. Rebuild Caddy (its image now includes `mlcheck`) and start the sidecar:

   ```sh
   docker compose build caddy
   docker compose up -d
   docker compose ps argus-sidecar          # healthy after a few seconds
   docker compose logs argus-sidecar | grep listening
   ```

   The sidecar image is `ghcr.io/mobytefon/argus-sidecar:v0.2.1` (`ARGUS_SIDECAR_VERSION` picks another tag). If it cannot be pulled, Compose builds it from the repository.

4. Turn the WAF on with **Load OWASP CRS** (the CRS turns on request-body access, which `mlcheck` needs), then add the **detect** rules below to the global WAF custom directives, or to one host's.

## Rules

Paste each rule on one line. Use the ids `1899999099`–`1899999199` for ML rules: they are free in MOBI-WAF and in the CRS. Rules must run in `phase:2`, when the body has been read.

**Detect only** (start here): ML detections are recorded in Security events; the CRS keeps blocking on its own.

```
SecAction "id:1899999100,phase:2,pass,nolog,noauditlog,mlcheck"
SecRule TX:argus_is_clean "@streq 0" "id:1899999101,phase:2,pass,log,auditlog,ctl:auditEngine=On,severity:WARNING,msg:'Argus ML detected',tag:'argus-sentinel',logdata:'attack_prob=%{tx.argus_risk_score}'"
SecRule TX:argus_error "@rx .+" "id:1899999102,phase:2,pass,log,severity:WARNING,msg:'Argus ML unavailable',tag:'argus-sentinel/error',logdata:'reason=%{tx.argus_error}'"
```

`ctl:auditEngine=On` puts a detection on a request that still gets a 200 into Security events (with the CRS loaded, only 4xx/5xx transactions are audited otherwise). The error rule leaves it out on purpose: a stopped sidecar would otherwise add one event per request. Its messages are in the Caddy log.

**Detect with a threshold of your own** (per host, without touching the sidecar): add this line before the three above. Any number in `[0,1]` works; attack means `attack_prob > threshold`.

```
SecAction "id:1899999099,phase:2,pass,nolog,noauditlog,setvar:'tx.argus_threshold=0.998175'"
```

Global directives come before a host's in merge mode, so a host threshold after a global `mlcheck` comes too late. To give one host its own threshold, keep the whole ML rule set on that host (or use the host's override mode).

**Block**: once detections on real traffic look right, replace rule `1899999101` with this one. The WAF mode must be **On** (in detection-only mode every deny is a pass).

```
SecRule TX:argus_is_clean "@streq 0" "id:1899999101,phase:2,deny,status:403,log,auditlog,severity:CRITICAL,msg:'Argus ML blocked',tag:'argus-sentinel',logdata:'attack_prob=%{tx.argus_risk_score}'"
```

### TX variables

| Variable | Value |
|---|---|
| `tx.argus_is_clean` | `0` attack, `1` clean, empty when there is no verdict |
| `tx.argus_risk_score` | `attack_prob`, only with a verdict |
| `tx.argus_error` | why there is no verdict: `rpc_error`, `rpc_timeout`, `overload`, `circuit_open`, … |
| `tx.argus_threshold` | optional input: the threshold `mlcheck` applies instead of the sidecar's |

Block on `@streq 0`, never on the score: Coraza's `@gt` compares integers, which is why the threshold is compared inside `mlcheck`.

## Replacing the model while it runs

Copy all five new files over `ARGUS_MODEL_DIR`, in one command. Nothing needs restarting:

```sh
cp new/{model.onnx,tokenizer.json,config.json,preprocess.py,inference_cpu.py} ~/argus-model/
docker compose logs -f argus-sidecar      # "model reloaded version=… run=… threshold=…"
```

- Every `ARGUS_RELOAD_INTERVAL_S` seconds (5 by default) the sidecar checks the size and modification time of the five files. When they have changed and then stay the same for one more check, it loads the new model, runs test requests through it, and only then switches. Requests already running finish on the old model.
- A model that does not load (a file copied halfway, a model with other inputs, a `config.json` without the threshold preset you use) leaves the old model serving, and the log says why. The same files are not tried again; copy them again to retry.
- To load at once instead of waiting: `docker compose kill -s HUP argus-sidecar`.
- The threshold preset (`ARGUS_THRESHOLD`, `fpr0.1%` by default) is read again from the new `config.json`, so a model trained with new thresholds brings them along.
- Copy the files together: copied one by one, more than 5 seconds apart, the sidecar can load a mix of old and new files for a moment.
- Keep the previous model in another directory: going back is copying it over again.

## Users, socket and rootless Docker

The sidecar runs as `0:0`, like the `web` and `caddy` services in `docker-compose.yml`. Under rootless Docker that is the host user running `dockerd`:

- The model directory only has to belong to that user (a directory in its home, mode `0700`, works). No `chown` to another UID, and files copied in by that user are read as they are.
- The socket `/run/argus/argus.sock` (mode `0660`) is created by that user in the `argus-run` volume; `caddy`, the same user, opens it. Nothing else mounts the volume, and the sidecar has no network.
- The sidecar drops every capability and runs on a read-only filesystem, so it relies on file ownership alone. `/run/argus` is mode `1777` in both images, so a fresh volume works whichever container mounts it first.

With rootful Docker (Docker Desktop and its WSL integration included), `0:0` is real root on the host, as it is for `web` and `caddy`, but the sidecar still has no capability, no network and a read-only filesystem. Root without capabilities cannot read another user's private files: the model directory must then be readable by everyone (`chmod 0755` on the directory, `0644` on the files) or belong to root. `ARGUS_USER` changes the sidecar's user; it must then be the user `caddy` runs as, or Caddy cannot open the socket.

After changing `ARGUS_USER` on an existing installation, the old socket belongs to the other user and cannot be replaced: stop `caddy` and `argus-sidecar`, run `docker volume rm <project>_argus-run` once, and start them again.

`ARGUS_CPUS` and `ARGUS_MEM_LIMIT` are enforced by rootless Docker only when the cgroup v2 controllers are delegated to the user (`docker info` warns when they are not); otherwise they are ignored.

## Capacity and limits

| Setting | Default | Where |
|---|---|---|
| `ARGUS_WORKERS` | 4 | sidecar inference threads |
| `ARGUS_MAX_CONCURRENT_RPCS` | 16 | requests the sidecar takes at once; more are refused as busy |
| `ARGUS_MAX_INFLIGHT` | 16 | requests Caddy sends at once; more wait 5 ms, then go on without a verdict (`overload`) |
| `ARGUS_TIMEOUT_MS` | 50 | Caddy's budget per request, queueing included |
| `ARGUS_CPUS`, `ARGUS_MEM_LIMIT` | 2, 512m | sidecar container limits |

Keep `ARGUS_MAX_INFLIGHT` at or below `ARGUS_MAX_CONCURRENT_RPCS`, so extra load is shed in Caddy before it reaches the sidecar. A sidecar that refuses a request because it is busy is not counted as failing: only real failures (10 in a row) switch ML off for 5 seconds. Caddy's settings are environment variables of the `caddy` service; set them in a `docker-compose.override.yml` if you change them (list that file in `COMPOSE_FILE` too when you set `COMPOSE_FILE`; the l4-port-manager always includes it when it recreates `caddy`).

Caddy logs a summary of `mlcheck` every minute (`mlcheck metrics summary calls=… ok=… failures=… latency_quantiles=…`): `docker compose logs caddy | grep mlcheck`.

## What the model does not see

The model scores the method, the URI (first 512 characters), `User-Agent`, `Referer`, `Cookie` (160 each) and the body (first 512 characters after URL decoding). A payload in another header, after those limits, or encoded otherwise (base64, HTML entities, three or more URL encodings) is not seen, and it was trained on public data sets: apostrophes and braces in legitimate requests (a name like O'Brien, a password, GraphQL) can score high. Run detect-only on real traffic first, check the detections in **Security events** (filter on `argus-sentinel`), and raise or lower the threshold before blocking. The CRS stays the main defence.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `argus-sidecar` restarts, log `Permission denied` on `/model/…` | `ARGUS_MODEL_DIR` is not readable by the sidecar's user, or is not an absolute path. With rootful Docker: `chmod 0755` the directory and `0644` the files (see above) |
| log `refusing to replace a non-socket path` / `Permission denied` on `/run/argus/argus.sock` | a socket or file left by another user in the volume: remove the volume once (see above) |
| `Argus ML unavailable` with `reason=rpc_error` | the sidecar is not running or Caddy cannot open the socket (different users) |
| `reason=overload` | more requests at once than `ARGUS_MAX_INFLIGHT`: raise it together with `ARGUS_MAX_CONCURRENT_RPCS`, `ARGUS_WORKERS` and `ARGUS_CPUS` |
| `reason=circuit_open` | 10 real failures in a row; ML is skipped for 5 seconds, then retried |
| `model reload failed, keeping the running model` | the new files do not load; the message says why, and the old model keeps serving |

## Turning it off

1. Remove the ML rules from the WAF custom directives and save (Caddy applies the change).
2. Then stop the sidecar: `docker compose stop argus-sidecar`, and take `docker-compose.argus.yml` out of `COMPOSE_FILE`.

With the rules removed first, nothing calls the sidecar. If the sidecar stops while rules remain, requests go on without a verdict and Caddy logs `Argus ML unavailable`.
