# Operating tester nodes

A node is one binary, `nst-node`. It always answers direct requests from the
website on its HTTP port, and also pulls requests from an S3 feed that the
website writes ([S3_FEED.md](S3_FEED.md)) when `FEED_URLS` is set. Releases
publish it as a signed multi-arch image (`ghcr.io/the-dot-squad/netsurveil-tester`,
linux/amd64 and linux/arm64) and as Linux binaries with `install.sh` on the
[GitHub release](https://github.com/the-dot-squad/netsurveil-tester/releases). To
build it yourself, run `make build` (into `bin/`) or `make docker`.

## 1. Deploy a node

First generate the node's shared secret and store it, encrypted, on the
node's row in the website:

```sh
openssl rand -base64 32
```

### With Docker

Create `.env` from `.env.example` and set `NODE_ID` (for example
`ir-tehran-mci-1`), `NODE_SECRET`, and `FEED_URLS` if the node should pull.
Then start the node:

```sh
docker compose up -d
docker compose ps          # STATUS shows (healthy); in pull mode only while the feed is reachable
```

Direct requests reach the node on `NODE_PORT` (default 8080).

### As a systemd service

On a Linux amd64 or arm64 host with systemd:

```sh
curl -fsSL https://github.com/the-dot-squad/netsurveil-tester/releases/latest/download/install.sh | sudo NODE_ID=ir-tehran-mci-1 sh
```

The installer:

- downloads the release archive and verifies it against `SHA256SUMS`;
- installs `/usr/local/bin/nst-node` and creates the system user `nst-node`;
- on first install, writes `/etc/netsurveil-tester/node.env` (mode `0640`)
  with a newly generated `NODE_SECRET`, which it prints once;
- installs and starts `netsurveil-tester.service`, which runs as `nst-node`
  with only `CAP_NET_RAW`, a read-only system, and memory and task limits.

`VERSION`, `FEED_URLS` and `NODE_PORT` can be passed the same way as
`NODE_ID`. Edit `node.env` and run `systemctl restart netsurveil-tester` to
change settings. Re-running the installer upgrades the binary and keeps
`node.env`. `install.sh --uninstall` removes the service, binary and user;
add `--purge` to delete `node.env` too. Logs go to the journal
(`journalctl -u netsurveil-tester`).

Finally, register the node's address and secret on the website and run an
`info` check from there.

### Node environment

| Variable                | Default | Meaning |
|-------------------------|---------|---------|
| `NODE_ID`               | required | `[A-Za-z0-9._-]{1,64}`; bound into every envelope |
| `NODE_SECRET`           | required | 32 bytes as 64 hex characters or base64 (`openssl rand -base64 32`) |
| `LISTEN_ADDR`           | `:8080` | inbound listener; `off` disables direct requests (compose leaves the default and maps it to `NODE_PORT`) |
| `HEALTH_ADDR`           | `127.0.0.1:8099` | loopback-only health listener used by the image's `HEALTHCHECK`; a loopback `IP:port`, or `off` (the systemd install turns it off) |
| `HTTP_PATH_PREFIX`      | empty   | e.g. `/k3x9q`; every route lives under it |
| `FEED_URLS`             | empty   | enables pull mode: up to 8 comma-separated URLs of the node's feed object, used in order as mirrors |
| `ALLOW_PRIVATE_TARGETS` | `false` | allow RFC 1918, CGNAT and ULA targets (lab use only) |
| `RATE_LIMIT_PER_MIN`    | `30`    | rejected requests per minute per client IP; once exceeded, that client gets only empty 404s until the minute ends. Authenticated requests are never counted |
| `LOG_LEVEL`             | `info` (`warn` in compose) | `debug`, `info`, `warn` or `error` (any case); anything else stops the node at startup. `debug` also logs why each request was rejected |

At least one of direct and pull mode must be enabled. On `SIGTERM` the node
stops taking work, cancels running checks and delivers their final feed
answers before it exits; compose and the systemd unit allow 30 s for this.

### Health

`GET /healthz` is served only on `HEALTH_ADDR`, which only loopback callers
can reach, and never on the public listener. It answers `200 ok`. In pull
mode it answers `503 feed stale` once no feed poll has succeeded for 2
minutes, so `docker compose ps` shows the node as unhealthy when it loses
its feed. The image's `HEALTHCHECK` runs `nst-node -healthcheck`, which
probes this endpoint.

### Hardening applied by `docker-compose.yml`

- The image is distroless: no shell and no package manager. It contains only
  the static binary.
- `read_only: true`. The node writes nothing to disk; all state is in memory
  and disappears with the container.
- `cap_drop: [ALL]` plus `cap_add: [NET_RAW]`. Raw sockets are needed for ICMP
  ping and traceroute. Without `NET_RAW`, `ping` falls back to unprivileged ICMP
  where the kernel allows it, and `traceroute` returns
  `error/raw_socket_unavailable`.
- `no-new-privileges`, `mem_limit: 128m`, `pids_limit: 128`, and log rotation
  (two files of 1 MB each).
- `stop_grace_period: 30s`, so in-flight feed answers are delivered on shutdown.
- The systemd unit applies the same idea: `User=nst-node`, only
  `CAP_NET_RAW`, `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`,
  `PrivateTmp`, `PrivateDevices`, `MemoryMax=128M` and `TasksMax=128`.
- Built-in limits: 20 checks per job, 4 concurrent checks, 8 active jobs,
  64 KB request bodies, a 256 KB cap on fetched pages, a 10 MB cap on throttle
  downloads, and per-check timeouts. Options that could outlast the check's
  timeout (many slow ports, long ping series, deep traceroutes) are rejected
  when the job is submitted.

## 2. Exposure and transport security

- The node speaks plain HTTP. Envelopes are end-to-end encrypted and
  authenticated, so this reveals neither commands nor results, but it does
  show an on-path observer (the ISP) that the endpoint exists, its path, and
  how much traffic it handles. To hide that, terminate TLS in a reverse proxy
  (such as Caddy) in front of the node.
- **Behind a reverse proxy:** the node does not trust `X-Forwarded-For`, so
  every caller shares the proxy's rate-limit bucket. This never blocks the
  website, because only rejected requests are counted, but scanners then
  share one budget; rate-limit at the proxy if that matters.
- **Firewall:** if you know your controller IPs, allow inbound traffic only
  from them. The node needs only outbound access to the targets it tests.
- **Clock:** requests are valid for ±120 s. Keep NTP running on node hosts and
  on controllers. Clock skew shows up as `404`s and, with `LOG_LEVEL=debug`,
  as `envelope rejected` in the node log.

## 3. Low-profile operation

A tester node lives on a network whose operator may be watching. The defaults
aim to make the node look like an ordinary host that browses the web.

**Nothing to find from outside**
- The node never contacts the website. Pulling adds only an HTTPS `GET` to a
  regional S3 endpoint every 5–8 s, with randomized spacing. Use path-style
  URLs, so DNS and SNI show only the S3 endpoint and never the bucket name.
- For the listener, use a random `HTTP_PATH_PREFIX`, and a TLS reverse proxy
  on a common port if the endpoint itself must stay hidden. Every invalid, unknown, rate-limited or non-canonical request gets an empty
  `404`. There is no server banner, no Go default error page and no redirect,
  and the public listener has no health endpoint (health lives on a separate
  loopback listener). A scanner sees a closed web server.

**Checks that look like browsing**
- HTTP fetches, DoH lookups and the info lookups send a current desktop browser
  `User-Agent`. The `web` check's TLS handshake and its HTTP request both
  present a Chrome TLS fingerprint.
- `info` asks Cloudflare's trace endpoint for the public IP, racing
  `1.1.1.1`, `1.0.0.1` and `www.cloudflare.com` so one blocked route does not
  fail the check, then looks that IP up on `ipinfo.io` and RIPEstat
  (`stat.ripe.net`). These are common destinations, but a periodic `info` run
  is a regular pattern; schedule it no more often than you need.
- `tcp` dials at most 3 ports at a time, with a random 50–250 ms pause before
  each dial. A batch of ports therefore doesn't look like a scan.
- The `dns` injection probe, which sends a query to an IP that runs no DNS
  server, is a known measurement signature. It is **off unless a check asks for
  it** with `"injection_probe": "on"`.
- The other checks are only as visible as their targets. `sni` connects to a
  neutral IP with a censored SNI, and `traceroute` sends TTL-limited probes;
  both are standard techniques, and both are visible to a network that
  inspects them closely. Run them deliberately, not on a tight schedule.

**Nothing left behind**
- There is no disk state and the root filesystem is read-only. The secret
  lives only in `.env` or `node.env` (mode `0640`).
- Logs default to `warn` in compose and the installer's `node.env`. Even at `info` they hold job IDs, check
  types and counts, never targets, results, envelopes or secrets. Logs are
  capped at 2 MB on disk.

**Testing without touching the network**
The e2e suite runs on an `internal` Docker network that has no route to the
internet, and the bucket serving the node's feed runs inside the test
process. Running `make e2e` on a node host therefore sends nothing beyond
that host's Docker bridge.

## 4. Nodes behind NAT: pull mode

1. Register the node on the website. The website generates its `feed_key` and
   creates an empty feed object ([S3_FEED.md](S3_FEED.md#5-running-a-test-from-admin)).
2. On the node, set `FEED_URLS` to path-style URLs of that object. List alias
   hostnames and mirrors in the order the node should try them:

   ```sh
   FEED_URLS=https://s3.eu-west-1.amazonaws.com/netsurveil/feeds/<feed_key>.txt,https://s3-eu-west-1.amazonaws.com/netsurveil/feeds/<feed_key>.txt
   ```

3. Runs for that node are appended to the feed by the website and picked up
   on the node's next poll. A run the node has not answered within 120 s is
   treated as offline. A node that is already at its 8-job limit answers at
   once with a `too many active jobs` error instead of queueing the run. The
   feed accepts only `submit`; every accepted run gets a terminal final
   answer within 10 minutes, and checks still running at that point are
   cancelled.

The feed and the result objects only hold sealed envelopes. Someone who can
read the feed, or even write to the bucket, can delay or drop requests, but
cannot read them, forge them, or replay them successfully.

## 5. Reading results

Checks are run from the website, which shows each result as the node
returned it ([PROTOCOL.md](PROTOCOL.md#4-results)):
- Start with `verdict` and `mechanism`.
- `stages` shows where the connection failed (dns, tcp, tls or http) and how
  long each stage took.
- `evidence` holds the raw observations: resolver answers, port states, TLS
  certificate details, throttle samples in 250 ms buckets, and traceroute
  hops.
- For a confident conclusion, run the same check from an uncensored node and
  compare (see ADMIN_INTEGRATION.md, section 5).

## 6. Testing

| Command      | What it does |
|--------------|--------------|
| `make test`  | unit tests with the race detector: envelope (with test vectors), codec, client, config, netguard, verdict classifiers, option budgets, jobs, node handler (including fingerprint checks), health, and pull-mode round trips against an in-memory bucket (dead mirror, skipped lines, busy node, overdue job) |
| `make vet`   | `go vet`, including the e2e package |
| `make lint`  | golangci-lint with `.golangci.yml` |
| `make cover` | unit tests with a total coverage floor (`COVER_MIN`) |
| `make fuzz`  | fuzzes the envelope, request codec, secret, DNS response and ICMP quote parsers for `FUZZTIME` each |
| `make vuln`  | govulncheck |
| `make ci`    | vet, lint, test, cover, vuln and build |
| `make e2e`   | builds and runs `test/e2e/docker-compose.e2e.yml`, then tears it down |
| `make vectors` | regenerates `docs/testvectors.json` (only after a deliberate protocol change) |

**The e2e stack** builds a censored network in Docker:
- **`dnsd`** (CoreDNS) acts as the node's ISP resolver. It sinkholes
  `blocked.test` to `10.10.34.34` and hijacks `nx.test` with NXDOMAIN. A clean
  zone on `:5353` serves as the control. It forwards nothing upstream.
- **`targetsrv`** serves HTTP, HTTPS, HTTP/3 (QUIC), raw TCP and large files.
- **`censor`** shares the node's network namespace and enforces the censorship
  with iptables and tc:
  - TCP reset on port 7001 and a silent drop on 7002.
  - Resets for the `blocked-sni.test` SNI and for the `forbidden-keyword` URL.
  - QUIC dropped on UDP 8443.
  - Port 8081 policed to 1 Mbit/s, and port 8083 stalled after 64 KiB.
- **`e2e`** is the test runner. It also serves the node's feed and receives
  its feed responses from an in-memory bucket.

The node under test extends the production `docker-compose.yml` service, so
it runs with the same hardening. The tests assert the exact verdict and
mechanism for each scenario, in both direct and pull mode, including a large
article that quotes a block phrase (must stay `ok`) and a check that outlives
its timeout (`error/check_timeout`). They also cover cancellation, a busy
node, pull-mode health (the runner waits for the node's health check), and the
rejection of replayed, expired, future-dated, tampered, wrong-key and
wrong-node envelopes.
The `info` check is expected to report `public_lookup_failed`, which proves the
network is sealed. Docker must be able to pull `coredns/coredns`, `alpine` and
the distroless base images.

## 7. Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| direct requests get an empty `404` | wrong node ID or secret, a missing `HTTP_PATH_PREFIX` in the URL, clock skew over 120 s, or the rate limit |
| feed runs stay `pending`, then fail | the node cannot read any feed URL (logs show `feed poll failed` with the mirror index), `FEED_URLS` points at the wrong `feed_key`, the secret is wrong, or the clocks differ by more than 120 s |
| feed runs stay `running`, then fail | the node accepted the job but its final answer did not reach any reply URL (logs show `feed response not delivered`) |
| a feed run fails with `too many active jobs` | the node already runs 8 jobs; retry later or spread runs across nodes |
| `error/check_timeout` | the check did not finish within its `timeout_s`; raise it or reduce the options |
| a submit fails with `these options can take up to Ns, more than the Ms timeout` | the options could outlast the check's timeout; reduce them or raise `timeout_s` |
| `docker compose ps` shows `unhealthy` in pull mode | no feed poll has succeeded for 2 minutes; see `feed poll failed` in the logs |
| the node exits with `NODE_SECRET: ...` | the secret is missing or not 32 bytes; generate one with `openssl rand -base64 32` |
| `ping` returns `error/icmp_unavailable`, `traceroute` returns `raw_socket_unavailable` | the container lacks `NET_RAW`, or the systemd unit lacks `CAP_NET_RAW` |
| `error/forbidden_target` | the target resolves to a private, loopback or metadata address; this is intended unless `ALLOW_PRIVATE_TARGETS=true` |
| `throttle` returns `error/control_failed` | the control download failed from this node; pass a reachable `control_url` |
| `dns` returns `anomaly/dns_mismatch` | the local and control answers differ, and the local address could not prove itself with a valid certificate on port 443; inspect the evidence |

Logs are JSON on stdout (`docker compose logs`, or `journalctl -u
netsurveil-tester` for the systemd install). Set `LOG_LEVEL=debug` temporarily to see why
requests are rejected.
