# NetSurveil Tester Protocol v1

A controller (the netsurveil `/admin`) sends sealed requests to a tester node
and gets sealed responses back. A node is reached **directly** over HTTP, or
through a **feed**: a text file on S3
that the node polls, with responses uploaded to presigned S3 URLs. Storage in
between only ever holds ciphertext and cannot read or forge it.

Every node has a 32-byte secret (`NODE_SECRET`) that only the node and the
controller hold.

## 1. Envelope

### Key derivation

All keys come from HKDF-SHA256 with an empty salt (RFC 5869: HashLen zero
bytes) and a 32-byte output:

| Purpose        | HKDF `info`    | Use                                   |
|----------------|----------------|---------------------------------------|
| Request key    | `nst/v1/req`   | XChaCha20-Poly1305, controller → node |
| Response key   | `nst/v1/resp`  | XChaCha20-Poly1305, node → controller |

### Wire format

```json
{"v":1,"node":"node-1","ts":1800000000,"nonce":"<base64 24 bytes>","ct":"<base64>"}
```

- `v`: always `1`.
- `node`: the node ID (`[A-Za-z0-9._-]{1,64}`).
- `ts`: the sender's Unix time in seconds.
- `nonce`: 24 random bytes, standard base64 with padding.
- `ct`: the ciphertext followed by the 16-byte Poly1305 tag, standard base64.
- Additional authenticated data: the UTF-8 string `nst/v1|<node>|<dir>|<ts>`,
  where `<dir>` is `req` or `resp` and `<ts>` is the decimal value of `ts`.

### Acceptance rules

- **Requests** must be within ±120 s of the node's clock. Each nonce is
  accepted only once; the node remembers nonces until they would expire anyway.
- **Responses** must be at most one hour old and at most 120 s in the future.
- A response is bound to its request by `rid`. The controller picks a random
  `rid` for each request and must reject any response whose `rid` or `node`
  differs.
- Any failure (bad JSON, wrong node, stale timestamp, bad tag, replayed nonce)
  is one opaque error. The node answers every failure with an empty `404`.

`docs/testvectors.json` contains a fixed secret, timestamp and nonce, plus the
derived key, AAD and the exact envelope. Any implementation
must reproduce them byte for byte. To regenerate them, run `make vectors`.

## 2. Plaintext messages

### Request

```json
{
  "rid": "9f2c51d0a6b4e38f71c2d0aa",
  "op": "submit",
  "job_id": "",
  "checks": [{"type": "web", "target": "https://x.com", "options": {}, "timeout_s": 30}],
  "wait": true,
  "reply": ["https://s3.eu-west-1.amazonaws.com/netsurveil/results/node-1/4b1e...json?X-Amz-Signature=..."]
}
```

| `op`     | Fields                  | Effect                                                          |
|----------|-------------------------|-----------------------------------------------------------------|
| `submit` | `checks` (1–20), `wait` | starts a job; with `wait`, replies when it finishes (≤60 s)     |
| `get`    | `job_id`                | returns the job's current snapshot                              |
| `cancel` | `job_id`                | cancels the job; finished checks keep their results            |

- `rid` is required and at most 64 characters.
- `reply` is required for requests read from a feed and ignored on the direct
  transport. It holds 1–4 absolute http(s) URLs that accept a `PUT`, normally
  presigned S3 URLs (see [Feed](#feed-pull-mode)).
- Unknown fields are rejected.

### Response

```json
{
  "rid": "9f2c51d0a6b4e38f71c2d0aa",
  "node": "node-1",
  "version": "v0.1.0",
  "job": {
    "id": "c8d0a7cb02876ef7ffce75d5",
    "state": "done",
    "created_at": "2026-10-07T16:11:27.277164Z",
    "finished_at": "2026-10-07T16:11:28.664341Z",
    "results": [ { "...": "see section 4" } ]
  },
  "error": ""
}
```

- `state` is `running`, `done` or `cancelled`.
- `results` follows the order of `checks`. A `null` entry is a check that is
  still running.
- `error` is set instead of `job` for application errors: a validation failure
  (`check 0: ...`), `unknown job`, `too many active jobs`, or `too many checks
  in one job`. These errors come back inside a valid sealed response, so only
  an authenticated controller ever sees them.
- Jobs are kept in memory for 15 minutes after they finish. A node runs at
  most 8 active jobs and 4 checks at a time.

## 3. Transports

### Direct (inbound HTTP)

`{prefix}` is `HTTP_PATH_PREFIX`. It is empty by default; a random prefix makes
the endpoint harder to find.

| Method   | Path                      | Envelope location                  |
|----------|---------------------------|------------------------------------|
| `POST`   | `{prefix}/v1/jobs`        | request body (≤64 KB)              |
| `GET`    | `{prefix}/v1/jobs/{id}`   | `Authorization: NST <base64(envelope)>` |
| `DELETE` | `{prefix}/v1/jobs/{id}`   | `Authorization: NST <base64(envelope)>` |

- A successful call returns `200` with a sealed response body.
- Everything else returns `404` with an empty body. That includes unknown
  routes (`/healthz` among them), rate limiting (default 30 requests per
  minute per IP), unreadable or invalid envelopes, non-canonical paths such as
  `//v1/jobs` or `/a/../v1/jobs`, and requests whose sealed `op` or `job_id`
  disagrees with the method and path. Nothing in the response identifies the
  software.
- Waiting is requested only inside the envelope (`"wait": true`); there is no
  query parameter for it.
- The container health check is not part of this API. It runs on a separate
  loopback-only listener (`HEALTH_ADDR`, see [OPERATIONS.md](OPERATIONS.md#health)).

### Feed (pull mode)

A pull-mode node opens no port. It polls a **feed**, a plain text object that
only the controller writes, and uploads each response to a URL that the
request itself names. In production the feed and the responses live on S3;
[S3_FEED.md](S3_FEED.md) describes the bucket and the website side. The tests
use an in-memory stand-in, `test/fixtures/bucket`.

**Feed object**

- UTF-8 text. Each line holds one sealed request envelope, exactly as sealed
  (compact JSON, no line breaks), and lines are separated by `\n`. Blank lines
  are ignored, and so are lines longer than 64 KB.
- The node reads at most 2 MB. The controller should keep at most 32 lines,
  and drop lines whose cleartext `ts` is more than 120 s old whenever it
  rewrites the feed.
- Lines are never removed by the node. It remembers the SHA-256 of every line
  it has handled for 5 minutes, and the envelope's nonce cache and ±120 s
  window reject anything older, so each request runs at most once.
- Lines that fail authentication, are stale, replay a nonce or have no usable
  `reply` are skipped without any answer.

**Polling**

- The node is configured with up to 8 URLs for the same feed (`FEED_URLS`).
  It uses one URL until a request to it fails, then moves to the next.
- `GET` sends `If-None-Match` with the last `ETag` from that URL. `304` means
  nothing changed, `200` carries the feed, and any other status or a network
  error counts as a failure. Each request times out after 20 s.
- After every poll the node waits until at least 5 s have passed since the
  poll began, plus 0–3 s of random jitter, so polling never forms a tight
  loop or a fixed-period beacon. After a failure it backs off exponentially,
  from 1 s up to 30 s, and resets after the next success.
- Every new line is answered. A `submit` that would exceed the node's 8
  active jobs is answered at once with the `too many active jobs` error, so
  the controller learns of it immediately instead of timing out.

**Responses**

- The node `PUT`s each sealed response to the request's `reply` URLs, trying
  them in order until one returns `2xx`. It goes through the list up to three
  times, with growing pauses, and sends `Content-Type: application/json`.
- The feed accepts only `submit`. A `get` or `cancel` line is answered once
  with the error `op "get" is not accepted from the feed` (or `"cancel"`).
- A `submit` is answered twice under the same `rid`: first with the job's
  `running` snapshot as soon as it starts, then with the final job. The final
  answer is always terminal (`done` or `cancelled`) and comes within 10
  minutes: a job still running then is cancelled, and its unfinished checks
  report `error/cancelled`. The same happens when the node shuts down, which
  sends final answers before it exits. The second `PUT` overwrites the first,
  so the reply object always holds the latest state.
- Application errors are answered once. `wait` is ignored on this transport.
- The controller treats a missing reply object 120 s after queueing as a node
  that never read the request, and a reply that is still `running` after
  15 minutes as a node that stopped before finishing.

## 4. Results

```json
{
  "type": "web",
  "target": "https://x.com",
  "verdict": "blocked",
  "mechanism": "tls_sni_rst",
  "stages": [{"name": "dns", "ok": true, "ms": 12}, {"name": "tcp", "ok": true, "ms": 40},
             {"name": "tls", "ok": false, "ms": 41, "error": "connection reset by peer"}],
  "evidence": {"...": "check specific"},
  "error": "",
  "started_at": "2026-10-07T16:11:27Z",
  "duration_ms": 95
}
```

| `verdict`     | Meaning                                                          |
|---------------|------------------------------------------------------------------|
| `ok`          | reachable, nothing suspicious                                    |
| `blocked`     | interference detected; `mechanism` says how                      |
| `throttled`   | reachable but deliberately slowed                                |
| `anomaly`     | suspicious but not conclusive (e.g. untrusted certificate)       |
| `unreachable` | failed in a way consistent with the target itself being down     |
| `error`       | the check could not run (bad input, forbidden target, no raw sockets) |

The main `mechanism` values are:

- **DNS:** `dns_sinkhole`, `dns_nxdomain`, `dns_injection`, `dns_timeout`, `dns_failure`, `dns_private_answer`, `dns_mismatch`.
- **TCP and TLS stages:** `tcp_rst`, `tcp_timeout`, `tcp_refused`, `tls_rst`, `tls_timeout`, `tls_eof`.
- **TLS certificate:** `tls_invalid_cert`.
- **HTTP:** `http_rst`, `http_timeout`, `http_451`, `http_blockpage`, `http_redirect_sinkhole`, `http_rst_midstream`.
- **SNI:** `tls_sni_rst`, `tls_sni_timeout`, `tls_sni_eof`.
- **QUIC:** `quic_drop`, `quic_error`, `quic_unsupported`.
- **Throttle:** `bandwidth_cap`, `stall_after_bytes`.
- **Ping and traceroute:** `packet_loss`, `icmp_filtered`, `path_drop`.
- **Node-side:** `forbidden_target`, `raw_socket_unavailable`, `control_failed`.
- **Lifecycle (verdict `error`):** `check_timeout` when the check outlives its
  `timeout_s` (the evidence gathered so far is kept), and `cancelled` when the
  job is cancelled or the node shuts down.

## 5. Check reference

Every check accepts `timeout_s`, which must be within the maximum below.
Options outside the documented ranges are **rejected**, never clamped. Unknown
options are rejected too.

Options must also fit within the timeout. For `tcp`, `ping`, `traceroute` and
`throttle` the node computes how long the options can take at worst, plus
5 s for name resolution, and rejects the check if that exceeds `timeout_s`
(for example `check 0: tcp: these options can take up to 21s, more than the
20s timeout; reduce them or raise timeout_s`). The worst cases are:

- `tcp`: one `timeout_ms` plus 250 ms per round of 3 ports.
- `ping`: `(count-1) × interval_ms + wait_ms`, and the same again plus
  `count × wait_ms` when `tcp_port` is set.
- `traceroute`: `max_hops × wait_ms` plus 2 s for hop names.
- `throttle`: `2 × duration_s`.

| Type         | Target                    | Default / max timeout | Options |
|--------------|---------------------------|-----------------------|---------|
| `web`        | URL or hostname (https assumed) | 30 / 60 s | `insecure`, DNS controls* |
| `dns`        | hostname                  | 15 / 30 s  | `qtype` (`A`/`AAAA`), `resolvers` (≤5 IP[:port]), `injection_probe` (off by default; `"on"` queries `1.2.3.4`, or give an IP[:port] that runs no DNS server), DNS controls* |
| `tcp`        | hostname or IP            | 20 / 45 s  | `ports` (≤32, default `[80,443]`), `timeout_ms` (100–15000, default 5000) |
| `sni`        | hostname used as SNI      | 20 / 45 s  | `ip` (default: resolve `control_sni`), `port` (443), `control_sni` (`www.cloudflare.com`), `timeout_ms` (500–15000) |
| `quic`       | https URL or hostname     | 20 / 45 s  | `insecure`, `assume_h3`, `timeout_ms` (1000–15000) |
| `ping`       | hostname or IP            | 20 / 45 s  | `count` (1–20, default 4), `interval_ms` (200–5000, default 500), `wait_ms` (200–5000, default 2000), `tcp_port` (443; 0 disables TCP ping) |
| `traceroute` | hostname or IPv4          | 60 / 120 s | `mode` (`icmp`/`udp`/`tcp`), `port`, `max_hops` (≤30), `probes` (≤3), `wait_ms` (200–3000) |
| `throttle`   | http(s) URL               | 45 / 60 s  | `control_url` (default Cloudflare speed test), `max_bytes` (64 KiB–10 MiB), `duration_s` (2–20), `insecure` |
| `info`       | empty or `self`           | 15 / 30 s  | none |

\* **DNS controls**, shared by `web` and `dns`:
- `control_resolvers`: up to 5 UDP resolvers given as IP[:port].
- `doh`: up to 3 https DoH endpoints.
- `no_control`: disables the controls.

When neither `control_resolvers` nor `doh` is given, the check uses Cloudflare
(1.1.1.1) and Google (8.8.8.8) DoH, addressed by IP.

### Target policy

The node never contacts loopback, link-local, cloud metadata, multicast or
reserved addresses. It contacts private, CGNAT or ULA addresses only when
`ALLOW_PRIVATE_TARGETS=true`. IPv6 addresses that embed an IPv4 destination
(NAT64 `64:ff9b::/96`, 6to4 `2002::/16`, Teredo `2001::/32`) must pass the
policy for that IPv4 address as well. The policy is enforced on every connect,
so a DNS answer that changes after validation cannot get around it. A refused
target yields `error` with `forbidden_target`.
