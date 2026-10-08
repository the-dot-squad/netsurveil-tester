# Integrating tester nodes into netsurveil `/admin`

This document is the blueprint for driving tester nodes from the netsurveil
website. Nodes do not depend on the website: they never call it, and their
feed traffic only ever goes to S3. The wire
format itself is specified in [PROTOCOL.md](PROTOCOL.md).

## 1. Node registry

Each node gets one row. The secret is the only sensitive field: anyone who has
it can command the node and read its results.

```sql
create table tester_nodes (
  id               text primary key,          -- NODE_ID, [A-Za-z0-9._-]{1,64}
  label            text not null,             -- "Tehran / MCI mobile"
  country          char(2) not null,          -- where the node measures from
  asn              integer,                   -- filled from the info check
  transport        text not null check (transport in ('direct', 'feed')),
  endpoint_url     text,                      -- direct only: https://host:port/prefix
  feed_key         text unique,               -- feed only: 32 random hex chars, see S3_FEED.md
  secret_enc       bytea not null,            -- NODE_SECRET encrypted at rest (see below)
  secret_key_ver   integer not null,          -- which KEK encrypted it, for rotation
  is_control       boolean not null default false, -- uncensored vantage point used for comparison
  enabled          boolean not null default true,
  last_seen_at     timestamptz,
  last_version     text,
  created_at       timestamptz not null default now()
);

create table tester_runs (
  id            uuid primary key default gen_random_uuid(),
  batch_id      uuid not null,                -- one admin action across several nodes
  node_id       text not null references tester_nodes(id),
  job_id        text,                         -- node-side job id
  feed_ticket   text,                         -- feed mode: names the result object
  feed_rid      text,                         -- feed mode: rid sealed into the request
  queued_at     timestamptz,                  -- feed mode: when the request entered the feed
  checks        jsonb not null,               -- the submitted check specs
  state         text not null,                -- pending | running | done | cancelled | failed
  results       jsonb,                        -- job.results from the node
  error         text,
  requested_by  text not null,
  created_at    timestamptz not null default now(),
  finished_at   timestamptz
);
create index on tester_runs (batch_id);
```

**Secret at rest:**
- Encrypt `NODE_SECRET` with AES-256-GCM under a key-encryption key (KEK). The
  KEK lives in the platform's secret store (an environment variable), never in
  the database. Store `nonce || ciphertext` in `secret_enc` and the KEK version
  in `secret_key_ver`.
- Decrypt only in server-side code at the moment of sealing a request. Never
  send the secret, or anything derived from it, to the browser.
- To rotate a node secret: generate one with `openssl rand -base64 32`, update
  the node's `NODE_SECRET` and restart it, then update the row.

## 2. Envelope in TypeScript

XChaCha20-Poly1305 is not in WebCrypto. Use `@noble/ciphers` (audited, no
dependencies) together with Node's `crypto.hkdfSync`. This module reproduces
`docs/testvectors.json` byte for byte, and it has been exercised against a live
node.

```ts
import { hkdfSync, randomBytes } from "node:crypto";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";

export type Direction = "req" | "resp";

interface Envelope {
  v: 1;
  node: string;
  ts: number;
  nonce: string;
  ct: string;
}

const REQUEST_WINDOW_S = 120;
const RESPONSE_MAX_AGE_S = 3600;

function deriveKey(secret: Uint8Array, info: string): Uint8Array {
  return new Uint8Array(hkdfSync("sha256", secret, new Uint8Array(0), info, 32));
}

function aad(node: string, dir: Direction, ts: number): Uint8Array {
  return new TextEncoder().encode(`nst/v1|${node}|${dir}|${ts}`);
}

export function seal(
  secret: Uint8Array,
  node: string,
  dir: Direction,
  plaintext: string,
  ts: number = Math.floor(Date.now() / 1000),
  nonce: Uint8Array = randomBytes(24),
): string {
  const cipher = xchacha20poly1305(deriveKey(secret, `nst/v1/${dir}`), nonce, aad(node, dir, ts));
  const ct = cipher.encrypt(new TextEncoder().encode(plaintext));
  const env: Envelope = {
    v: 1,
    node,
    ts,
    nonce: Buffer.from(nonce).toString("base64"),
    ct: Buffer.from(ct).toString("base64"),
  };
  return JSON.stringify(env);
}

export function open(
  secret: Uint8Array,
  node: string,
  dir: Direction,
  raw: string,
  now: number = Math.floor(Date.now() / 1000),
): string {
  const env = JSON.parse(raw) as Envelope;
  const maxAge = dir === "resp" ? RESPONSE_MAX_AGE_S : REQUEST_WINDOW_S;
  if (env.v !== 1 || env.node !== node || env.ts < now - maxAge || env.ts > now + REQUEST_WINDOW_S) {
    throw new Error("invalid envelope");
  }
  const cipher = xchacha20poly1305(
    deriveKey(secret, `nst/v1/${dir}`),
    Buffer.from(env.nonce, "base64"),
    aad(node, dir, env.ts),
  );
  return new TextDecoder().decode(cipher.decrypt(Buffer.from(env.ct, "base64")));
}
```

**Verification test:** add this to the website's test suite so a library
upgrade cannot silently break compatibility.

```ts
import vectors from "./testvectors.json"; // copy of docs/testvectors.json

for (const v of vectors) {
  const secret = Buffer.from(v.secret_hex, "hex");
  const nonce = Buffer.from(v.nonce_b64, "base64");
  expect(seal(secret, v.node_id, v.direction as Direction, v.plaintext, v.ts, nonce)).toBe(v.envelope);
  expect(open(secret, v.node_id, v.direction as Direction, v.envelope, v.ts)).toBe(v.plaintext);
}
```

**Rules the website must keep:**
- Use a fresh random `rid` for each request (12 random bytes, hex encoded).
- After opening a response, reject it unless `resp.rid === rid` and
  `resp.node === node.id`.
- Never retry the same sealed request. Seal a new one, because the node
  accepts each nonce only once.
- Keep the server clock NTP-synced. The node rejects requests more than
  120 s off its own clock.

## 3. Submit and poll flow

Run the whole flow server-side, in a route handler or a background job. The
browser only ever sees `tester_runs` rows.

**Direct mode** (`transport = 'direct'`):

1. Insert a `tester_runs` row with `state = 'pending'`.
2. `POST {endpoint_url}/v1/jobs` with the sealed body `{rid, op: "submit", checks, wait: true}`.
   The node holds the request for up to 60 s while the job runs.
   - With `200`, open the response. If `job.state === "done"`, store the
     results and finish. Otherwise store `job_id` and set `state = 'running'`.
   - With `404`, the cause is one of: wrong secret or node ID, clock skew, rate
     limit, or wrong prefix. Mark the run `failed` with a generic message.
3. While the run is `running`, poll every 2–5 s with `GET {endpoint_url}/v1/jobs/{job_id}`.
   Send the sealed `{rid, op: "get", job_id}` in `Authorization: NST <base64(envelope)>`.
   Stop when `state !== "running"`.
4. To cancel, send `DELETE` with a sealed `{op: "cancel", job_id}`. The reply
   contains the final snapshot.

**Feed mode** (`transport = 'feed'`). The website writes the node's request
feed on S3 and reads the results the node uploads there. The node never
contacts the website. [S3_FEED.md](S3_FEED.md) has the bucket setup and a
complete module; the flow is:

1. `queueRun` seals `{rid, op: "submit", checks, reply}`, where `reply` holds
   presigned PUT URLs for the run's result object, and appends it to the feed.
   Store `ticket`, `rid` and `queuedAt` on the run.
2. Poll `runState` every 2–5 s. It reports `pending` until the node uploads
   its first answer, `running` while the job runs, then `done` with the final,
   rid-checked response. A run with no answer after 120 s, or still running
   after 15 minutes, is `failed`. If the first answer carries an `error`
   (for example `too many active jobs` from a node already at its limit),
   mark the run `failed` with that message right away.
3. Store the results and delete the result object. A final job may be
   `cancelled`: the node cancels checks still running after 10 minutes, or
   when it shuts down, and those checks report `error/cancelled`.

The feed accepts only `submit`, so cancellation is not offered for feed nodes.

**Choosing the transport:**
- Use **direct** when the node has a reachable address. It is simplest and it
  supports live status and cancel.
- Use **feed** for nodes behind NAT or CGNAT, on mobile links, or wherever an
  open inbound port would draw attention. The node then only makes outbound
  HTTPS requests to a regional S3 endpoint, which looks like ordinary web
  traffic, and the website's domain never appears in its traffic.
- A node can also do both, listening and pulling at the same time.

**Bounds to respect:**
- At most 20 checks per job and 8 active jobs per node.
- Default rate limit of 30 requests per minute per controller IP. Poll at a
  modest interval.
- The response `error` field carries validation errors such as
  `check 2: ports ...` or the option budget error (`these options can take up
  to Ns, more than the Ms timeout ...`). Show it to the operator as-is.
- A result with verdict `error` and mechanism `check_timeout` or `cancelled`
  describes the run, not the target; don't count it as censorship.

## 4. Hosting the feed

Feed-mode nodes need no route on the website. The website only needs
server-side access to one S3 bucket (more if you mirror), and the feed module
from [S3_FEED.md](S3_FEED.md):

- When registering a feed node, generate `feed_key` with `newFeedKey()`, call
  `sweepFeed(feed_key)` to create the empty feed, and hand the operator the
  node's `FEED_URLS`: path-style URLs of that object, comma-separated.
- Seal each request immediately before queueing it. The node rejects requests
  sealed more than 120 s earlier.
- Run `sweepFeed` for every feed node from a scheduled job, and mark stale runs
  `failed` in the same job.
- Never log feed contents or presigned URLs. A presigned URL lets anyone
  overwrite that result object until it expires.

## 5. Comparing nodes: control vantage points

A single measurement shows only what one network does. Censorship becomes
evident when the same check gives a different answer from an uncensored
network. To compare:

1. Mark one or more nodes in uncensored countries `is_control = true`.
2. When an operator tests `x.com` on node *A*, send the same `checks` to *A*
   and to a control node in the same `batch_id`.
3. Judge the pair:

| Node A        | Control       | Conclusion                                              |
|---------------|---------------|---------------------------------------------------------|
| `blocked`     | `ok`          | censorship at A, with high confidence; show A's `mechanism` |
| `unreachable` | `ok`          | probable censorship (silent drop) at A                  |
| `throttled`   | `ok`          | throttling at A                                         |
| `anomaly`     | `ok`          | worth a look; show the evidence                         |
| anything      | `unreachable` | the target itself is down; not censorship               |
| `ok`          | `ok`          | accessible                                              |

The node's own controls (DoH answers, control SNI, control download URL)
already remove most false positives. The cross-node comparison is the second
line of evidence, for checks whose verdict is `unreachable` or `anomaly`.

Run the `info` check periodically (e.g. hourly) on every node, and store
`public_ip`, `country`, `org` and `version` on the node row. This catches
nodes that moved networks (a VPN or roaming) and would otherwise produce
misleading results.

## 6. UI suggestions

- **Nodes page:**
  - One card per node: label, flag, ASN/org, transport, last-seen time and version.
  - A health dot driven by a periodic `info` run.
  - Actions: "Run info" and "Rotate secret". Rotation shows the new
    `NODE_SECRET` exactly once.
- **New test form:**
  - Pick the target and one or more check types from presets: "Is this site
    blocked?" runs `dns`, `web`, `sni` and `quic`; "Port check" runs `tcp`;
    "Speed/throttle" runs `throttle`; "Path" runs `ping` and `traceroute`.
  - Pick nodes, with a control node preselected.
  - Advanced options as JSON, validated by the node.
- **Results view:**
  - A matrix with checks as rows, nodes as columns, and verdict chips.
    Colours: ok green, blocked red, throttled orange, anomaly yellow,
    unreachable grey, error outlined.
  - Clicking a chip opens a stage timeline (dns → tcp → tls → http, with ms
    and errors) and the raw evidence JSON.
  - `throttle` evidence includes `buckets_250ms`; render it as a sparkline
    against the control so stalls and caps are visible at a glance.
  - Render `traceroute` hops as a list, highlighting the last responding hop
    when the verdict is `path_drop`.
- **History:** filter `tester_runs` by target, country and mechanism. A
  per-target timeline shows when blocking started and stopped.
- **Permissions:** limit `/admin/testers` to staff. Record `requested_by` on
  every run. Rotating a secret or adding a node should need a second
  confirmation.
