# Design: connections to origins shared between workers

Status: proposed 2026-11-14 and its four decisions taken by the owner the same day (section 9, all
as proposed). Built the same day, steps 1 to 4 of section 8; the measurements are in section 10.
Step 5, the default, is open: `"worker"` in the release that brings the key, as decided. It follows the comparison with Pingora (`bench/pingora/README.md`) and the two changes
that came out of it (0.1.0-alpha.147: an idle origin connection holds no read buffer, an idle TLS
client connection gives back its buffers).

## 1. Why

agensio keeps its connections to origins per worker (`UpstreamPool`, one per worker, no lock). That
is the cheapest design for an origin with steady traffic and it is why a proxied request costs
agensio half of what it costs Pingora. It has one weakness, which the comparison measured: every
worker opens and keeps its own connections to every origin.

| 2,000 origins, 256 clients, four workers | agensio | Pingora |
|---|---|---|
| connections opened to origins, first 10 s | 16,622 | 5,899 |
| connections opened, next 10 s | 618 | 279 |
| CPU per request | 10.0 us | 20.6 us |

With one worker the two open the same number (5,322 against 4,857). The difference is the worker
count: agensio's connections grow with it, Pingora's do not, because its pool is one for the
process. On a 24-thread host the factor would be larger than the 2.8 measured with four.

What a connection too many costs:

- **At the origin.** An application server that gives each connection a thread or a process
  (Apache prefork, php-fpm, a small Puma) is occupied by connections that carry nothing. This is
  the cost that matters outside a benchmark. agensio already met it with php-fpm
  (`keep_conn` and the children an idle connection pins) and answered it with a rule per worker.
- **In agensio.** About 1.5 KB of its own memory per kept connection since 0.1.0-alpha.147, a
  descriptor, and the kernel's socket buffers.
- **On the wire.** A TCP handshake, and for an `https://` origin a TLS handshake, for every
  connection a worker opens although another worker holds an idle one.

## 2. What the others do

- **nginx** keeps upstream connections per worker process (`keepalive` in an `upstream` block), as
  agensio does. Cloudflare named this as a reason to leave nginx.
- **Pingora** has one pool for the process (`pingora-pool`): per origin a lock-free queue of 16
  connections in front of a map under a lock, and a sharded LRU that evicts across origins
  (read in the source of 0.9.1). Every thread takes from and returns to the same store. Its
  runtime has one event queue for all threads, so a connection needs no move between threads.
- **HAProxy** keeps idle server connections per thread and lets a thread take another thread's idle
  connection when it has none (from memory of its documentation, not checked for this note).

## 3. The constraint: a connection belongs to one worker's event loop

Each agensio worker has its own event loop, and a socket is registered with one of them. For
another worker to use an idle connection, the first must take it out of its loop and the second
put it into its own. Measured on this machine (a standalone program, both steps on one core):

| step | cost |
|---|---|
| take a connection out of one loop and put it into another, two locks included | 341 ns |
| the check agensio already makes on a connection idle for long (one `recv`) | 103 ns |
| one uncontended lock | 2.5 ns |

A proxied request costs agensio 5 us unpinned and 7 to 10 us pinned, so a move adds 3 to 7 %.
Between two cores it will be somewhat more, since the kernel's socket state changes core; that is
measured in step 4, not assumed.

This rules out the simple design, one pool for everything: it would tax every proxied request to
help the ones that need it. The design below makes a request pay the move only when it saves a
connection.

## 4. The design: two levels

**Level one is today's pool, unchanged**: each worker's own idle connections per origin, no lock,
no system call. **Level two is a store for the process**: idle connections that belong to no
worker, held as bare descriptors.

A worker decides per origin, from its own traffic, which level its idle connections go to:

- **An origin this worker asks often** keeps its connections in the worker (level one). Nothing
  changes for it: the same instructions, the same system calls as today.
- **An origin this worker asks seldom** has its connection handed to the store when the exchange
  ends, and taken from the store when the next one starts. Any worker can take it.

"Often" is decided when a connection is asked for: while this worker's requests to the origin come
less than a set time apart on average (`kDenseGap`, 1 ms, section 9), the origin is dense on this
worker. Otherwise it is sparse. No timer and no extra clock read: the pool already reads the time
when it releases a connection and when it takes an idle one.

The average is over the last eight or so requests, and one gap counts for at most sixteen
thresholds, so a pause makes an origin sparse at once and about twenty requests in a row make it
dense again. The first version looked at the last gap alone and was measured wrong: of requests
arriving at random 23 ms apart, one in twenty-three follows its predecessor within a millisecond,
and each such pair kept a connection in one worker for a tick, out of the others' reach. Four
workers then opened 9,585 connections to 2,000 origins where the average opens 6,190 and one
pool needs about 5,300.

Asking for a connection, in order:

1. One of the worker's own idle connections to the origin (as today).
2. Else, when the store holds one for the origin: take it. The worker first reads a counter of
   the origin's entry without a lock, so an empty store costs one memory read.
3. Else a new connection (as today).

Giving one back:

1. The origin is dense on this worker: into the worker's own idle list (as today).
2. The origin is sparse: out of the worker's loop and into the store.

And one sweep, on the tick the pool already has (250 ms, armed only while something is idle): a
connection that sat idle in a worker for more than a tick goes to the store. This covers an origin
that was dense and went quiet.

What this gives:

- A busy origin (the proxy rows of `bench/ab.sh`, a site under load) never touches the store. Its
  cost is today's.
- A cold start shares from the first connection: a worker's first request to an origin is sparse
  by definition, so its connection goes to the store and the next worker's first request takes it.
- 2,000 origins at 44 requests a second per worker each (the comparison's row) are sparse:
  the four workers share one set of connections, as Pingora's threads do. Each request pays the
  move.
- The store is touched under a lock per origin, so two workers contend only when they take or
  give a connection of the same origin at the same instant.

A server with one worker does not use the store at all: a connection handed to it could only come
back to the same worker, at the price of the move (measured: 11.6 against 10.1 us per request on
the many-origins row). There `pool = "shared"` behaves as `"worker"`.

### 4.1 The store

`upstream/shared_pool.{hpp,cpp}`: one object owned by the server, alive across reloads.

- Per pool key (the same key the workers use: the address, and for `https://` the TLS policy) one
  entry: a mutex, a counter readable without it, and a stack of idle connections.
- An idle connection there is a descriptor, the time it went idle, its idle timeout, and for a TLS
  origin its TLS session object. About 32 bytes besides the socket itself.
- A worker finds its origin's entry once, under the store's own lock, and keeps the pointer;
  entries are never moved or freed while the server runs.
- Last in, first out, so the connections in use stay warm and the others age out from the bottom.
- Bounded per origin by `max_idle` (the location's key, 64 by default): beyond it the oldest is
  closed.
- Expired connections (the location's `idle_timeout`, 30 s) are closed by whoever meets them
  when taking, and by a sweep on worker 0's tick, so a quiet store empties.
- A connection taken after more than a tick of idleness gets the same one-`recv` check as today
  before a request is written to it (an origin may have closed it).
- At shutdown the store closes what it holds.

Nothing of a worker is touched by another worker: the giving worker takes the connection out of
its own loop before the store sees it, and the taking worker puts it into its own loop after
taking it out of the store. It is the pattern of the file cache: a shared store under a lock, and
a lock-free part per worker.

### 4.2 TLS to the origin

A kept `https://` connection is a socket and a TLS session (`BasicTlsStream`). The session object
is not tied to a thread, so it moves with the descriptor: the stream gains a way to give its
session up and a constructor that adopts one. Before a TLS connection goes to the store it sheds
its buffers (the 0.1.0-alpha.147 shed), so an idle one there holds about 25 KB, not 76.

Sharing matters most here: a connection saved is a TLS handshake saved, hundreds of microseconds
of CPU on each side against the 0.3 us of a move.

### 4.3 What stays per worker

- **The limits**: `max_connections`, the queue and its wait count a worker's exchanges in flight,
  as today. A connection taken from the store counts for the worker that took it.
- **Passive health** (`max_fails`, `fail_timeout`): per worker, as today.
- **php-fpm and CGI**: not shared in this design. A php-fpm connection kept open pins a child, and
  agensio's rules for that (`keep_conn`, `max_connections = children / workers`) are per worker.
  A shared pool could later replace those rules with one count for the process; that is a
  separate step with its own measurements (section 8).

## 5. Configuration

One key in the `proxy` table of a site or a location:

```toml
proxy = { pool = "shared" }     # idle connections to this origin are shared by all workers
```

- `pool = "worker"`: today's behaviour, each worker keeps its own. The default in the first
  release that carries the key (decision 1).
- `pool = "shared"`: the two levels of section 4.

It applies on reload. Locations reaching one origin must agree on it, as on the other pool keys
(`max_idle`, `idle_timeout`, ...): a load with two values for one origin is refused. Managed
sites: the setting `proxy_pool` (`site_update` with `settings`, `agensio ctl site-update NAME
--set proxy_pool=shared`), with the reference row, the cookbook recipe and the MCP texts, as for
every key.

No key for the threshold or for the store's size: `kDenseGap` is a constant chosen by measurement,
and the store is bounded by the existing `max_idle`.

## 6. What is seen

- `server_status`: per origin with `pool = "shared"`, the idle connections in the store, and since
  the start how many were taken from it, given to it, expired there and found closed by the
  origin. With these an administrator sees whether sharing does anything for a site.
- The error log's lines for an origin's failures are unchanged.

## 7. Risks, and what answers each

| risk | answer |
|---|---|
| A connection is used by two workers at once | It is in exactly one place at any time: a worker's loop or the store. The giving worker removes it from its loop first; the store hands it out under its lock. Unit test with several threads; the thread sanitizer run on it. |
| A connection with unread bytes or a half-read answer is shared | Only a connection today's code would keep is given: the exchange complete, the origin allowing keep-alive, no bytes left over. The rule is not changed. |
| The origin closed the idle connection | The existing check before reuse, and the existing single retry for GET and HEAD. |
| A descriptor leaks | The store owns what it holds and closes it on expiry, on overflow and at shutdown. The integration suite counts the server's descriptors before and after a shared-pool run. |
| A blocking descriptor reaches OpenSSL or sendfile (hardening item 7) | The descriptor keeps its `O_NONBLOCK` flag across the move; a test reads the flag after a move. |
| The busy path gets slower | `pool = "worker"` compiles to today's path plus one test of an option. With `"shared"`, a dense origin adds one comparison of two times per exchange. Gate: `bench/ab.sh -P` flat for both values on the proxy rows. |
| The move costs more between cores than measured on one | Measured in step 4 on the comparison's row before anything is decided about the default. |
| Requests of one site reach another's origin | The key is the address and the TLS policy, as today; today two sites proxying to one address already share a worker's connections to it. Unchanged. |
| Entries of origins that left the configuration stay | They hold no connections after `idle_timeout` and about 100 bytes each. A sweep after a reload can drop them later if it ever matters. |

## 8. Staged plan

Each step is its own commit with its tests first, and its measurements in the commit.

1. **The TLS stream can give up and adopt a session.** Unit test: a handshake, the session moved
   to a second stream on another event loop, an exchange after the move.
2. **The store.** `SharedPool` with its unit tests: take and give, the bound, expiry, the counter,
   several threads at once (also under the thread sanitizer).
3. **The pool uses it.** The `pool` key, the dense and sparse rule, the sweep, the status fields,
   the reference row, the cookbook, the MCP texts. Integration rows: two workers and one origin
   that counts its connections; an `https://` origin; the origin closing idle connections; a
   reload; descriptors before and after.
4. **Measure.** `bench/ab.sh -P` for both values. `bench/pingora/run.sh -T origins` with
   `pool = "shared"`, then the whole comparison once. Target for the four-worker row: connections
   opened at or below Pingora's (5,899 cold, 279 warm), CPU per request within 10 % of today's
   10.0 us.
5. **Decide the default** from step 4 (decision 1).

Not in this plan, to consider after it: sharing php-fpm connections with one count for the process
in place of the per-worker `keep_conn` rules; a limit of connections to an origin for the whole
process.

## 9. Decisions for the owner

1. **The default.** Proposed: `"worker"` in the release that brings the key, and `"shared"` as
   the default afterwards if step 4 shows the proxy rows flat and the many-origins row as targeted.
   The alternative is to make it the default at once; the design costs a busy origin nothing by
   construction, but that is a claim until it is measured.
2. **The key's name and values.** Proposed `pool = "worker" | "shared"` in the `proxy` table.
   Alternatives: a boolean (`share_connections = true`), or the values `"per_worker"` and
   `"shared"`.
3. **The threshold.** Proposed 1 ms: an origin a worker asks more than about a thousand times a
   second keeps its connections in the worker. A larger value keeps more connections private
   (fewer moves, more connections); with 20 ms or more the comparison's row would stay as it is
   today. To be fixed by step 4's measurements, not exposed as a key.
4. **php-fpm.** Proposed: out of this design, noted as a later step.

## 10. Measured (2026-11-14)

`bench/pingora/run.sh -S`, three rounds, `bench/results/pingora-20261114-043030.md`; the proxy A/B
of the default against the commit before, six rounds, `bench/results/ab-20261114-031846.md`.

| 2,000 origins, four workers | pool per worker | shared | Pingora | target |
|---|---|---|---|---|
| connections opened, first 10 s | 16,512 | 6,145 | 5,828 | at or below Pingora's: 5 % above |
| connections opened, next 10 s | 486 | 216 | 315 | at or below Pingora's: met |
| CPU per request | 10.2 us | 9.9 us | 20.3 us | within 10 % of 10.0 us: met |

- The default (`"worker"`) against the commit before: proxy rows 0.980, 0.983 and 1.012.
- A busy single origin, the two values alternated on one row: 7.57 us per worker, 7.40 us shared.
  The store was touched 45 times in 800,000 requests (the tick handing on spare idle connections).
- One worker: the store is not used (section 4), so the row is the per-worker row.
- The cold phase stays 5 % above Pingora and 16 % above agensio's own count with one worker
  (5,308). The cause was not isolated; workers asking a cold origin at the same instant each
  open a connection, which one pool also does.
- The rule changed once on the way (section 4): the last gap alone gave 9,585 connections.
