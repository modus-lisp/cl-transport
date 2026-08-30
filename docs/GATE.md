# The gate

Every outbound connection this image opens — whoever opened it — recorded, and
subject to a policy that can name not only *where* the bytes may go but **how they
may travel**.

```lisp
(cl-transport.gate:initialize)   ; at boot: load the policy, arm the gate
...
(cl-transport.gate:report)
```

```
2 connections, most recent first
  11:29:59  allow   main thread   example.com:443
  11:29:59  DENY    main thread   example.com:443  (policy.conf:2; via any)
```

Those two lines are the same host in the same image, moments apart: the first was
dialled through `cl-transport:dial`, the second was a library opening its own socket.

## Why it lives here

`DIAL` is where a carrier is chosen — `:direct`, `:socks5`, `:tor`, or any backend
registered at runtime. So `DIAL` is where the carrier can be *declared*: it binds
`*carrier*` around the connection it makes.

But declaring is not enforcing. Code that would rather open its own socket simply
does, and a policy expressed only where carriers are chosen governs exactly the
callers that already agreed to be governed. So the gate itself sits lower, on
`sb-bsd-sockets:socket-connect` and `socket-send` — where seal, weft, conch, and
usocket (and so cl-tor and cl-transport's own `:direct`) all end up, along with any
quicklisp library nobody here has read.

The two halves meet at `*carrier*`, whose default is `:raw` — **nobody dialled
this**. That single default is what makes the policy below mean what it says.

## Must use cl-transport

```
require * via cl-transport      # or `via any' — the same thing
```

Anything that opened its own socket is carrying `:raw`, satisfies no carrier
requirement, and is refused. A machine can insist that its networking go through the
one place that knows how to route it *before* insisting on anything about where it
goes.

This is also how the rest of the workspace gets migrated. Nothing has to be
converted up front: turn the requirement on, and every path that still opens its own
socket announces itself in the log with the principal that did it. Migration becomes
a list rather than a refactor.

## Requiring a carrier

```
require loom/*  via tor         # the browser may only reach the world over Tor
require *       via any         # everything must at least be dialled
```

A requirement is checked *before* the allow/deny list, because it is a different kind
of statement: a rule says whether a destination is permitted, a requirement says how
the bytes are permitted to travel. A machine that may reach a host over Tor and not
directly needs both answers, separately.

## The policy document

Line-oriented, `#` comments, first match wins — the shape kiln's profiles already
use, and the ordering every firewall config in the world uses.

```
default deny                              # the verdict when nothing matches
require loom/*     via tor

allow  loom/*      news.ycombinator.com   # any port
allow  *           *:443                  # https anywhere
deny   *           *:25                   # nothing here sends mail
allow  10.0.0.1                           # principal omitted = anybody
```

`*` globs, case-insensitively, in principals and hosts alike. A host pattern is
matched against the address **and** against every hostname that address has been seen
resolved from, because `connect(2)` only ever sees an address and the name existed a
moment earlier, in the resolver.

An unparsable line stops the load rather than being skipped: a firewall that quietly
ignores a rule it did not understand is worse than one that refuses to start, because
the rule looks present and is not.

## Who is asking

A principal is whatever `*principal*` is bound to, falling back to the **thread
name** — which in this workspace already says `loom-glass-nav` or `wm-browse-pump`
rather than `sbcl`. So a rule can tell the browser loading a page you asked for apart
from that page phoning home: the distinction a process-level firewall structurally
cannot make, because from outside, all of this is one process.

```lisp
(cl-transport.gate:with-principal ("loom/browser") ...)
```

## Boot

`initialize` loads a policy and arms the gate. It looks at `$TRANSPORT_POLICY`, then
`~/.config/transport-policy.conf`, then `/etc/transport-policy.conf`, and does
nothing at all if there is none — loading this system does not police its host, since
cl-consensus and cl-tor both pull it in for `DIAL` alone.

A gate armed late is not a gate: arm while the image is still starting, before a seat
is served or a relay dialled. `$TRANSPORT_POLICY` naming a file that does not exist is
an error rather than an open gate — somebody who set it meant for a policy to be in
force.

## What it does not cover

- **Anything reaching the kernel by its own FFI** rather than through
  `sb-bsd-sockets`. Nothing in this workspace does today.
- **Inbound.** Listening sockets are a different question; `EXPOSE` is where it lives.
- **Names are observations, not truth.** An address is learned from a resolver call
  some caller made; it is not proof the address belongs to that name, and a host
  behind a CDN will honestly collect several. Rules that must be exact should name
  addresses, which are what the kernel is actually given.
- **Connection pools.** The gate sees a socket open, not each request over it, so a
  pooled connection opened by one principal and handed to another travels on the
  first one's permission. weft is partitioned against this — set
  `weft.fetch:*pool-partition*` to `#'cl-transport.gate:principal` — but any other
  pool has the same property until it is.
- **Loopback is exempt by default** (`*allow-loopback*`), because the desktop's
  control socket, its seats and the local viewer all talk over 127.0.0.1. Unix-domain
  sockets are not gated at all — they cannot go anywhere.

UDP *is* covered: a datagram socket usually never connects, and ICE and TURN put the
destination on each send, so `socket-send` is gated too. Per-packet verdicts are
memoised against a policy generation counter so the policy stays out of the media
path.

## Gate

```
sbcl --script inspect/transport-gate.lisp
```
