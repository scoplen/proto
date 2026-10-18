# SSH Keystroke Latency Diagnostics

`10-protocol-core.md` §8 limits added per-keystroke latency to one event-loop turn. The
`keystroke_latency` example measures a narrower, observable quantity: elapsed time from sending
one byte until receiving the matching byte from an authenticated SSH echo server. It provides an
in-process comparison to direct `russh` and a separate comparison to the OpenSSH CLI against one
disposable OpenSSH server.

## In-process `russh` comparison

Run a release build on an otherwise idle machine:

```text
cargo run --locked --release -p scoplen-ssh --example keystroke_latency
```

The example creates a disposable listener bound to `127.0.0.1` and an Ed25519 host key. Both clients
pin that key, authenticate, and open one session. The server immediately echoes each received byte.
Each client completes 100 warmup exchanges, followed by 1,000 measured exchanges. Their order
alternates each trial. The timer starts just before the one-byte send and stops after the matching
echo event; a missing or unexpected byte fails the run. Each send-to-echo exchange has a five-second
deadline. The output includes every measured sample in microseconds and a separate summary for
each client: minimum, nearest-rank p50, p95, p99, and maximum. This permits independent analysis
of outliers and distributions. The clients and server use TCP_NODELAY; the server offers only
`chacha20-poly1305@openssh.com`. Key exchange follows each client's default preferences.

## External OpenSSH comparison

Run the disposable-server script from the repository root:

```powershell
pwsh ./scripts/ssh-keystroke-latency.ps1
```

It requires PowerShell 7, Docker with a running Linux daemon, `ssh`, `ssh-keygen`, Rust 1.99.0,
and access to the Alpine package repository. `-Image` defaults to `alpine:3.21`; use the recorded
image digest for a repeat with the same base image. The script pins Alpine's OpenSSH package to
`9.9_p2-r0` and fails if it is unavailable. It binds each server to a random loopback port,
creates disposable Ed25519 user and host keys, pins the host key in both clients, and removes its
container and temporary files on success or failure.
It prints the source revision and whether the worktree has uncommitted changes, so measurements
from a modified checkout are identifiable.

For each of `chacha20-poly1305@openssh.com` and `aes256-gcm@openssh.com`, Scoplen's public
`ClientConnection`/`ClientChannel` API and the local OpenSSH CLI authenticate to that same server.
Both keep one non-PTY session running `cat`. The Scoplen timer covers `send_data` through the
matching `next_event`; the OpenSSH timer covers writing and flushing one byte to the CLI's stdin
through reading the matching byte from its stdout. Connection, authentication, and command
startup are outside the retained samples. A mismatch, connection failure, unexpected SSH event,
nonzero OpenSSH exit, or five-second echo timeout fails the run. The same 100 warmups, 1,000
retained samples, alternating order, raw per-sample output, and nearest-rank summaries apply.

Both wall-clock comparisons include scheduling, encryption, loopback TCP, server handling, and
operating-system noise. The external comparison also includes OpenSSH process and pipe overhead;
it is not an isolated comparison of SSH engines. Neither run counts event-loop turns or proves
the one-turn requirement. The client's keystroke-to-render budget in
`13-testing-and-quality.md` §7 and remote network paths are likewise unmeasured. Repeat on fixed
hardware before comparing revisions; a scheduling trace is needed to establish the event-loop
turn bound. Gate S4's latency outcome remains Incomplete, as do its other open performance
criteria.

## Local runs, 2026-10-18

On Windows 10.0.26200 with Rust 1.85.0, the release example completed all 1,000 measured
exchanges for each client. Scoplen's p50/p95/p99 were 56.9/112.1/165.3 µs; direct `russh`'s were
55.9/109.8/175.7 µs. These are one local diagnostic run, not a stable hardware baseline or a
pass/fail judgment for the one-turn requirement.

After the send-to-echo deadline was applied to the whole exchange, a second run on the same host
gave Scoplen 103.4/165.9/206.9 µs and direct `russh` 100.6/163.2/202.8 µs at p50/p95/p99.
Both runs completed all 1,000 exchanges per client; the difference shows why one run is not a
stable baseline.

The external comparison ran on Windows 10.0.26200 with an AMD Ryzen 9 7945HX, Rust 1.85.0,
OpenSSH for Windows 9.5p2, and disposable OpenSSH 9.9p2 from Alpine 3.21 image
`sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507`. Each cipher
had 100 warmups and 1,000 retained samples per client:

The first external run measured:

| Server cipher | Client | p50 | p95 | p99 |
|---|---|---:|---:|---:|
| ChaCha20-Poly1305 | Scoplen | 626.7 µs | 850.8 µs | 1,070.1 µs |
| ChaCha20-Poly1305 | OpenSSH CLI | 827.5 µs | 1,113.6 µs | 1,327.3 µs |
| AES256-GCM | Scoplen | 682.7 µs | 923.8 µs | 1,072.2 µs |
| AES256-GCM | OpenSSH CLI | 889.9 µs | 1,157.2 µs | 1,391.2 µs |

The second run used the modified worktree after the send-to-echo deadline and child cleanup
changes, before those changes were committed. It measured:

| Server cipher | Client | p50 | p95 | p99 |
|---|---|---:|---:|---:|
| ChaCha20-Poly1305 | Scoplen | 625.8 µs | 852.5 µs | 1,021.5 µs |
| ChaCha20-Poly1305 | OpenSSH CLI | 844.9 µs | 1,119.0 µs | 1,315.6 µs |
| AES256-GCM | Scoplen | 646.3 µs | 874.2 µs | 1,047.5 µs |
| AES256-GCM | OpenSSH CLI | 869.5 µs | 1,164.6 µs | 1,319.2 µs |

These are same-host diagnostic observations. The CLI's local pipe and process costs contribute
to its RTT; the lower Scoplen values cannot be interpreted as a measured event-loop turn count or
a release performance gate result.
