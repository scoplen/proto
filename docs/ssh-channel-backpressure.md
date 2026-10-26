# SSH Channel Backpressure Evidence

`10-protocol-core.md` §8 requires bounded per-channel buffers and SSH-window-based backpressure.
Run the public `scoplen-ssh` client against a disposable in-process `russh` server with:

```text
cargo test --locked -p scoplen-ssh --test channel_backpressure -- --nocapture
```

The test sends an 8 MiB stream in 32 KiB blocks in each direction. While the receiver deliberately
does not read its channel, it waits until the sender's completed byte count stops increasing and
requires that count to remain below a finite guard. After reads resume, it checks every byte and
the exact transfer length. A separate two-channel case advertises a zero receive window for one
channel; its pending send does not prevent a byte from arriving on the other channel of the same
SSH connection. All waits have a 15-second deadline, and the stall probe samples every 200 ms.

The guards are 4 MiB for client-to-server and 6 MiB for server-to-client. They are regression
limits for this fixture, not a product memory budget. The server uses a 2 MiB receive window and
an eight-message channel queue in the first case. The client uses the engine's default 2 MiB
window, 32 KiB maximum packet, and 100-message channel queue in the second. The client wrapper
splits caller data into chunks of at most 64 KiB and awaits each engine send. These finite queues
and the peer window explain why an 8 MiB transfer cannot be accepted while its consumer is paused.

## Local run, 2026-10-18

On Windows 10.0.26200, all three tests passed. The completed byte counts at the stable stall were
1,638,400 bytes from client to server and 4,194,304 bytes from server to client. Both transfers
then completed with the exact 8,388,608 expected bytes. The zero-window channel remained pending
while a second channel delivered its byte.

## Local run, 2026-10-19

The same three tests passed on Windows 10.0.26200 with Rust 1.99.0 and `russh` 0.64.1. Stable
stall counts were 1,638,400 client-to-server bytes and 4,259,840 server-to-client bytes. Both
transfers resumed with all 8,388,608 bytes intact, and the independent channel still progressed
while the zero-window send remained pending.

This test measures accepted bytes and transfer behavior, not process RSS or peak heap use. It does
not establish a per-channel allocation ceiling under many simultaneous saturated channels or
prove that a completely full inbound queue cannot delay other channels on the same connection.
The latency requirement of at most one added event-loop turn per keystroke is also unmeasured.
Gate S4's memory and latency performance requirements remain Incomplete until those measurements
and the fixed-hardware performance runs are available.
