# SSH Single-Channel Throughput Comparison

## Purpose

`10-protocol-core.md` §8 requires at least 80% of OpenSSH's single-channel throughput on the
same hardware for `chacha20-poly1305@openssh.com` and `aes256-gcm@openssh.com`. Run the paired
comparison from the repository root:

```powershell
pwsh ./scripts/ssh-throughput.ps1
```

The script needs PowerShell 7, Docker with a running Linux daemon, `ssh`, `ssh-keygen`, Rust
1.85.0, and network access to the Alpine package repository. It builds the comparison example in
release mode. `-BytesMiB` (16–1024, default 256), `-Samples` (3–20, default 5), and `-Image`
(default `alpine:3.21`) are optional. For a repeat with the same base image, pass the recorded
repository digest to `-Image`. The script pins Alpine's `openssh-server` package to
`9.9_p2-r0`; it fails rather than silently changing the server version if that package becomes
unavailable. It removes the temporary private key, host pin, and containers on success or failure.

## Method

For each cipher, a disposable OpenSSH server listens on a random loopback port and offers only
that cipher. Both local clients use the same Ed25519 user key and pin the same generated Ed25519
host key. They use one SSH session channel, no PTY, and no compression. The server command writes
exactly the configured number of bytes from `/dev/zero` with 64 KiB `dd` blocks. The comparison
program reads each client's stdout through the same 64 KiB pipe sink, checks that all bytes are
zero, requires the exact byte count and a successful exit status, and times from the first data
byte to the last. Connection, authentication, and remote-command startup are excluded from the
timed interval. A 120-second bound prevents a stalled trial from hanging the comparison.

One warmup per client is discarded. The clients then alternate order for each paired sample.
Each client's median MiB/s is computed independently; the reported percentage is
`100 × median(Scoplen) / median(OpenSSH)` for that cipher. The script prints the host OS and CPU,
both OpenSSH versions, image ID, code revision, per-sample times, medians, and whether the local
ratio reaches 80%.

The stdout pipe and zero-byte scan are shared measurement costs. The disposable server, Docker
networking, host scheduler, and thermal state can affect either side. This local comparison is
reproducible evidence for one machine; the fixed-hardware, dedicated benchmark jobs and
regression tracking required by `13-testing-and-quality.md` §2 and §7 remain open.

## Windows run, 2026-10-18

- Host: Windows 10.0.26200, AMD Ryzen 9 7945HX, Rust 1.85.0.
- OpenSSH client: OpenSSH for Windows 9.5p2. Server: OpenSSH 9.9p2, OpenSSL 3.3.7.
- Base image ID: `sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507`.
- Source revision: `scoplen-proto@b893d03` plus the comparison code in this change.
- Transfer: 256 MiB per trial; one warmup and five retained samples for each client and cipher.

| Server cipher | OpenSSH median | Scoplen median | Scoplen / OpenSSH |
|---|---:|---:|---:|
| `chacha20-poly1305@openssh.com` | 110.12 MiB/s | 122.66 MiB/s | 111.39% |
| `aes256-gcm@openssh.com` | 126.77 MiB/s | 127.37 MiB/s | 100.48% |

The retained samples varied substantially: OpenSSH ranged from 69.73 to 147.83 MiB/s and
Scoplen from 40.41 to 137.89 MiB/s for ChaCha20; OpenSSH ranged from 63.28 to 142.45 MiB/s and
Scoplen from 89.62 to 162.92 MiB/s for AES-GCM. The first warmup was especially slow after the
container started. These medians exceed 80% on this host, but the variance prevents treating this
run as the release performance gate or as evidence for other hosts.
