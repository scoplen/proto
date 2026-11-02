# Local ssh-key patch

This directory retains the runtime source, normalized package manifest, README and both licenses
from the crates.io `ssh-key` 0.7.0-rc.11 package published by RustCrypto Developers under
`Apache-2.0 OR MIT`. The upstream repository is <https://github.com/RustCrypto/SSH>; the package's
recorded source revision is `7a1c757d2e2fcde32680e373d5226481de6d434e`, path `ssh-key`.
The downloaded package SHA-256 is
`f9a32fae177b74a22aa9c5b01bf7e68b33545be32d9e381e248058d2adc15ce3`.

`src/private/ecdsa.rs` removes the decoder's 32-byte lower bound on nonempty ECDSA scalar
`mpint` values. OpenSSH omits leading zero bytes; a valid P-256 scalar may therefore occupy
31 bytes or fewer. The existing fixed-width left padding, maximum width and leading sign-byte
handling remain in place. No other runtime source is changed.

The manifest omits upstream integration-test targets and development-only dependencies because
those files are not vendored. The package is excluded from the Scoplen workspace's member tests;
regression coverage instead imports complete OpenSSH files and signs SSH authentication requests
through the public APIs in `crates/scoplen-ssh/tests/ecdsa_auth.rs`.

The workspace and fuzz workspace apply this patch separately. Downstream workspaces must also
select this source explicitly because Cargo does not inherit dependency patches. Remove this
directory and those patch entries when a published compatible release accepts the same valid
short scalars and passes the import/signing and OpenSSH interoperability regressions.
