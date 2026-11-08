# scoplen-browser

Thin Rust/WebAssembly bindings for D-140 over the existing shared password, D-136 invitation
and D-137 simple-rule implementations. This package derives only the Account authentication
secret. It does not open Personal bootstrap material, export Account roots, enroll a Device or
run SSH. Rule generation retains the shared strict Cedar schema and reference validation.

## Build

The fixed tools are Rust **1.99.0**, target **wasm32-unknown-unknown** and **wasm-bindgen-cli
0.2.129**, matching the exact locked `wasm-bindgen` crate. Node **24** runs the build/check
scripts.

Clang and LLVM's `llvm-ar` must also be on `PATH`: the locked `psm` dependency archives its
precompiled WebAssembly stack-support object through those tools. On Debian/Ubuntu, install
`clang` and `llvm` alongside the normal native Rust build prerequisites. No CMake or WASI C
sysroot is needed for this target.

Install the target and CLI, then build from the proto repository root:

```text
rustup target add --toolchain 1.99.0 wasm32-unknown-unknown
cargo +1.99.0 install wasm-bindgen-cli --version 0.2.129 --locked
node scripts/build-browser.mjs
node scripts/check-browser.mjs
```

`WASM_BINDGEN` may name an installed matching CLI outside `PATH`.

The build script rejects a mismatched CLI or source pin, uses `cargo build --locked --release`,
and reads the configured target directory from Cargo metadata. Generated `pkg/` files are
ignored. They include web bindings, the actual `.wasm`, TypeScript declarations and a private
local `@scoplen/browser` package. `build.json` records tool pins, source revision, source kind,
Git dirty state when available, and generated asset sizes/hashes. It is build evidence, not a
source-authentication mechanism. Do not commit or publish the generated binaries/package.

## Consumer packaging

Build from the consumer's own exact published proto revision. A clean Git checkout records its
HEAD automatically. A consumer that freshly retrieves a source archive by its literal exact pin
must pass the same full lowercase revision:

```text
node scripts/build-browser.mjs --source-revision <full-published-proto-revision>
```

The archive caller owns retrieval and revision binding. Archive metadata has `sourceKind:
"archive"` and `sourceDirty: null`; it does not claim a Git cleanliness check. A Git checkout
rejects a declared revision different from HEAD. Consumers must check the expected revision and
tool pins, reject a dirty Git source, and package from that build's `pkg/`. Builds must work
without a sibling proto checkout or a developer worktree.

The generated package exports `.` with `scoplen_browser.d.ts`/`scoplen_browser.js` and
`./scoplen_browser_bg.wasm` with the module bytes. Keep initial locked package-manager
installation independent of these generated files. Run the consumer's pinned-source preparation
after dependency installation and before its Vite build. The console stages the resulting
package at `.browser/package` and uses Vite aliases for `@scoplen/browser` and its `.wasm`
subpath; a clean initial installation therefore needs no generated file dependency. With those
aliases in place, import the module as follows:

```ts
import init from '@scoplen/browser';
import wasmUrl from '@scoplen/browser/scoplen_browser_bg.wasm?url';

await init({ module_or_path: wasmUrl });
```

Serve `.wasm` as `application/wasm`. Package the module and dedicated Worker through the
consumer's existing bounded asset manifest. The Worker and module need same-origin script,
worker and fetch permissions plus `script-src 'wasm-unsafe-eval'`; broader evaluation or remote
asset permissions are unnecessary.

## Secret and failure boundary

`derivePasswordAuth` takes password UTF-8 bytes and writes a 32-byte authentication secret into
an explicitly owned `Uint8Array`. Rust validates UTF-8, NFC, password bounds and the fixed
Argon2id profile, while secret containers erase owned Rust buffers on drop. The private KEK
drops inside Rust. Secret output is copied directly to the provided JS buffer rather than
returned through an unzeroized wasm-bindgen byte-vector output.

The production consumer owns a one-use password Worker. Before `TextEncoder`, reject a JS
password string for which `isWellFormed()` is false; encoding otherwise silently replaces lone
surrogates. The Worker must send AuthSecret only in its same-origin login request, clear all
explicit password/authentication byte buffers in `finally`, and return only the bounded login
result. The UI clears its password field and always terminates the Worker, including on failure
or timeout. No secret enters general UI state, logs or browser storage. JavaScript strings,
DOM, compiler and platform copies have no reliable erasure guarantee.

The invitation exports reuse the exact shared CSPRNG, parser and context-bound verifier.
Password/verifier buffers and original request data belong only to the dedicated transient
invitation operation; consumers clear them on completion or discard. Reload loses pending
state and requires explicit review/revoke/recreate. Simple-rule generation accepts strict
shared JSON and grants no authority. Resource, RNG, Worker and input failures are terminal;
there is no weaker KDF, JavaScript crypto/template fallback or automatic password retry.

## Verification

```text
cargo test --locked -p scoplen-browser --test public_contract
cargo test --locked -p scoplen-api --no-default-features --lib
node scripts/build-browser.mjs
node scripts/check-browser.mjs
```

The native facade and packaged module use the public independent password, invitation and
simple-rule vectors. The browser check launches installed Chrome/Edge in a fresh headless
profile, imports the generated module in a one-use module Worker, and checks exact password and
NFC answers, context substitutions, malformed inputs, all invitation/simple-rule vectors,
real CSPRNG generation, injected RNG failure, real constrained-memory Argon2 allocation failure,
Worker failure and termination. It rejects browser console/runtime/network failures and cleans
its own temporary profile. Set `CHROME_BIN` when Chromium is outside its normal location.
`node scripts/check-browser.mjs --serve` exposes the same local fixture for manual browser runs.

These checks establish the shared adapter boundary. They do not establish the consumer's
production Worker, HTTPS login, CSP/asset packaging, refresh or UI acceptance; those remain
separate D-140 consumer checks. Native API users keep `internal-grpc` enabled by default; only
the browser dependency disables that transport feature.
