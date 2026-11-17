// SPDX-License-Identifier: Apache-2.0
// All plaintext and passphrases below are public synthetic test data; pipes stay in memory.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const reference = fileURLToPath(new URL("./portable-age-reference/", import.meta.url));
const vectorsFile = new URL("../vectors/portable-age.json", import.meta.url);
const passphrase = "\tD-142 synthetic e\u0301\0\u5bc6\n";

function invoke(command, args, input, cwd = root) {
  const result = spawnSync(command, args, {
    cwd,
    input,
    maxBuffer: 16 * 1024 * 1024,
    windowsHide: true,
  });
  if (result.error || result.status !== 0) {
    // Build diagnostics and fixed helper errors do not include the pipe's payload.
    process.stderr.write(result.stderr ?? "");
    throw new Error(
      `portable-age ${command} operation failed: status=${result.status}, ` +
      `signal=${result.signal}, spawn=${result.error?.code ?? "none"}`,
    );
  }
  return result.stdout;
}

function go(operation, input) {
  return invoke("go", ["run", "-mod=readonly", ".", operation], input, reference);
}

const mode = process.argv.slice(2);
assert.ok(
  mode.length === 0 ||
    (mode.length === 1 && ["--write-vectors", "--check-vectors"].includes(mode[0])),
  "unsupported portable-age check option",
);

if (mode[0] === "--write-vectors") {
  const bytes = go("vectors");
  const document = JSON.parse(bytes);
  assert.equal(document.format, "scoplen-test-vectors");
  assert.equal(document.version, 1);
  assert.equal(document.vectors.length, 3);
  writeFileSync(vectorsFile, bytes);
  console.log("Generated 3 independent standard age fixtures.");
} else {
  const document = JSON.parse(readFileSync(vectorsFile, "utf8"));
  assert.equal(document.format, "scoplen-test-vectors");
  assert.equal(document.version, 1);
  assert.equal(document.vectors.length, 3);
  for (const vector of document.vectors) {
    assert.equal(vector.kind, "crypto.portable-age.decrypt");
    const input = JSON.parse(vector.input);
    assert.equal(input.passphrase, passphrase);
    const actual = go("decrypt", Buffer.from(input.ciphertext_base64, "base64"));
    assert.ok(actual.equals(Buffer.from(vector.expected, "base64")), "age fixture mismatch");
  }
  console.log("Checked 3 standard Go age fixtures.");

  if (mode.length === 0) {
    // age calibrates its cost bound at runtime; interop must measure optimized production code.
    const artifacts = invoke("cargo", [
      "build", "--release", "--locked", "-p", "scoplen-crypto", "--features", "portable-export",
      "--example", "portable_age_interop", "--message-format=json",
    ]).toString("utf8").trim().split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
    const executable = artifacts.findLast((artifact) =>
      artifact.reason === "compiler-artifact" && artifact.target?.name === "portable_age_interop" &&
      artifact.executable)?.executable;
    assert.equal(typeof executable, "string", "missing portable-age test executable");

    for (const size of [0, 17, 131_089]) {
      const plaintext = Buffer.alloc(size);
      for (let index = 0; index < size; index++) plaintext[index] = index % 251;
      const fromGo = go("encrypt", plaintext);
      assert.ok(invoke(executable, ["decrypt"], fromGo).equals(plaintext), "Go to Rust mismatch");
      const fromRust = invoke(executable, ["encrypt"], plaintext);
      assert.ok(go("decrypt", fromRust).equals(plaintext), "Rust to Go mismatch");
      for (const encrypted of [fromGo, fromRust]) {
        const corrupt = Buffer.from(encrypted);
        corrupt[corrupt.length - 1] ^= 1;
        for (const broken of [corrupt, encrypted.subarray(0, encrypted.length - 1)]) {
          const rustResult = spawnSync(executable, ["decrypt"], {
            input: broken, maxBuffer: 1024 * 1024, windowsHide: true,
          });
          assert.equal(rustResult.status, 1, "Rust accepted a broken age final chunk");
          const goResult = spawnSync("go", ["run", "-mod=readonly", ".", "decrypt"], {
            cwd: reference, input: broken, maxBuffer: 1024 * 1024, windowsHide: true,
          });
          assert.equal(goResult.status, 1, "Go accepted a broken age final chunk");
        }
      }
    }
    console.log("Passed standard age interoperability in both directions for 3 payload sizes; rejected tampered and truncated final chunks.");
  }
}
