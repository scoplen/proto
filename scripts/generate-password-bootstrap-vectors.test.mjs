// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { derive, fixtureInput, normalize, selfTest } from "./generate-password-bootstrap-vectors.mjs";

test("independent Argon2id v19 and HChaCha20 match published answers", selfTest);

test("normalization preserves raw scalars, case, NUL, BOM and spaces with strict UTF-8", () => {
  assert.equal(normalize(Buffer.from("  Cafe\u0301 and A\0Z  ")).toString(), "  Café and A\0Z  ");
  assert.equal(normalize(Buffer.from("\ufeff" + "Ａ".repeat(15))).toString(), "\ufeff" + "Ａ".repeat(15));
  for (const bytes of [Buffer.from([0xed, 0xa0, 0x80]), Buffer.from([0xc0, 0x80]), Buffer.alloc(2049, 97)]) {
    assert.throws(() => normalize(bytes));
  }
});

test("HKDF labels and exact origin/username/salt separate both outputs", () => {
  const input = fixtureInput();
  const original = derive(input);
  assert.notEqual(original.auth_secret, original.kek);
  for (const changed of [
    { ...input, origin: "https://other.example.com" },
    { ...input, username: "alice.changed" },
    { ...input, salt: "03".repeat(16) },
  ]) {
    const answer = derive(changed);
    assert.notEqual(answer.auth_secret, original.auth_secret);
    assert.notEqual(answer.kek, original.kek);
    assert.notEqual(answer.verifier, original.verifier);
    assert.notEqual(answer.envelope, original.envelope);
    if (changed.salt === input.salt) assert.equal(answer.material, original.material);
  }
  assert.deepEqual(derive({ ...input, password_hex: original.normalized }), original);
});

test("generator detects vector drift and exact binary seeds across checkout newlines", async () => {
  const parent = resolve(tmpdir());
  const root = await mkdtemp(join(parent, "scoplen-password-vectors-"));
  assert.equal(dirname(root), parent);
  try {
    await mkdir(join(root, "scripts"));
    const script = "scripts/generate-password-bootstrap-vectors.mjs";
    await copyFile(new URL(script, new URL("../", import.meta.url)), join(root, script));
    const run = (...args) => spawnSync(process.execPath, [join(root, script), ...args], {
      cwd: root, encoding: "utf8", timeout: 30_000,
    });
    let result = run();
    assert.equal(result.status, 0, result.stderr);
    const json = join(root, "vectors/password-bootstrap.json");
    const original = await readFile(json, "utf8");
    await writeFile(json, original.replaceAll("\n", "\r\n"));
    result = run("--check");
    assert.equal(result.status, 0, result.stderr);
    await writeFile(json, original.replace("password-bootstrap-known-answer", "changed-known-answer"));
    result = run("--check");
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /D-127 output is stale: vectors\/password-bootstrap.json/);
    await writeFile(json, original);
    const seed = join(root, "fuzz/corpus/crypto_decoders/seed-password-envelope");
    await writeFile(seed, Buffer.concat([await readFile(seed), Buffer.from("\r\n")]));
    result = run("--check");
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /D-127 output is stale: fuzz\/corpus\/crypto_decoders\/seed-password-envelope/);
    result = run("--unknown");
    assert.notEqual(result.status, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("generator CLI runs through a directory symlink", async () => {
  const parent = resolve(tmpdir());
  const owned = await mkdtemp(join(parent, "scoplen-password-link-"));
  assert.equal(dirname(owned), parent);
  try {
    const physical = join(owned, "physical");
    const linked = join(owned, "linked");
    const script = "scripts/generate-password-bootstrap-vectors.mjs";
    await mkdir(join(physical, "scripts"), { recursive: true });
    await copyFile(new URL(script, new URL("../", import.meta.url)), join(physical, script));
    await symlink(physical, linked, process.platform === "win32" ? "junction" : "dir");
    const run = (...args) => spawnSync(process.execPath, [join(linked, script), ...args], {
      cwd: owned, encoding: "utf8", timeout: 30_000,
    });
    let result = run();
    assert.equal(result.status, 0, result.stderr);
    const json = join(physical, "vectors/password-bootstrap.json");
    assert.match(await readFile(json, "utf8"), /password-bootstrap-known-answer/);
    result = run("--check");
    assert.equal(result.status, 0, result.stderr);
    result = run("--unknown");
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /expected only --check/);
  } finally {
    await rm(owned, { recursive: true, force: true });
  }
});
