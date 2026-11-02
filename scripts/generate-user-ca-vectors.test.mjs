// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import test from "node:test";

test("D-137 independent producer freezes public Ed25519 blob fingerprints and exact parser seeds", async () => {
  const parent = resolve(tmpdir());
  const root = await mkdtemp(join(parent, "scoplen-user-ca-vectors-"));
  try {
    for (const directory of ["scripts", "vectors", "fuzz/corpus/api_json"]) await mkdir(join(root, directory), { recursive: true });
    const script = "scripts/generate-user-ca-vectors.mjs";
    await copyFile(new URL(script, new URL("../", import.meta.url)), join(root, script));
    const run = (...args) => spawnSync(process.execPath, [join(root, script), ...args], { cwd: root, encoding: "utf8", timeout: 15000 });
    let result = run(); assert.equal(result.status, 0, result.stderr);
    const vectorPath = join(root, "vectors/user-ca.json");
    const text = await readFile(vectorPath, "utf8");
    const { vectors } = JSON.parse(text);
    assert.equal(vectors.length, 107);
    assert.equal(new Set(vectors.map(vector => vector.id)).size, vectors.length);
    const find = name => vectors.find(vector => vector.id === `user-ca-${name}-v1`);
    const resource = JSON.parse(find("resource").input);
    assert.equal(resource.data.public_key, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea");
    assert.equal(resource.data.fingerprint, "SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8");
    assert.deepEqual(JSON.parse(find("create").expected), { id: resource.id, data: { kind: "user", backend: "local" } });
    for (const name of ["resource-hash-line", "resource-hash-bare-key", "resource-fingerprint-padding", "resource-key-base64url", "create-data-unknown", "page-duplicate-id"]) assert.equal(find(name).expected, "rejected");
    for (const kind of ["create", "resource"]) for (const extra of [0, 1]) assert.equal((await readFile(join(root, `fuzz/corpus/api_json/seed-user-ca-${kind}-bound-${extra}`))).byteLength, 16384 + extra);
    for (const extra of [0, 1]) {
      const seed = await readFile(join(root, `fuzz/corpus/api_json/seed-user-ca-page-item-bound-${extra}`), "utf8");
      assert.deepEqual(JSON.parse(seed), { items: [resource], next_cursor: null });
      const rawItem = seed.slice('{"items":['.length, -'],"next_cursor":null}'.length);
      assert.equal(Buffer.byteLength(rawItem), 16384 + extra);
    }
    await writeFile(vectorPath, text.replaceAll("\n", "\r\n"));
    result = run("--check"); assert.equal(result.status, 0, result.stderr);
    await writeFile(vectorPath, text.replace("bbXpuKG6", "AbXpuKG6"));
    result = run("--check"); assert.notEqual(result.status, 0);
    assert.match(result.stderr, /D-137 user-CA output stale: vectors\/user-ca.json/);
    await writeFile(vectorPath, text);
    // Seed bytes remain exact even when a text checkout normalizes JSON line endings.
    const seed = join(root, "fuzz/corpus/api_json/seed-user-ca-resource-bound-0");
    await writeFile(seed, Buffer.concat([await readFile(seed), Buffer.from("\r\n")]));
    result = run("--check"); assert.notEqual(result.status, 0);
    assert.match(result.stderr, /D-137 user-CA output stale: fuzz\/corpus\/api_json\/seed-user-ca-resource-bound-0/);
  } finally {
    assert.ok(relative(parent, resolve(root)).startsWith("scoplen-user-ca-vectors-"));
    await rm(root, { recursive: true, force: true });
  }
});
