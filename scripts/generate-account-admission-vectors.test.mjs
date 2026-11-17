// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import test from "node:test";

test("D-128/D-152 independent producer retains proofs and checks exact fixture bytes", async () => {
  const root = await mkdtemp(join(tmpdir(), "scoplen-account-entry-"));
  try {
    for (const directory of ["scripts", "vectors", "fuzz/corpus/api_json"]) await mkdir(join(root, directory), { recursive: true });
    const script = "scripts/generate-account-admission-vectors.mjs";
    for (const path of [script, "vectors/account-hierarchy.json", "vectors/crypto.json", "vectors/account-admission.json"]) {
      await copyFile(new URL(path, new URL("../", import.meta.url)), join(root, path));
    }
    const run = (...args) => spawnSync(process.execPath, [join(root, script), ...args], { encoding: "utf8", timeout: 15000 });
    const file = join(root, "vectors/account-admission.json");
    const initial = JSON.parse(await readFile(file, "utf8"));
    let result = run();
    assert.equal(result.status, 0, result.stderr);
    const original = await readFile(file, "utf8");
    const { vectors } = JSON.parse(original);
    assert.deepEqual(JSON.parse(original), initial);
    assert.equal(new Set(vectors.map(vector => vector.id)).size, vectors.length);
    assert.equal(vectors.length, 102);
    const proofs = vectors.filter(vector => vector.kind === "account.admission.proof");
    assert.equal(proofs.length, 6);
    const changeProofs = proofs.filter(vector => JSON.parse(vector.input).kind === "password_change");
    assert.equal(changeProofs.length, 2);
    const prefixBytes = Buffer.byteLength("spl-account-request-proof-v1");
    assert.deepEqual(changeProofs.map(vector => Buffer.from(vector.expected, "hex")[prefixBytes]), [3, 3]);
    assert.deepEqual(changeProofs.map(vector => Buffer.from(vector.expected, "hex")[prefixBytes + 1]), [1, 2]);
    result = run("--check");
    assert.equal(result.status, 0, result.stderr);
    await writeFile(file, original.replaceAll("\n", "\r\n"));
    result = run("--check");
    assert.equal(result.status, 0, result.stderr);
    const seed = join(root, "fuzz/corpus/api_json/seed-account-admission-password_change-protected");
    const bytes = await readFile(seed);
    await writeFile(seed, Buffer.concat([bytes, Buffer.from([0])]));
    result = run("--check");
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /stale: fuzz\/corpus\/api_json\/seed-account-admission-password_change-protected/);
    await writeFile(seed, bytes);
    for (const size of [16384, 16385]) assert.equal((await readFile(join(root, `fuzz/corpus/api_json/seed-account-password-change-complete-${size}`))).length, size);
    await writeFile(file, original + " ");
    result = run("--check");
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /stale: vectors\/account-admission.json/);
  } finally {
    assert.ok(resolve(root).startsWith(resolve(tmpdir()) + sep));
    await rm(root, { recursive: true, force: true });
  }
});
