// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import test from "node:test";

test("D-137 independent producer covers all typed routes, exact integers and K-1 answers", async () => {
  const root = await mkdtemp(join(tmpdir(), "scoplen-inventory-vectors-"));
  try {
    for (const directory of ["scripts", "vectors", "fuzz/corpus/api_json"]) await mkdir(join(root, directory), { recursive: true });
    const script = "scripts/generate-inventory-vectors.mjs";
    await copyFile(new URL(script, new URL("../", import.meta.url)), join(root, script));
    const run = (...args) => spawnSync(process.execPath, [join(root, script), ...args], { encoding: "utf8", timeout: 15000 });
    let result = run(); assert.equal(result.status, 0, result.stderr);
    const path = join(root, "vectors/organization-inventory.json");
    const text = await readFile(path, "utf8");
    const { vectors } = JSON.parse(text);
    assert.equal(new Set(vectors.map(v => v.id)).size, vectors.length);
    assert.equal(vectors.filter(v => v.kind === "inventory.model").length, 7);
    assert.equal(vectors.filter(v => v.kind === "inventory.bound").length, 42);
    for (const vector of vectors.filter(v => v.kind === "inventory.model")) {
      assert.match(vector.expected, /^a40150/);
      assert.equal(Buffer.from(vector.expected, "hex").toString("hex"), vector.expected);
    }
    const integer = vectors.find(v => v.id === "inventory-snippets-integer--9223372036854775808-v1");
    assert.equal(JSON.parse(integer.expected).variables.n.default, "-9223372036854775808");
    const timestamp = vectors.find(v => v.id === "inventory-trust-records-timestamp-valid-18446744073709551615-v1");
    assert.equal(JSON.parse(timestamp.expected).data.fields.accepted_at, "18446744073709551615");
    const empty = vectors.find(v => v.id === "inventory-hosts-empty-maps-v1");
    assert.deepEqual(Object.keys(JSON.parse(empty.expected)), ["address", "name"]);
    const seed = vectors.find(v => v.id === "inventory-hosts-create-whitespace-v1");
    assert.equal(await readFile(join(root, `fuzz/corpus/api_json/seed-${seed.id}`), "utf8"), JSON.parse(seed.input).json);
    result = run("--check"); assert.equal(result.status, 0, result.stderr);
    const staleSeed = join(root, "fuzz/corpus/api_json/seed-inventory-retired-v1");
    await writeFile(staleSeed, "{}");
    result = run("--check"); assert.notEqual(result.status, 0);
    assert.match(result.stderr, /D-137 inventory output stale/);
    result = run(); assert.equal(result.status, 0, result.stderr);
    await assert.rejects(readFile(staleSeed), { code: "ENOENT" });
    await writeFile(path, text.replace('"inventory-hosts-create-v1"', '"inventory-hosts-create-drift"'));
    result = run("--check"); assert.notEqual(result.status, 0);
    assert.match(result.stderr, /D-137 inventory output stale/);
  } finally {
    assert.ok(resolve(root).startsWith(resolve(tmpdir()) + sep));
    await rm(root, { recursive: true, force: true });
  }
});
