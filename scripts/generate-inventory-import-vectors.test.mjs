// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import test from "node:test";
test("D-151 independent producer is deterministic and checks drift/stale parser seeds", async () => {
  const root = await mkdtemp(join(tmpdir(), "scoplen-inventory-import-"));
  try {
    for (const directory of ["scripts", "vectors", "fuzz/corpus/api_json"]) await mkdir(join(root, directory), { recursive: true });
    const script = "scripts/generate-inventory-import-vectors.mjs";
    await copyFile(new URL(script, new URL("../", import.meta.url)), join(root, script));
    const run = (...args) => spawnSync(process.execPath, [join(root, script), ...args], { encoding: "utf8", timeout: 15000 });
    let result = run(); assert.equal(result.status, 0, result.stderr);
    const path = join(root, "vectors/organization-inventory-import.json");
    const original = await readFile(path, "utf8"); const { vectors } = JSON.parse(original);
    assert.equal(new Set(vectors.map(value => value.id)).size, vectors.length);
    assert.ok(vectors.length >= 70);
    for (const kind of ["csv", "request", "result", "binding", "bound"]) assert.ok(vectors.some(value => value.kind === `inventory.import.${kind}`));
    const utf8 = await readFile(join(root, "fuzz/corpus/api_json/seed-inventory-import-utf8-v1")); assert.deepEqual(utf8, Buffer.from([255]));
    result = run("--check"); assert.equal(result.status, 0, result.stderr);
    const stale = join(root, "fuzz/corpus/api_json/seed-inventory-import-stale"); await writeFile(stale, "{}");
    assert.notEqual(run("--check").status, 0); assert.equal(run().status, 0); await assert.rejects(readFile(stale), { code: "ENOENT" });
    await writeFile(path, original + " "); assert.notEqual(run("--check").status, 0);
  } finally {
    assert.ok(resolve(root).startsWith(resolve(tmpdir()) + sep)); await rm(root, { recursive: true, force: true });
  }
});
