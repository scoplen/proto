// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";

test("certificate problem generation preserves existing D-88 vectors with the same prefix", async () => {
  const parent = resolve(tmpdir());
  const root = await mkdtemp(join(parent, "scoplen-certificate-problems-"));
  try {
    for (const directory of ["scripts", "vectors", "fuzz/corpus/api_json", "fuzz/corpus/sync_data"]) {
      await mkdir(join(root, directory), { recursive: true });
    }
    const script = "scripts/generate-certificate-problem-vectors.mjs";
    await copyFile(new URL(script, new URL("../", import.meta.url)), join(root, script));
    const old = [
      { id: "api-problem-certificate-invalid-request-json", kind: "api.problem.json", input: "fixture-original", expected: "fixture-original" },
      { id: "api-problem-certificate-request-too-large-json", kind: "api.problem.json", input: "second-original", expected: "second-original" },
    ];
    const path = join(root, "vectors/api-problem.json");
    await writeFile(path, JSON.stringify({ format: "scoplen-test-vectors", version: 1, vectors: old }));
    const run = (...args) => spawnSync(process.execPath, [join(root, script), ...args], { cwd: root, encoding: "utf8", timeout: 15000 });
    let result = run();
    assert.equal(result.status, 0, result.stderr);
    const generated = JSON.parse(await readFile(path, "utf8"));
    assert.equal(generated.vectors.length, 6);
    assert.deepEqual(generated.vectors.slice(0, 2), old);
    result = run("--check");
    assert.equal(result.status, 0, result.stderr);
    result = run();
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(await readFile(path, "utf8")), generated);
    generated.vectors.find(vector => vector.id === "api-problem-certificate-revoked-json").expected = "drift";
    await writeFile(path, JSON.stringify(generated));
    result = run("--check");
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /D-141 problem output is stale/);
  } finally {
    assert.equal(dirname(resolve(root)), parent);
    assert.ok(root.startsWith(join(parent, "scoplen-certificate-problems-")));
    await rm(root, { recursive: true, force: true });
  }
});
