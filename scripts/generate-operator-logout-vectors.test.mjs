// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";

test("logout vector checks tolerate checkout newlines only in JSON", async () => {
  const parent = resolve(tmpdir());
  const root = await mkdtemp(join(parent, "scoplen-logout-vectors-"));
  assert.equal(dirname(root), parent);
  try {
    for (const directory of ["scripts", "vectors", "fuzz/corpus/api_json"]) {
      await mkdir(join(root, directory), { recursive: true });
    }
    const script = "scripts/generate-operator-logout-vectors.mjs";
    await copyFile(new URL(script, new URL("../", import.meta.url)), join(root, script));
    const run = (...args) => spawnSync(process.execPath, [join(root, script), ...args], {
      cwd: root, encoding: "utf8", timeout: 15_000,
    });
    let result = run();
    assert.equal(result.status, 0, result.stderr);
    const json = join(root, "vectors/operator-logout.json");
    await writeFile(json, (await readFile(json, "utf8")).replaceAll("\n", "\r\n"));
    result = run("--check");
    assert.equal(result.status, 0, result.stderr);
    const seed = join(root, "fuzz/corpus/api_json/seed-operator-logout-request-exact");
    await writeFile(seed, Buffer.concat([await readFile(seed), Buffer.from("\r\n")]));
    result = run("--check");
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /D-124 output is stale: fuzz\/corpus\/api_json\/seed-operator-logout-request-exact/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
