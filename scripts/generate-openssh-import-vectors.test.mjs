// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { document, materialize } from "./generate-openssh-import-vectors.mjs";

test("independent producer retains exact published answers and bounded-input recipes", async () => {
  const published = JSON.parse(await readFile(new URL("../vectors/openssh-inventory-import.json", import.meta.url), "utf8"));
  assert.deepEqual(published, document);
  assert.ok(document.vectors.length > 130);
  assert.equal(new Set(document.vectors.map(vector => vector.id)).size, document.vectors.length);
  assert.equal(new Set(document.vectors.map(vector => vector.id.toLowerCase())).size, document.vectors.length);
  for (const vector of document.vectors) {
    assert.ok(Buffer.isBuffer(materialize(vector)));
    const expected = JSON.parse(vector.expected);
    if (expected.candidates) {
      assert.ok(expected.candidates.length >= 1 && expected.candidates.length <= 100);
      for (const [index, candidate] of expected.candidates.entries()) {
        assert.equal(candidate.status === "ready" ? candidate.candidate : candidate.diagnostic.candidate, index + 1);
        if (candidate.status === "ready") assert.equal(candidate.fields.login_name, undefined);
        else assert.deepEqual(Object.keys(candidate.diagnostic).filter(key => !["kind", "line", "candidate", "field"].includes(key)), []);
      }
    } else assert.ok(["raw_too_large", "invalid_utf8", "invalid_syntax", "unsupported_scope", "no_candidates", "too_many_candidates"].includes(expected.kind));
  }
  execFileSync(process.execPath, [fileURLToPath(new URL("./generate-openssh-import-vectors.mjs", import.meta.url)), "--check"], { windowsHide: true });
});

test("producer contains no Rust/WASM/OpenSSH execution or production parsing", async () => {
  const source = await readFile(new URL("./generate-openssh-import-vectors.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(source, /child_process|scoplen_browser|parse_inventory|WebAssembly|\.wasm/);
});

test("isolated producer checks exact raw seeds and preserves neighboring producers", async () => {
  const owned = await mkdtemp(join(tmpdir(), "scoplen-openssh-producer-"));
  try {
    for (const path of ["scripts", "vectors", "fuzz/corpus/api_json"]) await mkdir(join(owned, path), { recursive: true });
    // An arbitrary entry name also proves execution does not depend on a filename spelling.
    const entry = join(owned, "scripts", "producer-entry.mjs");
    await copyFile(new URL("./generate-openssh-import-vectors.mjs", import.meta.url), entry);
    const neighbor = join(owned, "fuzz/corpus/api_json/seed-inventory-import-preserved");
    await writeFile(neighbor, "neighbor bytes");
    const run = (...args) => spawnSync(process.execPath, [entry, ...args], { encoding: "utf8", timeout: 15000, windowsHide: true });
    let result = run();
    assert.equal(result.status, 0, result.stderr);
    result = run("--check");
    assert.equal(result.status, 0, result.stderr);
    const path = join(owned, "vectors/openssh-inventory-import.json");
    const original = await readFile(path, "utf8");
    assert.deepEqual(JSON.parse(original), document);
    const alias = join(owned, "aliased-scripts");
    await symlink(join(owned, "scripts"), alias, process.platform === "win32" ? "junction" : "dir");
    await writeFile(path, "stale through aliased entry");
    const aliased = spawnSync(process.execPath, [join(alias, "producer-entry.mjs")], { encoding: "utf8", timeout: 15000, windowsHide: true });
    assert.equal(aliased.status, 0, aliased.stderr);
    assert.equal(await readFile(path, "utf8"), original);
    await writeFile(path, original.replaceAll("\n", "\r\n"));
    assert.equal(run("--check").status, 0);
    const seed = join(owned, "fuzz/corpus/api_json/seed-openssh-import-bom-crlf-v1");
    const raw = await readFile(seed);
    await writeFile(seed, raw.toString("utf8").replaceAll("\r\n", "\n"));
    assert.notEqual(run("--check").status, 0);
    assert.equal(run().status, 0);
    assert.deepEqual(await readFile(seed), raw);
    const stale = join(owned, "fuzz/corpus/api_json/seed-openssh-import-stale");
    await writeFile(stale, "stale");
    assert.notEqual(run("--check").status, 0);
    assert.equal(run().status, 0);
    await assert.rejects(readFile(stale), { code: "ENOENT" });
    assert.equal(await readFile(neighbor, "utf8"), "neighbor bytes");
    await writeFile(path, original + " ");
    assert.notEqual(run("--check").status, 0);
  } finally {
    assert.ok(resolve(owned).startsWith(resolve(tmpdir()) + sep));
    await rm(owned, { recursive: true, force: true });
  }
});
