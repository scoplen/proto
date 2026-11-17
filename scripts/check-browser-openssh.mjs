// SPDX-License-Identifier: Apache-2.0
// Calls the production web-target package in Node; never launches a browser.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { initSync, parseInventoryOpenSsh } from "../crates/scoplen-browser/pkg/scoplen_browser.js";
import { materialize } from "./generate-openssh-import-vectors.mjs";

const { values } = parseArgs({ options: { "source-revision": { type: "string" }, "require-archive": { type: "boolean" } } });
const crate = new URL("../crates/scoplen-browser/", import.meta.url);
const build = JSON.parse(await readFile(new URL("pkg/build.json", crate), "utf8"));
const pins = JSON.parse(await readFile(new URL("toolchain.json", crate), "utf8"));
for (const [key, value] of Object.entries(pins)) assert.equal(build[key], value);
assert.match(build.sourceRevision, /^[0-9a-f]{40}$/);
if (values["source-revision"]) assert.equal(build.sourceRevision, values["source-revision"]);
if (values["require-archive"]) {
  assert.equal(build.sourceKind, "archive");
  assert.equal(build.sourceDirty, null);
} else if (build.sourceKind === "git") assert.equal(build.sourceDirty, false);
for (const [name, expected] of Object.entries(build.assets)) {
  assert.ok(!name.includes("/") && !name.includes("\\"));
  const bytes = await readFile(new URL(`pkg/${name}`, crate));
  assert.equal(bytes.length, expected.bytes);
  assert.equal(createHash("sha256").update(bytes).digest("hex"), expected.sha256);
}
initSync({ module: await readFile(new URL("pkg/scoplen_browser_bg.wasm", crate)) });
const { vectors } = JSON.parse(await readFile(new URL("../vectors/openssh-inventory-import.json", import.meta.url), "utf8"));
for (const vector of vectors) {
  let actual;
  try { actual = parseInventoryOpenSsh(materialize(vector)); }
  catch (error) { actual = String(error); }
  assert.equal(actual, vector.expected, vector.id);
}
assert.ok(vectors.length > 130);
const declarations = await readFile(new URL("pkg/scoplen_browser.d.ts", crate), "utf8");
assert.match(declarations, /parseInventoryOpenSsh\(input: Uint8Array\): string/);
console.log(`Production WebAssembly OpenSSH export passed ${vectors.length} independent vectors in Node; source=${build.sourceKind}@${build.sourceRevision}; no browser interaction verified.`);
