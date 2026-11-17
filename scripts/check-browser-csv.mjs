// SPDX-License-Identifier: Apache-2.0
// Calls the production web-target bindings in Node without launching a browser.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { initSync, parseInventoryCsv } from "../crates/scoplen-browser/pkg/scoplen_browser.js";

const crate = new URL("../crates/scoplen-browser/", import.meta.url);
const build = JSON.parse(await readFile(new URL("pkg/build.json", crate), "utf8"));
for (const [name, expected] of Object.entries(build.assets)) {
  assert.ok(!name.includes("/") && !name.includes("\\"));
  const bytes = await readFile(new URL(`pkg/${name}`, crate));
  assert.equal(bytes.length, expected.bytes);
  assert.equal(createHash("sha256").update(bytes).digest("hex"), expected.sha256);
}
initSync({ module: await readFile(new URL("pkg/scoplen_browser_bg.wasm", crate)) });
const { vectors } = JSON.parse(await readFile(new URL("../vectors/organization-inventory-import.json", import.meta.url), "utf8"));
let count = 0;
for (const vector of vectors.filter(vector => vector.kind === "inventory.import.csv")) {
  let actual;
  try { actual = parseInventoryCsv(Buffer.from(vector.input, "hex")); }
  catch (error) { actual = String(error); }
  assert.equal(actual, vector.expected, vector.id);
  count += 1;
}
assert.ok(count > 30);
const declarations = await readFile(new URL("pkg/scoplen_browser.d.ts", crate), "utf8");
assert.match(declarations, /parseInventoryCsv\(input: Uint8Array\): string/);
console.log(`Production WebAssembly CSV export passed ${count} independent vectors in Node; no browser interaction verified.`);
