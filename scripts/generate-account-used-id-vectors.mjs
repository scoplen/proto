// SPDX-License-Identifier: Apache-2.0
// Independent Node D-129 producer using synthetic UUIDs and built-in SHA-256.
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const cases = [
  ["account", "04000000-0000-7000-8000-000000000000"],
  ["adjacent", "04000000-0000-7000-8000-000000000001"],
  ["maximum-time", "ffffffff-ffff-7fff-bfff-ffffffffffff"],
  ["nil", "00000000-0000-0000-0000-000000000000"],
  ["v4", "018f35d4-1f8f-4e2a-9e56-7a5e8a9f1101"],
  ["v8", "018f35d4-1f8f-8e2a-9e56-7a5e8a9f1101"],
  ["variant", "018f35d4-1f8f-7e2a-7e56-7a5e8a9f1101"],
];
const vectors = cases.map(([name, input]) => ({
  id: `account-used-id-${name}`,
  kind: "account.used-id.digest",
  input,
  expected: /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(input)
    ? createHash("sha256").update(Buffer.from("spl-account-used-id-v1", "ascii"))
      .update(Buffer.from(input.replaceAll("-", ""), "hex")).digest("hex")
    : "rejected",
}));
const outputs = [["vectors/account-used-id.json", Buffer.from(`${JSON.stringify({ format: "scoplen-test-vectors", version: 1, vectors }, null, 2)}\n`)]];
for (const [name, id] of cases) outputs.push([`fuzz/corpus/crypto_decoders/seed-account-used-id-${name}`, Buffer.from(id)]);
for (const [path, expected] of outputs) {
  const url = new URL(path, root);
  if (process.argv.includes("--check")) {
    const actual = await readFile(url);
    const normalized = path.endsWith(".json") ? Buffer.from(actual.toString().replaceAll("\r\n", "\n")) : actual;
    if (!normalized.equals(expected)) throw new Error(`D-129 output is stale: ${path}`);
  } else await writeFile(url, expected);
}
console.log(`validated ${vectors.length} independent D-129 vectors and ${outputs.length - 1} UUID seeds`);
