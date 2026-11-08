// SPDX-License-Identifier: Apache-2.0
// Independent D-141 JSON/CBOR problem producer; no Rust implementation is loaded.
import { readFile, writeFile } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const prefix = "api-problem-certificate-";
const cases = [
  ["revoked", 409, "Certificate revoked", "The original certificate was revoked. No new certificate was issued. Review access and start a new connection explicitly; replaying this request will not restore it."],
  ["quota_exceeded", 413, "Certificate quota exceeded", "No certificate was issued. Wait for existing certificates to expire before starting a new connection; do not automatically replay this request."],
];

function head(major, value) {
  if (value < 24) return Buffer.from([(major << 5) | value]);
  if (value <= 255) return Buffer.from([(major << 5) | 24, value]);
  const result = Buffer.alloc(3);
  result[0] = (major << 5) | 25;
  result.writeUInt16BE(value, 1);
  return result;
}
function cbor(value) {
  if (typeof value === "boolean") return Buffer.from([value ? 0xf5 : 0xf4]);
  if (typeof value === "number") return head(0, value);
  if (typeof value === "string") {
    const bytes = Buffer.from(value);
    return Buffer.concat([head(3, bytes.length), bytes]);
  }
  const pairs = Object.entries(value).map(([key, item]) => [cbor(key), cbor(item)])
    .sort(([a], [b]) => Buffer.compare(a, b));
  return Buffer.concat([head(5, pairs.length), ...pairs.flat()]);
}

const vectors = [];
const outputs = [];
for (const [name, status, title, detail] of cases) {
  const id = `${prefix}${name.replaceAll("_", "-")}`;
  const problem = { type: "about:blank", title, status, detail, instance: `${name}-1`, code: `certificate.${name}`, changed: false, retryable: false };
  const input = JSON.stringify(problem);
  const bytes = cbor(problem);
  vectors.push({ id: `${id}-json`, kind: "api.problem.json", input, expected: input });
  vectors.push({ id: `${id}-cbor`, kind: "api.problem.cbor", input, expected: bytes.toString("hex") });
  outputs.push([`fuzz/corpus/api_json/seed-${id}-json`, Buffer.from(input)]);
  outputs.push([`fuzz/corpus/sync_data/seed-16-${id}-cbor`, Buffer.concat([Buffer.from([16]), bytes])]);
}
const vectorPath = new URL("vectors/api-problem.json", root);
const existing = JSON.parse(await readFile(vectorPath, "utf8"));
const ownedIds = new Set(vectors.map(vector => vector.id));
const expected = { ...existing, vectors: [...existing.vectors.filter(vector => !ownedIds.has(vector.id)), ...vectors] };
outputs.push(["vectors/api-problem.json", Buffer.from(JSON.stringify(expected, null, 2) + "\n")]);
for (const [path, bytes] of outputs) {
  const url = new URL(path, root);
  if (process.argv.includes("--check")) {
    const actual = await readFile(url);
    const normalized = path.endsWith(".json") ? Buffer.from(actual.toString().replaceAll("\r\n", "\n")) : actual;
    if (!normalized.equals(bytes)) throw new Error(`D-141 problem output is stale: ${path}`);
  } else await writeFile(url, bytes);
}
console.log("validated four certificate problem vectors and four parser seeds");
