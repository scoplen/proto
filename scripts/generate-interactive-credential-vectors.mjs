// SPDX-License-Identifier: Apache-2.0
// Independent finite CBOR producer for D-123 model acceptance and rejection inputs.
import { readFileSync, writeFileSync } from "node:fs";

function head(major, value) {
  if (value < 24) return Buffer.from([(major << 5) | value]);
  const size = value <= 255 ? 1 : value <= 65535 ? 2 : 4;
  const bytes = Buffer.alloc(size + 1);
  bytes[0] = (major << 5) | { 1: 24, 2: 25, 4: 26 }[size];
  bytes.writeUIntBE(value, 1, size);
  return bytes;
}

function cbor(value) {
  if (value === null) return Buffer.from([0xf6]);
  if (typeof value === "number") return head(0, value);
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value]);
  if (typeof value === "string") {
    const bytes = Buffer.from(value);
    return Buffer.concat([head(3, bytes.length), bytes]);
  }
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(cbor)]);
  const pairs = [...value].map(([key, item]) => [cbor(key), cbor(item)]);
  pairs.sort((left, right) => Buffer.compare(left[0], right[0]));
  return Buffer.concat([head(5, pairs.length), ...pairs.flat()]);
}

function uuid(seed) {
  const bytes = Buffer.alloc(16);
  bytes[0] = seed;
  bytes[6] = 0x70;
  bytes[8] = 0x80;
  return bytes;
}

const entry = (value) => [value, 65536, uuid(2)];
const credential = (binding = 3, additional = []) => new Map([
  [1, uuid(1)], [2, 3], [3, 1],
  [4, new Map([[1, entry("Interactive login")], [2, entry(8)], [3, entry(binding)], ...additional])],
]);
const vector = (name, object, valid) => {
  const input = cbor(object).toString("hex");
  return { id: `interactive-credential-${name}`, kind: valid ? "model.object" : "model.object-invalid", input, expected: valid ? input : "invalid-fields" };
};
const vectors = [
  vector("valid", credential(), true),
  vector("cleared-fields", credential(3, [4, 6, 8].map((field) => [field, entry(null)]).concat([[[5, uuid(3)], entry(null)], [[7, "type"], entry(null)]])), true),
  vector("unknown-field", credential(3, [[99, entry("future")]]), true),
  vector("shared-binding", credential(1), false),
  vector("device-binding", credential(2), false),
  vector("secret", credential(3, [[4, entry(Buffer.from("synthetic"))]]), false),
  vector("device-entry", credential(3, [[[5, uuid(3)], entry(new Map([[1, "ssh-ed25519 synthetic"], [2, "test"]]))]]), false),
  vector("public-key", credential(3, [[6, entry("ssh-ed25519 synthetic")]]), false),
  vector("provider", credential(3, [[[7, "type"], entry("command")]]), false),
  vector("certificate-scope", credential(3, [[8, entry(uuid(4))]]), false),
];
const output = `${JSON.stringify({ format: "scoplen-test-vectors", version: 1, vectors }, null, 2)}\n`;
const destination = new URL("../vectors/interactive-credential.json", import.meta.url);
if (process.argv.includes("--check")) {
  if (readFileSync(destination, "utf8") !== output) throw new Error("interactive credential vectors have drifted");
} else {
  writeFileSync(destination, output);
}
for (const item of vectors) {
  const seed = new URL(`../fuzz/corpus/object_decoder/seed-${item.id}`, import.meta.url);
  const bytes = Buffer.from(item.input, "hex");
  if (process.argv.includes("--check")) {
    if (!readFileSync(seed).equals(bytes)) throw new Error(`object seed has drifted: ${item.id}`);
  } else {
    writeFileSync(seed, bytes);
  }
}
