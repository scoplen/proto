// SPDX-License-Identifier: Apache-2.0
// Independent D-141 OpenSSH wire writer; it does not read Rust or generated schemas.
import { readFile, realpath, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const root = new URL("../", import.meta.url);
export const u32 = value => { const out = Buffer.alloc(4); out.writeUInt32BE(value); return out; };
export const u64 = value => { const out = Buffer.alloc(8); out.writeBigUInt64BE(BigInt(value)); return out; };
export const sshString = bytes => Buffer.concat([u32(bytes.length), bytes]);
const caBlob = hex => Buffer.concat([sshString(Buffer.from("ssh-ed25519")), sshString(Buffer.from(hex, "hex"))]);
// RFC 8032 section 7.1 test 1 and test 2 public keys, wrapped as RFC 4253 key blobs.
const ca = caBlob("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
const foreignCa = caBlob("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
export const PUBLIC_CA = `ssh-ed25519 ${ca.toString("base64")}`;
const publicForeignCa = `ssh-ed25519 ${foreignCa.toString("base64")}`;

// Deliberately permits invalid profile values so rejection vectors have an independent writer.
export function encodeKrl({ ca_public_key = PUBLIC_CA, version = "1", generated_at_seconds = "1762646400", serials = [] }) {
  const header = Buffer.concat([Buffer.from("SSHKRL\n\0"), u32(1), u64(version), u64(generated_at_seconds), u64(0), u32(0), u32(0)]);
  if (!serials.length) return header;
  const key = Buffer.from(ca_public_key.split(" ")[1], "base64");
  const subsection = Buffer.concat([Buffer.from([0x20]), sshString(Buffer.concat(serials.map(u64)))]);
  return Buffer.concat([header, Buffer.from([1]), sshString(Buffer.concat([sshString(key), u32(0), subsection]))]);
}

export function krlVectors() {
  const vectors = [];
  const add = (name, kind, input, expected = "rejected") => vectors.push({ id: `user-ca-krl-${name}-v1`, kind: `user_ca.krl.${kind}`, input: JSON.stringify(input), expected });
  const fixture = overrides => ({ ca_public_key: PUBLIC_CA, version: "1", generated_at_seconds: "1762646400", serials: [], ...overrides });
  const base = encodeKrl(fixture({ serials: ["1", "256", "18446744073709551615"] }));
  const changed = (position, bytes) => { const out = Buffer.from(base); bytes.copy(out, position); return out; };
  const reject = (name, bytes, key = PUBLIC_CA) => add(name, "reject", { ca_public_key: key, hex: bytes.toString("hex") });
  for (const [name, recipe] of [
    ["empty", fixture({})],
    ["one", fixture({ serials: ["1"] })],
    ["discrete", fixture({ serials: ["1", "256", "18446744073709551615"] })],
    ["uint64-header", fixture({ version: "18446744073709551615", generated_at_seconds: "18446744073709551615", serials: ["18446744073709551615"] })],
    ["epoch-zero", fixture({ generated_at_seconds: "0" })],
    ["foreign-empty-binding", fixture({ ca_public_key: publicForeignCa })],
  ]) add(name, "bytes", recipe, encodeKrl(recipe).toString("hex"));
  for (const [name, bytes] of [
    ["magic", changed(0, Buffer.from([0]))], ["format", changed(8, u32(2))],
    ["zero-version", changed(12, u64(0))], ["flags", changed(28, u64(1))],
    ["reserved", Buffer.concat([base.subarray(0, 36), sshString(Buffer.from("x")), base.subarray(40)])],
    ["comment", Buffer.concat([base.subarray(0, 40), sshString(Buffer.from("x")), base.subarray(44)])],
    ["section-length-small", changed(45, u32(base.length - 50))],
    ["section-length-large", changed(45, u32(base.length - 48))],
    ["section-length-u32-max", changed(45, u32(0xffffffff))],
    ["ca-length", changed(49, u32(50))], ["ca-wildcard", Buffer.concat([base.subarray(0, 45), u32(base.length - 100), u32(0), base.subarray(104)])],
    ["section-reserved", changed(104, u32(1))], ["serial-length", changed(109, u32(23))],
    ["serial-zero", encodeKrl(fixture({ serials: ["0"] }))],
    ["serial-duplicate", encodeKrl(fixture({ serials: ["1", "1"] }))],
    ["serial-descending", encodeKrl(fixture({ serials: ["2", "1"] }))],
    ["empty-subsection", Buffer.concat([base.subarray(0, 45), u32(64), base.subarray(49, 109), u32(0)])],
    ["duplicate-section", Buffer.concat([base, base.subarray(44)])],
    ["duplicate-subsection", Buffer.concat([base.subarray(0, 45), u32(base.length - 49 + base.length - 108), base.subarray(49), base.subarray(108)])],
    ["trailing", Buffer.concat([base, Buffer.from([0])])],
  ]) reject(name, bytes);
  for (const kind of [2, 3, 4, 5, 255]) reject(`outer-${kind}`, changed(44, Buffer.from([kind])));
  for (const kind of [0x21, 0x22, 0x23, 0x39]) reject(`subsection-${kind}`, changed(108, Buffer.from([kind])));
  for (const length of [0, 7, 8, 11, 19, 27, 35, 39, 43, 44, 48, 52, 103, 107, 108, 112, base.length - 1]) {
    if (length !== 44) reject(`truncated-${length}`, base.subarray(0, length));
  }
  reject("wrong-ca", base, publicForeignCa);
  for (const [name, key] of [
    ["comment", `${PUBLIC_CA} fixture`], ["newline", `${PUBLIC_CA}\n`], ["space", PUBLIC_CA.replace(" ", "  ")],
    ["algorithm", PUBLIC_CA.replace("ssh-ed25519", "ssh-rsa")], ["invalid", "ssh-ed25519 invalid"],
  ]) {
    reject(`expected-ca-${name}`, base, key);
    reject(`empty-expected-ca-${name}`, encodeKrl(fixture({})), key);
  }
  for (const count of [100000, 100001]) add(`count-${count}`, "bound", { ca_public_key: PUBLIC_CA, count }, count === 100000 ? "accepted" : "too-many-serials");
  for (const bytes of [4194304, 4194305]) add(`bytes-${bytes}`, "bound", { ca_public_key: PUBLIC_CA, bytes }, bytes === 4194304 ? "invalid-format" : "input-too-large");
  return vectors;
}

async function main() {
  const vectors = krlVectors();
  const outputs = [["vectors/user-ca-krl.json", Buffer.from(JSON.stringify({ format: "scoplen-test-vectors", version: 1, vectors }, null, 2) + "\n")]];
  for (const vector of vectors.filter(vector => vector.kind !== "user_ca.krl.bound")) {
    const recipe = JSON.parse(vector.input);
    const bytes = vector.kind === "user_ca.krl.bytes" ? Buffer.from(vector.expected, "hex") : Buffer.from(recipe.hex, "hex");
    outputs.push([`fuzz/corpus/api_json/seed-${vector.id}`, bytes]);
  }
  for (const [path, expected] of outputs) {
    const url = new URL(path, root);
    if (process.argv.includes("--check")) {
      const actual = await readFile(url);
      const equal = path.endsWith(".json") ? actual.toString("utf8").replaceAll("\r\n", "\n") === expected.toString("utf8") : actual.equals(expected);
      if (!equal) throw new Error(`D-141 KRL output stale: ${path}`);
    } else await writeFile(url, expected);
  }
  console.log(`validated ${vectors.length} D-141 KRL vectors and ${outputs.length - 1} raw parser seeds`);
}

if (process.argv[1]
  && await realpath(process.argv[1]) === await realpath(fileURLToPath(import.meta.url))) {
  await main();
}
