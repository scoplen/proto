// SPDX-License-Identifier: Apache-2.0
// Independent D-127 producer: Node/OpenSSL Argon2id, HMAC/HKDF, and ChaCha20-Poly1305.
import assert from "node:assert/strict";
import {
  argon2Sync, createCipheriv, createHash, createHmac, createPrivateKey, createPublicKey,
} from "node:crypto";
import { mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const label = (value) => Buffer.from(value, "ascii");
const hex = (value) => value.toString("hex");
const concat = (...values) => Buffer.concat(values);
const hash = (bytes) => createHash("sha256").update(bytes).digest();
const hmac = (key, bytes) => createHmac("sha256", key).update(bytes).digest();
const lp = (value) => {
  const bytes = label(value);
  const length = Buffer.alloc(2);
  length.writeUInt16BE(bytes.length);
  return concat(length, bytes);
};
const u64 = (value) => {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(BigInt(value));
  return bytes;
};
const uuid = (value) => Buffer.from(value.replaceAll("-", ""), "hex");

export function normalize(bytes) {
  if (bytes.length > 2048) throw new Error("invalid password");
  const input = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  const normalized = input.normalize("NFC");
  const count = [...normalized].length;
  const output = Buffer.from(normalized, "utf8");
  if (count < 15 || count > 128 || output.length > 512) throw new Error("invalid password");
  return output;
}

// This test-only HChaCha adaptation is checked against the published draft's block answer.
// Production uses the maintained Rust XChaCha20-Poly1305 implementation.
export function hchacha20(key, nonce) {
  assert.equal(key.length, 32);
  assert.equal(nonce.length, 16);
  const words = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
  for (let i = 0; i < 8; i++) words.push(key.readUInt32LE(i * 4));
  for (let i = 0; i < 4; i++) words.push(nonce.readUInt32LE(i * 4));
  const rotate = (word, bits) => ((word << bits) | (word >>> (32 - bits))) >>> 0;
  const quarter = (a, b, c, d) => {
    words[a] = (words[a] + words[b]) >>> 0; words[d] = rotate(words[d] ^ words[a], 16);
    words[c] = (words[c] + words[d]) >>> 0; words[b] = rotate(words[b] ^ words[c], 12);
    words[a] = (words[a] + words[b]) >>> 0; words[d] = rotate(words[d] ^ words[a], 8);
    words[c] = (words[c] + words[d]) >>> 0; words[b] = rotate(words[b] ^ words[c], 7);
  };
  for (let round = 0; round < 10; round++) {
    quarter(0, 4, 8, 12); quarter(1, 5, 9, 13); quarter(2, 6, 10, 14); quarter(3, 7, 11, 15);
    quarter(0, 5, 10, 15); quarter(1, 6, 11, 12); quarter(2, 7, 8, 13); quarter(3, 4, 9, 14);
  }
  const result = Buffer.alloc(32);
  for (const [index, word] of [0, 1, 2, 3, 12, 13, 14, 15].entries()) {
    result.writeUInt32LE(words[word], index * 4);
  }
  return result;
}

export function xchachaSeal(key, nonce, plaintext, aad) {
  const subkey = hchacha20(key, nonce.subarray(0, 16));
  const iv = concat(Buffer.alloc(4), nonce.subarray(16));
  const cipher = createCipheriv("chacha20-poly1305", subkey, iv, { authTagLength: 16 });
  cipher.setAAD(aad, { plaintextLength: plaintext.length });
  return concat(cipher.update(plaintext), cipher.final(), cipher.getAuthTag());
}

export function selfTest() {
  assert.equal(process.versions.unicode, "17.0", "D-127 generation requires Unicode 17.0 tables");
  // RFC 9106 section 5.3 confirms the maintained implementation's Argon2id version 19.
  assert.equal(hex(argon2Sync("argon2id", {
    message: Buffer.alloc(32, 1), nonce: Buffer.alloc(16, 2),
    secret: Buffer.alloc(8, 3), associatedData: Buffer.alloc(12, 4),
    parallelism: 4, tagLength: 32, memory: 32, passes: 3,
  })), "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
  // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03#section-2.2.1
  assert.equal(hex(hchacha20(
    Buffer.from(Array.from({ length: 32 }, (_, index) => index)),
    Buffer.from("000000090000004a0000000031415927", "hex"),
  )), "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");
}

function publicRoot(kind, seed) {
  const prefix = kind === "ed25519" ? "302e020100300506032b657004220420" : "302e020100300506032b656e04220420";
  const privateKey = createPrivateKey({ key: concat(Buffer.from(prefix, "hex"), seed), format: "der", type: "pkcs8" });
  return createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32);
}

export function derive(input) {
  const normalized = normalize(Buffer.from(input.password_hex, "hex"));
  const salt = Buffer.from(input.salt, "hex");
  const material = argon2Sync("argon2id", {
    message: normalized, nonce: salt, parallelism: 4, tagLength: 32, memory: 65536, passes: 3,
    secret: Buffer.alloc(0), associatedData: Buffer.alloc(0),
  });
  const context = concat(label("spl-password-kdf-v1"), Buffer.from([1]), lp(input.origin), lp(input.username), salt);
  const prk = hmac(context, material);
  const auth = hmac(prk, concat(label("spl-password-auth-v1"), context, Buffer.from([1])));
  const kek = hmac(prk, concat(label("spl-password-kek-v1"), context, Buffer.from([1])));
  const aad = concat(
    label("spl-password-ark-v1"), Buffer.from([1]), lp(input.origin), lp(input.username),
    uuid(input.account_id), uuid(input.personal_vault_id),
    Buffer.from(input.signing_public_key, "hex"), Buffer.from(input.kem_public_key, "hex"),
    u64(input.generation), Buffer.from([1]), salt,
  );
  const nonce = Buffer.from(input.nonce, "hex");
  const envelope = concat(Buffer.from([1]), nonce, xchachaSeal(kek, nonce, Buffer.from(input.ark, "hex"), aad));
  const accountWrap = (domain, root, privateByte, nonceByte) => {
    const ark = Buffer.from(input.ark, "hex");
    const info = label(domain);
    const accountPrk = hmac(uuid(input.account_id), ark);
    const key = hmac(accountPrk, concat(info, Buffer.from([1])));
    const context = concat(info, Buffer.from([1]), uuid(input.account_id), Buffer.from(root, "hex"));
    const nonce = Buffer.alloc(24, nonceByte);
    return hex(concat(Buffer.from([1]), nonce, xchachaSeal(key, nonce, Buffer.alloc(32, privateByte), context)));
  };
  return {
    normalized: hex(normalized), material: hex(material), context: hex(context), prk: hex(prk),
    auth_secret: hex(auth), kek: hex(kek), verifier: hex(hash(auth)), aad: hex(aad), envelope: hex(envelope),
    signing_wrap: accountWrap("spl-account-signing-key-v1", input.signing_public_key, 6, 0x33),
    kem_wrap: accountWrap("spl-account-kem-key-v1", input.kem_public_key, 8, 0x55),
    // Valid tags under the expected roots, but plaintext reconstructs different roots.
    signing_wrap_wrong_private: accountWrap("spl-account-signing-key-v1", input.signing_public_key, 7, 0x34),
    kem_wrap_wrong_private: accountWrap("spl-account-kem-key-v1", input.kem_public_key, 9, 0x56),
  };
}

export function fixtureInput() {
  return {
    origin: "https://control.example.com", username: "alice._-09", profile: 1,
    password_hex: Buffer.from("  Cafe\u0301 and A\0Z  ", "utf8").toString("hex"),
    salt: hex(Buffer.from(Array.from({ length: 16 }, (_, index) => index))),
    account_id: "019c8a50-1000-7000-8000-000000000001",
    personal_vault_id: "019c8a50-1000-7000-8000-000000000002",
    signing_public_key: hex(publicRoot("ed25519", Buffer.alloc(32, 6))),
    kem_public_key: hex(publicRoot("x25519", Buffer.alloc(32, 8))),
    generation: "72623859790382856",
    nonce: hex(Buffer.from(Array.from({ length: 24 }, (_, index) => index + 16))),
    ark: hex(Buffer.alloc(32, 4)),
  };
}

export function generate() {
  selfTest();
  const vectors = [];
  const add = (id, kind, input, expected) => vectors.push({
    id, kind, input: typeof input === "string" ? input : JSON.stringify(input),
    expected: typeof expected === "string" ? expected : JSON.stringify(expected),
  });
  const input = fixtureInput();
  const answer = derive(input);
  add("password-bootstrap-known-answer", "crypto.password-bootstrap", input, answer);
  for (const [name, value, accepted] of [
    ["composed", "  Caf\u00e9 and A\0Z  ", true],
    ["decomposed", "  Cafe\u0301 and A\0Z  ", true],
    ["scalar-minimum", "a".repeat(15), true],
    ["scalar-too-short", "a".repeat(14), false],
    ["scalar-maximum", "a".repeat(128), true],
    ["scalar-too-long", "a".repeat(129), false],
    ["byte-maximum", "\u{1f600}".repeat(128), true],
    ["byte-too-long", "\u{1f600}".repeat(129), false],
    ["non-stream-safe", "a" + "\u0301".repeat(31) + "b".repeat(15), true],
    ["unicode17-mark", "a" + "\u{1e6e3}" + "\u0323" + "b".repeat(15), true],
    ["canonical-decomposition", "\u03b1\u0313\u0300\u0345".repeat(128), true],
    ["nfkc-not-applied", "\uff21".repeat(15), true],
    ["bom-preserved", "\ufeff" + "a".repeat(15), true],
    ["raw-bound", "a".repeat(2048), false],
    ["raw-too-long", "a".repeat(2049), false],
  ]) {
    const bytes = Buffer.from(value, "utf8");
    add(`password-normalization-${name}`, "crypto.password-normalization", hex(bytes), accepted ? hex(normalize(bytes)) : "reject");
  }
  for (const [name, bytes] of [
    ["malformed", Buffer.from([0xc3, 0x28])],
    ["surrogate", Buffer.from([0xed, 0xa0, 0x80])],
    ["overlong-nul", Buffer.from([0xc0, 0x80])],
  ]) add(`password-normalization-${name}`, "crypto.password-normalization", hex(bytes), "reject");
  const outputs = new Map([["vectors/password-bootstrap.json", Buffer.from(JSON.stringify({ format: "scoplen-test-vectors", version: 1, vectors }, null, 2) + "\n")]]);
  const envelope = Buffer.from(answer.envelope, "hex");
  const seed = (name, bytes) => outputs.set(`fuzz/corpus/crypto_decoders/seed-password-${name}`, bytes);
  seed("envelope", envelope);
  seed("envelope-truncated", envelope.subarray(0, -1));
  seed("envelope-surplus", concat(envelope, Buffer.from([0])));
  seed("envelope-version", concat(Buffer.from([2]), envelope.subarray(1)));
  seed("context", Buffer.from(input.origin + "\n" + input.username));
  seed("unknown-profile", concat(Buffer.from([2]), Buffer.from(input.salt, "hex"), label(input.username)));
  const metadata = concat(
    Buffer.from([1]), Buffer.from(input.salt, "hex"), label(input.account_id), label(input.personal_vault_id),
    Buffer.from(input.signing_public_key, "hex"), Buffer.from(input.kem_public_key, "hex"), u64(input.generation),
  );
  seed("metadata", metadata);
  seed("metadata-zero-generation", concat(metadata.subarray(0, -8), Buffer.alloc(8)));
  for (const vector of vectors.filter((value) => value.kind === "crypto.password-normalization")) {
    seed(vector.id.replace("password-normalization-", "normalization-"), Buffer.from(vector.input, "hex"));
  }
  return outputs;
}

export async function main(args = process.argv.slice(2)) {
  assert(args.length === 0 || (args.length === 1 && args[0] === "--check"), "expected only --check");
  for (const [path, expected] of generate()) {
    const target = resolve(root, path);
    if (args[0] === "--check") {
      const actual = await readFile(target);
      const equal = path.endsWith(".json")
        ? actual.toString("utf8").replaceAll("\r\n", "\n") === expected.toString("utf8")
        : actual.equals(expected);
      assert(equal, `D-127 output is stale: ${path}`);
    } else {
      await mkdir(dirname(target), { recursive: true });
      await writeFile(target, expected);
    }
  }
}

if (process.argv[1]
  && await realpath(resolve(process.argv[1])) === await realpath(fileURLToPath(import.meta.url))) {
  await main();
}
