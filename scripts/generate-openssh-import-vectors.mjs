// SPDX-License-Identifier: Apache-2.0
// Independently authored answers; never invokes Rust, WASM or a production parser.
import { readFile, readdir, unlink, writeFile } from "node:fs/promises";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

const vectors = [];
const ready = (candidate, name, address = name.toLowerCase(), username = "operator", port = 22) => ({ status: "ready", candidate, fields: { name, address, port, username } });
const blocked = (candidate, kind, line, field) => ({ status: "blocked", diagnostic: { kind, ...(line === undefined ? {} : { line }), candidate, ...(field ? { field } : {}) } });
const preview = (...candidates) => ({ candidates });
const file = (kind, line) => ({ kind, ...(line === undefined ? {} : { line }) });
const add = (name, source, expected) => vectors.push({ id: `openssh-import-${name}-v1`, kind: "inventory.import.openssh", input: Buffer.from(source).toString("hex"), expected: JSON.stringify(expected) });
const good = (name, source, ...rows) => add(name, source, preview(...rows));
const bad = (name, source, kind, line) => add(name, source, file(kind, line));

good("example", 'Host Mixed\n HostName prefix-%h\n User "part"word\n Port=2203', ready(1, "Mixed", "prefix-mixed", "partword", 2203));
good("bom-crlf", '\ufeffHost Upper\r\n\tUser OPERATOR\r\n', ready(1, "Upper", "upper", "OPERATOR"));
good("blank-comment-scope", '\n \t\n # ignored "quote\nUser global\nHost A\n# ignored\n \t\nHostName TARGET\nHost B\n', ready(1, "A", "target", "global"), ready(2, "B", "b", "global"));
good("keyword-separators", ' \thOsT = Mixed\n\tUsEr\t =\t op\nHoStNaMe= =VALUE\nPoRt = 65535', ready(1, "Mixed", "=value", "op", 65535));
good("quotes-concatenate", `Host 'A'"B"C\nUser 'part'"two"three`, ready(1, "ABC", "abc", "parttwothree"));
good("escaped-space", String.raw`Host x
User part\ word`, ready(1, "x", "x", "part word"));
good("literal-escapes", String.raw`Host x
User "a\ b\tc\\d\"e\'f"`, ready(1, "x", "x", String.raw`a\ b\tc\d"e'f`));
good("single-quote-escapes", String.raw`Host x
User 'a\"b\'c\\d'`, ready(1, "x", "x", `a"b'c\\d`));
bad("tab-not-escaped", "Host x\nUser a\\\tb", "invalid_syntax", 2);
good("comments", 'Host hash#alias # ignored\nUser "#op"#tail # ignored', ready(1, "hash#alias", "hash#alias", "#op#tail"));
good("value-whitespace", 'Host " A "\nHostName " TARGET "\nUser " OP "', ready(1, " A ", " target ", " OP "));
good("default-percent-dollar", 'Host PCT%h Cash$X\nUser op', ready(1, "PCT%h", "pct%h", "op"), ready(2, "Cash$X", "cash$x", "op"));
good("no-shorthand", 'Host user@Host:2200 ssh://Target\nUser explicit', ready(1, "user@Host:2200", "user@host:2200", "explicit"), ready(2, "ssh://Target", "ssh://target", "explicit"));
good("ip-spelling", 'Host 192.0.2.10 2001:DB8::A\nUser OP', ready(1, "192.0.2.10", "192.0.2.10", "OP"), ready(2, "2001:DB8::A", "2001:DB8::A", "OP"));
good("explicit-ip", 'Host a\nHostName 2001:DB8:0:0::A\nUser op', ready(1, "a", "2001:DB8:0:0::A", "op"));
good("ascii-only-case", 'Host ÄHOST\nUser OPerator', ready(1, "ÄHOST", "Ähost", "OPerator"));
good("percent-single-pass", 'Host PCT%h\nHostName %%-%h\nUser op', ready(1, "PCT%h", "%-pct%h", "op"));
good("dollar-alias-single-pass", 'Host Cash$X\nHostName prefix-%h\nUser op', ready(1, "Cash$X", "prefix-cash$x", "op"));
good("percent-literal-h", 'Host x\nHostName %%h\nUser op', ready(1, "x", "%h", "op"));
good("global-first", 'User global\nHostName GLOBAL\nPort 2200\nHost a b\nUser local\nHostName LOCAL\nPort 2201', ready(1, "a", "global", "global", 2200), ready(2, "b", "global", "global", 2200));
good("matching-first", 'Host a b\nUser first\nHost *\nUser second\nHostName target-%h\nHost a\nPort 2202', ready(1, "a", "target-a", "first", 2202), ready(2, "b", "target-b", "first"));
good("dedup-case-order", 'Host z A z a\nUser first\nHost z\nUser second', ready(1, "z", "z", "first"), ready(2, "A", "a", "first"), ready(3, "a", "a", "first"));
good("decoded-dedup", 'Host "A" A \'A\'\nUser op', ready(1, "A", "a", "op"));
good("wildcard-negation", 'Host prod-a prod-b other\nUser op\nHost prod-* !prod-b\nPort 2205', ready(1, "prod-a", "prod-a", "op", 2205), ready(2, "prod-b", "prod-b", "op"), ready(3, "other", "other", "op"));
good("whole-case-sensitive", 'Host Ab a b ab\nUser op\nHost a\nPort 2201\nHost A*\nHostName Upper', ready(1, "Ab", "upper", "op"), ready(2, "a", "a", "op", 2201), ready(3, "b", "b", "op"), ready(4, "ab", "ab", "op"));
good("question-byte", 'Host é a\nUser op\nHost ?\nPort 2201\nHost ??\nHostName TWO', ready(1, "é", "two", "op"), ready(2, "a", "a", "op", 2201));
good("star-empty-backtrack", 'Host a axyb\nUser op\nHost a*b\nPort 2201\nHost a*\nHostName STAR', ready(1, "a", "star", "op"), ready(2, "axyb", "star", "op", 2201));
good("negative-only-block", 'Host a\nUser op\nHost !b\nIdentityFile none', ready(1, "a", "a", "op"));
good("literal-comma-brackets", 'Host a,b [ab] a\nUser op\nHost [ab]\nPort 2202', ready(1, "a,b", "a,b", "op"), ready(2, "[ab]", "[ab]", "op", 2202), ready(3, "a", "a", "op"));
good("no-hostname-rematch", 'Host a\nHostName target\nUser op\nHost target*\nProxyJump none', ready(1, "a", "target", "op"));
good("unmatched-unknown-scope", 'Host bad*\nPrivateUnknown value\nUser wrong\nHost good\nUser right', ready(1, "good", "good", "right"));
good("mixed-results-order", 'Host a\nUser op\nHost b\nProxyJump none\nHost c\nUser OP', ready(1, "a", "a", "op"), blocked(2, "unsupported_option", 4), ready(3, "c", "c", "OP"));
good("global-unknown", 'PrivateUnknown secret\nHost a b\nUser op', blocked(1, "unsupported_option", 1), blocked(2, "unsupported_option", 1));
for (const directive of ["ProxyJump none", "ProxyCommand none", "IdentityFile none", "CertificateFile none", "ForwardAgent no", "RemoteCommand none", "CanonicalizeHostname no", "StrictHostKeyChecking no", "Ciphers default", "IgnoreUnknown *", "UserKnownHostsFile none"]) {
  good(`unsupported-${directive.split(" ")[0]}`, `Host a\nUser op\n${directive}`, blocked(1, "unsupported_option", 3));
}
good("missing-user", 'Host a', blocked(1, "missing_username", 1, "username"));
for (const value of ["%u", "%", "$USER", "literal$", "%%", "x%h"]) good(`user-expansion-${Buffer.from(value).toString("hex")}`, `Host a\nUser "${value}"`, blocked(1, "unsupported_value", 2, "username"));
for (const value of ["%r", "%", "%H", "$HOST", "x$y"]) good(`hostname-expansion-${Buffer.from(value).toString("hex")}`, `Host a\nUser op\nHostName "${value}"`, blocked(1, "unsupported_value", 3, "address"));
for (const value of ["0", "00", "01", "+22", "-1", "65536", "22.0", "22e0", "ssh", " 22", "22 ", ""]) good(`port-${Buffer.from(value).toString("hex") || "empty"}`, `Host a\nUser op\nPort "${value}"`, blocked(1, "unsupported_value", 3, "port"));
good("port-one", 'Host a\nUser op\nPort 1', ready(1, "a", "a", "op", 1));
for (const [name, source, line, field] of [
  ["empty-user", 'Host a\nUser ""', 2, "username"], ["empty-address", 'Host a\nUser op\nHostName ""', 3, "address"],
  ["nfc-alias", 'Host e\u0301\nUser op', 1, "name"], ["nfc-user", 'Host a\nUser e\u0301', 2, "username"], ["nfc-address", 'Host a\nUser op\nHostName e\u0301', 3, "address"],
]) good(name, source, blocked(1, "invalid_field", line, field));
good("shadowed-port", 'Host a\nUser op\nPort 22\nPort 022', blocked(1, "unsupported_value", 4, "port"));
good("shadowed-user", 'Host a\nUser op\nUser %u', blocked(1, "unsupported_value", 3, "username"));
good("shadowed-address", 'Host a\nUser op\nHostName valid\nHostName %r', blocked(1, "unsupported_value", 4, "address"));
good("earliest-option", 'User $USER\nHost a\nProxyJump none', blocked(1, "unsupported_value", 1, "username"));
good("earliest-k1", 'User ""\nHost a\nProxyJump none', blocked(1, "invalid_field", 1, "username"));
good("same-line-name-first", 'Host e\u0301', blocked(1, "invalid_field", 1, "name"));
good("profile-before-k1", `Host a\nUser "%${"x".repeat(16385)}"`, blocked(1, "unsupported_value", 2, "username"));
good("global-expanded-source-line", `HostName %h%h\nUser op\nHost ${"a".repeat(9000)}`, blocked(1, "invalid_field", 1, "address"));
good("shadowed-expanded-limit", `Host ${"a".repeat(9000)}\nUser op\nHostName valid\nHostName %h%h`, blocked(1, "invalid_field", 4, "address"));
for (const [field, make] of [["name", n => `Host ${"x".repeat(n)}\nUser op`], ["address", n => `Host a\nUser op\nHostName ${"x".repeat(n)}`], ["username", n => `Host a\nUser ${"x".repeat(n)}`]]) {
  for (const n of [16384, 16385]) {
    const expected = n === 16385 ? blocked(1, "invalid_field", field === "name" ? 1 : field === "address" ? 3 : 2, field) : ready(1, field === "name" ? "x".repeat(n) : "a", field === "address" || field === "name" ? "x".repeat(n) : "a", field === "username" ? "x".repeat(n) : "op");
    good(`${field}-bound-${n}`, make(n), expected);
  }
}
good("expanded-exact-limit", `Host ${"a".repeat(8192)}\nUser op\nHostName %h%h`, ready(1, "a".repeat(8192), "a".repeat(16384), "op"));
for (const count of [1, 100, 101]) {
  const source = `User op\nHost ${Array.from({ length: count }, (_, i) => `h${i}`).join(" ")}`;
  add(`candidates-${count}`, source, count > 100 ? file("too_many_candidates") : preview(...Array.from({ length: count }, (_, i) => ready(i + 1, `h${i}`, `h${i}`, "op"))));
}
bad("blocked-count-before-filter", `ProxyJump none\nHost ${Array.from({ length: 101 }, (_, i) => `h${i}`).join(" ")}`, "too_many_candidates");
good("dedup-before-count", `User op\nHost ${Array(101).fill('"a" a').join(" ")}`, ready(1, "a", "a", "op"));
for (const [name, source] of [["empty", ""], ["only-bom", "\ufeff"], ["comments", '\n # "unterminated\n\t'], ["global-only", "User op"], ["patterns-only", "Host * ? !a\nUser op"]]) bad(`no-candidates-${name}`, source, "no_candidates");
for (const [name, source, line] of [
  ["bare-cr", "Host a\rUser op", 1], ["final-cr", "Host a\nUser op\r", 2], ["nul-comment", "# ignored\0", 1], ["nul-value", "Host a\nUser a\0b", 2],
  ["quote", 'Host a\nUser "op', 2], ["quote-physical", 'Host a\nUser "op\nerator"', 2], ["keyword-quoted", '"Host" a', 1], ["keyword-escaped", 'Ho\\st a', 1], ["keyword-nonascii", 'Höst a', 1], ["keyword-empty", '=a', 1],
  ["missing-host", "Host", 1], ["missing-user", "Host a\nUser # comment", 2], ["extra-user", "Host a\nUser op extra", 2], ["extra-port", "Host a\nPort 22 extra", 2], ["extra-hostname", "Host a\nHostName host extra", 2], ["unknown-arity", "Host unmatched*\nPrivateUnknown", 2],
  ["empty-selector", 'Host a ""\nUser op', 1], ["negation-selector", "Host a !\nUser op", 1], ["double-bom", "\ufeff\ufeffHost a\nUser op", 1],
]) bad(`syntax-${name}`, source, "invalid_syntax", line);
for (const keyword of ["Include", "Match", "iNcLuDe", "mAtCh"]) bad(`scope-${Buffer.from(keyword).toString("hex")}`, `Host unmatched*\n${keyword} ignored\nHost a\nUser op`, "unsupported_scope", 2);
bad("scope-before-later-syntax", 'Include ignored\nUser "', "unsupported_scope", 1);
bad("syntax-before-later-scope", 'User "\nInclude ignored', "invalid_syntax", 1);
bad("syntax-before-count", `Host ${Array.from({ length: 101 }, (_, i) => `h${i}`).join(" ")}\nUser "`, "invalid_syntax", 2);
bad("no-line-continuation", 'Host a\nUser part\\\nword', "invalid_syntax", 3);
good("shadowed-nfc", 'Host a\nUser op\nUser e\u0301', blocked(1, "invalid_field", 3, "username"));
good("unicode-expansion", 'Host ÉX\nUser op\nHostName prefix-%h', ready(1, "ÉX", "prefix-Éx", "op"));
good("expanded-nfc-source-line", 'Host \u0301\nUser op\nHostName e%h', blocked(1, "invalid_field", 3, "address"));
add("invalid-utf8", Buffer.from([0xff]), file("invalid_utf8"));
add("utf8-before-syntax", Buffer.from([0, 0xff]), file("invalid_utf8"));
for (const extra of [0, 1]) vectors.push({ id: `openssh-import-raw-bound-${extra}-v1`, kind: "inventory.import.openssh.bound", input: JSON.stringify({ source: "Host a\nUser op\n#", bytes: 1048576 + extra }), expected: JSON.stringify(extra ? file("raw_too_large") : preview(ready(1, "a", "a", "op"))) });
vectors.push({ id: "openssh-import-raw-before-utf8-v1", kind: "inventory.import.openssh.bound", input: JSON.stringify({ source: "", bytes: 1048577, fill: 255 }), expected: JSON.stringify(file("raw_too_large")) });

export const document = { format: "scoplen-test-vectors", version: 1, vectors };
export function materialize(vector) {
  if (vector.kind.endsWith(".bound")) {
    const { source, bytes, fill = 120 } = JSON.parse(vector.input);
    const input = Buffer.alloc(bytes, fill);
    input.set(Buffer.from(source));
    return input;
  }
  return Buffer.from(vector.input, "hex");
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const root = new URL("../", import.meta.url);
  const outputs = [["vectors/openssh-inventory-import.json", Buffer.from(`${JSON.stringify(document, null, 2)}\n`)]];
  for (const vector of vectors.filter(vector => vector.kind === "inventory.import.openssh")) outputs.push([`fuzz/corpus/api_json/seed-${vector.id}`, materialize(vector)]);
  const expectedSeeds = new Set(outputs.slice(1).map(([path]) => path.split("/").at(-1)));
  for (const entry of await readdir(new URL("fuzz/corpus/api_json/", root), { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.startsWith("seed-openssh-import-") || expectedSeeds.has(entry.name)) continue;
    if (process.argv.includes("--check")) throw new Error(`D-153 stale seed: ${entry.name}`);
    await unlink(new URL(`fuzz/corpus/api_json/${entry.name}`, root));
  }
  for (const [path, expected] of outputs) {
    const url = new URL(path, root);
    if (process.argv.includes("--check")) {
      const bytes = await readFile(url);
      const actual = path.endsWith(".json") ? Buffer.from(bytes.toString("utf8").replaceAll("\r\n", "\n")) : bytes;
      if (!actual.equals(expected)) throw new Error(`D-153 stale output: ${path}`);
    } else await writeFile(url, expected);
  }
  console.log(`validated ${vectors.length} independent D-153 vectors and ${outputs.length - 1} seeds`);
}
