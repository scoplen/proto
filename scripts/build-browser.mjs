// SPDX-License-Identifier: Apache-2.0
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const root = fileURLToPath(new URL("../", import.meta.url));
const { values } = parseArgs({ options: { "source-revision": { type: "string" } } });
const declaredRevision = values["source-revision"];
if (declaredRevision !== undefined && !/^[0-9a-f]{40}$/.test(declaredRevision)) {
  throw new Error("--source-revision requires the exact full lowercase Git revision");
}
const crate = join(root, "crates/scoplen-browser");
const versions = JSON.parse(await readFile(join(crate, "toolchain.json"), "utf8"));
const toolchain = await readFile(join(root, "rust-toolchain.toml"), "utf8");
const manifest = await readFile(join(crate, "Cargo.toml"), "utf8");
if (!toolchain.includes(`channel = "${versions.rust}"`) || !manifest.includes(`wasm-bindgen = "=${versions.wasmBindgen}"`)) {
  throw new Error("Browser build pins differ from the repository toolchain or binding crate");
}
const run = (program, args, capture = false) => execFileSync(program, args, {
  cwd: root, encoding: "utf8", stdio: capture ? ["ignore", "pipe", "inherit"] : "inherit", windowsHide: true,
});
let gitRoot;
try {
  gitRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
    cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], windowsHide: true,
  }).trim();
} catch {}
const canonicalPath = path => process.platform === "win32" ? resolve(path).toLowerCase() : resolve(path);
const sourceKind = gitRoot && canonicalPath(gitRoot) === canonicalPath(root) ? "git" : "archive";
const sourceRevision = sourceKind === "git" ? run("git", ["rev-parse", "HEAD"], true).trim() : declaredRevision;
if (!sourceRevision) throw new Error("A source archive requires --source-revision with the consumer's exact published proto pin");
if (declaredRevision !== undefined && sourceRevision !== declaredRevision) throw new Error("Source checkout does not match --source-revision");
const sourceDirty = sourceKind === "git" ? run("git", ["status", "--porcelain", "--untracked-files=normal"], true).trim() !== "" : null;
const bindgen = process.env.WASM_BINDGEN || "wasm-bindgen";
let installed;
try { installed = run(bindgen, ["--version"], true).trim(); }
catch { throw new Error(`Install wasm-bindgen-cli exactly ${versions.wasmBindgen}; set WASM_BINDGEN to its executable when it is outside PATH`); }
if (installed !== `wasm-bindgen ${versions.wasmBindgen}`) throw new Error(`Expected wasm-bindgen ${versions.wasmBindgen}, found ${installed}`);
const targets = run("rustup", ["target", "list", "--installed", "--toolchain", versions.rust], true).split(/\s+/);
if (!targets.includes(versions.target)) throw new Error(`Run rustup target add --toolchain ${versions.rust} ${versions.target}`);

run("cargo", [`+${versions.rust}`, "build", "--locked", "--release", "--target", versions.target, "--package", "scoplen-browser"]);
const metadata = JSON.parse(run("cargo", [`+${versions.rust}`, "metadata", "--locked", "--no-deps", "--format-version", "1"], true));
const output = join(crate, "pkg");
await mkdir(output, { recursive: true });
run(bindgen, [join(metadata.target_directory, versions.target, "release/scoplen_browser.wasm"), "--target", "web", "--out-dir", output, "--out-name", "scoplen_browser"]);
const files = ["scoplen_browser.js", "scoplen_browser.d.ts", "scoplen_browser_bg.wasm", "scoplen_browser_bg.wasm.d.ts"];
await writeFile(join(output, "package.json"), `${JSON.stringify({
  name: "@scoplen/browser", version: "0.1.0", private: true, type: "module",
  exports: {
    ".": { types: "./scoplen_browser.d.ts", default: "./scoplen_browser.js" },
    "./scoplen_browser_bg.wasm": "./scoplen_browser_bg.wasm",
  },
  files: [...files, "build.json"],
}, null, 2)}\n`);
files.push("package.json");
const assets = {};
for (const name of files) {
  const bytes = await readFile(join(output, name));
  assets[name] = { bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") };
}
await writeFile(join(output, "build.json"), `${JSON.stringify({ ...versions, sourceKind, sourceRevision, sourceDirty, assets }, null, 2)}\n`);
console.log(`Built ${versions.target} browser module with wasm-bindgen ${versions.wasmBindgen}`);
