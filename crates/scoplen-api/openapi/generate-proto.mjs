// SPDX-License-Identifier: Apache-2.0
// Generate TypeScript bindings and reflection metadata from the checked-in protobuf contracts.
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.dirname(fileURLToPath(import.meta.url));
const protoRoot = path.resolve(root, "../proto");
const outputPath = path.join(root, "internal-proto.ts");
const sources = [
  path.join(protoRoot, "spl/gateway/v1/control.proto"),
  path.join(protoRoot, "spl/agent/v1/agent.proto"),
];

function tokenize(source) {
  const withoutComments = source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/[^\r\n]*/g, "");
  const tokens = withoutComments.match(/[A-Za-z_][A-Za-z0-9_.]*|\d+|"(?:\\.|[^"\\])*"|[{}();=<>\[\],]/g);
  return tokens ?? [];
}

function parseProto(source, fileName) {
  const tokens = tokenize(source);
  let index = 0;
  let packageName = "";
  const messages = [];
  const enums = [];
  const services = [];

  const peek = () => tokens[index];
  const take = () => tokens[index++];
  const expect = (token) => {
    const actual = take();
    if (actual !== token) throw new Error(`${fileName}: expected ${token}, got ${actual ?? "end of file"}`);
    return actual;
  };
  const skipStatement = () => {
    let depth = 0;
    while (index < tokens.length) {
      const token = take();
      if (token === "{") depth += 1;
      if (token === "}") {
        if (depth === 0) return;
        depth -= 1;
      }
      if (token === ";" && depth === 0) return;
    }
  };
  const parseField = (oneof) => {
    let repeated = false;
    let optional = false;
    if (peek() === "repeated") {
      repeated = true;
      take();
    } else if (peek() === "optional") {
      optional = true;
      take();
    }
    const type = take();
    const name = take();
    if (!type || !name) throw new Error(`${fileName}: incomplete field`);
    expect("=");
    const number = Number(take());
    if (!Number.isInteger(number) || number < 1) throw new Error(`${fileName}: invalid field number`);
    if (peek() === "[") {
      take();
      while (peek() && peek() !== "]") take();
      expect("]");
    }
    expect(";");
    return { type, name, number, repeated, optional, oneof };
  };
  const parseMessage = () => {
    expect("message");
    const name = take();
    expect("{");
    const fields = [];
    const oneofs = [];
    while (peek() && peek() !== "}") {
      if (peek() === "oneof") {
        take();
        const oneofName = take();
        expect("{");
        const members = [];
        while (peek() && peek() !== "}") members.push(parseField(oneofName));
        expect("}");
        oneofs.push({ name: oneofName, members });
      } else if (["option", "reserved", "extensions", "extend"].includes(peek())) {
        skipStatement();
      } else {
        fields.push(parseField(undefined));
      }
    }
    expect("}");
    messages.push({ name, fields, oneofs });
  };
  const parseEnum = () => {
    expect("enum");
    const name = take();
    expect("{");
    const values = [];
    while (peek() && peek() !== "}") {
      if (peek() === "option" || peek() === "reserved") {
        skipStatement();
        continue;
      }
      const valueName = take();
      expect("=");
      const number = Number(take());
      if (!Number.isInteger(number)) throw new Error(`${fileName}: invalid enum number`);
      if (peek() === "[") {
        take();
        while (peek() && peek() !== "]") take();
        expect("]");
      }
      expect(";");
      values.push({ name: valueName, number });
    }
    expect("}");
    enums.push({ name, values });
  };
  const parseService = () => {
    expect("service");
    const name = take();
    expect("{");
    const methods = [];
    while (peek() && peek() !== "}") {
      if (peek() !== "rpc") {
        skipStatement();
        continue;
      }
      take();
      const methodName = take();
      expect("(");
      const requestStreaming = peek() === "stream";
      if (requestStreaming) take();
      const requestType = take();
      expect(")");
      expect("returns");
      expect("(");
      const responseStreaming = peek() === "stream";
      if (responseStreaming) take();
      const responseType = take();
      expect(")");
      if (peek() === "{") {
        skipStatement();
      } else {
        expect(";");
      }
      methods.push({ methodName, requestType, responseType, requestStreaming, responseStreaming });
    }
    expect("}");
    services.push({ name, methods });
  };

  while (peek()) {
    switch (peek()) {
      case "syntax":
      case "import":
        skipStatement();
        break;
      case "package":
        take();
        packageName = take();
        expect(";");
        break;
      case "message":
        parseMessage();
        break;
      case "enum":
        parseEnum();
        break;
      case "service":
        parseService();
        break;
      default:
        skipStatement();
    }
  }
  if (!packageName) throw new Error(`${fileName}: missing package declaration`);
  return { fileName: path.relative(protoRoot, fileName).replaceAll(path.sep, "/"), packageName, messages, enums, services };
}

function camelCase(value) {
  return value.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());
}

function pascalCase(value) {
  return value.replace(/(^|_)([a-z])/g, (_, _separator, letter) => letter.toUpperCase());
}

function packagePrefix(packageName) {
  return pascalCase(packageName.split(".").at(-2) ?? packageName);
}

function typeName(type, packageName) {
  return `${packagePrefix(packageName)}${pascalCase(type.split(".").at(-1))}`;
}

function typeScriptType(type, packageName) {
  if (type === "string") return "string";
  if (type === "bytes") return "Uint8Array";
  if (type === "bool") return "boolean";
  if (["uint32", "int32"].includes(type)) return "number";
  if (["uint64", "int64"].includes(type)) return "bigint";
  if (type === "google.protobuf.Timestamp") return "Timestamp";
  return typeName(type, packageName);
}

function wireType(type, enumNames) {
  if (["bool", "uint32", "uint64", "int32", "int64"].includes(type) || enumNames.has(type)) return "varint";
  return "length-delimited";
}

function renderFile(files) {
  const allMessages = files.flatMap((file) => file.messages);
  const allEnums = files.flatMap((file) => file.enums);
  const allServices = files.flatMap((file) => file.services);
  const enumNames = new Set(allEnums.map((enumeration) => enumeration.name));
  const lines = [
    "// SPDX-License-Identifier: Apache-2.0",
    "// Generated by openapi/generate-proto.mjs. Do not edit by hand.",
    "",
    "/** Protobuf well-known timestamp represented without a Date precision loss. */",
    "export interface Timestamp { seconds: bigint; nanos: number; }",
    "",
    "/** Reflection metadata consumed by a future gRPC runtime adapter. */",
    "export interface ProtoFieldDefinition {",
    "  readonly name: string;",
    "  readonly number: number;",
    "  readonly type: string;",
    "  readonly wireType: \"varint\" | \"length-delimited\";",
    "  readonly repeated: boolean;",
    "  readonly oneof?: string;",
    "}",
    "export interface ProtoMessageDefinition { readonly fullName: string; readonly fields: readonly ProtoFieldDefinition[]; }",
    "export interface ProtoEnumDefinition { readonly fullName: string; readonly values: Readonly<Record<string, number>>; }",
    "export interface ProtoMethodDefinition {",
    "  readonly name: string;",
    "  readonly service: string;",
    "  readonly inputType: string;",
    "  readonly outputType: string;",
    "  readonly clientStreaming: boolean;",
    "  readonly serverStreaming: boolean;",
    "}",
    "export interface ProtoServiceDefinition { readonly fullName: string; readonly methods: readonly ProtoMethodDefinition[]; }",
    "",
  ];

  for (const file of files) {
    for (const enumeration of file.enums) {
      lines.push(`export enum ${packagePrefix(file.packageName)}${enumeration.name} {`);
      for (const value of enumeration.values) lines.push(`  ${value.name} = ${value.number},`);
      lines.push("}", "");
    }
    for (const message of file.messages) {
      for (const oneof of message.oneofs) {
        lines.push(`export type ${packagePrefix(file.packageName)}${message.name}${pascalCase(oneof.name)} =`);
        for (const member of oneof.members) {
          lines.push(`  | { readonly case: ${JSON.stringify(camelCase(member.name))}; readonly value: ${typeScriptType(member.type, file.packageName)} }`);
        }
        lines.push(";", "");
      }
      lines.push(`export interface ${packagePrefix(file.packageName)}${message.name} {`);
      for (const field of message.fields) {
        const fieldType = typeScriptType(field.type, file.packageName);
        const valueType = field.repeated ? `readonly ${fieldType}[]` : fieldType;
        lines.push(`  readonly ${camelCase(field.name)}?: ${valueType};`);
      }
      for (const oneof of message.oneofs) {
        lines.push(`  readonly ${camelCase(oneof.name)}?: ${packagePrefix(file.packageName)}${message.name}${pascalCase(oneof.name)};`);
      }
      lines.push("}", "");
    }
  }

  lines.push("export const internalProtoDescriptor = {");
  lines.push("  messages: {");
  for (const file of files) {
    for (const message of file.messages) {
      lines.push(`    ${JSON.stringify(`${file.packageName}.${message.name}`)}: {`);
      lines.push(`      fullName: ${JSON.stringify(`${file.packageName}.${message.name}`)},`);
      lines.push("      fields: [");
      for (const field of [...message.fields, ...message.oneofs.flatMap((oneof) => oneof.members)]) {
        lines.push(`        { name: ${JSON.stringify(field.name)}, number: ${field.number}, type: ${JSON.stringify(field.type)}, wireType: ${JSON.stringify(wireType(field.type, enumNames))}, repeated: ${field.repeated},${field.oneof ? ` oneof: ${JSON.stringify(field.oneof)},` : ""} },`);
      }
      lines.push("      ],", "    },");
    }
  }
  lines.push("  },", "  enums: {");
  for (const file of files) {
    for (const enumeration of file.enums) {
      lines.push(`    ${JSON.stringify(`${file.packageName}.${enumeration.name}`)}: {`);
      lines.push(`      fullName: ${JSON.stringify(`${file.packageName}.${enumeration.name}`)},`);
      lines.push("      values: {");
      for (const value of enumeration.values) lines.push(`        ${value.name}: ${value.number},`);
      lines.push("      },", "    },");
    }
  }
  lines.push("  },", "  services: {");
  for (const file of files) {
    for (const service of file.services) {
      lines.push(`    ${JSON.stringify(`${file.packageName}.${service.name}`)}: {`);
      lines.push(`      fullName: ${JSON.stringify(`${file.packageName}.${service.name}`)},`, "      methods: [");
      for (const method of service.methods) {
        lines.push(`        { name: ${JSON.stringify(method.methodName)}, service: ${JSON.stringify(`${file.packageName}.${service.name}`)}, inputType: ${JSON.stringify(`${file.packageName}.${method.requestType}`)}, outputType: ${JSON.stringify(`${file.packageName}.${method.responseType}`)}, clientStreaming: ${method.requestStreaming}, serverStreaming: ${method.responseStreaming} },`);
      }
      lines.push("      ],", "    },");
    }
  }
  lines.push("  },", "} as const;", "");

  for (const file of files) {
    for (const service of file.services) {
      const serviceType = `${file.packageName}.${service.name}`;
      lines.push(`export const ${service.name}Service = internalProtoDescriptor.services[${JSON.stringify(serviceType)}];`);
    }
  }
  lines.push("");
  return `${lines.join("\n")}\n`;
}

const files = [];
for (const source of sources) files.push(parseProto(await readFile(source, "utf8"), source));
const generated = renderFile(files);
if (process.argv.includes("--check")) {
  const existing = await readFile(outputPath, "utf8").catch(() => "");
  if (existing !== generated) {
    console.error(`generated file is stale: ${path.relative(process.cwd(), outputPath)}`);
    process.exitCode = 1;
  }
} else {
  await writeFile(outputPath, generated);
  console.log(`generated TypeScript protobuf bindings for ${files.length} files`);
}

export { parseProto, renderFile };



