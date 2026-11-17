# LuaObf

**A polymorphic obfuscator primarily targeting Lua 5.1, with support for Roblox's Luau runtime.**

LuaObf compiles source into a custom register-based instruction format and generates a polymorphic virtual machine to execute it. Opcode mappings, operand layouts, and other parts of the generated runtime vary between builds.

## Video demo
https://github.com/user-attachments/assets/78b30248-c904-4dba-8ea0-97c4aa391790

### Requirements

- Node.js 18 or later, as specified in `package.json`.
- Windows for the bundled Luau `.exe` tools used by the current implementation.
- The project's `bin/` directory, including `luau-ast.exe` and `luau-compile.exe`.

From the project directory, run:

```sh
npm start
```

Open [http://localhost:8090](http://localhost:8090), paste or upload your source, select a preset, and run the obfuscator.

The current package has no declared npm dependencies.

## Protection presets

| Preset | Configuration |
| --- | --- |
| Low | Operand masking and constant scrambling, with fewer additional transformations. |
| Medium | Adds duplicate opcodes, decoy handlers, control-flow transformations, string splitting, selected bit operation virtualization, and runtime checks. |
| High | Extends Medium with runtime-dependent constant expressions. This is the default preset. |
| Extra High | Extends High with additional opcode variants, a higher decoy-block injection limit, and ambiguous identifier styling. |

## JavaScript usage

```js
const fs = require("node:fs");
const { obfuscate } = require("./src/index");

const source = fs.readFileSync("input.lua", "utf8");
const result = obfuscate(source, { preset: "high" });

fs.writeFileSync("output.lua", result.code);
console.log(result.stats);
```

## How it works

1. Validate and parse the source through Luau's frontend tooling, with normalization for selected Lua syntax differences.
2. Compile the AST into a custom register-based intermediate representation.
3. Generate a randomized instruction set and per-build packing parameters.
4. Apply constant and control-flow transformations, then encode instructions using execution-dependent state.
5. Pack and encrypt the module and its string vault.
6. Generate the matching polymorphic VM and embed the encoded payload.

Lua 5.1 is the primary target, with Roblox Luau support. The build pipeline uses Luau tooling; language features and host APIs should be checked with the scripts and runtime you intend to use.

## Development and testing

This project was created with **AI assistance and code beautification tools**.

An earlier version of the obfuscated output was decompiled using **ChatGPT's 6.2 Ultra model**. I personally patched the weaknesses exposed by that attempt and used the findings to improve the obfuscator.

## Feedback

Feedback on language compatibility, runtime behavior, and the compiler or VM architecture is welcome. When reporting a problem, include a minimal source example, the preset used, the target runtime, and the expected behavior.
