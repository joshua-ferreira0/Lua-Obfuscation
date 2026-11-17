"use strict";

const { PolymorphicRNG } = require("./prng");
const { parseLuauToAST, executeLuauScript } = require("./frontend");
const { buildPolymorphicISA } = require("./isa");
const { compileASTToIR } = require("./compiler");
const { obfuscateAndLowerModuleIR } = require("./ir_obfuscator");
const { createCryptoProfile, packAndEncryptModule } = require("./crypto_packer");
const { generatePolymorphicLuauVM } = require("./vm_codegen");

const PRESETS = {
  low: {
    duplicateOps: false,
    maskOperands: true,
    decoyHandlers: false,
    scrambleConstants: true,
    bogusBlocks: false,
    opaquePredicates: false,
    shuffleBlocks: false,
    mbaConstants: false,
    splitConstants: false,
    virtualizeBit32: false,
    antiTamper: false,
    paranoid: false,
    idStyle: "luaobf"
  },
  medium: {
    duplicateOps: true,
    maskOperands: true,
    decoyHandlers: true,
    scrambleConstants: true,
    bogusBlocks: true,
    opaquePredicates: true,
    shuffleBlocks: true,
    mbaConstants: false,
    splitConstants: true,
    virtualizeBit32: true,
    antiTamper: true,
    paranoid: false,
    idStyle: "luaobf"
  },
  high: {
    duplicateOps: true,
    maskOperands: true,
    decoyHandlers: true,
    scrambleConstants: true,
    bogusBlocks: true,
    opaquePredicates: true,
    shuffleBlocks: true,
    mbaConstants: true,
    splitConstants: true,
    virtualizeBit32: true,
    antiTamper: true,
    paranoid: false,
    idStyle: "luaobf"
  },
  extra_high: {
    duplicateOps: true,
    maskOperands: true,
    decoyHandlers: true,
    scrambleConstants: true,
    bogusBlocks: true,
    opaquePredicates: true,
    shuffleBlocks: true,
    mbaConstants: true,
    splitConstants: true,
    virtualizeBit32: true,
    antiTamper: true,
    paranoid: true,
    idStyle: "il1"
  }
};

function resolveOptions(userOptions = {}) {
  const presetName = (userOptions.preset || "high").toLowerCase();
  const base = PRESETS[presetName] || PRESETS.high;
  return {
    preset: presetName,
    ...base,
    ...userOptions,
    payloadPrefix: "joshua",
    watermark: false
  };
}

function obfuscate(sourceCode, userOptions = {}) {
  const t0 = performance.now();
  const opts = resolveOptions(userOptions);
  const rng = new PolymorphicRNG(opts.seed);

  // 1. Parse Lua / Roblox Luau source to resolved AST
  const rootAst = parseLuauToAST(sourceCode);

  // 2. Compile AST to LuaObf Custom Register IR (with bit32 virtualization & constant/vault splitting)
  const irModule = compileASTToIR(rootAst, rng, opts);

  // 3. Generate unique per-build Polymorphic ISA
  const isa = buildPolymorphicISA(rng, opts);

  // 4. Generate per-build crypto profile & 16-element runtime ARX salt table T[1..16]
  const cryptoProfile = createCryptoProfile(rng, opts);

  // 5. Apply IR security passes & path-dependent stateKey basic-block encryption
  const irStats = obfuscateAndLowerModuleIR(irModule, isa, rng, cryptoProfile, opts);

  // 6. Encrypt & pack into keyless string vault + T-salted container + permuted Radix-85 armor
  const packed = packAndEncryptModule(irModule, rng, cryptoProfile, opts);

  // 7. Synthesize bespoke Polymorphic Luau VM + BST Dispatcher
  const obfuscatedCode = generatePolymorphicLuauVM(isa, packed, rng, opts);

  const compileTimeMs = +(performance.now() - t0).toFixed(2);

  const isaPreview = isa.physicalSpecs
    .slice()
    .sort((a, b) => a.opCode - b.opCode)
    .map((s) => ({
      opCode: `0x${s.opCode.toString(16).toUpperCase().padStart(2, "0")}`,
      semOp: s.semOp,
      perm: s.perm.map((p) => ["X", "Y", "Z"][p]).join(","),
      masks: [s.maskA, s.maskB, s.maskC].map(
        (m) => `0x${m.toString(16).toUpperCase().padStart(4, "0")}`
      )
    }));

  return {
    code: obfuscatedCode,
    stats: {
      preset: opts.preset,
      seed: rng.seedHex,
      inputBytes: Buffer.byteLength(sourceCode, "utf8"),
      outputBytes: Buffer.byteLength(obfuscatedCode, "utf8"),
      encryptedContainerBytes: packed.rawByteSize,
      payloadLength: packed.encodedPayload.length,
      prototypesCompiled: irModule.prototypes.length,
      totalInstructions: irStats.totalInstructions,
      bogusInstructions: irStats.totalBogusInstructions,
      vaultStrings: irModule.stringVault.length,
      uniquePhysicalOpcodes: isa.physicalSpecs.length,
      sectionOrder: packed.cryptoParams.sectionOrder.map(
        (i) => ["Constants", "Instructions", "Upvalues", "ChildProtos"][i]
      ),
      antiTamperActive: packed.cryptoParams.antiTamper,
      mbaActive: opts.mbaConstants !== false,
      compileTimeMs
    },
    isaPreview
  };
}

module.exports = {
  obfuscate,
  PRESETS,
  resolveOptions,
  executeLuauScript
};
