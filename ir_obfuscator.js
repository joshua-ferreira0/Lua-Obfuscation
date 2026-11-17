"use strict";

const { u32, rotl32, rotr32 } = require("./prng");
const { encodeInstructionWords } = require("./isa");

const UNCONDITIONAL_TERMINATORS = new Set(["JMP", "FORGPREP", "RETURN"]);

const CONDITIONAL_BRANCH_OPS = new Set([
  "JMP_TRUE",
  "JMP_FALSE",
  "TESTSET_TRUE",
  "TESTSET_FALSE",
  "EQ_JMP",
  "NE_JMP",
  "LT_JMP",
  "LE_JMP",
  "FORPREP",
  "FORLOOP",
  "FORGLOOP",
  "STATE_BRANCH"
]);

function remapConstantOperands(inst, remap) {
  switch (inst.semOp) {
    case "LOADK":
    case "GETGLOBAL":
    case "SETGLOBAL":
      inst.B = remap[inst.B];
      break;
    case "GETPROP":
    case "SELF":
    case "ADDK":
    case "SUBK":
    case "MULK":
      inst.C = remap[inst.C];
      break;
    case "SETPROP":
      inst.B = remap[inst.B];
      break;
    case "GETENV_PROP":
      inst.B = remap[inst.B];
      inst.C = remap[inst.C];
      break;
  }
}

/**
 * Pass 1: Injects context-matched decoy constants and shuffles each prototype's constant pool.
 */
function scrambleConstants(proto, rng, options) {
  if (options.scrambleConstants === false) return;

  if (options.bogusBlocks !== false) {
    const origConsts = proto.constants.slice();
    const numDecoys = rng.int(2, 5);
    for (let i = 0; i < numDecoys; i++) {
      if (origConsts.length > 0) {
        const src = rng.pick(origConsts);
        if (src.type === "number") {
          if (Number.isInteger(src.value) && src.value >= 0 && src.value <= 0xffffffff) {
            proto.constants.push({
              type: "number",
              value: (src.value ^ rng.int(1, 255)) >>> 0
            });
          } else {
            proto.constants.push({
              type: "number",
              value: src.value + rng.int(1, 63)
            });
          }
        } else if (src.type === "string") {
          const bytes = Array.from(src.value);
          if (bytes.length >= 2) {
            proto.constants.push({
              type: "string",
              value: Buffer.from(rng.shuffle(bytes))
            });
          } else {
            proto.constants.push({ type: "number", value: rng.nonZeroU32() });
          }
        }
      } else {
        proto.constants.push({ type: "number", value: rng.nonZeroU32() });
      }
    }
  }

  const n = proto.constants.length;
  if (n <= 1) return;

  const order = [];
  for (let i = 0; i < n; i++) order.push(i);
  const shuffledOrder = rng.shuffle(order);

  const newConstants = new Array(n);
  const remap = new Array(n + 1);
  for (let newZeroIdx = 0; newZeroIdx < n; newZeroIdx++) {
    const oldZeroIdx = shuffledOrder[newZeroIdx];
    newConstants[newZeroIdx] = proto.constants[oldZeroIdx];
    remap[oldZeroIdx + 1] = newZeroIdx + 1;
  }

  proto.constants = newConstants;
  for (const item of proto.ir) {
    if (item.kind === "INST") {
      remapConstantOperands(item, remap);
    }
  }
}

/**
 * Pass 2 & 3: Injects path-dependent STATE_BRANCH predicates + context-aware dead decoy blocks,
 * then partitions the IR into self-contained basic blocks and optionally scrambles block layout.
 */
function transformControlFlow(proto, rng, options) {
  let maxLabel = 1;
  for (const item of proto.ir) {
    if (item.kind === "LABEL" && item.id >= maxLabel) maxLabel = item.id + 1;
    if (item.kind === "INST" && item.targetLabel && item.targetLabel >= maxLabel) {
      maxLabel = item.targetLabel + 1;
    }
  }
  const allocLabel = () => maxLabel++;

  // Reserve 2 scratch registers above real maxRegs for harmless decoy block instructions
  const realMaxRegs = Math.max(proto.maxRegs, 1);
  const scratchR1 = realMaxRegs + 1;
  const scratchR2 = realMaxRegs + 2;
  if (options.opaquePredicates !== false) {
    proto.maxRegs = realMaxRegs + 2;
  }

  const numConstIndices = [];
  for (let i = 0; i < proto.constants.length; i++) {
    if (proto.constants[i].type === "number") numConstIndices.push(i + 1);
  }

  const decoyBlocks = [];
  if (options.opaquePredicates !== false) {
    const injectedIR = [];
    const realInstCount = proto.ir.filter((x) => x.kind === "INST").length;
    const prob = realInstCount > 80 ? 0.08 : 0.16;
    let injectedCount = 0;
    const maxInject = options.paranoid ? 14 : 7;

    for (let i = 0; i < proto.ir.length; i++) {
      const item = proto.ir[i];
      if (
        item.kind === "INST" &&
        injectedCount < maxInject &&
        !UNCONDITIONAL_TERMINATORS.has(item.semOp) &&
        rng.bool(prob)
      ) {
        const decoyLbl = allocLabel();
        injectedIR.push({
          kind: "INST",
          semOp: "STATE_BRANCH",
          A: 0,
          B: 0,
          C: 0,
          targetLabel: decoyLbl
        });
        injectedCount++;

        // Synthesize context-aware dead decoy basic block mirroring real register/constant ops
        const decoyItems = [{ kind: "LABEL", id: decoyLbl }];
        if (numConstIndices.length >= 1) {
          decoyItems.push({
            kind: "INST",
            semOp: "LOADK",
            A: scratchR1,
            B: rng.pick(numConstIndices),
            C: 0
          });
          if (numConstIndices.length >= 2) {
            decoyItems.push({
              kind: "INST",
              semOp: "LOADK",
              A: scratchR2,
              B: rng.pick(numConstIndices),
              C: 0
            });
            decoyItems.push({
              kind: "INST",
              semOp: rng.pick(["BIT_BAND", "BIT_BXOR", "ADD", "SUB"]),
              A: scratchR2,
              B: scratchR1,
              C: scratchR2
            });
          } else {
            decoyItems.push({
              kind: "INST",
              semOp: "MOVE",
              A: scratchR2,
              B: rng.int(1, realMaxRegs),
              C: 0
            });
            decoyItems.push({
              kind: "INST",
              semOp: rng.pick(["BIT_BAND", "ADD", "SUB"]),
              A: scratchR2,
              B: scratchR1,
              C: scratchR1
            });
          }
        } else if (proto.constants.length > 0) {
          decoyItems.push({
            kind: "INST",
            semOp: "GETGLOBAL",
            A: scratchR1,
            B: rng.int(1, proto.constants.length),
            C: 0
          });
          decoyItems.push({
            kind: "INST",
            semOp: "MOVE",
            A: scratchR2,
            B: scratchR1,
            C: 0
          });
        } else {
          decoyItems.push({
            kind: "INST",
            semOp: "LOADBOOL",
            A: scratchR1,
            B: rng.int(0, 1),
            C: 0
          });
          decoyItems.push({
            kind: "INST",
            semOp: "NOT",
            A: scratchR2,
            B: scratchR1,
            C: 0
          });
        }
        decoyItems.push({
          kind: "INST",
          semOp: "RETURN",
          A: scratchR2,
          B: 2,
          C: 0
        });
        decoyBlocks.push(decoyItems);
      }
      injectedIR.push(item);
    }

    proto.ir = injectedIR;
  }

  // Always partition IR into strict Basic Blocks (leading LABELs only, ending on UNCONDITIONAL_TERMINATORS)
  const blocks = [];
  let current = [];

  const flushBlock = () => {
    if (current.length > 0) {
      blocks.push(current);
      current = [];
    }
  };

  for (const item of proto.ir) {
    if (item.kind === "LABEL") {
      const hasInst = current.some((x) => x.kind === "INST");
      if (hasInst) flushBlock();
      current.push(item);
    } else {
      current.push(item);
      if (
        CONDITIONAL_BRANCH_OPS.has(item.semOp) ||
        UNCONDITIONAL_TERMINATORS.has(item.semOp)
      ) {
        flushBlock();
      }
    }
  }
  flushBlock();

  for (let b = 0; b < blocks.length; b++) {
    const blk = blocks[b];
    if (blk.length === 0 || blk[0].kind !== "LABEL") {
      blk.unshift({ kind: "LABEL", id: allocLabel() });
    }
  }

  for (let b = 0; b < blocks.length - 1; b++) {
    const blk = blocks[b];
    let lastInst = null;
    for (let k = blk.length - 1; k >= 0; k--) {
      if (blk[k].kind === "INST") {
        lastInst = blk[k];
        break;
      }
    }
    if (!lastInst || !UNCONDITIONAL_TERMINATORS.has(lastInst.semOp)) {
      const nextEntryLabel = blocks[b + 1][0].id;
      blk.push({
        kind: "INST",
        semOp: "JMP",
        A: 0,
        B: 0,
        C: 0,
        targetLabel: nextEntryLabel
      });
    }
  }

  let allBlocks;
  if (options.shuffleBlocks !== false) {
    const entryBlock = blocks[0];
    const restPool = blocks.slice(1).concat(decoyBlocks);
    const shuffledRest = rng.shuffle(restPool);
    allBlocks = entryBlock ? [entryBlock, ...shuffledRest] : shuffledRest;
  } else {
    allBlocks = blocks.concat(decoyBlocks);
  }

  proto.blocks = allBlocks;
  const flat = [];
  for (const blk of allBlocks) {
    for (const item of blk) flat.push(item);
  }
  proto.ir = flat;

  return {
    bogusInstsAdded: decoyBlocks.reduce(
      (s, b) => s + b.filter((x) => x.kind === "INST").length,
      0
    )
  };
}

/**
 * Pass 4 & 5: Path-dependent stateKey encryption across basic blocks and 96-bit word lowering.
 */
function lowerProtoIRToWords(proto, isa, rng, cryptoKeys) {
  const blocks = proto.blocks;
  if (!blocks || blocks.length === 0) {
    throw new Error("Prototype has no basic blocks to lower.");
  }

  // Pass 1: assign each block a fresh 32-bit entryKey, record startPC, and map labels
  const labelMap = new Map();
  let pc = 0;
  for (const blk of blocks) {
    blk.entryKey = rng.nonZeroU32();
    blk.startPC = pc;
    for (const item of blk) {
      if (item.kind === "LABEL") {
        labelMap.set(item.id, { pc: blk.startPC, entryKey: blk.entryKey });
      } else if (item.kind === "INST") {
        pc++;
      }
    }
  }

  if (pc > 0xffff) {
    throw new Error(`Function exceeds 65,535 VM instructions (${pc}).`);
  }

  proto.entryStateKey = blocks[0].entryKey;

  // Pass 2: thread stateKey through each block and encrypt 96-bit instruction words
  const encodedWords = []; // 3 u32 words per instruction: [w0, w1, w2]
  let curPC = 0;

  for (const blk of blocks) {
    let S = blk.entryKey >>> 0;
    for (const item of blk) {
      if (item.kind !== "INST") continue;

      let { A, B, C } = item;
      let raw2 = 0;
      let nextS = S;

      if (item.semOp === "STATE_BRANCH") {
        const tInfo = labelMap.get(item.targetLabel);
        if (!tInfo) {
          throw new Error(`Unresolved STATE_BRANCH label: ${item.targetLabel}`);
        }
        const mask = rng.int(0x0101, 0xffff);
        const trueBits = (S & mask) >>> 0;
        // Flip a bit position that is actually active inside `mask` so (wrongBits & ~mask) == 0
        const setBits = [];
        for (let b = 0; b < 16; b++) {
          if ((mask & (1 << b)) !== 0) setBits.push(b);
        }
        const flipBit = rng.pick(setBits);
        const wrongBits = (trueBits ^ (1 << flipBit)) & 0xffff;

        A = mask;
        B = wrongBits;
        C = (tInfo.pc ^ (S & 0xffff)) & 0xffff;
        raw2 = u32(S ^ tInfo.entryKey);
        nextS = rotl32(S, 7);
      } else if (item.targetLabel !== undefined) {
        const tInfo = labelMap.get(item.targetLabel);
        if (!tInfo) {
          throw new Error(`Unresolved IR jump label: ${item.targetLabel}`);
        }
        const encTarget = (tInfo.pc ^ (S & 0xffff)) & 0xffff;
        raw2 = u32(S ^ tInfo.entryKey);

        switch (item.semOp) {
          case "JMP":
            A = encTarget;
            break;
          case "JMP_TRUE":
          case "JMP_FALSE":
          case "FORPREP":
          case "FORLOOP":
          case "FORGPREP":
            B = encTarget;
            break;
          case "TESTSET_TRUE":
          case "TESTSET_FALSE":
          case "EQ_JMP":
          case "NE_JMP":
          case "LT_JMP":
          case "LE_JMP":
          case "FORGLOOP":
            C = encTarget;
            break;
          default:
            throw new Error(`Unexpected targetLabel on ${item.semOp}`);
        }

        if (CONDITIONAL_BRANCH_OPS.has(item.semOp)) {
          nextS = rotl32(S, 7);
        }
      } else {
        raw2 = rng.nonZeroU32();
        nextS = u32(rotl32(S, 5) ^ raw2);
      }

      const spec = isa.pickSpec(item.semOp);
      const [w0, w1, w2] = encodeInstructionWords(spec, A, B, C, raw2);

      const k0 = u32(rotl32(S, 3) ^ u32(curPC * cryptoKeys.kMul0));
      const k1 = u32(rotr32(S, 11) ^ u32(curPC * cryptoKeys.kMul1));
      const k2 = u32(rotl32(S, 19) ^ k0);

      encodedWords.push(u32(w0 ^ k0), u32(w1 ^ k1), u32(w2 ^ k2));

      S = nextS;
      curPC++;
    }
  }

  proto.encodedWords = encodedWords;
  proto.instCount = curPC;
}

function obfuscateAndLowerModuleIR(irModule, isa, rng, cryptoKeys, options = {}) {
  let totalInstructions = 0;
  let totalBogusInstructions = 0;

  for (const proto of irModule.prototypes) {
    scrambleConstants(proto, rng, options);
    const stats = transformControlFlow(proto, rng, options);
    totalBogusInstructions += stats.bogusInstsAdded;
    lowerProtoIRToWords(proto, isa, rng, cryptoKeys);
    totalInstructions += proto.instCount;
  }

  return {
    totalInstructions,
    totalBogusInstructions
  };
}

module.exports = {
  obfuscateAndLowerModuleIR
};
