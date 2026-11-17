"use strict";

/**
 * Semantic opcodes of the LuaObf Custom Register Virtual Machine.
 * All operands (A, B, C) are non-negative 16-bit unsigned integers (0..65535).
 */
const BASE_OPCODES = [
  "LOADNIL",
  "LOADBOOL",
  "LOADK",
  "MOVE",
  "GETGLOBAL",
  "SETGLOBAL",
  "GETUPVAL",
  "SETUPVAL",
  "CLOSE",
  "NEWTABLE",
  "GETTABLE",
  "SETTABLE",
  "GETPROP",
  "SETPROP",
  "SETLIST",
  "SELF",
  "GETENV_PROP",
  "ADDK",
  "SUBK",
  "MULK",
  "ADD",
  "SUB",
  "MUL",
  "DIV",
  "IDIV",
  "MOD",
  "POW",
  "BIT_BAND",
  "BIT_BOR",
  "BIT_BXOR",
  "BIT_BNOT",
  "BIT_LSH",
  "BIT_RSH",
  "CONCAT",
  "TOSTRING",
  "STR_DECRYPT",
  "UNM",
  "NOT",
  "LEN",
  "JMP",
  "JMP_TRUE",
  "JMP_FALSE",
  "TESTSET_TRUE",
  "TESTSET_FALSE",
  "EQ",
  "NE",
  "LT",
  "LE",
  "EQ_JMP",
  "NE_JMP",
  "LT_JMP",
  "LE_JMP",
  "FORPREP",
  "FORLOOP",
  "FORGPREP",
  "FORGLOOP",
  "CLOSURE",
  "CALL",
  "VARARG",
  "RETURN",
  "STATE_BRANCH"
];

// Hot opcodes eligible for polymorphic duplicate handler generation (anti-pattern analysis)
const HOT_DUPLICATABLE_OPS = [
  "LOADK",
  "MOVE",
  "GETGLOBAL",
  "GETPROP",
  "SETPROP",
  "CALL",
  "JMP",
  "ADD",
  "SUB",
  "EQ_JMP",
  "NE_JMP",
  "RETURN",
  "BIT_BAND",
  "BIT_BOR",
  "BIT_LSH",
  "BIT_RSH",
  "STR_DECRYPT"
];

// All 6 permutations of physical instruction slots [X, Y, Z] -> logical [A, B, C]
// perm = [idxForA, idxForB, idxForC] where 0=X, 1=Y, 2=Z
const SLOT_PERMUTATIONS = [
  [0, 1, 2],
  [0, 2, 1],
  [1, 0, 2],
  [1, 2, 0],
  [2, 0, 1],
  [2, 1, 0]
];

/**
 * Generates a unique per-build polymorphic ISA mapping:
 * - Shuffled opcode byte IDs (0..255)
 * - Duplicate mutated opcode variants for hot instructions
 * - Per-opcode physical operand permutations (X, Y, Z <-> A, B, C)
 * - Per-opcode 16-bit operand XOR masks (maskA, maskB, maskC)
 */
function buildPolymorphicISA(rng, options = {}) {
  const duplicateVariants = options.duplicateOps !== false ? (options.paranoid ? 2 : 1) : 0;
  const maskOperands = options.maskOperands !== false;

  const allOpIds = [];
  for (let i = 0; i < 256; i++) allOpIds.push(i);
  const shuffledIds = rng.shuffle(allOpIds);
  let idCursor = 0;

  const variantsBySemantic = new Map();
  const physicalSpecs = [];

  for (const semOp of BASE_OPCODES) {
    const copies = 1 + (HOT_DUPLICATABLE_OPS.includes(semOp) ? duplicateVariants : 0);
    const list = [];
    for (let c = 0; c < copies; c++) {
      const opCode = shuffledIds[idCursor++];
      const perm = rng.pick(SLOT_PERMUTATIONS);
      const maskA = maskOperands ? rng.int(0, 0xffff) : 0;
      const maskB = maskOperands ? rng.int(0, 0xffff) : 0;
      const maskC = maskOperands ? rng.int(0, 0xffff) : 0;
      const spec = {
        opCode,
        semOp,
        variantIndex: c,
        perm,
        maskA,
        maskB,
        maskC
      };
      list.push(spec);
      physicalSpecs.push(spec);
    }
    variantsBySemantic.set(semOp, list);
  }

  // Optional decoy trap opcodes inside the BST to confuse static VM handler lifters
  const decoyCount = options.decoyHandlers ? rng.int(4, 8) : 0;
  for (let d = 0; d < decoyCount && idCursor < 256; d++) {
    physicalSpecs.push({
      opCode: shuffledIds[idCursor++],
      semOp: "__DECOY_HANDLER__",
      variantIndex: d,
      perm: rng.pick(SLOT_PERMUTATIONS),
      maskA: rng.int(0, 0xffff),
      maskB: rng.int(0, 0xffff),
      maskC: rng.int(0, 0xffff)
    });
  }

  return {
    variantsBySemantic,
    physicalSpecs,
    pickSpec(semOp) {
      const list = variantsBySemantic.get(semOp);
      if (!list) throw new Error(`Unknown semantic opcode: ${semOp}`);
      return rng.pick(list);
    }
  };
}

/**
 * Encodes a logical instruction { semOp, A, B, C, aux32 } using a chosen physical `spec`
 * into three raw 32-bit unsigned words [w0, w1, w2] BEFORE path-dependent state encryption.
 *
 * Physical bit layout:
 *   w0 = (opCode & 0xFF) | ((X & 0xFFFFFF) << 8)
 *   w1 = (Y & 0xFFFF) | ((Z & 0xFFFF) << 16)
 *   w2 = aux32 >>> 0 (stateKey ratchet / jump-target key transition delta)
 */
function encodeInstructionWords(spec, A = 0, B = 0, C = 0, aux32 = 0) {
  if (A < 0 || A > 0xffff || B < 0 || B > 0xffff || C < 0 || C > 0xffff) {
    throw new Error(
      `Operand out of 16-bit range for ${spec.semOp}: A=${A}, B=${B}, C=${C}`
    );
  }
  const mA = (A ^ spec.maskA) & 0xffff;
  const mB = (B ^ spec.maskB) & 0xffff;
  const mC = (C ^ spec.maskC) & 0xffff;

  const slots = [0, 0, 0];
  slots[spec.perm[0]] = mA;
  slots[spec.perm[1]] = mB;
  slots[spec.perm[2]] = mC;

  const X = slots[0] >>> 0;
  const Y = slots[1] & 0xffff;
  const Z = slots[2] & 0xffff;

  const w0 = ((spec.opCode & 0xff) | ((X & 0xffffff) << 8)) >>> 0;
  const w1 = ((Y & 0xffff) | ((Z & 0xffff) << 16)) >>> 0;
  const w2 = aux32 >>> 0;
  return [w0, w1, w2];
}

module.exports = {
  BASE_OPCODES,
  HOT_DUPLICATABLE_OPS,
  SLOT_PERMUTATIONS,
  buildPolymorphicISA,
  encodeInstructionWords
};
