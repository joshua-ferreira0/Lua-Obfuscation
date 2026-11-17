"use strict";

const { IdentifierPool, saltedConstExpr } = require("./prng");

/**
 * Encrypts all VM bootstrapper API names ("bit32", "bxor", "buffer", "readu32", etc.)
 * using a pure modular rolling stream cipher so ZERO plaintext API names appear in the output!
 */
function buildEncryptedBootstrapTable(rng) {
  const rawEntries = [
    "bit32",
    "bxor",
    "band",
    "bor",
    "bnot",
    "lrotate",
    "rrotate",
    "lshift",
    "rshift",
    "buffer",
    "create",
    "readu8",
    "readu16",
    "readu32",
    "readf64",
    "writeu8",
    "writeu32",
    "copy",
    "tostring",
    "table",
    "concat",
    "pack",
    "unpack",
    "math",
    "floor",
    "select",
    "tonumber",
    "type",
    "getmetatable",
    "next",
    "error",
    "coroutine",
    "yield",
    "resume",
    "debug",
    "info",
    "[C]",
    "#",
    "l",
    "s",
    "function"
  ];

  const unique = [...new Set(rawEntries)];
  const shuffled = rng.shuffle(unique);
  const indexOf = {};
  shuffled.forEach((str, i) => {
    indexOf[str] = i + 1; // 1-based Luau array index
  });

  const seed = rng.int(19, 251);
  const step = rng.int(37, 241) | 1;
  let st = seed;
  const hexPairs = [];

  function pushByte(b) {
    st = (st * step + 73) % 256;
    const enc = (b + st) & 0xff;
    hexPairs.push(enc.toString(16).padStart(2, "0").toUpperCase());
  }

  for (const s of shuffled) {
    const buf = Buffer.from(s, "utf8");
    pushByte(buf.length);
    for (let i = 0; i < buf.length; i++) {
      pushByte(buf[i]);
    }
  }

  return {
    count: shuffled.length,
    hexBlob: hexPairs.join(""),
    seed,
    step,
    idx: indexOf
  };
}

/**
 * Synthesizes a 100% polymorphic LuaObf Virtual Machine featuring:
 * - Unified shuffled runtime context table U[] initialized in a flattened state machine
 * - 16-element runtime ARX salt table T[1..16] bound to integrity state (eliminates static constant folding)
 * - Keyless String Vault decryption (STR_DECRYPT) + virtualized bit32 ops
 * - Path-dependent 96-bit stateKey ratchet across every basic block and instruction
 * - Permuted Radix-85 CFB stream decryption + flattened outer loader & entry state machine
 */
function generatePolymorphicLuauVM(isa, packed, rng, options = {}) {
  const idStyle = options.idStyle || "luaobf";
  const useMBA = options.mbaConstants !== false;
  const ids = new IdentifierPool(rng, idStyle);
  const cp = packed.cryptoParams;
  const boot = buildEncryptedBootstrapTable(rng);

  // Shuffled unified runtime dispatch table U[1..23] for non-hot helpers & string tokens
  const U_KEYS = [
    "breadu16",
    "breadf64",
    "bwriteu32",
    "bcopy",
    "select",
    "tonumber",
    "tostring",
    "type",
    "getmetatable",
    "next",
    "error",
    "ccreate",
    "cyield",
    "cresume",
    "dbgInfo",
    "fnStr",
    "tblStr",
    "hashStr",
    "cSrcStr",
    "lStr",
    "sStr",
    "mfloor",
    "tconcat"
  ];
  const uSlotsArr = rng.shuffle(U_KEYS.map((_, idx) => idx + 1));
  const U_IDX = {};
  U_KEYS.forEach((k, idx) => {
    U_IDX[k] = uSlotsArr[idx];
  });

  const V = {
    ENV: ids.next(),
    sbyte: ids.next(),
    schar: ids.next(),
    bootTbl: ids.next(),
    U: ids.next(),
    isLuauNative: ids.next(),

    // Fast locals for hot VM operations
    bxor: ids.next(),
    band: ids.next(),
    bor: ids.next(),
    bnot: ids.next(),
    lrot: ids.next(),
    rrot: ids.next(),
    lsh: ids.next(),
    rsh: ids.next(),

    bcreate: ids.next(),
    breadu8: ids.next(),
    breadu32: ids.next(),
    bwriteu8: ids.next(),
    btostr: ids.next(),

    tcreate: ids.next(),
    tpack: ids.next(),
    tunpack: ids.next(),

    T: ids.next(),
    rawBuf: ids.next(),
    protos: ids.next(),
    vaultOffsets: ids.next(),
    vaultLens: ids.next(),
    vaultCache: ids.next(),

    lineA: ids.next(),
    nativeOk: ids.next(),
    lineB: ids.next(),
    integTag: ids.next(),

    iterWrap: ids.next(),
    vaultDecrypt: ids.next(),
    makeClosure: ids.next(),

    mainId: ids.next(),
    protoCount: ids.next(),
    cur: ids.next(),
    outerSt: ids.next(),

    // Per-proto loader vars
    pIdx: ids.next(),
    tSalt: ids.next(),
    pObj: ids.next(),
    nParams: ids.next(),
    isVararg: ids.next(),
    maxRegs: ids.next(),
    entryKey: ids.next(),
    K: ids.next(),
    Kstr: ids.next(),
    kLoad: ids.next(),
    cBuf: ids.next(),
    upDefs: ids.next(),
    childIds: ids.next(),
    secState: ids.next(),

    // Closure runtime variables
    protoArg: ids.next(),
    upvalsArg: ids.next(),
    R: ids.next(),
    top: ids.next(),
    pc: ids.next(),
    stateKey: ids.next(),
    openUpvals: ids.next(),
    closeUpvals: ids.next(),
    totalArgs: ids.next(),
    vList: ids.next(),
    vCount: ids.next(),
    packedArgs: ids.next(),
    copyN: ids.next(),

    // Fetch-decode loop vars
    off: ids.next(),
    k0: ids.next(),
    k1: ids.next(),
    k2: ids.next(),
    w0: ids.next(),
    w1: ids.next(),
    w2: ids.next(),
    vOp: ids.next(),
    vX: ids.next(),
    vY: ids.next(),
    vZ: ids.next()
  };

  const B = (name) => `${V.bootTbl}[${boot.idx[name]}]`;
  const U = (key) => `${V.U}[${U_IDX[key]}]`;
  const C = (n) => saltedConstExpr(n, V.T, cp.T, rng, useMBA);

  // Randomize internal prototype tuple slot indices (1..9) so getgc() sees no named keys
  const pSlots = rng.shuffle([1, 2, 3, 4, 5, 6, 7, 8, 9]);
  const PS_NPARAMS = pSlots[0];
  const PS_VARARG = pSlots[1];
  const PS_MAXREGS = pSlots[2];
  const PS_ENTRYKEY = pSlots[3];
  const PS_K = pSlots[4];
  const PS_KLOAD = pSlots[5];
  const PS_CBUF = pSlots[6];
  const PS_UPDEFS = pSlots[7];
  const PS_CHILDS = pSlots[8];

  function emitOperandBinding(spec, needed) {
    const physVars = [V.vX, V.vY, V.vZ];
    const parts = [];
    const outVars = {};

    if (needed.includes("A")) {
      const vA = ids.next();
      const src = physVars[spec.perm[0]];
      const expr = spec.maskA !== 0 ? `${V.bxor}(${src},${C(spec.maskA)})` : src;
      parts.push(`local ${vA}=${expr};`);
      outVars.A = vA;
    }
    if (needed.includes("B")) {
      const vB = ids.next();
      const src = physVars[spec.perm[1]];
      const expr = spec.maskB !== 0 ? `${V.bxor}(${src},${C(spec.maskB)})` : src;
      parts.push(`local ${vB}=${expr};`);
      outVars.B = vB;
    }
    if (needed.includes("C")) {
      const vC = ids.next();
      const src = physVars[spec.perm[2]];
      const expr = spec.maskC !== 0 ? `${V.bxor}(${src},${C(spec.maskC)})` : src;
      parts.push(`local ${vC}=${expr};`);
      outVars.C = vC;
    }
    return { code: parts.join(""), ...outVars };
  }

  function emitConstLookup(kIdxExpr) {
    return `(${V.K}[${kIdxExpr}] or ${V.kLoad}(${kIdxExpr}))`;
  }

  const advanceLinear = `${V.stateKey}=${V.bxor}(${V.lrot}(${V.stateKey},5),${V.w2});`;
  const skipBranch = `${V.stateKey}=${V.lrot}(${V.stateKey},7);`;
  const takeJump = (targetOp) =>
    `${V.pc}=${V.bxor}(${targetOp},${V.band}(${V.stateKey},65535));${V.stateKey}=${V.bxor}(${V.stateKey},${V.w2});`;

  function generateLeafHandler(spec) {
    const R = V.R;
    const top = V.top;

    switch (spec.semOp) {
      case "__DECOY_HANDLER__": {
        const { code, A, B } = emitOperandBinding(spec, ["A", "B"]);
        return `${code}${R}[${A}]=${V.bxor}(${A},${B});${advanceLinear}`;
      }

      case "LOADNIL": {
        const { code, A, B } = emitOperandBinding(spec, ["A", "B"]);
        const idx = ids.next();
        return `${code}for ${idx}=${A},${B} do ${R}[${idx}]=nil;end;${advanceLinear}`;
      }

      case "LOADBOOL": {
        const { code, A, B } = emitOperandBinding(spec, ["A", "B"]);
        return `${code}${R}[${A}]=(${B}~=0);${advanceLinear}`;
      }

      case "LOADK": {
        const { code, A, B } = emitOperandBinding(spec, ["A", "B"]);
        return `${code}${R}[${A}]=${emitConstLookup(B)};${advanceLinear}`;
      }

      case "MOVE": {
        const { code, A, B } = emitOperandBinding(spec, ["A", "B"]);
        return `${code}${R}[${A}]=${R}[${B}];${advanceLinear}`;
      }

      case "GETGLOBAL": {
        const { code, A, B } = emitOperandBinding(spec, ["A", "B"]);
        return `${code}${R}[${A}]=${V.ENV}[${emitConstLookup(B)}];${advanceLinear}`;
      }

      case "SETGLOBAL": {
        const { code, A, B } = emitOperandBinding(spec, ["A", "B"]);
        return `${code}${V.ENV}[${emitConstLookup(B)}]=${R}[${A}];${advanceLinear}`;
      }

      case "GETUPVAL": {
        const { code, A, B } = emitOperandBinding(spec, ["A", "B"]);
        const u = ids.next();
        return `${code}local ${u}=${V.upvalsArg}[${B}];${R}[${A}]=${u}[1][${u}[2]];${advanceLinear}`;
      }

      case "SETUPVAL": {
        const { code, A, B } = emitOperandBinding(spec, ["A", "B"]);
        const u = ids.next();
        return `${code}local ${u}=${V.upvalsArg}[${B}];${u}[1][${u}[2]]=${R}[${A}];${advanceLinear}`;
      }

      case "CLOSE": {
        const { code, A } = emitOperandBinding(spec, ["A"]);
        return `${code}${V.closeUpvals}(${A});${advanceLinear}`;
      }

      case "NEWTABLE": {
        const { code, A, B } = emitOperandBinding(spec, ["A", "B"]);
        return `${code}${R}[${A}]=${V.tcreate}(${B});${advanceLinear}`;
      }

      case "GETTABLE": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}${R}[${A}]=${R}[${B}][${R}[${cOp}]];${advanceLinear}`;
      }

      case "SETTABLE": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}${R}[${A}][${R}[${B}]]=${R}[${cOp}];${advanceLinear}`;
      }

      case "GETPROP": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}${R}[${A}]=${R}[${B}][${emitConstLookup(cOp)}];${advanceLinear}`;
      }

      case "SETPROP": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}${R}[${A}][${emitConstLookup(B)}]=${R}[${cOp}];${advanceLinear}`;
      }

      case "SETLIST": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        const tbl = ids.next();
        const cnt = ids.next();
        const idx = ids.next();
        return (
          `${code}local ${tbl}=${R}[${A}];` +
          `local ${cnt}=(${B}==0) and (${top}-${A}) or (${B}-1);` +
          `for ${idx}=1,${cnt} do ${tbl}[${cOp}+${idx}]=${R}[${A}+${idx}];end;${advanceLinear}`
        );
      }

      case "SELF": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        const obj = ids.next();
        return `${code}local ${obj}=${R}[${B}];${R}[${A}+1]=${obj};${R}[${A}]=${obj}[${emitConstLookup(cOp)}];${advanceLinear}`;
      }

      case "GETENV_PROP": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}${R}[${A}]=${V.ENV}[${emitConstLookup(B)}][${emitConstLookup(cOp)}];${advanceLinear}`;
      }

      case "ADDK": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}${R}[${A}]=${R}[${B}]+${emitConstLookup(cOp)};${advanceLinear}`;
      }

      case "SUBK": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}${R}[${A}]=${R}[${B}]-${emitConstLookup(cOp)};${advanceLinear}`;
      }

      case "MULK": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}${R}[${A}]=${R}[${B}]*${emitConstLookup(cOp)};${advanceLinear}`;
      }

      case "ADD": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}${R}[${A}]=${R}[${B}]+${R}[${cOp}];${advanceLinear}`;
      }

      case "SUB": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}${R}[${A}]=${R}[${B}]-${R}[${cOp}];${advanceLinear}`;
      }

      case "MUL": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}${R}[${A}]=${R}[${B}]*${R}[${cOp}];${advanceLinear}`;
      }

      case "DIV": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}${R}[${A}]=${R}[${B}]/${R}[${cOp}];${advanceLinear}`;
      }

      case "IDIV": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}${R}[${A}]=${U("mfloor")}(${R}[${B}]/${R}[${cOp}]);${advanceLinear}`;
      }

      case "MOD": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}${R}[${A}]=${R}[${B}]%${R}[${cOp}];${advanceLinear}`;
      }

      case "POW": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}${R}[${A}]=${R}[${B}]^${R}[${cOp}];${advanceLinear}`;
      }

      case "BIT_BAND": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}${R}[${A}]=${V.band}(${R}[${B}],${R}[${cOp}]);${advanceLinear}`;
      }

      case "BIT_BOR": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}${R}[${A}]=${V.bor}(${R}[${B}],${R}[${cOp}]);${advanceLinear}`;
      }

      case "BIT_BXOR": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}${R}[${A}]=${V.bxor}(${R}[${B}],${R}[${cOp}]);${advanceLinear}`;
      }

      case "BIT_BNOT": {
        const { code, A, B } = emitOperandBinding(spec, ["A", "B"]);
        return `${code}${R}[${A}]=${V.bnot}(${R}[${B}]);${advanceLinear}`;
      }

      case "BIT_LSH": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}${R}[${A}]=${V.lsh}(${R}[${B}],${R}[${cOp}]);${advanceLinear}`;
      }

      case "BIT_RSH": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}${R}[${A}]=${V.rsh}(${R}[${B}],${R}[${cOp}]);${advanceLinear}`;
      }

      case "CONCAT": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        const acc = ids.next();
        const idx = ids.next();
        return (
          `${code}if ${cOp}==${B}+1 then ${R}[${A}]=${R}[${B}]..${R}[${cOp}];` +
          `else local ${acc}=${R}[${cOp}];for ${idx}=${cOp}-1,${B},-1 do ${acc}=${R}[${idx}]..${acc};end;${R}[${A}]=${acc};end;${advanceLinear}`
        );
      }

      case "TOSTRING": {
        const { code, A, B } = emitOperandBinding(spec, ["A", "B"]);
        return `${code}${R}[${A}]=${U("tostring")}(${R}[${B}]);${advanceLinear}`;
      }

      case "STR_DECRYPT": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}${R}[${A}]=${V.vaultDecrypt}(${B},${R}[${cOp}]);${advanceLinear}`;
      }

      case "UNM": {
        const { code, A, B } = emitOperandBinding(spec, ["A", "B"]);
        return `${code}${R}[${A}]=- ${R}[${B}];${advanceLinear}`;
      }

      case "NOT": {
        const { code, A, B } = emitOperandBinding(spec, ["A", "B"]);
        return `${code}${R}[${A}]=not ${R}[${B}];${advanceLinear}`;
      }

      case "LEN": {
        const { code, A, B } = emitOperandBinding(spec, ["A", "B"]);
        return `${code}${R}[${A}]=#${R}[${B}];${advanceLinear}`;
      }

      case "JMP": {
        const { code, A } = emitOperandBinding(spec, ["A"]);
        return `${code}${takeJump(A)}`;
      }

      case "JMP_TRUE": {
        const { code, A, B } = emitOperandBinding(spec, ["A", "B"]);
        return `${code}if ${R}[${A}] then ${takeJump(B)}else ${skipBranch}end;`;
      }

      case "JMP_FALSE": {
        const { code, A, B } = emitOperandBinding(spec, ["A", "B"]);
        return `${code}if not ${R}[${A}] then ${takeJump(B)}else ${skipBranch}end;`;
      }

      case "TESTSET_TRUE": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        const val = ids.next();
        return `${code}local ${val}=${R}[${B}];if ${val} then ${R}[${A}]=${val};${takeJump(cOp)}else ${skipBranch}end;`;
      }

      case "TESTSET_FALSE": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        const val = ids.next();
        return `${code}local ${val}=${R}[${B}];if not ${val} then ${R}[${A}]=${val};${takeJump(cOp)}else ${skipBranch}end;`;
      }

      case "EQ": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}${R}[${A}]=(${R}[${B}]==${R}[${cOp}]);${advanceLinear}`;
      }

      case "NE": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}${R}[${A}]=(${R}[${B}]~=${R}[${cOp}]);${advanceLinear}`;
      }

      case "LT": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}${R}[${A}]=(${R}[${B}]<${R}[${cOp}]);${advanceLinear}`;
      }

      case "LE": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}${R}[${A}]=(${R}[${B}]<=${R}[${cOp}]);${advanceLinear}`;
      }

      case "EQ_JMP": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}if ${R}[${A}]==${R}[${B}] then ${takeJump(cOp)}else ${skipBranch}end;`;
      }

      case "NE_JMP": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}if ${R}[${A}]~=${R}[${B}] then ${takeJump(cOp)}else ${skipBranch}end;`;
      }

      case "LT_JMP": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}if ${R}[${A}]<${R}[${B}] then ${takeJump(cOp)}else ${skipBranch}end;`;
      }

      case "LE_JMP": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}if ${R}[${A}]<=${R}[${B}] then ${takeJump(cOp)}else ${skipBranch}end;`;
      }

      case "FORPREP": {
        const { code, A, B } = emitOperandBinding(spec, ["A", "B"]);
        const init = ids.next();
        const lim = ids.next();
        const stp = ids.next();
        const tn = U("tonumber");
        return (
          `${code}local ${init}=${tn}(${R}[${A}]);` +
          `local ${lim}=${tn}(${R}[${A}+1]);` +
          `local ${stp}=${tn}(${R}[${A}+2]);` +
          `${R}[${A}]=${init};${R}[${A}+1]=${lim};${R}[${A}+2]=${stp};` +
          `if (${stp}>0 and ${init}>${lim}) or (${stp}<=0 and ${init}<${lim}) then ${takeJump(B)}` +
          `else ${R}[${A}+3]=${init};${skipBranch}end;`
        );
      }

      case "FORLOOP": {
        const { code, A, B } = emitOperandBinding(spec, ["A", "B"]);
        const stp = ids.next();
        const idx = ids.next();
        const lim = ids.next();
        return (
          `${code}local ${stp}=${R}[${A}+2];` +
          `local ${idx}=${R}[${A}]+${stp};` +
          `local ${lim}=${R}[${A}+1];` +
          `if (${stp}>0 and ${idx}<=${lim}) or (${stp}<=0 and ${idx}>=${lim}) then ` +
          `${R}[${A}]=${idx};${R}[${A}+3]=${idx};${takeJump(B)}else ${skipBranch}end;`
        );
      }

      case "FORGPREP": {
        const { code, A, B: bOp } = emitOperandBinding(spec, ["A", "B"]);
        const gen = ids.next();
        const tf = U("type");
        return (
          `${code}local ${gen}=${R}[${A}];` +
          `if ${tf}(${gen})~=${U("fnStr")} then ` +
          `if ${tf}(${gen})==${U("tblStr")} and ${U("getmetatable")}(${gen})==nil then ` +
          `${R}[${A}+1]=${gen};${R}[${A}]=${U("next")};${R}[${A}+2]=nil;` +
          `else ${R}[${A}]=${V.iterWrap}(${gen},${R}[${A}+1],${R}[${A}+2]);${R}[${A}+1]=nil;${R}[${A}+2]=nil;end;end;` +
          `${takeJump(bOp)}`
        );
      }

      case "FORGLOOP": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        const r1 = ids.next();
        const r2 = ids.next();
        const res = ids.next();
        const idx = ids.next();
        return (
          `${code}if ${B}==2 then ` +
          `local ${r1},${r2}=${R}[${A}](${R}[${A}+1],${R}[${A}+2]);` +
          `${R}[${A}+3]=${r1};${R}[${A}+4]=${r2};` +
          `if ${r1}~=nil then ${R}[${A}+2]=${r1};${takeJump(cOp)}else ${skipBranch}end;` +
          `elseif ${B}==1 then ` +
          `local ${r1}=${R}[${A}](${R}[${A}+1],${R}[${A}+2]);` +
          `${R}[${A}+3]=${r1};` +
          `if ${r1}~=nil then ${R}[${A}+2]=${r1};${takeJump(cOp)}else ${skipBranch}end;` +
          `else ` +
          `local ${res}=${V.tpack}(${R}[${A}](${R}[${A}+1],${R}[${A}+2]));` +
          `local ${r1}=${res}[1];` +
          `for ${idx}=1,${B} do ${R}[${A}+2+${idx}]=${res}[${idx}];end;` +
          `if ${r1}~=nil then ${R}[${A}+2]=${r1};${takeJump(cOp)}else ${skipBranch}end;end;`
        );
      }

      case "CLOSURE": {
        const { code, A, B } = emitOperandBinding(spec, ["A", "B"]);
        const cid = ids.next();
        const cProto = ids.next();
        const defs = ids.next();
        const nu = ids.next();
        const cu = ids.next();
        const idx = ids.next();
        const d = ids.next();
        const cell = ids.next();
        return (
          `${code}local ${cid}=${V.childIds}[${B}];` +
          `local ${cProto}=${V.protos}[${cid}];` +
          `local ${defs}=${cProto}[${PS_UPDEFS}];` +
          `local ${nu}=#${defs};` +
          `local ${cu}=${nu}>0 and ${V.tcreate}(${nu}) or nil;` +
          `for ${idx}=1,${nu} do ` +
          `local ${d}=${defs}[${idx}];` +
          `if ${d}[1] then ` +
          `if not ${V.openUpvals} then ${V.openUpvals}={};end;` +
          `local ${cell}=${V.openUpvals}[${d}[2]];` +
          `if not ${cell} then ${cell}={${R},${d}[2]};${V.openUpvals}[${d}[2]]=${cell};end;` +
          `${cu}[${idx}]=${cell};` +
          `else ${cu}[${idx}]=${V.upvalsArg}[${d}[2]];end;end;` +
          `${R}[${A}]=${V.makeClosure}(${cProto},${cu});${advanceLinear}`
        );
      }

      case "CALL": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        const fn = ids.next();
        const aEnd = ids.next();
        const nArgs = ids.next();
        const ret = ids.next();
        const rn = ids.next();
        const idx = ids.next();
        return (
          `${code}local ${fn}=${R}[${A}];` +
          `local ${aEnd}=(${B}==0) and ${top} or (${A}+${B}-1);` +
          `local ${nArgs}=${aEnd}-${A};` +
          `if ${cOp}==1 then ` +
          `if ${nArgs}<=0 then ${fn}();elseif ${nArgs}==1 then ${fn}(${R}[${A}+1]);elseif ${nArgs}==2 then ${fn}(${R}[${A}+1],${R}[${A}+2]);else ${fn}(${V.tunpack}(${R},${A}+1,${aEnd}));end;` +
          `elseif ${cOp}==2 then ` +
          `if ${nArgs}<=0 then ${R}[${A}]=${fn}();elseif ${nArgs}==1 then ${R}[${A}]=${fn}(${R}[${A}+1]);elseif ${nArgs}==2 then ${R}[${A}]=${fn}(${R}[${A}+1],${R}[${A}+2]);else ${R}[${A}]=${fn}(${V.tunpack}(${R},${A}+1,${aEnd}));end;` +
          `elseif ${cOp}==0 then ` +
          `local ${ret}=${nArgs}<=0 and ${V.tpack}(${fn}()) or ${V.tpack}(${fn}(${V.tunpack}(${R},${A}+1,${aEnd})));` +
          `local ${rn}=${ret}.n;` +
          `for ${idx}=1,${rn} do ${R}[${A}+${idx}-1]=${ret}[${idx}];end;` +
          `${top}=${A}+${rn}-1;` +
          `else ` +
          `local ${ret}=${nArgs}<=0 and ${V.tpack}(${fn}()) or ${V.tpack}(${fn}(${V.tunpack}(${R},${A}+1,${aEnd})));` +
          `for ${idx}=1,${cOp}-1 do ${R}[${A}+${idx}-1]=${ret}[${idx}];end;end;${advanceLinear}`
        );
      }

      case "VARARG": {
        const { code, A, B } = emitOperandBinding(spec, ["A", "B"]);
        const want = ids.next();
        const idx = ids.next();
        return (
          `${code}if ${B}==0 then ` +
          `if ${V.vList} then for ${idx}=1,${V.vCount} do ${R}[${A}+${idx}-1]=${V.vList}[${idx}];end;end;` +
          `${top}=${A}+${V.vCount}-1;` +
          `else local ${want}=${B}-1;` +
          `for ${idx}=1,${want} do if ${idx}<=${V.vCount} and ${V.vList} then ${R}[${A}+${idx}-1]=${V.vList}[${idx}];else ${R}[${A}+${idx}-1]=nil;end;end;end;${advanceLinear}`
        );
      }

      case "RETURN": {
        const { code, A, B } = emitOperandBinding(spec, ["A", "B"]);
        return (
          `${code}${V.closeUpvals}(1);` +
          `if ${B}==1 then return;` +
          `elseif ${B}==2 then return ${R}[${A}];` +
          `elseif ${B}==0 then if ${top}<${A} then return;end;return ${V.tunpack}(${R},${A},${top});` +
          `else return ${V.tunpack}(${R},${A},${A}+${B}-2);end;`
        );
      }

      case "STATE_BRANCH": {
        const { code, A, B, C: cOp } = emitOperandBinding(spec, ["A", "B", "C"]);
        return `${code}if ${V.band}(${V.stateKey},${A})==${B} then ${takeJump(cOp)}else ${skipBranch}end;`;
      }

      default:
        throw new Error(`Missing Luau VM codegen for semantic opcode: ${spec.semOp}`);
    }
  }

  const sortedSpecs = isa.physicalSpecs.slice().sort((a, b) => a.opCode - b.opCode);

  function buildBSTDispatch(lo, hi) {
    if (lo === hi) {
      return generateLeafHandler(sortedSpecs[lo]);
    }
    if (hi - lo === 1) {
      const leftSpec = sortedSpecs[lo];
      const rightSpec = sortedSpecs[hi];
      if (rng.bool(0.5)) {
        return `if ${V.vOp}==${C(leftSpec.opCode)} then ${generateLeafHandler(leftSpec)}else ${generateLeafHandler(rightSpec)}end;`;
      }
      return `if ${V.vOp}==${C(rightSpec.opCode)} then ${generateLeafHandler(rightSpec)}else ${generateLeafHandler(leftSpec)}end;`;
    }
    const mid = (lo + hi) >> 1;
    const pivot = sortedSpecs[mid].opCode;
    const leftCode = buildBSTDispatch(lo, mid);
    const rightCode = buildBSTDispatch(mid + 1, hi);

    if (rng.bool(0.5)) {
      return `if ${V.vOp}<=${C(pivot)} then ${leftCode}else ${rightCode}end;`;
    }
    return `if ${V.vOp}>${C(pivot)} then ${rightCode}else ${leftCode}end;`;
  }

  const bstDispatcherCode = buildBSTDispatch(0, sortedSpecs.length - 1);

  // Unique random state IDs across init machine, proto section machine, and outer execution machine
  const usedStates = new Set();
  function allocStateIds(count) {
    const out = [];
    for (let i = 0; i < count; i++) {
      let st = rng.int(17, 991);
      while (usedStates.has(st)) st = rng.int(17, 991);
      usedStates.add(st);
      out.push(st);
    }
    return out;
  }

  // 1. Flattened Initialization State Machine (binds U[] and hot locals; native Luau + pure Lua 5.1-5.4 fallbacks)
  const initIds = allocStateIds(5);
  const INIT_END = initIds[4];
  const initStVar = ids.next();
  const initBranches = rng
    .shuffle([
      {
        st: initIds[0],
        body: (() => {
          const lib = ids.next();
          const mlib = ids.next();
          const selFn = ids.next();
          const hTok = ids.next();
          return (
            `local ${lib}=${V.ENV}[${B("table")}];` +
            `local ${mlib}=${V.ENV}[${B("math")}];` +
            `local ${selFn}=${V.ENV}[${B("select")}];` +
            `local ${hTok}=${B("#")};` +
            `${U("select")}=${selFn};${U("hashStr")}=${hTok};` +
            `${U("mfloor")}=${mlib}[${B("floor")}];` +
            `${U("tconcat")}=${lib}[${B("concat")}];` +
            `${V.tcreate}=${lib}[${B("create")}] or function() return {};end;` +
            `${V.tpack}=${lib}[${B("pack")}] or function(...) return {n=${selFn}(${hTok},...),...};end;` +
            `${V.tunpack}=${lib}[${B("unpack")}] or ${V.ENV}[${B("unpack")}];` +
            `${U("tonumber")}=${V.ENV}[${B("tonumber")}];${U("tostring")}=${V.ENV}[${B("tostring")}];` +
            `${U("type")}=${V.ENV}[${B("type")}];${U("getmetatable")}=${V.ENV}[${B("getmetatable")}];` +
            `${U("next")}=${V.ENV}[${B("next")}];${U("error")}=${V.ENV}[${B("error")}];` +
            `${initStVar}=${initIds[1]};`
          );
        })()
      },
      {
        st: initIds[1],
        body: (() => {
          const lib = ids.next();
          const mf = ids.next();
          const xl = ids.next();
          const a = ids.next();
          const b = ids.next();
          const ha = ids.next();
          const ba = ids.next();
          const hb = ids.next();
          const x = ids.next();
          const y = ids.next();
          const d = ids.next();
          const p = ids.next();
          const q = ids.next();
          const x0 = ids.next();
          const y0 = ids.next();
          const x1 = ids.next();
          const y1 = ids.next();
          const x2 = ids.next();
          const y2 = ids.next();
          const x3 = ids.next();
          const y3 = ids.next();
          return (
            `local ${lib}=${V.ENV}[${B("bit32")}];` +
            `if ${lib} then ` +
            `${V.bxor}=${lib}[${B("bxor")}];${V.band}=${lib}[${B("band")}];${V.bor}=${lib}[${B("bor")}];${V.bnot}=${lib}[${B("bnot")}];` +
            `${V.lrot}=${lib}[${B("lrotate")}];${V.rrot}=${lib}[${B("rrotate")}];${V.lsh}=${lib}[${B("lshift")}];${V.rsh}=${lib}[${B("rshift")}];` +
            `else ` +
            `local ${mf}=${U("mfloor")};local ${xl}={};` +
            `for ${a}=0,255 do local ${ha}=(${a}-${a}%2)/2;local ${ba}=${a}%2;` +
            `for ${b}=0,255 do local ${hb}=(${b}-${b}%2)/2;` +
            `${xl}[${a}*256+${b}]=(${xl}[${ha}*256+${hb}] or 0)*2+((${ba}~=${b}%2) and 1 or 0);end;end;` +
            `${V.bxor}=function(${x},${y}) ${x}=${mf}(${x})%4294967296;${y}=${mf}(${y})%4294967296;` +
            `local ${x0}=${x}%256;local ${y0}=${y}%256;${x}=(${x}-${x0})/256;${y}=(${y}-${y0})/256;` +
            `local ${x1}=${x}%256;local ${y1}=${y}%256;${x}=(${x}-${x1})/256;${y}=(${y}-${y1})/256;` +
            `local ${x2}=${x}%256;local ${y2}=${y}%256;local ${x3}=(${x}-${x2})/256;local ${y3}=(${y}-${y2})/256;` +
            `return ${xl}[${x0}*256+${y0}]+${xl}[${x1}*256+${y1}]*256+${xl}[${x2}*256+${y2}]*65536+${xl}[${x3}*256+${y3}]*16777216;end;` +
            `${V.band}=function(${x},${y}) ${x}=${mf}(${x})%4294967296;${y}=${mf}(${y})%4294967296;return ${mf}(((${x}+${y})-${V.bxor}(${x},${y}))/2);end;` +
            `${V.bor}=function(${x},${y}) ${x}=${mf}(${x})%4294967296;${y}=${mf}(${y})%4294967296;return ${mf}((${x}+${y})-${V.band}(${x},${y}));end;` +
            `${V.bnot}=function(${x}) return 4294967295-(${mf}(${x})%4294967296);end;` +
            `${V.lsh}=function(${x},${d}) ${x}=${mf}(${x})%4294967296;${d}=${mf}(${d});if ${d}<0 then return ${V.rsh}(${x},-${d});end;if ${d}>=32 then return 0;end;local ${p}=2^${d};return ${mf}((${x}%(4294967296/${p}))*${p});end;` +
            `${V.rsh}=function(${x},${d}) ${x}=${mf}(${x})%4294967296;${d}=${mf}(${d});if ${d}<0 then return ${V.lsh}(${x},-${d});end;if ${d}>=32 then return 0;end;return ${mf}(${x}/(2^${d}));end;` +
            `${V.lrot}=function(${x},${d}) ${x}=${mf}(${x})%4294967296;${d}=${mf}(${d})%32;if ${d}==0 then return ${x};end;local ${p}=2^${d};local ${q}=4294967296/${p};return ${mf}((${x}%${q})*${p}+${mf}(${x}/${q}));end;` +
            `${V.rrot}=function(${x},${d}) ${x}=${mf}(${x})%4294967296;${d}=${mf}(${d})%32;if ${d}==0 then return ${x};end;local ${p}=2^${d};local ${q}=4294967296/${p};return ${mf}((${x}%${p})*${q}+${mf}(${x}/${p}));end;` +
            `end;` +
            `${initStVar}=${initIds[2]};`
          );
        })()
      },
      {
        st: initIds[2],
        body: (() => {
          const lib = ids.next();
          const mf = ids.next();
          const tc = ids.next();
          const bf = ids.next();
          const of = ids.next();
          const vl = ids.next();
          const dst = ids.next();
          const src = ids.next();
          const so = ids.next();
          const cnt = ids.next();
          const k = ids.next();
          const b0 = ids.next();
          const b1 = ids.next();
          const b2 = ids.next();
          const lo = ids.next();
          const hi = ids.next();
          const sgn = ids.next();
          const h31 = ids.next();
          const ex = ids.next();
          const mh = ids.next();
          const fr = ids.next();
          const fv = ids.next();
          const iv = ids.next();
          return (
            `local ${lib}=${V.ENV}[${B("buffer")}];` +
            `if ${lib} and ${V.ENV}[${B("bit32")}] then ${V.isLuauNative}=true;else ${V.isLuauNative}=false;end;` +
            `if ${lib} then ` +
            `${V.bcreate}=${lib}[${B("create")}];${V.breadu8}=${lib}[${B("readu8")}];${V.breadu32}=${lib}[${B("readu32")}];${V.bwriteu8}=${lib}[${B("writeu8")}];${V.btostr}=${lib}[${B("tostring")}];` +
            `${U("breadu16")}=${lib}[${B("readu16")}];${U("breadf64")}=${lib}[${B("readf64")}];${U("bwriteu32")}=${lib}[${B("writeu32")}];${U("bcopy")}=${lib}[${B("copy")}];` +
            `else ` +
            `local ${mf}=${U("mfloor")};local ${tc}=${U("tconcat")};` +
            `${V.bcreate}=function(${cnt}) return {n=${cnt}};end;` +
            `${V.breadu8}=function(${bf},${of}) return ${bf}[${of}] or 0;end;` +
            `${V.bwriteu8}=function(${bf},${of},${vl}) ${bf}[${of}]=${mf}(${vl})%256;end;` +
            `${U("breadu16")}=function(${bf},${of}) return (${bf}[${of}] or 0)+(${bf}[${of}+1] or 0)*256;end;` +
            `${V.breadu32}=function(${bf},${of}) return (${bf}[${of}] or 0)+(${bf}[${of}+1] or 0)*256+(${bf}[${of}+2] or 0)*65536+(${bf}[${of}+3] or 0)*16777216;end;` +
            `${U("bwriteu32")}=function(${bf},${of},${vl}) ${vl}=${mf}(${vl})%4294967296;local ${b0}=${vl}%256;${vl}=(${vl}-${b0})/256;local ${b1}=${vl}%256;${vl}=(${vl}-${b1})/256;local ${b2}=${vl}%256;${bf}[${of}]=${b0};${bf}[${of}+1]=${b1};${bf}[${of}+2]=${b2};${bf}[${of}+3]=(${vl}-${b2})/256;end;` +
            `${U("bcopy")}=function(${dst},${of},${src},${so},${cnt}) for ${k}=0,${cnt}-1 do ${dst}[${of}+${k}]=${src}[${so}+${k}] or 0;end;end;` +
            `${V.btostr}=function(${bf}) local ${cnt}=${bf}.n or 0;if ${cnt}==0 then return "";end;local ${dst}={};for ${k}=1,${cnt} do ${dst}[${k}]=${V.schar}(${bf}[${k}-1] or 0);end;return ${tc}(${dst});end;` +
            `${U("breadf64")}=function(${bf},${of}) local ${lo}=${V.breadu32}(${bf},${of});local ${hi}=${V.breadu32}(${bf},${of}+4);local ${sgn}=(${hi}>=2147483648) and -1 or 1;local ${h31}=${hi}%2147483648;local ${ex}=${mf}(${h31}/1048576);local ${mh}=${h31}%1048576;` +
            `if ${ex}==0 and ${mh}==0 and ${lo}==0 then return 0*${sgn};end;` +
            `if ${ex}==2047 then if ${mh}==0 and ${lo}==0 then return ${sgn}*(1/0);end;return 0/0;end;` +
            `local ${fr}=(${mh}*4294967296+${lo})/4503599627370496;` +
            `if ${ex}==0 then return ${sgn}*${fr}*(2^-1022);end;` +
            `local ${fv}=${sgn}*(1+${fr})*(2^(${ex}-1023));` +
            `if ${ex}>=1023 and ${ex}<=1075 then local ${iv}=${mf}(${fv});if ${iv}==${fv} then return ${iv};end;end;` +
            `return ${fv};end;` +
            `end;` +
            `${initStVar}=${initIds[3]};`
          );
        })()
      },
      {
        st: initIds[3],
        body: (() => {
          const co = ids.next();
          const dbg = ids.next();
          return (
            `local ${co}=${V.ENV}[${B("coroutine")}];` +
            `${U("ccreate")}=${co}[${B("create")}];${U("cyield")}=${co}[${B("yield")}];${U("cresume")}=${co}[${B("resume")}];` +
            `local ${dbg}=${V.ENV}[${B("debug")}];` +
            `${U("dbgInfo")}=${dbg} and ${dbg}[${B("info")}];` +
            `${U("fnStr")}=${B("function")};${U("tblStr")}=${B("table")};` +
            `${U("cSrcStr")}=${B("[C]")};${U("lStr")}=${B("l")};${U("sStr")}=${B("s")};` +
            `${initStVar}=${INIT_END};`
          );
        })()
      }
    ])
    .map((b, i) => `${i === 0 ? "if" : "elseif"} ${initStVar}==${b.st} then ${b.body}`)
    .join("") + "end;";

  // 2. Per-Prototype Section Loader State Machine
  const stateIds = allocStateIds(5);
  const END_STATE = stateIds[4];

  function genSectionCode(secType, nextStateVal) {
    if (secType === 0) {
      const kCnt = ids.next();
      const kIdx = ids.next();
      const tag = ids.next();
      const sSeed = ids.next();
      const sLen = ids.next();
      const info = ids.next();
      const sb = ids.next();
      const bi = ids.next();
      const st = ids.next();
      const strVal = ids.next();
      const kArg = ids.next();
      return (
        `local ${kCnt}=${U("breadu16")}(${V.rawBuf},${V.cur});${V.cur}=${V.cur}+2;` +
        `${V.K}=${V.tcreate}(${kCnt});${V.Kstr}={};` +
        `for ${kIdx}=1,${kCnt} do ` +
        `local ${tag}=${V.breadu8}(${V.rawBuf},${V.cur});${V.cur}=${V.cur}+1;` +
        `if ${tag}==1 then ${V.K}[${kIdx}]=${U("breadf64")}(${V.rawBuf},${V.cur});${V.cur}=${V.cur}+8;` +
        `else local ${sSeed}=${V.bxor}(${V.breadu32}(${V.rawBuf},${V.cur}),${V.tSalt});local ${sLen}=${V.breadu32}(${V.rawBuf},${V.cur}+4);${V.cur}=${V.cur}+8;` +
        `${V.Kstr}[${kIdx}]={${V.cur},${sLen},${sSeed}};${V.cur}=${V.cur}+${sLen};end;end;` +
        `local ${info}=${V.Kstr};local ${sb}=${V.K};` +
        `${V.kLoad}=function(${kArg}) ` +
        `local ${st}=${info}[${kArg}];` +
        `local ${sLen}=${st}[2];local ${sSeed}=${st}[3];local ${tag}=${st}[1];` +
        `local ${bi}=${V.bcreate}(${sLen});` +
        `for ${kIdx}=1,${sLen} do ${sSeed}=${V.bxor}(${V.lrot}(${sSeed},5),${kIdx}*${C(cp.sPrime)});` +
        `${V.bwriteu8}(${bi},${kIdx}-1,${V.bxor}(${V.breadu8}(${V.rawBuf},${tag}+${kIdx}-1),${V.band}(${sSeed},255)));end;` +
        `local ${strVal}=${V.btostr}(${bi});${sb}[${kArg}]=${strVal};${info}[${kArg}]=nil;return ${strVal};end;` +
        `${V.secState}=${C(nextStateVal)};`
      );
    } else if (secType === 1) {
      const iCnt = ids.next();
      const bLen = ids.next();
      return (
        `local ${iCnt}=${V.breadu32}(${V.rawBuf},${V.cur});${V.cur}=${V.cur}+4;` +
        `local ${bLen}=${iCnt}*12;` +
        `${V.cBuf}=${V.bcreate}(${bLen});` +
        `if ${bLen}>0 then ${U("bcopy")}(${V.cBuf},0,${V.rawBuf},${V.cur},${bLen});${V.cur}=${V.cur}+${bLen};end;` +
        `${V.secState}=${C(nextStateVal)};`
      );
    } else if (secType === 2) {
      const uCnt = ids.next();
      const uIdx = ids.next();
      const inStk = ids.next();
      const rIdx = ids.next();
      return (
        `local ${uCnt}=${U("breadu16")}(${V.rawBuf},${V.cur});${V.cur}=${V.cur}+2;` +
        `${V.upDefs}=${V.tcreate}(${uCnt});` +
        `for ${uIdx}=1,${uCnt} do ` +
        `local ${inStk}=${V.breadu8}(${V.rawBuf},${V.cur})~=0;` +
        `local ${rIdx}=${U("breadu16")}(${V.rawBuf},${V.cur}+1);${V.cur}=${V.cur}+3;` +
        `${V.upDefs}[${uIdx}]={${inStk},${rIdx}};end;` +
        `${V.secState}=${C(nextStateVal)};`
      );
    } else {
      const pCnt = ids.next();
      const cIdx = ids.next();
      return (
        `local ${pCnt}=${U("breadu16")}(${V.rawBuf},${V.cur});${V.cur}=${V.cur}+2;` +
        `${V.childIds}=${V.tcreate}(${pCnt});` +
        `for ${cIdx}=1,${pCnt} do ` +
        `${V.childIds}[${cIdx}]=${U("breadu16")}(${V.rawBuf},${V.cur});${V.cur}=${V.cur}+2;end;` +
        `${V.secState}=${C(nextStateVal)};`
      );
    }
  }

  const stateBranches = [0, 1, 2, 3].map((stepIdx) => ({
    stateVal: stateIds[stepIdx],
    body: genSectionCode(cp.sectionOrder[stepIdx], stateIds[stepIdx + 1])
  }));
  const visualStateBranches = rng.shuffle(stateBranches);
  const loaderBranchesCode =
    visualStateBranches
      .map(
        (b, i) =>
          `${i === 0 ? "if" : "elseif"} ${V.secState}==${C(b.stateVal)} then ${b.body}`
      )
      .join("") + `else (${V.rawBuf})();end;`;

  // Generalized iterator coroutine helper
  const iwObj = ids.next();
  const iwSt = ids.next();
  const iwCt = ids.next();
  const iwCo = ids.next();
  const iwOk = ids.next();
  const iv1 = ids.next();
  const iv2 = ids.next();
  const iv3 = ids.next();
  const iv4 = ids.next();
  const iv5 = ids.next();
  const iv6 = ids.next();

  const iterWrapCode =
    `local function ${V.iterWrap}(${iwObj},${iwSt},${iwCt}) ` +
    `local ${iwCo}=${U("ccreate")}(function() ` +
    `for ${iv1},${iv2},${iv3},${iv4},${iv5},${iv6} in ${iwObj},${iwSt},${iwCt} do ` +
    `${U("cyield")}(${iv1},${iv2},${iv3},${iv4},${iv5},${iv6});end;end);` +
    `return function() ` +
    `local ${iwOk},${iv1},${iv2},${iv3},${iv4},${iv5},${iv6}=${U("cresume")}(${iwCo});` +
    `if not ${iwOk} then ${U("error")}(${iv1},0);end;` +
    `return ${iv1},${iv2},${iv3},${iv4},${iv5},${iv6};end;end;`;

  // Keyless String Vault lazy/cached decryptor
  const vdIdx = ids.next();
  const vdKey = ids.next();
  const vdCached = ids.next();
  const vdLen = ids.next();
  const vdOff = ids.next();
  const vdBi = ids.next();
  const vdSt = ids.next();
  const vdIter = ids.next();
  const vdOut = ids.next();

  const vaultDecryptCode =
    `local function ${V.vaultDecrypt}(${vdIdx},${vdKey}) ` +
    `local ${vdCached}=${V.vaultCache}[${vdIdx}];` +
    `if ${vdCached}~=nil then return ${vdCached};end;` +
    `local ${vdLen}=${V.vaultLens}[${vdIdx}];` +
    `local ${vdOff}=${V.vaultOffsets}[${vdIdx}];` +
    `local ${vdBi}=${V.bcreate}(${vdLen});` +
    `local ${vdSt}=${vdKey};` +
    `for ${vdIter}=1,${vdLen} do ` +
    `${vdSt}=${V.bxor}(${V.lrot}(${vdSt},5),${vdIter}*${C(cp.vPrime)});` +
    `${V.bwriteu8}(${vdBi},${vdIter}-1,${V.bxor}(${V.breadu8}(${V.rawBuf},${vdOff}+${vdIter}-1),${V.band}(${vdSt},255)));` +
    `end;` +
    `local ${vdOut}=${V.btostr}(${vdBi});` +
    `${V.vaultCache}[${vdIdx}]=${vdOut};` +
    `return ${vdOut};end;`;

  // Anti-tamper anchors (before and after makeClosure/BST dispatcher)
  const magicMask = rng.nonZeroU32();
  const encMagic = (cp.integrityMagic ^ magicMask) >>> 0;

  let antiTamperAnchorTop = "";
  let antiTamperComputeBottom = `local ${V.integTag}=0;`;
  if (cp.antiTamper) {
    antiTamperAnchorTop =
      `local ${V.lineA}=${U("dbgInfo")} and ${U("dbgInfo")}(1,${U("lStr")}) or 0;` +
      `local ${V.nativeOk}=(${U("dbgInfo")}==nil) or (not ${V.isLuauNative}) or (${U("dbgInfo")}(${V.bxor},${U("sStr")})==${U("cSrcStr")} and ${U("dbgInfo")}(${V.sbyte},${U("sStr")})==${U("cSrcStr")} and ${U("dbgInfo")}(${V.breadu32},${U("sStr")})==${U("cSrcStr")});`;
    antiTamperComputeBottom =
      `local ${V.lineB}=${U("dbgInfo")} and ${U("dbgInfo")}(1,${U("lStr")}) or 0;` +
      `local ${V.integTag}=${V.bxor}(${encMagic},${magicMask})+(${V.lineB}-${V.lineA})*257+(${V.nativeOk} and 0 or 9991);`;
  }

  // Pre-T computation for 16-element runtime salt table T[1..16]
  const sp = cp.saltParams;
  const txVar = ids.next();
  const tyVar = ids.next();
  const tIdxVar = ids.next();
  const tRndVar = ids.next();
  const seedAMask = rng.nonZeroU32();
  const seedBMask = rng.nonZeroU32();
  const mulStepMask = rng.nonZeroU32();

  const saltComputeCode =
    `${V.T}=${V.tcreate}(16);` +
    `do ` +
    `local ${txVar}=(${V.bxor}(${(sp.seedA ^ seedAMask) >>> 0},${seedAMask})+${V.integTag}*${V.bxor}(${(sp.mulStep ^ mulStepMask) >>> 0},${mulStepMask}))%4294967296;` +
    `local ${tyVar}=${V.bxor}(${V.bxor}(${(sp.seedB ^ seedBMask) >>> 0},${seedBMask}),${V.lrot}(${txVar},11));` +
    `for ${tIdxVar}=1,16 do ` +
    `for ${tRndVar}=1,4 do ` +
    `${txVar}=${V.bxor}(${V.bxor}(${V.lrot}(${txVar},7),${tyVar}),(${tIdxVar}*17+${tRndVar})*${V.bxor}(${(sp.mulStep ^ mulStepMask) >>> 0},${mulStepMask}));` +
    `${tyVar}=${V.bxor}(${V.rrot}(${tyVar},5),${txVar});` +
    `end;` +
    `${V.T}[${tIdxVar}]=${txVar};` +
    `end;end;`;

  // Pure arithmetic bootstrapper inside scoped do..end
  const bootHex = ids.next();
  const bootCur = ids.next();
  const bootSt = ids.next();
  const bootDecByte = ids.next();
  const iVar = ids.next();
  const jVar = ids.next();
  const bLenVar = ids.next();
  const charsTmp = ids.next();
  const hiN = ids.next();
  const loN = ids.next();

  const bootstrapCode = [
    `local ${V.sbyte},${V.schar}=string.byte,string.char;`,
    `local ${V.bootTbl}={};`,
    `do `,
    `local ${bootHex}="${boot.hexBlob}";`,
    `local ${bootCur}=1;`,
    `local ${bootSt}=${boot.seed};`,
    `local function ${bootDecByte}() `,
    `local ${hiN},${loN}=${V.sbyte}(${bootHex},${bootCur},${bootCur}+1);`,
    `${bootCur}=${bootCur}+2;`,
    `${hiN}=${hiN}>=65 and (${hiN}-55) or (${hiN}-48);`,
    `${loN}=${loN}>=65 and (${loN}-55) or (${loN}-48);`,
    `${bootSt}=(${bootSt}*${boot.step}+73)%256;`,
    `return (${hiN}*16+${loN}-${bootSt})%256;end;`,
    `for ${iVar}=1,${boot.count} do `,
    `local ${bLenVar}=${bootDecByte}();`,
    `local ${charsTmp}={};`,
    `for ${jVar}=1,${bLenVar} do ${charsTmp}[${jVar}]=${V.schar}(${bootDecByte}());end;`,
    `local ${loN}="";for ${jVar}=1,${bLenVar} do ${loN}=${loN}..${charsTmp}[${jVar}];end;`,
    `${V.bootTbl}[${iVar}]=${loN};end;`,
    `end;`
  ].join("");

  // 3. Flattened Outer Loader & Entry Execution State Machine (4 states)
  const outerIds = allocStateIds(4);
  const dp = cp.digitPerm;

  const outerState0 = (() => {
    const alphaStr = ids.next();
    const payloadStr = ids.next();
    const lut = ids.next();
    const s0 = ids.next();
    const s1 = ids.next();
    const pos = ids.next();
    const wi = ids.next();
    const b0 = ids.next();
    const b1 = ids.next();
    const b2 = ids.next();
    const b3 = ids.next();
    const b4 = ids.next();
    const cWord = ids.next();
    const pWord = ids.next();
    const bVars = [b0, b1, b2, b3, b4];
    const wordRecon =
      `${lut}[${bVars[dp[0]]}]+` +
      `${lut}[${bVars[dp[1]]}]*85+` +
      `${lut}[${bVars[dp[2]]}]*7225+` +
      `${lut}[${bVars[dp[3]]}]*614125+` +
      `${lut}[${bVars[dp[4]]}]*52200625`;

    return (
      `local ${alphaStr}="${packed.alphabet}";` +
      `local ${payloadStr}="${packed.encodedPayload}";` +
      `local ${lut}=${V.tcreate}(128);` +
      `for ${wi}=1,85 do ${lut}[${V.sbyte}(${alphaStr},${wi})]=${wi}-1;end;` +
      `${V.rawBuf}=${V.bcreate}(${C(packed.wordCount * 4)});` +
      `local ${s0}=${V.bxor}(${C(cp.masterK0)},${V.T}[16]);` +
      `local ${s1}=${V.bxor}(${C(cp.masterK1)},${V.T}[15]);` +
      `local ${pos}=${C(packed.prefixLen + 1)};` +
      `for ${wi}=0,${C(packed.wordCount - 1)} do ` +
      `local ${b0},${b1},${b2},${b3},${b4}=${V.sbyte}(${payloadStr},${pos},${pos}+4);` +
      `${pos}=${pos}+5;` +
      `local ${cWord}=${wordRecon};` +
      `${s0}=${V.bxor}(${V.bxor}(${V.lrot}(${s0},${C(cp.outerRotA)}),${s1}),${V.band}(${wi},65535)*${C(cp.outerPrime)});` +
      `${s1}=${V.bxor}(${V.rrot}(${s1},${C(cp.outerRotB)}),${s0});` +
      `local ${pWord}=${V.bxor}(${cWord},${s0});` +
      `${s1}=${V.bxor}(${s1},${cWord});` +
      `${U("bwriteu32")}(${V.rawBuf},${wi}*4,${pWord});` +
      `end;` +
      `${V.outerSt}=${C(outerIds[1])};`
    );
  })();

  const outerState1 = (() => {
    const vCnt = ids.next();
    const vi = ids.next();
    const vl = ids.next();
    return (
      `${V.mainId}=${V.bxor}(${U("breadu16")}(${V.rawBuf},0),${V.band}(${V.T}[1],65535));` +
      `${V.protoCount}=${V.bxor}(${U("breadu16")}(${V.rawBuf},2),${V.band}(${V.T}[2],65535));` +
      `local ${vCnt}=${V.bxor}(${U("breadu16")}(${V.rawBuf},4),${V.band}(${V.T}[3],65535));` +
      `${V.cur}=6;` +
      `${V.vaultOffsets}=${V.tcreate}(${vCnt});` +
      `${V.vaultLens}=${V.tcreate}(${vCnt});` +
      `${V.vaultCache}=${V.tcreate}(${vCnt});` +
      `for ${vi}=1,${vCnt} do ` +
      `local ${vl}=${V.breadu32}(${V.rawBuf},${V.cur});${V.cur}=${V.cur}+4;` +
      `${V.vaultOffsets}[${vi}]=${V.cur};` +
      `${V.vaultLens}[${vi}]=${vl};` +
      `${V.cur}=${V.cur}+${vl};` +
      `end;` +
      `${V.protos}=${V.tcreate}(${V.protoCount});` +
      `${V.outerSt}=${C(outerIds[2])};`
    );
  })();

  const outerState2 =
    `for ${V.pIdx}=1,${V.protoCount} do ` +
    `local ${V.tSalt}=${V.T}[((${V.pIdx}-1)%16)+1];` +
    `local ${V.nParams}=${V.breadu8}(${V.rawBuf},${V.cur});` +
    `local ${V.isVararg}=${V.breadu8}(${V.rawBuf},${V.cur}+1)~=0;` +
    `local ${V.maxRegs}=${U("breadu16")}(${V.rawBuf},${V.cur}+2);` +
    `local ${V.entryKey}=${V.bxor}(${V.breadu32}(${V.rawBuf},${V.cur}+4),${V.tSalt});` +
    `${V.cur}=${V.cur}+8;` +
    `local ${V.K},${V.Kstr},${V.kLoad},${V.cBuf},${V.upDefs},${V.childIds};` +
    `local ${V.secState}=${C(stateIds[0])};` +
    `while ${V.secState}~=${C(END_STATE)} do ` +
    loaderBranchesCode +
    `end;` +
    `local ${V.pObj}=${V.tcreate}(9);` +
    `${V.pObj}[${PS_NPARAMS}]=${V.nParams};` +
    `${V.pObj}[${PS_VARARG}]=${V.isVararg};` +
    `${V.pObj}[${PS_MAXREGS}]=${V.maxRegs};` +
    `${V.pObj}[${PS_ENTRYKEY}]=${V.entryKey};` +
    `${V.pObj}[${PS_K}]=${V.K};` +
    `${V.pObj}[${PS_KLOAD}]=${V.kLoad};` +
    `${V.pObj}[${PS_CBUF}]=${V.cBuf};` +
    `${V.pObj}[${PS_UPDEFS}]=${V.upDefs};` +
    `${V.pObj}[${PS_CHILDS}]=${V.childIds};` +
    `${V.protos}[${V.pIdx}]=${V.pObj};` +
    `end;` +
    `${V.outerSt}=${C(outerIds[3])};`;

  const outerState3 = `return ${V.makeClosure}(${V.protos}[${V.mainId}],nil)(...);`;

  const outerBranches = rng
    .shuffle([
      { st: outerIds[0], body: outerState0 },
      { st: outerIds[1], body: outerState1 },
      { st: outerIds[2], body: outerState2 },
      { st: outerIds[3], body: outerState3 }
    ])
    .map(
      (b, i) =>
        `${i === 0 ? "if" : "elseif"} ${V.outerSt}==${C(b.st)} then ${b.body}`
    )
    .join("") + `else (${V.rawBuf})();end;`;

  const minRegArg = ids.next();
  const regKey = ids.next();
  const cellVar = ids.next();
  const argIdx = ids.next();

  const vmBody = [
    `return(function(...)`,
    `local ${V.ENV}=(getfenv and getfenv()) or _ENV or _G;`,
    bootstrapCode,
    `local ${V.U}={};local ${V.isLuauNative};`,
    `local ${V.bxor},${V.band},${V.bor},${V.bnot},${V.lrot},${V.rrot},${V.lsh},${V.rsh};`,
    `local ${V.bcreate},${V.breadu8},${V.breadu32},${V.bwriteu8},${V.btostr};`,
    `local ${V.tcreate},${V.tpack},${V.tunpack};`,
    `do local ${initStVar}=${initIds[0]};while ${initStVar}~=${INIT_END} do ${initBranches}end;end;`,
    `${V.bootTbl}=nil;`,
    `local ${V.T},${V.rawBuf},${V.protos},${V.vaultOffsets},${V.vaultLens},${V.vaultCache};`,
    antiTamperAnchorTop,
    iterWrapCode,
    vaultDecryptCode,

    `local function ${V.makeClosure}(${V.protoArg},${V.upvalsArg}) `,
    `local ${V.nParams}=${V.protoArg}[${PS_NPARAMS}];`,
    `local ${V.isVararg}=${V.protoArg}[${PS_VARARG}];`,
    `local ${V.maxRegs}=${V.protoArg}[${PS_MAXREGS}];`,
    `local ${V.entryKey}=${V.protoArg}[${PS_ENTRYKEY}];`,
    `local ${V.K}=${V.protoArg}[${PS_K}];`,
    `local ${V.kLoad}=${V.protoArg}[${PS_KLOAD}];`,
    `local ${V.cBuf}=${V.protoArg}[${PS_CBUF}];`,
    `local ${V.childIds}=${V.protoArg}[${PS_CHILDS}];`,
    `return function(...) `,
    `local ${V.R}=${V.tcreate}(${V.maxRegs});`,
    `local ${V.top}=0;`,
    `local ${V.totalArgs}=${U("select")}(${U("hashStr")},...);`,
    `local ${V.vList},${V.vCount};`,
    `if ${V.totalArgs}>0 then `,
    `local ${V.packedArgs}=${V.tpack}(...);`,
    `local ${V.copyN}=${V.totalArgs}<${V.nParams} and ${V.totalArgs} or ${V.nParams};`,
    `for ${argIdx}=1,${V.copyN} do ${V.R}[${argIdx}]=${V.packedArgs}[${argIdx}];end;`,
    `if ${V.isVararg} then `,
    `${V.vCount}=${V.totalArgs}-${V.nParams};`,
    `if ${V.vCount}>0 then ${V.vList}=${V.tcreate}(${V.vCount});for ${argIdx}=1,${V.vCount} do ${V.vList}[${argIdx}]=${V.packedArgs}[${V.nParams}+${argIdx}];end;else ${V.vCount}=0;end;`,
    `end;`,
    `else ${V.vCount}=0;end;`,
    `local ${V.openUpvals};`,
    `local function ${V.closeUpvals}(${minRegArg}) `,
    `if ${V.openUpvals} then `,
    `for ${regKey},${cellVar} in ${U("next")},${V.openUpvals} do `,
    `if ${regKey}>=${minRegArg} then ${cellVar}[3]=${cellVar}[1][${cellVar}[2]];${cellVar}[1]=${cellVar};${cellVar}[2]=3;${V.openUpvals}[${regKey}]=nil;end;`,
    `end;end;end;`,
    `local ${V.pc}=0;`,
    `local ${V.stateKey}=${V.entryKey};`,
    `while true do `,
    `local ${V.off}=${V.pc}*12;`,
    `local ${V.k0}=${V.bxor}(${V.lrot}(${V.stateKey},3),${V.pc}*${C(cp.kMul0)});`,
    `local ${V.k1}=${V.bxor}(${V.rrot}(${V.stateKey},11),${V.pc}*${C(cp.kMul1)});`,
    `local ${V.k2}=${V.bxor}(${V.lrot}(${V.stateKey},19),${V.k0});`,
    `local ${V.w0}=${V.bxor}(${V.breadu32}(${V.cBuf},${V.off}),${V.k0});`,
    `local ${V.w1}=${V.bxor}(${V.breadu32}(${V.cBuf},${V.off}+4),${V.k1});`,
    `local ${V.w2}=${V.bxor}(${V.breadu32}(${V.cBuf},${V.off}+8),${V.k2});`,
    `${V.pc}=${V.pc}+1;`,
    `local ${V.vOp}=${V.band}(${V.w0},255);`,
    `local ${V.vX}=${V.rsh}(${V.w0},8);`,
    `local ${V.vY}=${V.band}(${V.w1},65535);`,
    `local ${V.vZ}=${V.rsh}(${V.w1},16);`,
    bstDispatcherCode,
    `end;`,
    `end;end;`,

    antiTamperComputeBottom,
    saltComputeCode,
    `local ${V.mainId},${V.protoCount},${V.cur};`,
    `local ${V.outerSt}=${C(outerIds[0])};`,
    `while true do `,
    outerBranches,
    `end;`,
    `end)(...);`
  ].join("");

  return vmBody;
}

module.exports = {
  generatePolymorphicLuauVM
};
