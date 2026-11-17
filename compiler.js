"use strict";

/**
 * LuaObf Compiler: Official Roblox Luau AST -> LuaObf Custom Register IR.
 *
 * Conventions:
 * - Registers R[1..maxRegs] are 1-based (fast Luau table.create array part).
 * - Constants K[1..numK] are 1-based; K entries are { type: "nil"|"bool"|"number"|"string", value }.
 *   For strings, `value` is a raw Buffer (exact Luau byte array).
 * - Upvalues U[1..numU] are 1-based; prototype upvalue descriptors are { inStack: boolean, idx: number }.
 * - Child Prototypes P[1..numP] are 1-based indices into module prototype list.
 * - Jump targets in IR use symbolic `targetLabel` IDs resolved to 0-based `pc` after IR obfuscation passes.
 */

function declKey(astLocal) {
  return `${astLocal.name}@${astLocal.location}`;
}

const BIT32_2ARG_OPS = new Set([
  "band",
  "bor",
  "bxor",
  "lshift",
  "rshift",
  "lrotate",
  "rrotate"
]);
const BIT32_1ARG_OPS = new Set(["bnot"]);

function getBit32IntrinsicName(callAst) {
  if (
    !callAst ||
    callAst.type !== "AstExprCall" ||
    callAst.self ||
    !callAst.func ||
    callAst.func.type !== "AstExprIndexName" ||
    !callAst.func.expr ||
    callAst.func.expr.type !== "AstExprGlobal" ||
    callAst.func.expr.global !== "bit32"
  ) {
    return null;
  }
  const name = callAst.func.index;
  const args = callAst.args || [];
  if (BIT32_2ARG_OPS.has(name) && args.length === 2) {
    if (args[0].type === "AstExprVarargs" || args[1].type === "AstExprVarargs") {
      return null;
    }
    if (args[1].type === "AstExprCall" && !getBit32IntrinsicName(args[1])) {
      return null;
    }
    return name;
  }
  if (BIT32_1ARG_OPS.has(name) && args.length === 1) {
    if (args[0].type === "AstExprVarargs") {
      return null;
    }
    if (args[0].type === "AstExprCall" && !getBit32IntrinsicName(args[0])) {
      return null;
    }
    return name;
  }
  return null;
}

/**
 * Pre-pass: identifies every AstLocal declaration captured across a function boundary.
 */
function collectCapturedDecls(rootBlock) {
  const declDepth = new Map();
  const captured = new Set();

  function registerLocal(loc, depth) {
    if (loc && loc.type === "AstLocal") {
      declDepth.set(declKey(loc), depth);
    }
  }

  function walk(node, depth) {
    if (!node || typeof node !== "object") return;

    switch (node.type) {
      case "AstExprFunction": {
        const nextDepth = depth + 1;
        if (node.self) registerLocal(node.self, nextDepth);
        if (node.args) {
          for (const arg of node.args) registerLocal(arg, nextDepth);
        }
        walk(node.body, nextDepth);
        return;
      }
      case "AstStatLocal": {
        if (node.values) {
          for (const v of node.values) walk(v, depth);
        }
        if (node.vars) {
          for (const v of node.vars) registerLocal(v, depth);
        }
        return;
      }
      case "AstStatLocalFunction": {
        registerLocal(node.name, depth);
        walk(node.func, depth);
        return;
      }
      case "AstStatFor": {
        walk(node.from, depth);
        walk(node.to, depth);
        if (node.step) walk(node.step, depth);
        registerLocal(node.var, depth);
        walk(node.body, depth);
        return;
      }
      case "AstStatForIn": {
        if (node.values) {
          for (const v of node.values) walk(v, depth);
        }
        if (node.vars) {
          for (const v of node.vars) registerLocal(v, depth);
        }
        walk(node.body, depth);
        return;
      }
      case "AstExprLocal": {
        const key = declKey(node.local);
        const defD = declDepth.get(key);
        if (defD !== undefined && defD < depth) {
          captured.add(key);
        }
        return;
      }
      default: {
        for (const val of Object.values(node)) {
          if (Array.isArray(val)) {
            for (const item of val) walk(item, depth);
          } else if (val && typeof val === "object") {
            walk(val, depth);
          }
        }
      }
    }
  }

  walk(rootBlock, 0);
  return captured;
}

class FunctionCompiler {
  constructor(moduleCompiler, parent, numParams, isVararg) {
    this.mod = moduleCompiler;
    this.parent = parent;
    this.numParams = numParams;
    this.isVararg = isVararg;

    this.ir = [];
    this.constants = [];
    this.constIndexMap = new Map();
    this.upvalues = []; // { inStack: boolean, idx: number, key: string }
    this.childProtos = []; // 1-based proto IDs in module

    this.nextReg = 1;
    this.maxReg = 1;
    this.nextLabelId = 1;

    // Lexical scopes stack: { savedReg, locals: Map<declKey, reg>, hasCaptured: boolean, minCapturedReg: number }
    this.scopes = [];
    // Active loop stack for break/continue: { breakLabel, continueLabel, scopeDepth }
    this.loops = [];
  }

  newLabel() {
    return this.nextLabelId++;
  }

  markLabel(id) {
    this.ir.push({ kind: "LABEL", id });
  }

  emit(semOp, A = 0, B = 0, C = 0, extra = null) {
    const inst = { kind: "INST", semOp, A, B, C };
    if (extra) Object.assign(inst, extra);
    this.ir.push(inst);
    return inst;
  }

  emitJump(semOp, A, B, targetLabel) {
    return this.emit(semOp, A, B, 0, { targetLabel });
  }

  allocReg(count = 1) {
    const start = this.nextReg;
    this.nextReg += count;
    if (this.nextReg - 1 > this.maxReg) {
      this.maxReg = this.nextReg - 1;
    }
    return start;
  }

  freeRegsTo(regWatermark) {
    this.nextReg = regWatermark;
  }

  pushScope() {
    this.scopes.push({
      savedReg: this.nextReg,
      locals: new Map(),
      hasCaptured: false,
      minCapturedReg: Infinity
    });
  }

  popScope(emitClose = true) {
    const scope = this.scopes.pop();
    if (emitClose && scope.hasCaptured) {
      this.emit("CLOSE", scope.minCapturedReg, 0, 0);
    }
    this.freeRegsTo(scope.savedReg);
  }

  declareLocal(astLocal, existingReg = null) {
    const reg = existingReg !== null ? existingReg : this.allocReg(1);
    const key = declKey(astLocal);
    const topScope = this.scopes[this.scopes.length - 1];
    topScope.locals.set(key, reg);
    if (this.mod.capturedDecls.has(key)) {
      topScope.hasCaptured = true;
      if (reg < topScope.minCapturedReg) {
        topScope.minCapturedReg = reg;
      }
    }
    return reg;
  }

  /**
   * Emits CLOSE if any scope from `fromScopeIdx`..end has captured locals (used before break/continue/return).
   */
  emitCloseFromScopeIndex(fromScopeIdx) {
    let minCap = Infinity;
    for (let i = fromScopeIdx; i < this.scopes.length; i++) {
      if (this.scopes[i].hasCaptured && this.scopes[i].minCapturedReg < minCap) {
        minCap = this.scopes[i].minCapturedReg;
      }
    }
    if (minCap !== Infinity) {
      this.emit("CLOSE", minCap, 0, 0);
    }
  }

  resolveLocalReg(key) {
    for (let i = this.scopes.length - 1; i >= 0; i--) {
      const reg = this.scopes[i].locals.get(key);
      if (reg !== undefined) return reg;
    }
    return null;
  }

  resolveUpvalue(key) {
    for (let i = 0; i < this.upvalues.length; i++) {
      if (this.upvalues[i].key === key) return i + 1; // 1-based
    }
    if (!this.parent) return null;

    const parentLocal = this.parent.resolveLocalReg(key);
    if (parentLocal !== null) {
      this.upvalues.push({ inStack: true, idx: parentLocal, key });
      return this.upvalues.length;
    }

    const parentUpval = this.parent.resolveUpvalue(key);
    if (parentUpval !== null) {
      this.upvalues.push({ inStack: false, idx: parentUpval, key });
      return this.upvalues.length;
    }

    return null;
  }

  addNumberConst(num) {
    // Distinguish -0 and +0 as well as NaN safely
    const mapKey = Object.is(num, -0) ? "num:-0" : `num:${num}`;
    const existing = this.constIndexMap.get(mapKey);
    if (existing !== undefined) return existing;
    this.constants.push({ type: "number", value: num });
    const idx = this.constants.length; // 1-based
    this.constIndexMap.set(mapKey, idx);
    return idx;
  }

  addStringConstFromLatin1(latin1Str) {
    const mapKey = `str:${latin1Str}`;
    const existing = this.constIndexMap.get(mapKey);
    if (existing !== undefined) return existing;
    const rawBuf = Buffer.from(latin1Str, "latin1");
    this.constants.push({ type: "string", value: rawBuf });
    const idx = this.constants.length; // 1-based
    this.constIndexMap.set(mapKey, idx);
    return idx;
  }

  addStringConstAscii(asciiStr) {
    return this.addStringConstFromLatin1(Buffer.from(asciiStr, "utf8").toString("latin1"));
  }
}

class ModuleCompiler {
  constructor(rootAst, rng = null, options = {}) {
    this.rootAst = rootAst;
    this.rng = rng;
    this.options = options;
    this.capturedDecls = collectCapturedDecls(rootAst);
    this.prototypes = [];
    this.stringVault = [];
  }

  addVaultString(rawBuf) {
    const seed = this.rng ? this.rng.nonZeroU32() : 0x5a5a5a5a;
    this.stringVault.push({ rawBuf, seed });
    return { vaultIdx: this.stringVault.length, seed };
  }

  emitLoadSynthesizedInt(fc, dstReg, intVal) {
    if (
      this.options.splitConstants !== false &&
      this.rng &&
      Number.isInteger(intVal) &&
      !Object.is(intVal, -0)
    ) {
      if (intVal >= 0 && intVal <= 0xffffffff && this.rng.bool(0.6)) {
        const m1 = this.rng.nonZeroU32();
        const m2 = (intVal ^ m1) >>> 0;
        const saved = fc.nextReg;
        const r1 = fc.allocReg(1);
        const r2 = fc.allocReg(1);
        fc.emit("LOADK", r1, fc.addNumberConst(m1), 0);
        fc.emit("LOADK", r2, fc.addNumberConst(m2), 0);
        if (this.rng.bool(0.5)) {
          fc.emit("BIT_BXOR", dstReg, r1, r2);
        } else {
          fc.emit("BIT_BOR", dstReg, r1, r2);
          fc.emit("BIT_BAND", r1, r1, r2);
          fc.emit("SUB", dstReg, dstReg, r1);
        }
        fc.freeRegsTo(saved);
        return;
      }
      if (Math.abs(intVal) <= 0x3fffffffffff) {
        const delta = this.rng.int(1000, 900000);
        const kSum = fc.addNumberConst(intVal + delta);
        const kDelta = fc.addNumberConst(delta);
        fc.emit("LOADK", dstReg, kSum, 0);
        fc.emit("SUBK", dstReg, dstReg, kDelta);
        return;
      }
    }
    const k = fc.addNumberConst(intVal);
    fc.emit("LOADK", dstReg, k, 0);
  }

  emitLoadVaultString(fc, dstReg, latin1Str) {
    if (
      this.options.splitConstants !== false &&
      this.rng &&
      this.stringVault.length < 65530
    ) {
      const rawBuf = Buffer.from(latin1Str, "latin1");
      if (rawBuf.length >= 6) {
        const mid = this.rng.int(2, rawBuf.length - 2);
        const part1 = rawBuf.subarray(0, mid);
        const part2 = rawBuf.subarray(mid);
        const saved = fc.nextReg;
        const pairBase = fc.allocReg(2);
        const kReg = fc.allocReg(1);

        const v1 = this.addVaultString(part1);
        this.emitLoadSynthesizedInt(fc, kReg, v1.seed);
        fc.emit("STR_DECRYPT", pairBase, v1.vaultIdx, kReg);

        const v2 = this.addVaultString(part2);
        this.emitLoadSynthesizedInt(fc, kReg, v2.seed);
        fc.emit("STR_DECRYPT", pairBase + 1, v2.vaultIdx, kReg);

        fc.emit("CONCAT", dstReg, pairBase, pairBase + 1);
        fc.freeRegsTo(saved);
        return;
      }
      const saved = fc.nextReg;
      const v = this.addVaultString(rawBuf);
      const kReg = fc.allocReg(1);
      this.emitLoadSynthesizedInt(fc, kReg, v.seed);
      fc.emit("STR_DECRYPT", dstReg, v.vaultIdx, kReg);
      fc.freeRegsTo(saved);
      return;
    }
    const k = fc.addStringConstFromLatin1(latin1Str);
    fc.emit("LOADK", dstReg, k, 0);
  }

  isMultretExpr(expr) {
    if (expr.type === "AstExprVarargs") return true;
    if (expr.type === "AstExprCall") {
      return !(
        this.options.virtualizeBit32 !== false &&
        getBit32IntrinsicName(expr) !== null
      );
    }
    return false;
  }

  compile() {
    const mainProtoId = this.compileProto(null, [], null, true, this.rootAst);
    return {
      prototypes: this.prototypes,
      mainProtoId, // 1-based
      stringVault: this.stringVault
    };
  }

  compileProto(parentFC, argsAst, selfAst, isVararg, bodyBlockAst) {
    const paramLocals = [];
    if (selfAst) paramLocals.push(selfAst);
    if (argsAst) {
      for (const a of argsAst) paramLocals.push(a);
    }

    const fc = new FunctionCompiler(this, parentFC, paramLocals.length, isVararg);
    fc.pushScope();

    for (const p of paramLocals) {
      fc.declareLocal(p);
    }

    this.compileBlockBody(fc, bodyBlockAst);

    // Ensure implicit trailing RETURN 0 values
    fc.emitCloseFromScopeIndex(0);
    fc.emit("RETURN", 1, 1, 0);
    fc.popScope(false);

    const protoObj = {
      numParams: fc.numParams,
      isVararg: fc.isVararg,
      maxRegs: Math.max(fc.maxReg, 2),
      ir: fc.ir,
      constants: fc.constants,
      upvalues: fc.upvalues.map((u) => ({ inStack: u.inStack, idx: u.idx })),
      childProtos: fc.childProtos
    };

    this.prototypes.push(protoObj);
    return this.prototypes.length; // 1-based ID
  }

  compileBlockScoped(fc, blockAst) {
    fc.pushScope();
    this.compileBlockBody(fc, blockAst);
    fc.popScope(true);
  }

  compileBlockBody(fc, blockAst) {
    if (!blockAst || !blockAst.body) return;
    for (const stmt of blockAst.body) {
      this.compileStmt(fc, stmt);
    }
  }

  compileStmt(fc, stmt) {
    if (!stmt) return;

    switch (stmt.type) {
      case "AstStatTypeAlias":
      case "AstStatTypeFunction":
        // Erase compile-time Luau static type declarations
        return;

      case "AstStatBlock":
        this.compileBlockScoped(fc, stmt);
        return;

      case "AstStatLocal":
        this.compileStatLocal(fc, stmt);
        return;

      case "AstStatLocalFunction":
        this.compileStatLocalFunction(fc, stmt);
        return;

      case "AstStatFunction":
        this.compileStatFunction(fc, stmt);
        return;

      case "AstStatAssign":
        this.compileStatAssign(fc, stmt);
        return;

      case "AstStatCompoundAssign":
        this.compileStatCompoundAssign(fc, stmt);
        return;

      case "AstStatExpr": {
        const saved = fc.nextReg;
        if (stmt.expr.type === "AstExprCall") {
          this.compileCallExpr(fc, stmt.expr, null, 0);
        } else {
          const tmp = fc.allocReg(1);
          this.compileExprToReg(fc, stmt.expr, tmp);
        }
        fc.freeRegsTo(saved);
        return;
      }

      case "AstStatIf":
        this.compileStatIf(fc, stmt);
        return;

      case "AstStatWhile":
        this.compileStatWhile(fc, stmt);
        return;

      case "AstStatRepeat":
        this.compileStatRepeat(fc, stmt);
        return;

      case "AstStatFor":
        this.compileStatFor(fc, stmt);
        return;

      case "AstStatForIn":
        this.compileStatForIn(fc, stmt);
        return;

      case "AstStatBreak": {
        if (fc.loops.length === 0) throw new Error("`break` outside loop.");
        const loop = fc.loops[fc.loops.length - 1];
        fc.emitCloseFromScopeIndex(loop.scopeDepth);
        fc.emitJump("JMP", 0, 0, loop.breakLabel);
        return;
      }

      case "AstStatContinue": {
        if (fc.loops.length === 0) throw new Error("`continue` outside loop.");
        const loop = fc.loops[fc.loops.length - 1];
        // Close inner body scopes inside the loop; the loop's own continueLabel handles closing loop-header vars
        fc.emitCloseFromScopeIndex(loop.bodyInnerScopeDepth);
        fc.emitJump("JMP", 0, 0, loop.continueLabel);
        return;
      }

      case "AstStatReturn":
        this.compileStatReturn(fc, stmt);
        return;

      default:
        throw new Error(`Unsupported Luau statement AST node: ${stmt.type}`);
    }
  }

  compileStatLocal(fc, stmt) {
    const vars = stmt.vars || [];
    const values = stmt.values || [];
    const nVars = vars.length;

    if (nVars === 0) return;

    // Allocate target registers first, evaluate RHS BEFORE binding names into lexical scope
    // (so `local x = x + 1` reads outer `x`, matching Lua/Luau scoping!)
    const baseReg = fc.allocReg(nVars);
    this.evalExprListIntoRegs(fc, values, baseReg, nVars);

    for (let i = 0; i < nVars; i++) {
      fc.declareLocal(vars[i], baseReg + i);
    }
  }

  compileStatLocalFunction(fc, stmt) {
    // `local function f()` binds `f` BEFORE compiling the body so recursive calls resolve to `f`
    const reg = fc.declareLocal(stmt.name);
    this.compileFunctionExprToReg(fc, stmt.func, reg);
  }

  compileStatFunction(fc, stmt) {
    const saved = fc.nextReg;
    const prep = this.prepareLValue(fc, stmt.name);
    const valReg = fc.allocReg(1);
    this.compileFunctionExprToReg(fc, stmt.func, valReg);
    this.storePreparedLValue(fc, prep, valReg);
    fc.freeRegsTo(saved);
  }

  prepareLValue(fc, lhs) {
    if (lhs.type === "AstExprLocal") {
      const key = declKey(lhs.local);
      const localReg = fc.resolveLocalReg(key);
      if (localReg !== null) {
        return { kind: "local", reg: localReg };
      }
      const upIdx = fc.resolveUpvalue(key);
      if (upIdx !== null) {
        return { kind: "upval", upIdx };
      }
      throw new Error(`Unresolved local variable: ${lhs.local.name}`);
    }

    if (lhs.type === "AstExprGlobal") {
      const kIdx = fc.addStringConstAscii(lhs.global);
      return { kind: "global", kIdx };
    }

    if (lhs.type === "AstExprIndexName") {
      const objReg = fc.allocReg(1);
      this.compileExprToReg(fc, lhs.expr, objReg);
      const kIdx = fc.addStringConstAscii(lhs.index);
      return { kind: "prop", objReg, kIdx };
    }

    if (lhs.type === "AstExprIndexExpr") {
      const objReg = fc.allocReg(1);
      this.compileExprToReg(fc, lhs.expr, objReg);
      const keyReg = fc.allocReg(1);
      this.compileExprToReg(fc, lhs.index, keyReg);
      return { kind: "index", objReg, keyReg };
    }

    throw new Error(`Invalid assignment target AST node: ${lhs.type}`);
  }

  loadPreparedLValue(fc, prep, dstReg) {
    switch (prep.kind) {
      case "local":
        if (dstReg !== prep.reg) fc.emit("MOVE", dstReg, prep.reg, 0);
        return;
      case "upval":
        fc.emit("GETUPVAL", dstReg, prep.upIdx, 0);
        return;
      case "global":
        fc.emit("GETGLOBAL", dstReg, prep.kIdx, 0);
        return;
      case "prop":
        fc.emit("GETPROP", dstReg, prep.objReg, prep.kIdx);
        return;
      case "index":
        fc.emit("GETTABLE", dstReg, prep.objReg, prep.keyReg);
        return;
    }
  }

  storePreparedLValue(fc, prep, srcReg) {
    switch (prep.kind) {
      case "local":
        if (srcReg !== prep.reg) fc.emit("MOVE", prep.reg, srcReg, 0);
        return;
      case "upval":
        fc.emit("SETUPVAL", srcReg, prep.upIdx, 0);
        return;
      case "global":
        fc.emit("SETGLOBAL", srcReg, prep.kIdx, 0);
        return;
      case "prop":
        fc.emit("SETPROP", prep.objReg, prep.kIdx, srcReg);
        return;
      case "index":
        fc.emit("SETTABLE", prep.objReg, prep.keyReg, srcReg);
        return;
    }
  }

  compileStatAssign(fc, stmt) {
    const vars = stmt.vars || [];
    const values = stmt.values || [];
    const nVars = vars.length;
    const saved = fc.nextReg;

    // 1. Pre-evaluate LHS base/key expressions left-to-right
    const preps = vars.map((v) => this.prepareLValue(fc, v));

    // 2. Evaluate all RHS values into fresh temporaries to preserve parallel assignment semantics
    const rhsBase = fc.allocReg(nVars);
    this.evalExprListIntoRegs(fc, values, rhsBase, nVars);

    // 3. Commit writes
    for (let i = 0; i < nVars; i++) {
      this.storePreparedLValue(fc, preps[i], rhsBase + i);
    }

    fc.freeRegsTo(saved);
  }

  compileStatCompoundAssign(fc, stmt) {
    const saved = fc.nextReg;
    // Evaluate LHS target & key ONCE (official Luau compound assignment semantics)
    const prep = this.prepareLValue(fc, stmt.var);

    if (prep.kind === "local" && stmt.op !== "Concat") {
      const rhsReg = fc.allocReg(1);
      this.compileExprToReg(fc, stmt.value, rhsReg);
      this.emitBinaryArith(fc, stmt.op, prep.reg, prep.reg, rhsReg);
      fc.freeRegsTo(saved);
      return;
    }

    const pairBase = fc.allocReg(2); // contiguous [lhsVal, rhsVal] (required for CONCAT too!)
    this.loadPreparedLValue(fc, prep, pairBase);
    this.compileExprToReg(fc, stmt.value, pairBase + 1);

    if (stmt.op === "Concat") {
      fc.emit("CONCAT", pairBase, pairBase, pairBase + 1);
    } else {
      this.emitBinaryArith(fc, stmt.op, pairBase, pairBase, pairBase + 1);
    }

    this.storePreparedLValue(fc, prep, pairBase);
    fc.freeRegsTo(saved);
  }

  compileStatIf(fc, stmt) {
    const endLabel = fc.newLabel();
    let cur = stmt;

    while (cur && cur.type === "AstStatIf") {
      const nextBranchLabel = fc.newLabel();
      this.compileBranchFalse(fc, cur.condition, nextBranchLabel);
      this.compileBlockScoped(fc, cur.thenbody);
      if (cur.elsebody) {
        fc.emitJump("JMP", 0, 0, endLabel);
      }
      fc.markLabel(nextBranchLabel);
      cur = cur.elsebody;
    }

    if (cur) {
      // Final `else` block
      this.compileBlockScoped(fc, cur);
    }

    fc.markLabel(endLabel);
  }

  compileStatWhile(fc, stmt) {
    const startLabel = fc.newLabel();
    const breakLabel = fc.newLabel();
    const scopeDepth = fc.scopes.length;

    fc.markLabel(startLabel);
    this.compileBranchFalse(fc, stmt.condition, breakLabel);

    fc.pushScope();
    fc.loops.push({
      breakLabel,
      continueLabel: startLabel,
      scopeDepth,
      bodyInnerScopeDepth: fc.scopes.length - 1
    });

    this.compileBlockBody(fc, stmt.body);

    fc.loops.pop();
    fc.popScope(true);
    fc.emitJump("JMP", 0, 0, startLabel);

    fc.markLabel(breakLabel);
  }

  compileStatRepeat(fc, stmt) {
    // In Luau/Lua, `until <cond>` sees locals declared inside the `repeat` body!
    const startLabel = fc.newLabel();
    const condLabel = fc.newLabel();
    const breakLabel = fc.newLabel();
    const outerScopeDepth = fc.scopes.length;

    fc.markLabel(startLabel);
    fc.pushScope();
    const bodyScopeIdx = fc.scopes.length - 1;

    fc.loops.push({
      breakLabel,
      continueLabel: condLabel,
      scopeDepth: outerScopeDepth,
      bodyInnerScopeDepth: bodyScopeIdx + 1
    });

    this.compileBlockBody(fc, stmt.body);
    fc.loops.pop();

    fc.markLabel(condLabel);
    const saved = fc.nextReg;
    const condReg = fc.allocReg(1);
    this.compileExprToReg(fc, stmt.condition, condReg);

    // Close body upvalues BEFORE either repeating or exiting the loop!
    if (fc.scopes[bodyScopeIdx].hasCaptured) {
      fc.emit("CLOSE", fc.scopes[bodyScopeIdx].minCapturedReg, 0, 0);
    }

    fc.emitJump("JMP_FALSE", condReg, 0, startLabel);
    fc.freeRegsTo(saved);
    fc.popScope(false); // already closed above

    fc.markLabel(breakLabel);
  }

  compileStatFor(fc, stmt) {
    const saved = fc.nextReg;
    const outerScopeDepth = fc.scopes.length;

    // Frame at `base`:
    //   R[base]     = internal index
    //   R[base + 1] = limit
    //   R[base + 2] = step
    //   R[base + 3] = user-visible loop variable `stmt.var`
    const base = fc.allocReg(4);
    this.compileExprToReg(fc, stmt.from, base);
    this.compileExprToReg(fc, stmt.to, base + 1);
    if (stmt.step) {
      this.compileExprToReg(fc, stmt.step, base + 2);
    } else {
      this.emitLoadSynthesizedInt(fc, base + 2, 1);
    }

    const bodyLabel = fc.newLabel();
    const continueLabel = fc.newLabel();
    const breakLabel = fc.newLabel();

    fc.emitJump("FORPREP", base, 0, breakLabel);
    fc.markLabel(bodyLabel);

    fc.pushScope();
    fc.declareLocal(stmt.var, base + 3);
    const loopVarScopeIdx = fc.scopes.length - 1;

    fc.pushScope();
    fc.loops.push({
      breakLabel,
      continueLabel,
      scopeDepth: outerScopeDepth,
      bodyInnerScopeDepth: fc.scopes.length - 1
    });

    this.compileBlockBody(fc, stmt.body);
    fc.loops.pop();
    fc.popScope(true); // closes body locals

    fc.markLabel(continueLabel);
    // Close user loop variable `i` upvalue (if captured) BEFORE FORLOOP overwrites R[base+3]
    if (fc.scopes[loopVarScopeIdx].hasCaptured) {
      fc.emit("CLOSE", fc.scopes[loopVarScopeIdx].minCapturedReg, 0, 0);
    }
    fc.popScope(false);

    fc.emitJump("FORLOOP", base, 0, bodyLabel);
    fc.markLabel(breakLabel);
    fc.freeRegsTo(saved);
  }

  compileStatForIn(fc, stmt) {
    const saved = fc.nextReg;
    const outerScopeDepth = fc.scopes.length;
    const vars = stmt.vars || [];
    const nVars = vars.length;

    // Frame at `base`:
    //   R[base]     = generator / iterable
    //   R[base + 1] = state
    //   R[base + 2] = control
    //   R[base + 3 .. base + 2 + nVars] = loop variables
    const base = fc.allocReg(3 + nVars);
    this.evalExprListIntoRegs(fc, stmt.values || [], base, 3);

    const bodyLabel = fc.newLabel();
    const continueLabel = fc.newLabel();
    const testLabel = fc.newLabel();
    const breakLabel = fc.newLabel();

    fc.emitJump("FORGPREP", base, 0, testLabel);

    fc.markLabel(bodyLabel);
    fc.pushScope();
    for (let i = 0; i < nVars; i++) {
      fc.declareLocal(vars[i], base + 3 + i);
    }
    const loopVarScopeIdx = fc.scopes.length - 1;

    fc.pushScope();
    fc.loops.push({
      breakLabel,
      continueLabel,
      scopeDepth: outerScopeDepth,
      bodyInnerScopeDepth: fc.scopes.length - 1
    });

    this.compileBlockBody(fc, stmt.body);
    fc.loops.pop();
    fc.popScope(true);

    fc.markLabel(continueLabel);
    if (fc.scopes[loopVarScopeIdx].hasCaptured) {
      fc.emit("CLOSE", fc.scopes[loopVarScopeIdx].minCapturedReg, 0, 0);
    }
    fc.popScope(false);

    fc.markLabel(testLabel);
    fc.emit("FORGLOOP", base, nVars, 0, { targetLabel: bodyLabel });

    fc.markLabel(breakLabel);
    fc.freeRegsTo(saved);
  }

  compileStatReturn(fc, stmt) {
    const list = stmt.list || [];
    if (list.length === 0) {
      fc.emitCloseFromScopeIndex(0);
      fc.emit("RETURN", 1, 1, 0);
      return;
    }

    const saved = fc.nextReg;
    const n = list.length;
    const lastExpr = list[n - 1];
    const lastIsMultret = this.isMultretExpr(lastExpr);

    if (lastIsMultret) {
      const base = fc.allocReg(n);
      for (let i = 0; i < n - 1; i++) {
        this.compileExprToReg(fc, list[i], base + i);
      }
      this.compileMultretExprAtTop(fc, lastExpr, base + n - 1);
      fc.emitCloseFromScopeIndex(0);
      fc.emit("RETURN", base, 0, 0); // B=0 -> returns R[base..top]
      fc.freeRegsTo(saved);
      return;
    }

    const base = fc.allocReg(n);
    for (let i = 0; i < n; i++) {
      this.compileExprToReg(fc, list[i], base + i);
    }
    fc.emitCloseFromScopeIndex(0);
    fc.emit("RETURN", base, n + 1, 0);
    fc.freeRegsTo(saved);
  }

  /**
   * Evaluates `exprs` into `dstBase .. dstBase + nWanted - 1`.
   * Assumes `dstBase .. dstBase + nWanted - 1` is at the top of `fc.nextReg`!
   */
  evalExprListIntoRegs(fc, exprs, dstBase, nWanted) {
    const m = exprs.length;
    if (nWanted === 0) {
      const saved = fc.nextReg;
      for (const e of exprs) {
        if (e.type === "AstExprCall") this.compileCallExpr(fc, e, null, 0);
        else {
          const t = fc.allocReg(1);
          this.compileExprToReg(fc, e, t);
          fc.freeRegsTo(saved);
        }
      }
      return;
    }

    if (m === 0) {
      fc.emit("LOADNIL", dstBase, dstBase + nWanted - 1, 0);
      return;
    }

    // If more expressions than wanted, evaluate first nWanted into dstBase..dstBase+nWanted-1,
    // then evaluate remaining expressions for side-effects only.
    if (m > nWanted) {
      for (let i = 0; i < nWanted; i++) {
        this.compileExprToReg(fc, exprs[i], dstBase + i);
      }
      const saved = fc.nextReg;
      for (let i = nWanted; i < m; i++) {
        if (exprs[i].type === "AstExprCall") {
          this.compileCallExpr(fc, exprs[i], null, 0);
        } else {
          const t = fc.allocReg(1);
          this.compileExprToReg(fc, exprs[i], t);
          fc.freeRegsTo(saved);
        }
      }
      return;
    }

    // Here 1 <= m <= nWanted
    for (let i = 0; i < m - 1; i++) {
      this.compileExprToReg(fc, exprs[i], dstBase + i);
    }

    const last = exprs[m - 1];
    const tailCount = nWanted - (m - 1); // >= 1
    const lastReg = dstBase + (m - 1);

    if (last.type === "AstExprCall" && this.isMultretExpr(last)) {
      // Request exact `tailCount` results directly into R[lastReg .. dstBase + nWanted - 1]
      const savedAfterTargets = fc.nextReg;
      // Ensure call frame sits at top of register file; if tailCount > 1, temporarily set nextReg to lastReg
      fc.freeRegsTo(lastReg);
      const frame = fc.allocReg(1); // == lastReg
      this.compileCallAtFrame(fc, last, frame, tailCount);
      fc.freeRegsTo(savedAfterTargets);
      return;
    }

    if (last.type === "AstExprVarargs") {
      fc.emit("VARARG", lastReg, tailCount + 1, 0);
      return;
    }

    // Single value expression for `last`, pad remaining with nil
    this.compileExprToReg(fc, last, lastReg);
    if (tailCount > 1) {
      fc.emit("LOADNIL", lastReg + 1, dstBase + nWanted - 1, 0);
    }
  }

  compileMultretExprAtTop(fc, expr, targetFrameReg) {
    // Ensure targetFrameReg is the active top frame
    fc.freeRegsTo(targetFrameReg);
    const frame = fc.allocReg(1); // == targetFrameReg
    if (expr.type === "AstExprCall") {
      this.compileCallAtFrame(fc, expr, frame, -1); // -1 => MULTRET (C = 0)
    } else if (expr.type === "AstExprVarargs") {
      if (!fc.isVararg) throw new Error("Cannot use `...` outside a vararg function.");
      fc.emit("VARARG", frame, 0, 0); // B = 0 => MULTRET updating `top`
    } else {
      throw new Error(`Expected multret expression, got ${expr.type}`);
    }
  }

  compileCallExpr(fc, callAst, dstReg, numResults) {
    const saved = fc.nextReg;
    const frame = fc.allocReg(1);
    this.compileCallAtFrame(fc, callAst, frame, numResults);
    if (numResults === 1 && dstReg !== null && dstReg !== frame) {
      fc.emit("MOVE", dstReg, frame, 0);
    }
    fc.freeRegsTo(saved);
  }

  /**
   * `frame` MUST be `fc.nextReg - 1` (top of active registers).
   * `numResults`: -1 for MULTRET (`C = 0`), 0 for 0 results (`C = 1`), K for K results (`C = K + 1`).
   */
  compileCallAtFrame(fc, callAst, frame, numResults) {
    const args = callAst.args || [];

    // Direct virtualization of bit32 intrinsics (eliminates "bit32"/"bxor"/"lrotate" constants!)
    if (this.options.virtualizeBit32 !== false && numResults === 1) {
      const bName = getBit32IntrinsicName(callAst);
      if (bName) {
        const saved = fc.nextReg;
        if (bName === "bnot") {
          const r1 = fc.allocReg(1);
          this.compileExprToReg(fc, args[0], r1);
          fc.emit("BIT_BNOT", frame, r1, 0);
          fc.freeRegsTo(saved);
          return;
        }
        const r1 = fc.allocReg(1);
        const r2 = fc.allocReg(1);
        this.compileExprToReg(fc, args[0], r1);
        this.compileExprToReg(fc, args[1], r2);
        if (bName === "band") {
          fc.emit("BIT_BAND", frame, r1, r2);
        } else if (bName === "bor") {
          fc.emit("BIT_BOR", frame, r1, r2);
        } else if (bName === "lshift") {
          fc.emit("BIT_LSH", frame, r1, r2);
        } else if (bName === "rshift") {
          fc.emit("BIT_RSH", frame, r1, r2);
        } else if (bName === "bxor") {
          if (this.rng && this.rng.bool(0.5)) {
            const rOr = fc.allocReg(1);
            const rAnd = fc.allocReg(1);
            fc.emit("BIT_BOR", rOr, r1, r2);
            fc.emit("BIT_BAND", rAnd, r1, r2);
            fc.emit("SUB", frame, rOr, rAnd);
          } else {
            fc.emit("BIT_BXOR", frame, r1, r2);
          }
        } else if (bName === "lrotate" || bName === "rrotate") {
          const r31 = fc.allocReg(1);
          const r32 = fc.allocReg(1);
          const rAmt = fc.allocReg(1);
          const rInv = fc.allocReg(1);
          const rHi = fc.allocReg(1);
          const rLo = fc.allocReg(1);
          this.emitLoadSynthesizedInt(fc, r31, 31);
          this.emitLoadSynthesizedInt(fc, r32, 32);
          fc.emit("BIT_BAND", rAmt, r2, r31);
          fc.emit("SUB", rInv, r32, rAmt);
          if (bName === "lrotate") {
            fc.emit("BIT_LSH", rHi, r1, rAmt);
            fc.emit("BIT_RSH", rLo, r1, rInv);
          } else {
            fc.emit("BIT_RSH", rHi, r1, rAmt);
            fc.emit("BIT_LSH", rLo, r1, rInv);
          }
          fc.emit("BIT_BOR", frame, rHi, rLo);
        }
        fc.freeRegsTo(saved);
        return;
      }
    }

    let argStartReg;
    let fixedPrefixArgs = 0;

    if (callAst.self && callAst.func.type === "AstExprIndexName") {
      // Method call `obj:method(...)`:
      // R[frame] = method, R[frame + 1] = obj
      const selfSlot = fc.allocReg(1); // frame + 1
      const objTmp = fc.allocReg(1);
      this.compileExprToReg(fc, callAst.func.expr, objTmp);
      const kMethod = fc.addStringConstAscii(callAst.func.index);
      fc.emit("SELF", frame, objTmp, kMethod);
      fc.freeRegsTo(selfSlot + 1); // keep frame and frame+1 allocated
      argStartReg = frame + 2;
      fixedPrefixArgs = 1;
    } else {
      this.compileExprToReg(fc, callAst.func, frame);
      argStartReg = frame + 1;
      fixedPrefixArgs = 0;
    }

    const nArgs = args.length;
    const C = numResults < 0 ? 0 : numResults + 1;

    if (nArgs === 0) {
      const B = 1 + fixedPrefixArgs;
      fc.emit("CALL", frame, B, C);
      if (numResults > 1) {
        // Reserve registers in high-water mark if results extend past frame
        const endReg = frame + numResults - 1;
        if (endReg > fc.maxReg) fc.maxReg = endReg;
      }
      return;
    }

    const lastArg = args[nArgs - 1];
    const lastIsMultret = this.isMultretExpr(lastArg);

    if (lastIsMultret) {
      if (nArgs > 1) {
        const prefixRegs = fc.allocReg(nArgs - 1); // == argStartReg
        for (let i = 0; i < nArgs - 1; i++) {
          this.compileExprToReg(fc, args[i], prefixRegs + i);
        }
      }
      const multretReg = argStartReg + (nArgs - 1);
      this.compileMultretExprAtTop(fc, lastArg, multretReg);
      fc.emit("CALL", frame, 0, C); // B = 0 => variable arguments up to `top`
    } else {
      const argRegs = fc.allocReg(nArgs); // == argStartReg
      for (let i = 0; i < nArgs; i++) {
        this.compileExprToReg(fc, args[i], argRegs + i);
      }
      const B = 1 + fixedPrefixArgs + nArgs;
      fc.emit("CALL", frame, B, C);
    }

    if (numResults > 1) {
      const endReg = frame + numResults - 1;
      if (endReg > fc.maxReg) fc.maxReg = endReg;
    }
  }

  compileFunctionExprToReg(fc, funcAst, dstReg) {
    const protoId = this.compileProto(
      fc,
      funcAst.args || [],
      funcAst.self || null,
      Boolean(funcAst.vararg),
      funcAst.body
    );
    fc.childProtos.push(protoId);
    const localChildIdx = fc.childProtos.length; // 1-based index into proto.childProtos
    fc.emit("CLOSURE", dstReg, localChildIdx, 0);
  }

  compileBranchFalse(fc, condExpr, falseLabel) {
    // Unwrap groups & type assertions
    while (
      condExpr.type === "AstExprGroup" ||
      condExpr.type === "AstExprTypeAssertion"
    ) {
      condExpr = condExpr.expr;
    }

    if (condExpr.type === "AstExprUnary" && condExpr.op === "Not") {
      this.compileBranchTrue(fc, condExpr.expr, falseLabel);
      return;
    }

    if (condExpr.type === "AstExprBinary") {
      const saved = fc.nextReg;
      // Fused comparison jump when falsy -> jump on negated comparison!
      if (
        condExpr.op === "CompareEq" ||
        condExpr.op === "CompareNe" ||
        condExpr.op === "CompareLt" ||
        condExpr.op === "CompareLe" ||
        condExpr.op === "CompareGt" ||
        condExpr.op === "CompareGe"
      ) {
        const rL = fc.allocReg(1);
        const rR = fc.allocReg(1);
        this.compileExprToReg(fc, condExpr.left, rL);
        this.compileExprToReg(fc, condExpr.right, rR);
        // Note: With NaN or metamethods, `not (a < b)` is NOT always `b <= a` if NaN is involved!
        // Only `CompareEq` <-> `NE_JMP` and `CompareNe` <-> `EQ_JMP` are 100% NaN-exact under negation!
        if (condExpr.op === "CompareEq") {
          fc.emitJump("NE_JMP", rL, rR, falseLabel);
          fc.freeRegsTo(saved);
          return;
        }
        if (condExpr.op === "CompareNe") {
          fc.emitJump("EQ_JMP", rL, rR, falseLabel);
          fc.freeRegsTo(saved);
          return;
        }
        fc.freeRegsTo(saved);
      }
    }

    const saved = fc.nextReg;
    const r = fc.allocReg(1);
    this.compileExprToReg(fc, condExpr, r);
    fc.emitJump("JMP_FALSE", r, 0, falseLabel);
    fc.freeRegsTo(saved);
  }

  compileBranchTrue(fc, condExpr, trueLabel) {
    while (
      condExpr.type === "AstExprGroup" ||
      condExpr.type === "AstExprTypeAssertion"
    ) {
      condExpr = condExpr.expr;
    }

    if (condExpr.type === "AstExprUnary" && condExpr.op === "Not") {
      this.compileBranchFalse(fc, condExpr.expr, trueLabel);
      return;
    }

    if (condExpr.type === "AstExprBinary") {
      if (
        condExpr.op === "CompareEq" ||
        condExpr.op === "CompareNe" ||
        condExpr.op === "CompareLt" ||
        condExpr.op === "CompareLe" ||
        condExpr.op === "CompareGt" ||
        condExpr.op === "CompareGe"
      ) {
        const saved = fc.nextReg;
        const rL = fc.allocReg(1);
        const rR = fc.allocReg(1);
        this.compileExprToReg(fc, condExpr.left, rL);
        this.compileExprToReg(fc, condExpr.right, rR);
        switch (condExpr.op) {
          case "CompareEq":
            fc.emitJump("EQ_JMP", rL, rR, trueLabel);
            break;
          case "CompareNe":
            fc.emitJump("NE_JMP", rL, rR, trueLabel);
            break;
          case "CompareLt":
            fc.emitJump("LT_JMP", rL, rR, trueLabel);
            break;
          case "CompareLe":
            fc.emitJump("LE_JMP", rL, rR, trueLabel);
            break;
          case "CompareGt":
            fc.emitJump("LT_JMP", rR, rL, trueLabel);
            break;
          case "CompareGe":
            fc.emitJump("LE_JMP", rR, rL, trueLabel);
            break;
        }
        fc.freeRegsTo(saved);
        return;
      }
    }

    const saved = fc.nextReg;
    const r = fc.allocReg(1);
    this.compileExprToReg(fc, condExpr, r);
    fc.emitJump("JMP_TRUE", r, 0, trueLabel);
    fc.freeRegsTo(saved);
  }

  emitBinaryArith(fc, op, dst, rL, rR) {
    const map = {
      Add: "ADD",
      Sub: "SUB",
      Mul: "MUL",
      Div: "DIV",
      FloorDiv: "IDIV",
      Mod: "MOD",
      Pow: "POW"
    };
    const sem = map[op];
    if (!sem) throw new Error(`Unknown arithmetic operator: ${op}`);
    fc.emit(sem, dst, rL, rR);
  }

  compileExprToReg(fc, expr, dstReg) {
    switch (expr.type) {
      case "AstExprConstantNil":
        fc.emit("LOADNIL", dstReg, dstReg, 0);
        return;

      case "AstExprConstantBool":
        fc.emit("LOADBOOL", dstReg, expr.value ? 1 : 0, 0);
        return;

      case "AstExprConstantNumber": {
        this.emitLoadSynthesizedInt(fc, dstReg, expr.value);
        return;
      }

      case "AstExprConstantString": {
        this.emitLoadVaultString(fc, dstReg, expr.value);
        return;
      }

      case "AstExprInterpString": {
        const strings = expr.strings || [];
        const exprs = expr.expressions || [];
        if (exprs.length === 0) {
          this.emitLoadVaultString(fc, dstReg, strings[0] || "");
          return;
        }
        // Build segments: non-empty string literals interleaved with TOSTRING(expr[i])
        const parts = [];
        for (let i = 0; i < exprs.length; i++) {
          if (strings[i] && strings[i].length > 0) {
            parts.push({ kind: "str", val: strings[i] });
          }
          parts.push({ kind: "expr", ast: exprs[i] });
        }
        if (strings[exprs.length] && strings[exprs.length].length > 0) {
          parts.push({ kind: "str", val: strings[exprs.length] });
        }

        if (parts.length === 1 && parts[0].kind === "expr") {
          const saved = fc.nextReg;
          const tmp = fc.allocReg(1);
          this.compileExprToReg(fc, parts[0].ast, tmp);
          fc.emit("TOSTRING", dstReg, tmp, 0);
          fc.freeRegsTo(saved);
          return;
        }

        const saved = fc.nextReg;
        const base = fc.allocReg(parts.length);
        for (let i = 0; i < parts.length; i++) {
          const p = parts[i];
          if (p.kind === "str") {
            this.emitLoadVaultString(fc, base + i, p.val);
          } else {
            this.compileExprToReg(fc, p.ast, base + i);
            fc.emit("TOSTRING", base + i, base + i, 0);
          }
        }
        fc.emit("CONCAT", dstReg, base, base + parts.length - 1);
        fc.freeRegsTo(saved);
        return;
      }

      case "AstExprLocal": {
        const key = declKey(expr.local);
        const reg = fc.resolveLocalReg(key);
        if (reg !== null) {
          if (reg !== dstReg) fc.emit("MOVE", dstReg, reg, 0);
          return;
        }
        const upIdx = fc.resolveUpvalue(key);
        if (upIdx !== null) {
          fc.emit("GETUPVAL", dstReg, upIdx, 0);
          return;
        }
        throw new Error(`Unresolved local reference: ${expr.local.name}`);
      }

      case "AstExprGlobal": {
        const k = fc.addStringConstAscii(expr.global);
        fc.emit("GETGLOBAL", dstReg, k, 0);
        return;
      }

      case "AstExprIndexName": {
        // Super-instruction candidate: `ENV[globalName][propName]` (e.g. math.sin, bit32.bxor, Vector3.new)
        if (expr.expr.type === "AstExprGlobal") {
          const kGlobal = fc.addStringConstAscii(expr.expr.global);
          const kProp = fc.addStringConstAscii(expr.index);
          fc.emit("GETENV_PROP", dstReg, kGlobal, kProp);
          return;
        }
        const saved = fc.nextReg;
        const objReg = fc.allocReg(1);
        this.compileExprToReg(fc, expr.expr, objReg);
        const kProp = fc.addStringConstAscii(expr.index);
        fc.emit("GETPROP", dstReg, objReg, kProp);
        fc.freeRegsTo(saved);
        return;
      }

      case "AstExprIndexExpr": {
        const saved = fc.nextReg;
        const objReg = fc.allocReg(1);
        this.compileExprToReg(fc, expr.expr, objReg);
        const keyReg = fc.allocReg(1);
        this.compileExprToReg(fc, expr.index, keyReg);
        fc.emit("GETTABLE", dstReg, objReg, keyReg);
        fc.freeRegsTo(saved);
        return;
      }

      case "AstExprGroup":
      case "AstExprTypeAssertion":
        // Group `(expr)` also forces single-value evaluation, which compileExprToReg naturally does!
        this.compileExprToReg(fc, expr.expr, dstReg);
        return;

      case "AstExprVarargs": {
        if (!fc.isVararg) throw new Error("Cannot use `...` outside vararg function.");
        fc.emit("VARARG", dstReg, 2, 0); // B = 2 => 1 result into dstReg
        return;
      }

      case "AstExprCall":
        this.compileCallExpr(fc, expr, dstReg, 1);
        return;

      case "AstExprFunction":
        this.compileFunctionExprToReg(fc, expr, dstReg);
        return;

      case "AstExprTable":
        this.compileTableExpr(fc, expr, dstReg);
        return;

      case "AstExprUnary": {
        const saved = fc.nextReg;
        const src = fc.allocReg(1);
        this.compileExprToReg(fc, expr.expr, src);
        if (expr.op === "Minus") fc.emit("UNM", dstReg, src, 0);
        else if (expr.op === "Not") fc.emit("NOT", dstReg, src, 0);
        else if (expr.op === "Len") fc.emit("LEN", dstReg, src, 0);
        else throw new Error(`Unknown unary op: ${expr.op}`);
        fc.freeRegsTo(saved);
        return;
      }

      case "AstExprBinary":
        this.compileBinaryExpr(fc, expr, dstReg);
        return;

      case "AstExprIfElse": {
        const falseLabel = fc.newLabel();
        const endLabel = fc.newLabel();
        this.compileBranchFalse(fc, expr.condition, falseLabel);
        this.compileExprToReg(fc, expr.trueExpr, dstReg);
        fc.emitJump("JMP", 0, 0, endLabel);
        fc.markLabel(falseLabel);
        this.compileExprToReg(fc, expr.falseExpr, dstReg);
        fc.markLabel(endLabel);
        return;
      }

      default:
        throw new Error(`Unsupported Luau expression AST node: ${expr.type}`);
    }
  }

  compileTableExpr(fc, expr, dstReg) {
    const items = expr.items || [];
    let arrayHint = 0;
    for (const it of items) {
      if (it.kind === "item") arrayHint++;
    }

    const saved = fc.nextReg;
    // Place table construction in a fresh top-of-stack register so SETLIST R[tbl+1..] never clobbers anything!
    const tblReg = fc.allocReg(1);
    fc.emit("NEWTABLE", tblReg, Math.min(arrayHint, 0xffff), 0);

    // Collect list ("item") elements in batches of 32 while executing "record"/"general" in exact source order!
    // Wait: in Lua/Luau `{ [1] = "a", "b" }`, source evaluation order matters if expressions have side effects!
    // Let's preserve exact source evaluation order AND trailing multret on the very last item if `kind === "item"`!
    let arrayOffset = 0; // 0-based count of array elements already committed
    const BATCH_SIZE = 32;
    let batchRegsStart = null;
    let batchCount = 0;

    const flushBatch = () => {
      if (batchCount > 0) {
        // SETLIST tblReg, B = batchCount + 1, C = arrayOffset
        fc.emit("SETLIST", tblReg, batchCount + 1, arrayOffset);
        arrayOffset += batchCount;
        batchCount = 0;
        fc.freeRegsTo(tblReg + 1);
        batchRegsStart = null;
      }
    };

    for (let i = 0; i < items.length; i++) {
      const it = items[i];
      const isVeryLastItem = i === items.length - 1;

      if (it.kind === "item") {
        const isMultret = isVeryLastItem && this.isMultretExpr(it.value);

        if (isMultret) {
          flushBatch();
          const multSlot = fc.allocReg(1); // == tblReg + 1
          this.compileMultretExprAtTop(fc, it.value, multSlot);
          fc.emit("SETLIST", tblReg, 0, arrayOffset); // B = 0 => MULTRET from R[tblReg+1..top]
          fc.freeRegsTo(tblReg + 1);
        } else {
          if (batchRegsStart === null) {
            batchRegsStart = fc.allocReg(1); // == tblReg + 1
          } else {
            fc.allocReg(1);
          }
          this.compileExprToReg(fc, it.value, tblReg + 1 + batchCount);
          batchCount++;
          if (batchCount >= BATCH_SIZE) {
            flushBatch();
          }
        }
      } else if (it.kind === "record") {
        flushBatch();
        const innerSaved = fc.nextReg;
        const valReg = fc.allocReg(1);
        this.compileExprToReg(fc, it.value, valReg);
        const kProp = fc.addStringConstFromLatin1(it.key.value);
        fc.emit("SETPROP", tblReg, kProp, valReg);
        fc.freeRegsTo(innerSaved);
      } else if (it.kind === "general") {
        flushBatch();
        const innerSaved = fc.nextReg;
        const keyReg = fc.allocReg(1);
        const valReg = fc.allocReg(1);
        this.compileExprToReg(fc, it.key, keyReg);
        this.compileExprToReg(fc, it.value, valReg);
        fc.emit("SETTABLE", tblReg, keyReg, valReg);
        fc.freeRegsTo(innerSaved);
      }
    }

    flushBatch();
    if (dstReg !== tblReg) {
      fc.emit("MOVE", dstReg, tblReg, 0);
    }
    fc.freeRegsTo(saved);
  }

  compileBinaryExpr(fc, expr, dstReg) {
    const op = expr.op;

    // Short-circuit `and` / `or` preserving exact Luau truthiness value
    if (op === "And") {
      const endLabel = fc.newLabel();
      const saved = fc.nextReg;
      const tmp = fc.allocReg(1);
      this.compileExprToReg(fc, expr.left, tmp);
      fc.emitJump("TESTSET_FALSE", dstReg, tmp, endLabel);
      fc.freeRegsTo(saved);
      this.compileExprToReg(fc, expr.right, dstReg);
      fc.markLabel(endLabel);
      return;
    }

    if (op === "Or") {
      const endLabel = fc.newLabel();
      const saved = fc.nextReg;
      const tmp = fc.allocReg(1);
      this.compileExprToReg(fc, expr.left, tmp);
      fc.emitJump("TESTSET_TRUE", dstReg, tmp, endLabel);
      fc.freeRegsTo(saved);
      this.compileExprToReg(fc, expr.right, dstReg);
      fc.markLabel(endLabel);
      return;
    }

    // Coalesce chained `a .. b .. c` into a single contiguous CONCAT instruction!
    if (op === "Concat") {
      const chain = [];
      let cur = expr;
      while (cur.type === "AstExprBinary" && cur.op === "Concat") {
        chain.push(cur.left);
        cur = cur.right;
      }
      chain.push(cur);

      const saved = fc.nextReg;
      const base = fc.allocReg(chain.length);
      for (let i = 0; i < chain.length; i++) {
        this.compileExprToReg(fc, chain[i], base + i);
      }
      fc.emit("CONCAT", dstReg, base, base + chain.length - 1);
      fc.freeRegsTo(saved);
      return;
    }

    // Fused constant arithmetic super-instructions: ADDK, SUBK, MULK (only when not splitting integers)
    if (
      (op === "Add" || op === "Sub" || op === "Mul") &&
      expr.right.type === "AstExprConstantNumber" &&
      (this.options.splitConstants === false || !this.rng || !Number.isInteger(expr.right.value))
    ) {
      const saved = fc.nextReg;
      const rL = fc.allocReg(1);
      this.compileExprToReg(fc, expr.left, rL);
      const kIdx = fc.addNumberConst(expr.right.value);
      const sem = op === "Add" ? "ADDK" : op === "Sub" ? "SUBK" : "MULK";
      fc.emit(sem, dstReg, rL, kIdx);
      fc.freeRegsTo(saved);
      return;
    }

    const saved = fc.nextReg;
    const rL = fc.allocReg(1);
    const rR = fc.allocReg(1);
    this.compileExprToReg(fc, expr.left, rL);
    this.compileExprToReg(fc, expr.right, rR);

    switch (op) {
      case "Add":
      case "Sub":
      case "Mul":
      case "Div":
      case "FloorDiv":
      case "Mod":
      case "Pow":
        this.emitBinaryArith(fc, op, dstReg, rL, rR);
        break;
      case "CompareEq":
        fc.emit("EQ", dstReg, rL, rR);
        break;
      case "CompareNe":
        fc.emit("NE", dstReg, rL, rR);
        break;
      case "CompareLt":
        fc.emit("LT", dstReg, rL, rR);
        break;
      case "CompareLe":
        fc.emit("LE", dstReg, rL, rR);
        break;
      case "CompareGt":
        fc.emit("LT", dstReg, rR, rL);
        break;
      case "CompareGe":
        fc.emit("LE", dstReg, rR, rL);
        break;
      default:
        throw new Error(`Unknown binary operator: ${op}`);
    }

    fc.freeRegsTo(saved);
  }
}

function compileASTToIR(rootAst, rng = null, options = {}) {
  const compiler = new ModuleCompiler(rootAst, rng, options);
  return compiler.compile();
}

module.exports = {
  compileASTToIR
};
