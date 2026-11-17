"use strict";

const crypto = require("crypto");

const LUAU_RESERVED = new Set([
  "and", "break", "do", "else", "elseif", "end", "false", "for",
  "function", "goto", "if", "in", "local", "nil", "not", "or", "repeat",
  "return", "then", "true", "until", "while", "continue", "type",
  "export", "typeof", "self"
]);

function u32(x) {
  return x >>> 0;
}

function rotl32(x, r) {
  const s = r & 31;
  if (s === 0) return x >>> 0;
  return ((x << s) | (x >>> (32 - s))) >>> 0;
}

function rotr32(x, r) {
  const s = r & 31;
  if (s === 0) return x >>> 0;
  return ((x >>> s) | (x << (32 - s))) >>> 0;
}

class PolymorphicRNG {
  constructor(seedInput) {
    let seedBuf;
    if (seedInput !== undefined && seedInput !== null && seedInput !== "") {
      seedBuf = crypto.createHash("sha256").update(String(seedInput)).digest();
      this.seedHex = seedBuf.subarray(0, 16).toString("hex");
    } else {
      seedBuf = crypto.randomBytes(32);
      this.seedHex = seedBuf.subarray(0, 16).toString("hex");
    }
    this.s0 = seedBuf.readUInt32LE(0) || 0x9e3779b9;
    this.s1 = seedBuf.readUInt32LE(4) || 0x243f6a88;
    this.s2 = seedBuf.readUInt32LE(8) || 0x85a308d3;
    this.s3 = seedBuf.readUInt32LE(12) || 0x13198a2e;
    for (let i = 0; i < 16; i++) this.nextU32();
  }

  nextU32() {
    const result = u32(Math.imul(rotl32(u32(Math.imul(this.s1, 5)), 7), 9));
    const t = u32(this.s1 << 9);
    this.s2 = u32(this.s2 ^ this.s0);
    this.s3 = u32(this.s3 ^ this.s1);
    this.s1 = u32(this.s1 ^ this.s2);
    this.s0 = u32(this.s0 ^ this.s3);
    this.s2 = u32(this.s2 ^ t);
    this.s3 = rotl32(this.s3, 11);
    return result;
  }

  int(min, max) {
    const range = max - min + 1;
    if (range <= 1) return min;
    return min + (this.nextU32() % range);
  }

  bool(prob = 0.5) {
    return (this.nextU32() / 0x100000000) < prob;
  }

  pick(arr) {
    return arr[this.int(0, arr.length - 1)];
  }

  shuffle(arr) {
    const out = arr.slice();
    for (let i = out.length - 1; i > 0; i--) {
      const j = this.int(0, i);
      const tmp = out[i];
      out[i] = out[j];
      out[j] = tmp;
    }
    return out;
  }

  nonZeroU32() {
    let v = this.nextU32();
    while (v === 0) v = this.nextU32();
    return v;
  }
}

class IdentifierPool {
  constructor(rng, style = "luaobf") {
    this.rng = rng;
    this.style = style;
    this.used = new Set(LUAU_RESERVED);
    this.counter = 0;
    const firstChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
    const restChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
    this.firstAlphabet = rng.shuffle(firstChars.split("")).join("");
    this.restAlphabet = rng.shuffle(restChars.split("")).join("");
  }

  next() {
    while (true) {
      let candidate;
      if (this.style === "il1") {
        const head = this.rng.pick(["I", "l", "_"]);
        const len = this.rng.int(6, 11);
        let body = "";
        const chars = ["I", "l", "1", "_"];
        for (let i = 0; i < len; i++) body += this.rng.pick(chars);
        candidate = head + body;
      } else if (this.style === "hex") {
        candidate = "_0x" + (this.rng.nextU32() >>> 8).toString(16).padStart(4, "0");
      } else {
        let n = this.counter++;
        candidate = this.firstAlphabet[n % this.firstAlphabet.length];
        n = Math.floor(n / this.firstAlphabet.length);
        while (n > 0) {
          candidate += this.restAlphabet[(n - 1) % this.restAlphabet.length];
          n = Math.floor((n - 1) / this.restAlphabet.length);
        }
      }
      if (!this.used.has(candidate)) {
        this.used.add(candidate);
        return candidate;
      }
    }
  }
}

/**
 * Computes the 16-element runtime ARX salt array T[1..16] matching the Luau VM bootstrapper bit-for-bit.
 * Because `T` depends on runtime integrity state and chaotic 64-round mixing, static constant-folders
 * cannot simplify expressions referencing `T[k]`.
 */
function computeRuntimeSaltTable(saltParams, expectedIntegrityTag) {
  const { seedA, seedB, mulStep, rot1, rot2 } = saltParams;
  let x = u32(seedA + expectedIntegrityTag * mulStep);
  let y = u32(seedB ^ rotl32(x, 11));
  const T = new Array(17).fill(0); // 1-based T[1..16]

  for (let idx = 1; idx <= 16; idx++) {
    for (let r = 1; r <= 4; r++) {
      const addend = u32((idx * 17 + r) * mulStep);
      x = u32(rotl32(x, rot1) ^ y ^ addend);
      y = u32(rotr32(y, rot2) ^ x);
    }
    T[idx] = x;
  }
  return T;
}

/**
 * Emits a Luau expression that evaluates to `target` at runtime using the dynamic `T[1..16]`
 * salt array so pure-numeric static constant folding is impossible, with ZERO function-call overhead!
 */
function saltedConstExpr(target, saltVarName, T, rng, enabled = true) {
  if (!enabled || !Number.isInteger(target)) {
    return String(target);
  }
  const mode = rng.int(0, 1);
  if (mode === 0) {
    const s1 = rng.int(1, 16);
    const diff = target - T[s1];
    if (diff === 0) return `${saltVarName}[${s1}]`;
    if (diff > 0) return `(${saltVarName}[${s1}]+${diff})`;
    return `(${saltVarName}[${s1}] - ${-diff})`;
  } else {
    const s1 = rng.int(1, 16);
    let s2 = rng.int(1, 16);
    if (s2 === s1) s2 = (s1 % 16) + 1;
    const base = T[s1] - T[s2];
    const diff = target - base;
    if (diff === 0) return `(${saltVarName}[${s1}] - ${saltVarName}[${s2}])`;
    if (diff > 0) return `(${saltVarName}[${s1}] - ${saltVarName}[${s2}]+${diff})`;
    return `(${saltVarName}[${s1}] - ${saltVarName}[${s2}] - ${-diff})`;
  }
}

module.exports = {
  u32,
  rotl32,
  rotr32,
  PolymorphicRNG,
  IdentifierPool,
  computeRuntimeSaltTable,
  saltedConstExpr,
  LUAU_RESERVED
};
