"use strict";

const { u32, rotl32, rotr32, computeRuntimeSaltTable } = require("./prng");

// 85 printable ASCII chars (33..126) excluding ", ', \, `, [, ], =
const SAFE_85_BASE = (() => {
  const excluded = new Set([34, 39, 92, 96, 91, 93, 61]);
  const chars = [];
  for (let code = 33; code <= 126; code++) {
    if (!excluded.has(code)) chars.push(String.fromCharCode(code));
    if (chars.length === 85) break;
  }
  return chars;
})();

class BinaryWriter {
  constructor() {
    this.chunks = [];
    this.length = 0;
  }

  writeU8(v) {
    const b = Buffer.allocUnsafe(1);
    b.writeUInt8(v & 0xff, 0);
    this.chunks.push(b);
    this.length += 1;
  }

  writeU16(v) {
    const b = Buffer.allocUnsafe(2);
    b.writeUInt16LE(v & 0xffff, 0);
    this.chunks.push(b);
    this.length += 2;
  }

  writeU32(v) {
    const b = Buffer.allocUnsafe(4);
    b.writeUInt32LE(v >>> 0, 0);
    this.chunks.push(b);
    this.length += 4;
  }

  writeF64(v) {
    const b = Buffer.allocUnsafe(8);
    b.writeDoubleLE(v, 0);
    this.chunks.push(b);
    this.length += 8;
  }

  writeBytes(buf) {
    if (buf.length > 0) {
      this.chunks.push(buf);
      this.length += buf.length;
    }
  }

  toBuffer() {
    return Buffer.concat(this.chunks, this.length);
  }
}

/**
 * Encrypts raw string bytes using a per-string rolling cipher.
 * Matches Luau lazy/vault string decryptor bit-for-bit.
 */
function encryptStringBytes(rawBuf, strSeed, prime) {
  const out = Buffer.allocUnsafe(rawBuf.length);
  let st = strSeed >>> 0;
  for (let i = 0; i < rawBuf.length; i++) {
    const idx1 = i + 1;
    st = u32(rotl32(st, 5) ^ u32(idx1 * prime));
    out[i] = (rawBuf[i] ^ (st & 0xff)) & 0xff;
  }
  return out;
}

/**
 * Generates per-build cryptographic parameters and the runtime-coupled 16-element salt table T[1..16].
 */
function createCryptoProfile(rng, options = {}) {
  const kMul0 = rng.int(16385, 32765) | 1;
  const kMul1 = rng.int(16385, 32765) | 1;
  const sPrime = rng.int(1025, 4093) | 1;
  const vPrime = rng.int(1025, 4093) | 1;
  const outerPrime = rng.int(16385, 65521) | 1;
  const outerRotA = rng.int(5, 19);
  const outerRotB = rng.int(3, 15);

  const masterK0 = rng.nonZeroU32();
  const masterK1 = rng.nonZeroU32();
  const integrityMagic = rng.int(0x1001, 0x7fff);
  const antiTamper = options.antiTamper !== false;
  const expectedIntegrityTag = antiTamper ? integrityMagic : 0;

  const sectionOrder = rng.shuffle([0, 1, 2, 3]);
  const digitPerm = rng.shuffle([0, 1, 2, 3, 4]);

  const saltParams = {
    seedA: rng.nonZeroU32(),
    seedB: rng.nonZeroU32(),
    mulStep: rng.int(16385, 32765) | 1,
    rot1: 7,
    rot2: 5
  };
  const T = computeRuntimeSaltTable(saltParams, expectedIntegrityTag);

  return {
    kMul0,
    kMul1,
    sPrime,
    vPrime,
    outerPrime,
    outerRotA,
    outerRotB,
    masterK0,
    masterK1,
    integrityMagic,
    antiTamper,
    sectionOrder,
    digitPerm,
    saltParams,
    T
  };
}

/**
 * Packs, encrypts (Keyless String Vault + T-salted headers + path-keyed 96-bit instructions + outer ARX CFB stream),
 * and encodes the module into a permuted custom-alphabet Radix-85 payload.
 */
function packAndEncryptModule(irModule, rng, cryptoProfile, options = {}) {
  const T = cryptoProfile.T;
  const writer = new BinaryWriter();

  // Header (no oracle canary!): mainProtoId, protoCount, vaultCount XORed with runtime salt T[1..3]
  writer.writeU16((irModule.mainProtoId ^ (T[1] & 0xffff)) & 0xffff);
  writer.writeU16((irModule.prototypes.length ^ (T[2] & 0xffff)) & 0xffff);
  writer.writeU16((irModule.stringVault.length ^ (T[3] & 0xffff)) & 0xffff);

  // Keyless String Vault: seeds are NEVER stored in the container; synthesized in VM registers!
  for (const entry of irModule.stringVault) {
    const encBytes = encryptStringBytes(entry.rawBuf, entry.seed, cryptoProfile.vPrime);
    writer.writeU32(encBytes.length);
    writer.writeBytes(encBytes);
  }

  // Prototype records
  for (let i = 0; i < irModule.prototypes.length; i++) {
    const proto = irModule.prototypes[i];
    const pIdx = i + 1;
    const tSalt = T[((pIdx - 1) % 16) + 1];

    writer.writeU8(proto.numParams & 0xff);
    writer.writeU8(proto.isVararg ? 1 : 0);
    writer.writeU16(proto.maxRegs & 0xffff);
    writer.writeU32(u32(proto.entryStateKey ^ tSalt));

    for (const sec of cryptoProfile.sectionOrder) {
      if (sec === 0) {
        writer.writeU16(proto.constants.length);
        for (const c of proto.constants) {
          if (c.type === "number") {
            writer.writeU8(1);
            writer.writeF64(c.value);
          } else if (c.type === "string") {
            writer.writeU8(2);
            const strSeed = rng.nonZeroU32();
            const encBytes = encryptStringBytes(c.value, strSeed, cryptoProfile.sPrime);
            writer.writeU32(u32(strSeed ^ tSalt));
            writer.writeU32(encBytes.length);
            writer.writeBytes(encBytes);
          } else {
            throw new Error(`Unsupported constant pool entry type: ${c.type}`);
          }
        }
      } else if (sec === 1) {
        writer.writeU32(proto.instCount);
        for (let w = 0; w < proto.encodedWords.length; w++) {
          writer.writeU32(proto.encodedWords[w] >>> 0);
        }
      } else if (sec === 2) {
        writer.writeU16(proto.upvalues.length);
        for (const u of proto.upvalues) {
          writer.writeU8(u.inStack ? 1 : 0);
          writer.writeU16(u.idx & 0xffff);
        }
      } else if (sec === 3) {
        writer.writeU16(proto.childProtos.length);
        for (const pid of proto.childProtos) {
          writer.writeU16(pid & 0xffff);
        }
      }
    }
  }

  // Pad to 4-byte boundary + random tail padding
  const rawPlain = writer.toBuffer();
  const extraWords = rng.int(1, 3);
  const padBytes = ((4 - (rawPlain.length % 4)) % 4) + extraWords * 4;
  const padBuf = Buffer.allocUnsafe(padBytes);
  for (let i = 0; i < padBytes; i++) padBuf[i] = rng.int(0, 255);
  const plainAligned = Buffer.concat([rawPlain, padBuf]);

  // Outer ARX + CFB Stream Encryption coupled to T[16] & T[15]
  const wordCount = plainAligned.length >>> 2;
  const cipherWords = new Uint32Array(wordCount);

  let s0 = u32(cryptoProfile.masterK0 ^ T[16]);
  let s1 = u32(cryptoProfile.masterK1 ^ T[15]);

  for (let i = 0; i < wordCount; i++) {
    const pWord = plainAligned.readUInt32LE(i * 4);
    s0 = u32(
      rotl32(s0, cryptoProfile.outerRotA) ^
        s1 ^
        u32((i & 0xffff) * cryptoProfile.outerPrime)
    );
    s1 = u32(rotr32(s1, cryptoProfile.outerRotB) ^ s0);
    const cWord = u32(pWord ^ s0);
    cipherWords[i] = cWord;
    s1 = u32(s1 ^ cWord);
  }

  // Encode cipherWords into permuted custom-alphabet Radix-85 ASCII armor
  const alphabetArr = rng.shuffle(SAFE_85_BASE);
  const alphabet = alphabetArr.join("");
  const dp = cryptoProfile.digitPerm;

  const prefix = options.payloadPrefix !== undefined ? options.payloadPrefix : "joshua";
  const chars = [prefix];
  const slotBuf = new Array(5);

  for (let i = 0; i < wordCount; i++) {
    let u = cipherWords[i];
    const d0 = u % 85;
    u = Math.floor(u / 85);
    const d1 = u % 85;
    u = Math.floor(u / 85);
    const d2 = u % 85;
    u = Math.floor(u / 85);
    const d3 = u % 85;
    const d4 = Math.floor(u / 85);

    slotBuf[dp[0]] = alphabetArr[d0];
    slotBuf[dp[1]] = alphabetArr[d1];
    slotBuf[dp[2]] = alphabetArr[d2];
    slotBuf[dp[3]] = alphabetArr[d3];
    slotBuf[dp[4]] = alphabetArr[d4];
    chars.push(slotBuf[0], slotBuf[1], slotBuf[2], slotBuf[3], slotBuf[4]);
  }

  const encodedPayload = chars.join("");

  return {
    encodedPayload,
    prefixLen: prefix.length,
    wordCount,
    rawByteSize: rawPlain.length,
    alphabet,
    cryptoParams: cryptoProfile
  };
}

module.exports = {
  createCryptoProfile,
  packAndEncryptModule
};
