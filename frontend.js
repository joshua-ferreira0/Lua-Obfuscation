"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { execFileSync } = require("child_process");

const BIN_DIR = path.join(__dirname, "..", "bin");
const LUAU_AST_BIN = path.join(BIN_DIR, "luau-ast.exe");
const LUAU_COMPILE_BIN = path.join(BIN_DIR, "luau-compile.exe");
const LUAU_RUN_BIN = path.join(BIN_DIR, "luau.exe");

const VALID_ESCAPES = new Set([
  "a", "b", "f", "n", "r", "t", "v", "\\", "\"", "'", "`",
  "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
  "x", "u", "z", "\n", "\r"
]);

/**
 * Normalizes minor Vanilla Lua 5.1 / 5.2 / 5.4 syntax differences (lenient string escapes,
 * redundant `;;` empty statements, and Lua 5.4 `<const>` attributes) while leaving comments
 * and long bracketed strings untouched.
 */
function normalizeVanillaLua(src) {
  let out = "";
  let i = 0;
  const n = src.length;

  function matchLongBracket(pos) {
    if (src[pos] !== "[") return -1;
    let eq = 0;
    let p = pos + 1;
    while (p < n && src[p] === "=") {
      eq++;
      p++;
    }
    return p < n && src[p] === "[" ? eq : -1;
  }

  while (i < n) {
    // Line or block comment
    if (src[i] === "-" && src[i + 1] === "-") {
      const eq = matchLongBracket(i + 2);
      if (eq >= 0) {
        const closeTag = "]" + "=".repeat(eq) + "]";
        const endIdx = src.indexOf(closeTag, i + 4 + eq);
        if (endIdx === -1) {
          out += src.slice(i);
          break;
        }
        out += src.slice(i, endIdx + closeTag.length);
        i = endIdx + closeTag.length;
        continue;
      }
      const nl = src.indexOf("\n", i + 2);
      if (nl === -1) {
        out += src.slice(i);
        break;
      }
      out += src.slice(i, nl + 1);
      i = nl + 1;
      continue;
    }

    // Long string [[ ... ]] or [=[ ... ]=]
    const eq = matchLongBracket(i);
    if (eq >= 0) {
      const closeTag = "]" + "=".repeat(eq) + "]";
      const endIdx = src.indexOf(closeTag, i + 2 + eq);
      if (endIdx === -1) {
        out += src.slice(i);
        break;
      }
      out += src.slice(i, endIdx + closeTag.length);
      i = endIdx + closeTag.length;
      continue;
    }

    // Short string literal ('...', "...", `...`)
    if (src[i] === "\"" || src[i] === "'" || src[i] === "`") {
      const quote = src[i];
      out += quote;
      i++;
      while (i < n && src[i] !== quote) {
        if (src[i] === "\\" && i + 1 < n) {
          const nextCh = src[i + 1];
          if (VALID_ESCAPES.has(nextCh)) {
            out += "\\" + nextCh;
          } else {
            // Lua 5.1 drops unknown backslash before literal char (e.g. "\%" -> "%")
            out += nextCh;
          }
          i += 2;
          continue;
        }
        out += src[i++];
      }
      if (i < n) out += src[i++];
      continue;
    }

    // Collapse consecutive semicolons (Lua 5.2+ empty statements)
    if (src[i] === ";") {
      out += ";";
      i++;
      while (i < n && (src[i] === ";" || src[i] === " " || src[i] === "\t")) {
        if (src[i] !== ";") out += src[i];
        i++;
      }
      continue;
    }

    // Strip Lua 5.4 `<const>` attribute on locals
    if (src[i] === "<" && src.slice(i, i + 7) === "<const>") {
      i += 7;
      continue;
    }

    out += src[i++];
  }

  return out;
}

function parseLuauToAST(sourceCode) {
  if (typeof sourceCode !== "string") {
    throw new Error("Input Lua source must be a string.");
  }

  const id = crypto.randomBytes(8).toString("hex");
  const tmpFile = path.join(os.tmpdir(), `luaobf_in_${id}.luau`);
  fs.writeFileSync(tmpFile, Buffer.from(sourceCode, "utf8"));

  try {
    // 1. Validate syntax using Luau parser; fallback to Vanilla Lua normalizer if needed
    try {
      execFileSync(LUAU_COMPILE_BIN, ["--only-parse", tmpFile], {
        stdio: ["ignore", "pipe", "pipe"],
        maxBuffer: 64 * 1024 * 1024
      });
    } catch (firstErr) {
      const normalized = normalizeVanillaLua(sourceCode);
      if (normalized !== sourceCode) {
        fs.writeFileSync(tmpFile, Buffer.from(normalized, "utf8"));
        try {
          execFileSync(LUAU_COMPILE_BIN, ["--only-parse", tmpFile], {
            stdio: ["ignore", "pipe", "pipe"],
            maxBuffer: 64 * 1024 * 1024
          });
        } catch {
          const stderr = firstErr.stderr ? firstErr.stderr.toString("utf8") : firstErr.message;
          const cleaned = stderr.replaceAll(tmpFile, "<input.lua>").trim();
          throw new Error(`Lua Syntax Error:\n${cleaned}`);
        }
      } else {
        const stderr = firstErr.stderr ? firstErr.stderr.toString("utf8") : firstErr.message;
        const cleaned = stderr.replaceAll(tmpFile, "<input.lua>").trim();
        throw new Error(`Lua Syntax Error:\n${cleaned}`);
      }
    }

    // 2. Extract complete resolved AST via luau-ast binary
    const rawAstBuf = execFileSync(LUAU_AST_BIN, [tmpFile], {
      stdio: ["ignore", "pipe", "pipe"],
      maxBuffer: 128 * 1024 * 1024
    });

    const parsed = JSON.parse(rawAstBuf.toString("latin1"));
    if (!parsed || !parsed.root) {
      throw new Error("Failed to obtain root AST node.");
    }
    return parsed.root;
  } finally {
    try {
      if (fs.existsSync(tmpFile)) fs.unlinkSync(tmpFile);
    } catch (_) {
      // ignore cleanup error
    }
  }
}

function executeLuauScript(luauCode, args = [], timeoutMs = 8000) {
  const id = crypto.randomBytes(8).toString("hex");
  const tmpFile = path.join(os.tmpdir(), `luaobf_exec_${id}.luau`);
  fs.writeFileSync(tmpFile, Buffer.from(luauCode, "utf8"));

  try {
    const cliArgs = [tmpFile];
    if (args.length > 0) {
      cliArgs.push("-a", ...args.map(String));
    }
    const t0 = performance.now();
    const stdout = execFileSync(LUAU_RUN_BIN, cliArgs, {
      stdio: ["ignore", "pipe", "pipe"],
      timeout: timeoutMs,
      maxBuffer: 32 * 1024 * 1024
    });
    const elapsedMs = performance.now() - t0;
    return {
      ok: true,
      stdout: stdout.toString("utf8").replace(/\r\n/g, "\n"),
      stderr: "",
      elapsedMs
    };
  } catch (err) {
    return {
      ok: false,
      stdout: err.stdout ? err.stdout.toString("utf8").replace(/\r\n/g, "\n") : "",
      stderr: (err.stderr ? err.stderr.toString("utf8") : err.message)
        .replaceAll(tmpFile, "<script.luau>")
        .replace(/\r\n/g, "\n"),
      elapsedMs: 0
    };
  } finally {
    try {
      if (fs.existsSync(tmpFile)) fs.unlinkSync(tmpFile);
    } catch (_) {
      // ignore
    }
  }
}

module.exports = {
  parseLuauToAST,
  executeLuauScript,
  LUAU_RUN_BIN
};
