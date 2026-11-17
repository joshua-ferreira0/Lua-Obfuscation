"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");
const { obfuscate } = require("./src/index");

const PORT = Number(process.env.PORT) || 8090;
const ROOT_DIR = __dirname;

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon"
};

function readJsonBody(req, maxBytes = 16 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        reject(new Error("Payload too large (max 16 MB)."));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      try {
        const raw = Buffer.concat(chunks).toString("utf8");
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        reject(new Error("Invalid JSON body."));
      }
    });
    req.on("error", reject);
  });
}

function sendJson(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store"
  });
  res.end(body);
}

const server = http.createServer(async (req, res) => {
  try {
    const urlPath = req.url.split("?")[0];

    if (req.method === "POST" && urlPath === "/api/obfuscate") {
      const body = await readJsonBody(req);
      if (typeof body.code !== "string" || body.code.trim().length === 0) {
        return sendJson(res, 400, { ok: false, error: "Please enter Lua / Luau source code to obfuscate." });
      }
      try {
        const opts = {
          ...(body.options || {}),
          payloadPrefix: "joshua",
          watermark: false
        };
        const result = obfuscate(body.code, opts);
        return sendJson(res, 200, { ok: true, ...result });
      } catch (err) {
        return sendJson(res, 400, { ok: false, error: err.message });
      }
    }

    if (req.method === "GET") {
      const relPath = urlPath === "/" ? "index.html" : urlPath.replace(/^\/+/, "");
      const safePath = path.normalize(path.join(ROOT_DIR, relPath));
      if (
        safePath.startsWith(ROOT_DIR) &&
        !relPath.startsWith("src") &&
        !relPath.startsWith("bin") &&
        fs.existsSync(safePath) &&
        fs.statSync(safePath).isFile()
      ) {
        const ext = path.extname(safePath).toLowerCase();
        const contentType = MIME_TYPES[ext] || "application/octet-stream";
        const content = fs.readFileSync(safePath);
        res.writeHead(200, {
          "Content-Type": contentType,
          "Cache-Control": "no-store"
        });
        res.end(content);
        return;
      }
    }

    sendJson(res, 404, { ok: false, error: "Not found" });
  } catch (err) {
    sendJson(res, 500, { ok: false, error: err.message });
  }
});

server.listen(PORT, () => {
  console.log(`LuaObf server running at http://localhost:${PORT}`);
});
