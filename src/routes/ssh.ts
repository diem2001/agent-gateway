import { Router } from "express";
import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import { log } from "../logging.js";

const router = Router();
const HOME = process.env.HOME || "/home/node";
const SSH_DIR = path.join(HOME, ".ssh");

router.post("/v1/ssh-keys", (req, res) => {
  const { privateKey, publicKey, filename } = req.body as { privateKey?: string; publicKey?: string; filename?: string; };
  if (!privateKey) { res.status(400).json({ error: "privateKey is required" }); return; }
  const keyName = filename || "id_ed25519";
  if (!/^[a-zA-Z0-9_-]+$/.test(keyName)) { res.status(400).json({ error: "Invalid key filename" }); return; }
  const dst = path.join(SSH_DIR, keyName);
  const dstPub = dst + ".pub";
  try {
    fs.mkdirSync(SSH_DIR, { recursive: true, mode: 0o700 });
    fs.writeFileSync(dst, privateKey.trim() + "\n", { mode: 0o600 });
    if (publicKey) { fs.writeFileSync(dstPub, publicKey.trim() + "\n", { mode: 0o644 }); }
    else { try { const derived = execSync("ssh-keygen -y -f " + dst + " 2>/dev/null").toString().trim(); if (derived) { fs.writeFileSync(dstPub, derived + "\n", { mode: 0o644 }); log("ssh", "Public key derived from private key"); } } catch { log("ssh", "Could not derive public key (key may require passphrase)"); } }
    const configPath = path.join(SSH_DIR, "config");
    fs.writeFileSync(configPath, "# Managed by agent-gateway\nHost *\n  StrictHostKeyChecking accept-new\n  IdentityFile " + dst + "\n", { mode: 0o644 });
    let pubKey = ""; try { pubKey = fs.readFileSync(dstPub, "utf-8").trim(); } catch { /* may not exist */ }
    log("ssh", "SSH key written: " + keyName);
    res.json({ status: "ok", message: "SSH keys updated", publicKey: pubKey });
  } catch (e) { const msg = e instanceof Error ? e.message : String(e); log("ssh", "Key write failed: " + msg); res.status(500).json({ error: msg }); }
});

export default router;
