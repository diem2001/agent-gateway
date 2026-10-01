import { Router } from "express";
import { execSync } from "node:child_process";
import { createRequire } from "node:module";
import path from "node:path";
import { log } from "../logging.js";
import { readAuthStatus } from "../model-proxy.js";

const router = Router();
const AUTH_TMUX_SESSION = "claude-auth";
const HOME = process.env.HOME || "/home/node";
function execEnv(): NodeJS.ProcessEnv { return { ...process.env, HOME }; }

/**
 * The login runs the Claude Code CLI bundled with the SDK in the image, never
 * `~/.local/bin/claude`: that path lives in the home directory agents could
 * write, so a planted binary would run here with the gateway's secrets
 * (MVP-7678). The bundled CLI is the same runtime the agent runs use.
 */
export function bundledCliCommand(): string {
  const sdkEntry = createRequire(import.meta.url).resolve("@anthropic-ai/claude-agent-sdk");
  const command = `${process.execPath} ${path.join(path.dirname(sdkEntry), "cli.js")}`;
  // The command is typed into tmux and a shell: refuse anything but a plain path.
  if (!/^[A-Za-z0-9_@.\/-]+ [A-Za-z0-9_@.\/-]+$/.test(command)) throw new Error("bundled CLI path is not a plain path");
  return command;
}

// The bundled CLI (2.0.77) has no `auth status` subcommand: the words would be
// taken as a prompt and start a model call. The state comes from the trusted
// files instead (model-proxy.ts readAuthStatus).
router.get("/v1/auth/status", (_req, res) => {
  try { res.json(readAuthStatus(HOME)); }
  catch { res.json({ loggedIn: false, tokenExpired: false, expiresAt: null }); }
});

router.post("/v1/auth/login", async (_req, res) => {
  try { execSync("tmux kill-session -t " + AUTH_TMUX_SESSION + " 2>/dev/null"); } catch { /* no session */ }
  const cli = bundledCliCommand();
  execSync("tmux new-session -d -s " + AUTH_TMUX_SESSION + " -x 500 -y 40 \"" + cli + " --dangerously-skip-permissions\"", { env: execEnv() });
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
  await sleep(3000); execSync("tmux send-keys -t " + AUTH_TMUX_SESSION + " Enter");
  await sleep(2000); execSync("tmux send-keys -t " + AUTH_TMUX_SESSION + " \"/login\" Enter");
  await sleep(2000); execSync("tmux send-keys -t " + AUTH_TMUX_SESSION + " Enter");
  log("auth", "Started interactive login flow");
  let attempts = 0;
  const interval = setInterval(() => {
    attempts++;
    try {
      const capture = execSync("tmux capture-pane -t " + AUTH_TMUX_SESSION + " -p -J 2>/dev/null", { timeout: 5000 }).toString();
      const urlMatch = capture.match(/https:\/\/[^\s]+authorize[^\s]*/);
      if (urlMatch) { clearInterval(interval); log("auth", "Auth URL found: " + urlMatch[0].substring(0, 80) + "..."); res.json({ url: urlMatch[0] }); }
      else if (attempts > 60) { clearInterval(interval); log("auth", "Timeout waiting for auth URL"); res.status(500).json({ error: "Timeout waiting for auth URL" }); try { execSync("tmux kill-session -t " + AUTH_TMUX_SESSION); } catch { /* ignore */ } }
    } catch { if (attempts > 60) { clearInterval(interval); res.status(500).json({ error: "tmux session died" }); } }
  }, 500);
});

router.post("/v1/auth/submit-code", (req, res) => {
  const { code } = req.body as { code?: string };
  if (!code) { res.status(400).json({ error: "code is required" }); return; }
  try { execSync("tmux has-session -t " + AUTH_TMUX_SESSION + " 2>/dev/null"); } catch { res.status(400).json({ error: "No auth login session running. Call POST /v1/auth/login first." }); return; }
  const escaped = code.replace(/'/g, "'\\''");
  execSync("tmux send-keys -t " + AUTH_TMUX_SESSION + " '" + escaped + "' Enter");
  log("auth", "Code sent via tmux: " + code.substring(0, 30) + "...");
  let attempts = 0;
  const interval = setInterval(() => {
    attempts++;
    try {
      const status = readAuthStatus(HOME);
      if (status.loggedIn && status.authMethod === "claude.ai") { clearInterval(interval); try { execSync("tmux kill-session -t " + AUTH_TMUX_SESSION + " 2>/dev/null"); } catch { /* ignore */ } log("auth", "Login successful: " + status.email); res.json({ success: true, ...status }); return; }
    } catch { /* keep polling */ }
    if (attempts > 30) {
      clearInterval(interval);
      let errorMsg = "Timeout waiting for login";
      try { const capture = execSync("tmux capture-pane -t " + AUTH_TMUX_SESSION + " -p -J 2>/dev/null").toString(); const errMatch = capture.match(/OAuth error: ([^\n]+)/); if (errMatch) errorMsg = errMatch[1]; } catch { /* ignore */ }
      try { execSync("tmux kill-session -t " + AUTH_TMUX_SESSION + " 2>/dev/null"); } catch { /* ignore */ }
      res.status(500).json({ error: errorMsg });
    }
  }, 500);
});

export default router;
