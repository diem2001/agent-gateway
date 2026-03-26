import { Router } from "express";
import { execSync } from "node:child_process";
import { log } from "../logging.js";

const router = Router();
const CLAUDE_CLI = process.env.CLAUDE_CLI || "/home/node/.local/bin/claude";
const AUTH_TMUX_SESSION = "claude-auth";
const HOME = process.env.HOME || "/home/node";
function execEnv(): NodeJS.ProcessEnv { return { ...process.env, HOME }; }

router.get("/v1/auth/status", (_req, res) => {
  try { const result = execSync(CLAUDE_CLI + " auth status", { timeout: 10_000, env: execEnv() }); res.json(JSON.parse(result.toString())); }
  catch { res.json({ loggedIn: false }); }
});

router.post("/v1/auth/login", async (_req, res) => {
  try { execSync("tmux kill-session -t " + AUTH_TMUX_SESSION + " 2>/dev/null"); } catch { /* no session */ }
  const claudeHost = process.env.CLAUDE_CLI_HOST || "/home/node/.local/bin/claude";
  execSync("tmux new-session -d -s " + AUTH_TMUX_SESSION + " -x 500 -y 40 \"" + claudeHost + " --dangerously-skip-permissions\"", { env: execEnv() });
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
      const result = execSync(CLAUDE_CLI + " auth status", { timeout: 5000, env: execEnv() });
      const status = JSON.parse(result.toString()) as { loggedIn?: boolean; email?: string };
      if (status.loggedIn) { clearInterval(interval); try { execSync("tmux kill-session -t " + AUTH_TMUX_SESSION + " 2>/dev/null"); } catch { /* ignore */ } log("auth", "Login successful: " + status.email); res.json({ success: true, ...status }); return; }
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
