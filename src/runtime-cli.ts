import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

/** The native Claude Code binary installed as the SDK's platform package. */
export function bundledCliPath(): string {
  const require = createRequire(import.meta.url);
  const platformPackage = `@anthropic-ai/claude-agent-sdk-${process.platform}-${process.arch}`;
  const packageJson = require.resolve(`${platformPackage}/package.json`);
  const binary = path.join(path.dirname(packageJson), "claude");
  if (!fs.statSync(binary).isFile()) throw new Error("bundled Claude CLI is missing");
  return binary;
}
