import fs from "node:fs";
import path from "node:path";
import { log } from "./logging.js";

/* ------------------------------------------------------------------ */
/*  Types                                                               */
/* ------------------------------------------------------------------ */

export interface ToolDefinition {
  name: string;
  description: string;
  input_schema: Record<string, unknown>;
  webhook_url: string;
  timeout_ms?: number;
}

/* ------------------------------------------------------------------ */
/*  State                                                               */
/* ------------------------------------------------------------------ */

const tools = new Map<string, ToolDefinition>();

const PERSIST_PATH =
  process.env.TOOLS_PERSIST_PATH || "./data/tools.json";

let persistTimer: ReturnType<typeof setTimeout> | null = null;

/* ------------------------------------------------------------------ */
/*  Validation                                                          */
/* ------------------------------------------------------------------ */

export function isValidJsonSchema(schema: unknown): boolean {
  if (typeof schema !== "object" || schema === null || Array.isArray(schema)) {
    return false;
  }
  const s = schema as Record<string, unknown>;
  return typeof s["type"] === "string";
}

/* ------------------------------------------------------------------ */
/*  Persistence                                                         */
/* ------------------------------------------------------------------ */

export function loadTools(): void {
  try {
    if (fs.existsSync(PERSIST_PATH)) {
      const raw = fs.readFileSync(PERSIST_PATH, "utf-8");
      const data: ToolDefinition[] = JSON.parse(raw);
      for (const tool of data) {
        tools.set(tool.name, tool);
      }
      log("tools", `Loaded ${tools.size} tool(s) from disk`);
    }
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    log("tools", `Failed to load: ${msg}`);
  }
}

export function persistTools(): void {
  if (persistTimer) return; // debounce
  persistTimer = setTimeout(() => {
    persistTimer = null;
    try {
      const dir = path.dirname(PERSIST_PATH);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      const data = Array.from(tools.values());
      fs.writeFileSync(PERSIST_PATH, JSON.stringify(data, null, 2));
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tools", `Failed to persist: ${msg}`);
    }
  }, 100);
}

/* ------------------------------------------------------------------ */
/*  CRUD                                                                */
/* ------------------------------------------------------------------ */

export function registerTool(def: ToolDefinition): boolean {
  const isNew = !tools.has(def.name);
  tools.set(def.name, def);
  persistTools();
  log("tools", `${isNew ? "Registered" : "Updated"} tool: ${def.name}`);
  return isNew;
}

export function getTool(name: string): ToolDefinition | undefined {
  return tools.get(name);
}

export function getAllTools(): ToolDefinition[] {
  return Array.from(tools.values());
}

export function deleteTool(name: string): boolean {
  const deleted = tools.delete(name);
  if (deleted) {
    persistTools();
    log("tools", `Deleted tool: ${name}`);
  }
  return deleted;
}
