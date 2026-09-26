import { log } from "./logging.js";
import { createPersistentStore, isNamedEntryList } from "./persistence.js";

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

const store = createPersistentStore({
  area: "tools",
  file: PERSIST_PATH,
  snapshot: () => Array.from(tools.values()),
  isValid: isNamedEntryList,
});

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
  const data = store.load() as ToolDefinition[] | undefined;
  if (!data) return;
  for (const tool of data) {
    tools.set(tool.name, tool);
  }
  log("tools", `Loaded ${tools.size} tool(s) from disk`);
}

/** Debounced atomic save (src/persistence.ts). */
export function persistTools(): void {
  store.schedule();
}

/** Save the tool registry now; false when the save failed or is suppressed. */
export function flushTools(): boolean {
  return store.flush();
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
