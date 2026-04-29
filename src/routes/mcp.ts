import { Router, type Request, type Response } from "express";
import {
  registerMcpServer,
  getMcpServer,
  getAllMcpServers,
  deleteMcpServer,
  checkMcpServerHealth,
  type McpServerDefinition,
  type UserCredentialSchema,
} from "../mcp-registry.js";
import { getCredentialTemplateFieldKeys } from "../credential-composer.js";

const router = Router();

type SchemaValidationErrorCode =
  | "SCHEMA_FIELD_KEY_DUPLICATE"
  | "SCHEMA_FIELD_TYPE_INVALID"
  | "SCHEMA_INVALID"
  | "SCHEMA_TARGET_MISMATCH"
  | "SCHEMA_TEMPLATE_UNKNOWN_FIELD";

interface SchemaValidationError {
  code: SchemaValidationErrorCode;
  message: string;
}

const FIELD_TYPES = new Set(["text", "password", "url", "email"]);
const OUTPUT_TARGETS = new Set(["headers", "env"]);

function schemaError(code: SchemaValidationErrorCode, message: string): SchemaValidationError {
  return { code, message };
}

function validateUserCredentialSchema(
  schema: unknown,
  transport: McpServerDefinition["type"],
): SchemaValidationError | null {
  if (schema === undefined) return null;
  if (!schema || typeof schema !== "object") {
    return schemaError("SCHEMA_INVALID", "userCredentialSchema must be an object");
  }

  const candidate = schema as Partial<UserCredentialSchema>;
  if (!Array.isArray(candidate.fields)) {
    return schemaError("SCHEMA_INVALID", "userCredentialSchema.fields must be an array");
  }
  if (!Array.isArray(candidate.outputs)) {
    return schemaError("SCHEMA_INVALID", "userCredentialSchema.outputs must be an array");
  }

  const fieldKeys = new Set<string>();
  for (const field of candidate.fields) {
    if (!field || typeof field !== "object") {
      return schemaError("SCHEMA_INVALID", "credential fields must be objects");
    }
    const typedField = field as Partial<UserCredentialSchema["fields"][number]>;
    if (!typedField.key || typeof typedField.key !== "string") {
      return schemaError("SCHEMA_INVALID", "credential field key is required");
    }
    if (fieldKeys.has(typedField.key)) {
      return schemaError(
        "SCHEMA_FIELD_KEY_DUPLICATE",
        `credential field key "${typedField.key}" is duplicated`,
      );
    }
    fieldKeys.add(typedField.key);
    if (!typedField.label || typeof typedField.label !== "string") {
      return schemaError("SCHEMA_INVALID", `credential field "${typedField.key}" label is required`);
    }
    if (!typedField.type || !FIELD_TYPES.has(typedField.type)) {
      return schemaError(
        "SCHEMA_FIELD_TYPE_INVALID",
        `credential field "${typedField.key}" type must be text, password, url, or email`,
      );
    }
    if (typeof typedField.required !== "boolean") {
      return schemaError(
        "SCHEMA_INVALID",
        `credential field "${typedField.key}" required must be a boolean`,
      );
    }
  }

  const expectedTarget = transport === "stdio" ? "env" : "headers";
  for (const output of candidate.outputs) {
    if (!output || typeof output !== "object") {
      return schemaError("SCHEMA_INVALID", "credential outputs must be objects");
    }
    const typedOutput = output as Partial<UserCredentialSchema["outputs"][number]>;
    if (!typedOutput.target || !OUTPUT_TARGETS.has(typedOutput.target)) {
      return schemaError("SCHEMA_INVALID", "credential output target must be headers or env");
    }
    if (typedOutput.target !== expectedTarget) {
      return schemaError(
        "SCHEMA_TARGET_MISMATCH",
        `credential output target "${typedOutput.target}" is invalid for ${transport} transport`,
      );
    }
    if (!typedOutput.outputKey || typeof typedOutput.outputKey !== "string") {
      return schemaError("SCHEMA_INVALID", "credential outputKey is required");
    }
    if (!typedOutput.template || typeof typedOutput.template !== "string") {
      return schemaError("SCHEMA_INVALID", `credential output "${typedOutput.outputKey}" template is required`);
    }
    for (const fieldKey of getCredentialTemplateFieldKeys(typedOutput.template)) {
      if (!fieldKeys.has(fieldKey)) {
        return schemaError(
          "SCHEMA_TEMPLATE_UNKNOWN_FIELD",
          `credential output "${typedOutput.outputKey}" references unknown field "${fieldKey}"`,
        );
      }
    }
  }

  return null;
}

/* ------------------------------------------------------------------ */
/*  PUT /v1/mcp-servers/:name — register or update                     */
/* ------------------------------------------------------------------ */

router.put("/v1/mcp-servers/:name", (req: Request, res: Response) => {
  const name = String(req.params.name);
  const body = req.body as Partial<McpServerDefinition>;

  if (!body.type || !["http", "sse", "stdio"].includes(body.type)) {
    res.status(400).json({ error: 'type is required and must be "http", "sse", or "stdio"' });
    return;
  }

  if ((body.type === "http" || body.type === "sse") && (!body.url || typeof body.url !== "string")) {
    res.status(400).json({ error: "url is required for http/sse transport" });
    return;
  }

  if (body.type === "stdio" && (!body.command || typeof body.command !== "string")) {
    res.status(400).json({ error: "command is required for stdio transport" });
    return;
  }

  const schemaValidationError = validateUserCredentialSchema(body.userCredentialSchema, body.type);
  if (schemaValidationError) {
    res.status(400).json({ error: schemaValidationError });
    return;
  }

  const existing = getMcpServer(name);
  const now = new Date().toISOString();

  const def: McpServerDefinition = {
    name,
    description: body.description || "",
    enabled: body.enabled !== false,
    type: body.type,
    url: body.url,
    headers: body.headers,
    command: body.command,
    args: body.args,
    env: body.env,
    allowedToolsPattern: body.allowedToolsPattern,
    userCredentialSchema: body.userCredentialSchema,
    createdAt: existing?.createdAt || now,
    updatedAt: now,
  };

  const isNew = registerMcpServer(def);
  res.status(isNew ? 201 : 200).json(def);
});

/* ------------------------------------------------------------------ */
/*  GET /v1/mcp-servers — list all                                     */
/* ------------------------------------------------------------------ */

router.get("/v1/mcp-servers", (_req: Request, res: Response) => {
  res.json({ servers: getAllMcpServers() });
});

/* ------------------------------------------------------------------ */
/*  GET /v1/mcp-servers/:name — get single                             */
/* ------------------------------------------------------------------ */

router.get("/v1/mcp-servers/:name", (req: Request, res: Response) => {
  const srv = getMcpServer(String(req.params.name));
  if (!srv) {
    res.status(404).json({ error: "MCP server not found" });
    return;
  }
  res.json(srv);
});

/* ------------------------------------------------------------------ */
/*  DELETE /v1/mcp-servers/:name — remove                              */
/* ------------------------------------------------------------------ */

router.delete("/v1/mcp-servers/:name", (req: Request, res: Response) => {
  const deleted = deleteMcpServer(String(req.params.name));
  if (!deleted) {
    res.status(404).json({ error: "MCP server not found" });
    return;
  }
  res.status(204).send();
});

/* ------------------------------------------------------------------ */
/*  POST /v1/mcp-servers/:name/restart — restart (toggle)              */
/* ------------------------------------------------------------------ */

router.post("/v1/mcp-servers/:name/restart", (req: Request, res: Response) => {
  const srv = getMcpServer(String(req.params.name));
  if (!srv) {
    res.status(404).json({ error: "MCP server not found" });
    return;
  }

  // For HTTP/SSE: "restart" means the SDK will reconnect on next query.
  // We toggle enabled off→on to force a fresh connection.
  const now = new Date().toISOString();
  registerMcpServer({ ...srv, enabled: true, updatedAt: now });

  res.json({ restarted: true, name: srv.name });
});

/* ------------------------------------------------------------------ */
/*  GET /v1/mcp-servers/:name/health — health check                    */
/* ------------------------------------------------------------------ */

router.get("/v1/mcp-servers/:name/health", async (req: Request, res: Response) => {
  const srv = getMcpServer(String(req.params.name));
  if (!srv) {
    res.status(404).json({ error: "MCP server not found" });
    return;
  }

  const health = await checkMcpServerHealth(srv);
  res.json({ name: srv.name, ...health });
});

export default router;
