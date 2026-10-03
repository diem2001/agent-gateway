import { Router, type Request, type Response } from "express";
import { log } from "../logging.js";
import {
  registerMcpServer,
  getMcpServer,
  getAllMcpServers,
  deleteMcpServer,
  checkMcpServerHealth,
  isMcpServerOwner,
  publicMcpServer,
  publicUrlProblem,
  resolveStoredCredentialMaps,
  type McpServerDefinition,
  type UserCredentialSchema,
} from "../mcp-registry.js";
import { getCredentialTemplateFieldKeys } from "../credential-composer.js";
import { testMcpServer, McpTestError } from "../mcp-test-client.js";
import { callMcpTool, McpCallError } from "../mcp-call-client.js";
import { carriesCredentialValue, credentialMapsError, hasUserCredential, type McpCredentialOverride } from "../mcp-overrides.js";
import {
  CREDENTIAL_HEADER,
  UPLOAD_MESSAGES,
  UPLOAD_ROUTE,
  isValidUploadTarget,
  matchUploadPath,
  parseCredentialHeader,
  readUploadIdleTimeout,
  refuseUpload,
  relayUpload,
} from "../mcp-upload-relay.js";

const router = Router();
const MCP_TEST_TIMEOUT_MS = parseInt(process.env.MCP_TEST_TIMEOUT_MS || "10000", 10);
const MCP_CALL_TIMEOUT_MS = parseInt(process.env.MCP_CALL_TIMEOUT_MS || "10000", 10);
const MCP_UPLOAD_IDLE_TIMEOUT_MS = readUploadIdleTimeout(process.env.MCP_UPLOAD_IDLE_TIMEOUT_MS);

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

/**
 * Name rule for NEW registry entries. The Agent SDK builds tool names as
 * `mcp__<server>__<tool>` without shortening them, so the cap stays at 32.
 * Existing entries are never refused because of their name, so an
 * administrator can still edit, switch off or delete an entry created earlier.
 */
const MCP_SERVER_NAME_RULE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/;
const MCP_SERVER_NAME_INVALID_MESSAGE = "Use 1–32 letters, digits, '-' or '_', starting with a letter or digit.";

/**
 * The one refusal for a registry entry the caller does not own (MVP-7925): status 403 and a fixed body that is the
 * same for an entry owned by another label and for an ownerless one, and never carries the owner label. The operator
 * log names the caller only.
 */
const OWNER_MISMATCH_CODE = "MCP_SERVER_OWNER_MISMATCH";

function ownerMismatchBody(name: string): { error: { code: string; message: string } } {
  return { error: { code: OWNER_MISMATCH_CODE, message: `MCP server "${name}" is registered by another application` } };
}

function logOwnerMismatch(name: string, method: string, label: string | undefined): void {
  log("audit", `mcp.registry.owner_mismatch serverName=${name} method=${method} caller=${label ?? ""}`);
}

/** Fixed refusals for the two write-only/public fields of MVP-7957; they never carry a part of the submitted value. */
const URL_INVALID_BODY = {
  error: {
    code: "MCP_SERVER_URL_INVALID",
    message:
      "The server address must be an http(s) URL without a login, query or fragment. Put credentials in headers, env or per-user credentials.",
  },
};
const ARGS_INVALID_BODY = {
  error: { code: "MCP_SERVER_ARGS_INVALID", message: "args must be a list of text values without NUL characters." },
};

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
  const existing = getMcpServer(name);

  // The owner check comes first, so a caller that does not own the entry gets the refusal whatever it sends. A new
  // name needs a caller label: it is recorded as the owner, an ownerless entry is never created.
  const label = req.clientLabel;
  if (existing ? !isMcpServerOwner(existing, label) : !label) {
    logOwnerMismatch(name, "PUT", label);
    res.status(403).json(ownerMismatchBody(name));
    return;
  }

  if (!existing && !MCP_SERVER_NAME_RULE.test(name)) {
    res.status(400).json({ error: { code: "MCP_SERVER_NAME_INVALID", message: MCP_SERVER_NAME_INVALID_MESSAGE } });
    return;
  }

  if (!body.type || !["http", "sse", "stdio"].includes(body.type)) {
    res.status(400).json({ error: 'type is required and must be "http", "sse", or "stdio"' });
    return;
  }

  // The address is public configuration, so it is checked on its way in (see publicUrlProblem). A same-family edit that
  // omits it keeps the stored one, which also leaves a legacy address that was never returned untouched.
  let url: string | undefined;
  if (body.type === "http" || body.type === "sse") {
    if (body.url === undefined) {
      const keepable = existing !== undefined && existing.type !== "stdio" && typeof existing.url === "string";
      if (!keepable) {
        res.status(400).json({ error: "url is required for http/sse transport" });
        return;
      }
      url = existing.url;
    } else if (publicUrlProblem(body.url) !== null) {
      res.status(400).json(URL_INVALID_BODY);
      return;
    } else {
      url = body.url;
    }
  }

  if (
    body.args !== undefined &&
    (!Array.isArray(body.args) || body.args.some((arg) => typeof arg !== "string" || arg.includes("\0")))
  ) {
    res.status(400).json(ARGS_INVALID_BODY);
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

  const credentialError = credentialMapsError(body.headers, body.env);
  if (credentialError) {
    res.status(400).json({ error: credentialError });
    return;
  }

  if (body.requireUserCredentials !== undefined && typeof body.requireUserCredentials !== "boolean") {
    res.status(400).json({ error: "requireUserCredentials must be a boolean" });
    return;
  }

  // The credential relay cannot cover SSE (its endpoint event may name another upstream URL).
  if (body.requireUserCredentials === true && body.type === "sse") {
    res.status(400).json({ error: "requireUserCredentials is not supported for sse transport" });
    return;
  }

  // headers, env and args are write-only: a body that omits one keeps the stored value (see resolveStoredCredentialMaps).
  const resolved = resolveStoredCredentialMaps(existing, body as { type: McpServerDefinition["type"] });
  if ("error" in resolved) {
    res.status(400).json({ error: resolved.error });
    return;
  }

  const now = new Date().toISOString();

  const def: McpServerDefinition = {
    name,
    description: body.description || "",
    enabled: body.enabled !== false,
    type: body.type,
    ...(url !== undefined ? { url } : {}),
    ...(resolved.maps.headers ? { headers: resolved.maps.headers } : {}),
    command: body.command,
    ...(resolved.maps.args ? { args: resolved.maps.args } : {}),
    ...(resolved.maps.env ? { env: resolved.maps.env } : {}),
    allowedToolsPattern: body.allowedToolsPattern,
    userCredentialSchema: body.userCredentialSchema,
    // Stored and returned only when sent.
    ...(body.requireUserCredentials !== undefined ? { requireUserCredentials: body.requireUserCredentials } : {}),
    // The owner is the authenticated label of the first registration; a body `owner` is ignored.
    owner: existing ? existing.owner : label,
    createdAt: existing?.createdAt || now,
    updatedAt: now,
  };

  const isNew = registerMcpServer(def);
  res.status(isNew ? 201 : 200).json(publicMcpServer(def));
});

/* ------------------------------------------------------------------ */
/*  GET /v1/mcp-servers — list all                                     */
/* ------------------------------------------------------------------ */

router.get("/v1/mcp-servers", (_req: Request, res: Response) => {
  res.json({ servers: getAllMcpServers().map(publicMcpServer) });
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
  res.json(publicMcpServer(srv));
});

/* ------------------------------------------------------------------ */
/*  DELETE /v1/mcp-servers/:name — remove                              */
/* ------------------------------------------------------------------ */

router.delete("/v1/mcp-servers/:name", (req: Request, res: Response) => {
  const name = String(req.params.name);
  const existing = getMcpServer(name);
  if (!existing) {
    res.status(404).json({ error: "MCP server not found" });
    return;
  }
  if (!isMcpServerOwner(existing, req.clientLabel)) {
    logOwnerMismatch(name, "DELETE", req.clientLabel);
    res.status(403).json(ownerMismatchBody(name));
    return;
  }
  deleteMcpServer(name);
  res.status(204).send();
});

/* ------------------------------------------------------------------ */
/*  POST /v1/mcp-servers/:name/test — probe tools/list                 */
/* ------------------------------------------------------------------ */

router.post("/v1/mcp-servers/:name/test", async (req: Request, res: Response) => {
  const name = String(req.params.name);
  const srv = getMcpServer(name);
  if (!srv) {
    res.status(400).json({ error: { code: "MCP_SERVER_NOT_FOUND", message: `${name} is not registered` } });
    return;
  }

  const body = (req.body ?? {}) as McpCredentialOverride;
  const credentialError = credentialMapsError(body.headers, body.env);
  if (credentialError) {
    res.status(400).json({ error: { code: "MCP_OVERRIDE_INVALID", message: credentialError } });
    return;
  }

  // An ownerless entry never receives a caller's credential (MVP-7925).
  if (srv.owner === undefined && carriesCredentialValue(body)) {
    logOwnerMismatch(name, "test", req.clientLabel);
    res.status(403).json(ownerMismatchBody(name));
    return;
  }

  try {
    const result = await testMcpServer(srv, body, MCP_TEST_TIMEOUT_MS);
    log("audit", `mcp.test.called serverName=${name} result=ok`);
    res.json(result);
  } catch (error) {
    if (error instanceof McpTestError) {
      const result =
        error.code === "MCP_AUTH_FAILED"
          ? "auth_failed"
          : error.code === "MCP_TIMEOUT"
            ? "timeout"
            : "network_error";
      log("audit", `mcp.test.called serverName=${name} result=${result}`);
      const status = error.code === "MCP_AUTH_FAILED" ? 401 : error.code === "MCP_TIMEOUT" ? 504 : 502;
      res.status(status).json({ error: { code: error.code, message: error.message } });
      return;
    }
    log("audit", `mcp.test.called serverName=${name} result=network_error`);
    res.status(502).json({ error: { code: "MCP_NETWORK_ERROR", message: "MCP transport failure" } });
  }
});

/* ------------------------------------------------------------------ */
/*  POST /v1/mcp-servers/:name/call — direct (LLM-free) tools/call      */
/* ------------------------------------------------------------------ */

router.post("/v1/mcp-servers/:name/call", async (req: Request, res: Response) => {
  const name = String(req.params.name);

  // 1. Unknown / unregistered server → 400 MCP_SERVER_NOT_FOUND.
  const srv = getMcpServer(name);
  if (!srv) {
    res.status(400).json({ error: { code: "MCP_SERVER_NOT_FOUND", message: `${name} is not registered` } });
    return;
  }

  // 2. Registered but disabled → 400 MCP_SERVER_DISABLED, BEFORE any upstream
  //    connection. This is the /call-specific gate (DEC-GW-003): unlike the
  //    /test diagnostic probe, /call is production execution and must not run
  //    tools on a disabled server.
  if (!srv.enabled) {
    res.status(400).json({
      error: {
        code: "MCP_SERVER_DISABLED",
        message: `${name} is registered but disabled; enable the server before calling its tools`,
      },
    });
    return;
  }

  // 3. Body validation: tool (non-empty string) + arguments (object) → 400 MCP_CALL_INVALID.
  const body = (req.body ?? {}) as {
    tool?: unknown;
    arguments?: unknown;
    credentials?: unknown;
  };
  if (typeof body.tool !== "string" || body.tool.length === 0) {
    res.status(400).json({ error: { code: "MCP_CALL_INVALID", message: "tool must be a non-empty string" } });
    return;
  }
  if (!body.arguments || typeof body.arguments !== "object" || Array.isArray(body.arguments)) {
    res.status(400).json({ error: { code: "MCP_CALL_INVALID", message: "arguments must be an object" } });
    return;
  }

  // 4. Credential override validation: credentials.headers / credentials.env
  //    (if present) must be string maps of sendable values → 400 MCP_OVERRIDE_INVALID. `credentials`
  //    is the per-server override VALUE (McpCredentialOverride), not a keyed map.
  const credentials = (body.credentials ?? {}) as McpCredentialOverride;
  if (body.credentials !== undefined) {
    if (!body.credentials || typeof body.credentials !== "object" || Array.isArray(body.credentials)) {
      res.status(400).json({ error: { code: "MCP_OVERRIDE_INVALID", message: "credentials must be an object" } });
      return;
    }
    const credentialError = credentialMapsError(credentials.headers, credentials.env, "credentials.");
    if (credentialError) {
      res.status(400).json({ error: { code: "MCP_OVERRIDE_INVALID", message: credentialError } });
      return;
    }
  }

  // 4a. An ownerless entry never receives a caller's credential (MVP-7925): the registry refusal, before any upstream request.
  if (srv.owner === undefined && carriesCredentialValue(credentials)) {
    logOwnerMismatch(name, "call", req.clientLabel);
    res.status(403).json(ownerMismatchBody(name));
    return;
  }

  // 4b. A server that requires a user credential is never called with the shared one (MVP-7679): refused
  //     before any upstream request, like the run that leaves such a server out.
  if (srv.requireUserCredentials === true && !hasUserCredential(srv, credentials)) {
    log("audit", `mcp.call.called serverName=${name} tool=${body.tool} result=auth_failed`);
    res.status(401).json({ error: { code: "MCP_AUTH_FAILED", message: "this server requires the user's credential and none was provided" } });
    return;
  }

  // 5. Execute the tool. Success → the MCP tools/call result verbatim at HTTP 200
  //    (a tool-level isError:true result is a normal 200, NOT the gateway envelope).
  try {
    const result = await callMcpTool(
      srv,
      body.tool,
      body.arguments as Record<string, unknown>,
      credentials,
      MCP_CALL_TIMEOUT_MS,
    );
    log("audit", `mcp.call.called serverName=${name} tool=${body.tool} result=ok`);
    res.json(result);
  } catch (error) {
    if (error instanceof McpCallError) {
      const result =
        error.code === "MCP_AUTH_FAILED"
          ? "auth_failed"
          : error.code === "MCP_TIMEOUT"
            ? "timeout"
            : "network_error";
      log("audit", `mcp.call.called serverName=${name} tool=${body.tool} result=${result}`);
      const status = error.code === "MCP_AUTH_FAILED" ? 401 : error.code === "MCP_TIMEOUT" ? 504 : 502;
      res.status(status).json({ error: { code: error.code, message: error.message } });
      return;
    }
    log("audit", `mcp.call.called serverName=${name} tool=${body.tool} result=network_error`);
    res.status(502).json({ error: { code: "MCP_NETWORK_ERROR", message: "MCP transport failure" } });
  }
});

/* ------------------------------------------------------------------ */
/*  POST /v1/mcp-servers/:name/uploads/* — streaming upload relay       */
/* ------------------------------------------------------------------ */

// Same expression as the parser skip and the pre-auth guard (mcp-upload-relay.ts),
// so the body of every request routed here is still unread.
router.post(UPLOAD_ROUTE, (req: Request, res: Response) => {
  const match = matchUploadPath(req.originalUrl);
  let name: string;
  try {
    name = decodeURIComponent(match?.rawName ?? "");
  } catch {
    name = match?.rawName ?? "";
  }

  // Checks run in this order, each before any upstream connection.
  // 1. Unknown / disabled server: same codes and texts as /call.
  const srv = getMcpServer(name);
  if (!srv) {
    refuseUpload(res, 400, "MCP_SERVER_NOT_FOUND", `${name} is not registered`);
    return;
  }
  if (!srv.enabled) {
    refuseUpload(
      res,
      400,
      "MCP_SERVER_DISABLED",
      `${name} is registered but disabled; enable the server before calling its tools`,
    );
    return;
  }

  // An ownerless entry never receives a caller's credential (MVP-7925): the registry refusal, before any upstream connection.
  if (srv.owner === undefined && req.headersDistinct[CREDENTIAL_HEADER] !== undefined) {
    logOwnerMismatch(name, "uploads", req.clientLabel);
    refuseUpload(res, 403, OWNER_MISMATCH_CODE, ownerMismatchBody(name).error.message);
    return;
  }

  // 2. Only http/sse servers have an origin to relay to.
  if (srv.type === "stdio") {
    refuseUpload(res, 400, "MCP_UPLOAD_UNSUPPORTED", UPLOAD_MESSAGES.unsupported(name));
    return;
  }

  // 3. Credential override header; the text never echoes its value.
  const override = parseCredentialHeader(req);
  if (!override.ok) {
    refuseUpload(res, 400, "MCP_OVERRIDE_INVALID", UPLOAD_MESSAGES.overrideInvalid);
    return;
  }

  // 4. Target path from the raw URL.
  if (!match || !isValidUploadTarget(match.target, match.query)) {
    refuseUpload(res, 400, "UPLOAD_TARGET_INVALID", UPLOAD_MESSAGES.targetInvalid);
    return;
  }

  relayUpload(req, res, {
    srv,
    match,
    authorization: override.authorization,
    idleTimeoutMs: MCP_UPLOAD_IDLE_TIMEOUT_MS,
  });
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
