import { Router, type Request, type Response } from "express";
import {
  registerMcpServer,
  getMcpServer,
  getAllMcpServers,
  deleteMcpServer,
  checkMcpServerHealth,
  type McpServerDefinition,
} from "../mcp-registry.js";

const router = Router();

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
