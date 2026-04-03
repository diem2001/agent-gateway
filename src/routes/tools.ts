import { Router, type Request, type Response } from "express";
import {
  registerTool,
  getTool,
  getAllTools,
  deleteTool,
  isValidJsonSchema,
  type ToolDefinition,
} from "../tools.js";

const router = Router();

const DEFAULT_TIMEOUT_MS = 30000;

/* ------------------------------------------------------------------ */
/*  PUT /v1/tools/:name — register or update                           */
/* ------------------------------------------------------------------ */

router.put("/v1/tools/:name", (req: Request, res: Response) => {
  const name = String(req.params.name);
  const body = req.body as Partial<ToolDefinition>;

  if (!body.description || typeof body.description !== "string") {
    res.status(400).json({ error: "description is required and must be a string" });
    return;
  }
  if (!body.input_schema || typeof body.input_schema !== "object") {
    res.status(400).json({ error: "input_schema is required and must be an object" });
    return;
  }
  if (!isValidJsonSchema(body.input_schema)) {
    res.status(400).json({ error: "input_schema must be a valid JSON Schema object with a 'type' field" });
    return;
  }
  if (!body.webhook_url || typeof body.webhook_url !== "string") {
    res.status(400).json({ error: "webhook_url is required and must be a string" });
    return;
  }

  const def: ToolDefinition = {
    name,
    description: body.description,
    input_schema: body.input_schema,
    webhook_url: body.webhook_url,
    timeout_ms: typeof body.timeout_ms === "number" ? body.timeout_ms : DEFAULT_TIMEOUT_MS,
  };

  const isNew = registerTool(def);
  res.status(isNew ? 201 : 200).json(def);
});

/* ------------------------------------------------------------------ */
/*  GET /v1/tools — list all tools                                     */
/* ------------------------------------------------------------------ */

router.get("/v1/tools", (_req: Request, res: Response) => {
  res.json({ tools: getAllTools() });
});

/* ------------------------------------------------------------------ */
/*  GET /v1/tools/:name — get single tool                              */
/* ------------------------------------------------------------------ */

router.get("/v1/tools/:name", (req: Request, res: Response) => {
  const tool = getTool(String(req.params.name));
  if (!tool) {
    res.status(404).json({ error: "Tool not found" });
    return;
  }
  res.json(tool);
});

/* ------------------------------------------------------------------ */
/*  DELETE /v1/tools/:name — remove tool                               */
/* ------------------------------------------------------------------ */

router.delete("/v1/tools/:name", (req: Request, res: Response) => {
  const deleted = deleteTool(String(req.params.name));
  if (!deleted) {
    res.status(404).json({ error: "Tool not found" });
    return;
  }
  res.status(204).send();
});

export default router;
