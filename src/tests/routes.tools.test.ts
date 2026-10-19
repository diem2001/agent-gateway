import { describe, it, expect, beforeEach } from "vitest";
import express from "express";
import request from "supertest";
import toolRoutes from "../routes/tools.js";
import { deleteTool } from "../tools.js";

function createApp() {
  const app = express();
  app.use(express.json());
  app.use(toolRoutes);
  return app;
}

const BASE_TOOL = {
  description: "A test tool",
  input_schema: { type: "object", properties: { query: { type: "string" } } },
  webhook_url: "https://example.com/webhook",
  timeout_ms: 5000,
};

describe("PUT /v1/tools/:name", () => {
  const name = `route-test-put-${Date.now()}`;

  it("returns 201 for a new tool", async () => {
    const app = createApp();
    const res = await request(app).put(`/v1/tools/${name}`).send(BASE_TOOL);
    expect(res.status).toBe(201);
    expect(res.body.name).toBe(name);
    expect(res.body.webhook_url).toBe(BASE_TOOL.webhook_url);
    deleteTool(name);
  });

  it("returns 200 when updating an existing tool", async () => {
    const app = createApp();
    const uniqueName = `route-test-update-${Date.now()}`;
    await request(app).put(`/v1/tools/${uniqueName}`).send(BASE_TOOL);
    const res = await request(app).put(`/v1/tools/${uniqueName}`).send({ ...BASE_TOOL, description: "updated" });
    expect(res.status).toBe(200);
    expect(res.body.description).toBe("updated");
    deleteTool(uniqueName);
  });

  it("returns 400 when description is missing", async () => {
    const app = createApp();
    const res = await request(app).put(`/v1/tools/missing-desc`).send({
      input_schema: { type: "object" },
      webhook_url: "https://example.com/hook",
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/description/);
  });

  it("returns 400 when input_schema is missing", async () => {
    const app = createApp();
    const res = await request(app).put(`/v1/tools/missing-schema`).send({
      description: "no schema",
      webhook_url: "https://example.com/hook",
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/input_schema/);
  });

  it("returns 400 when input_schema is invalid (missing type)", async () => {
    const app = createApp();
    const res = await request(app).put(`/v1/tools/invalid-schema`).send({
      description: "bad schema",
      input_schema: { properties: {} },
      webhook_url: "https://example.com/hook",
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/JSON Schema/);
  });

  it("returns 400 when webhook_url is missing", async () => {
    const app = createApp();
    const res = await request(app).put(`/v1/tools/missing-webhook`).send({
      description: "no webhook",
      input_schema: { type: "object" },
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/webhook_url/);
  });

  it("uses default timeout_ms when not provided", async () => {
    const app = createApp();
    const uniqueName = `route-test-default-timeout-${Date.now()}`;
    const res = await request(app).put(`/v1/tools/${uniqueName}`).send({
      description: "no timeout",
      input_schema: { type: "object" },
      webhook_url: "https://example.com/hook",
    });
    expect(res.status).toBe(201);
    expect(res.body.timeout_ms).toBe(30000);
    deleteTool(uniqueName);
  });
});

describe("GET /v1/tools", () => {
  it("returns list of tools", async () => {
    const app = createApp();
    const uniqueName = `route-test-list-${Date.now()}`;
    await request(app).put(`/v1/tools/${uniqueName}`).send(BASE_TOOL);

    const res = await request(app).get("/v1/tools");
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.tools)).toBe(true);
    const names = res.body.tools.map((t: { name: string }) => t.name);
    expect(names).toContain(uniqueName);

    deleteTool(uniqueName);
  });
});

describe("GET /v1/tools/:name", () => {
  it("returns the tool when it exists", async () => {
    const app = createApp();
    const uniqueName = `route-test-get-${Date.now()}`;
    await request(app).put(`/v1/tools/${uniqueName}`).send(BASE_TOOL);

    const res = await request(app).get(`/v1/tools/${uniqueName}`);
    expect(res.status).toBe(200);
    expect(res.body.name).toBe(uniqueName);

    deleteTool(uniqueName);
  });

  it("returns 404 for unknown tool", async () => {
    const app = createApp();
    const res = await request(app).get("/v1/tools/nonexistent-xyz-tool");
    expect(res.status).toBe(404);
    expect(res.body.error).toBe("Tool not found");
  });
});

describe("DELETE /v1/tools/:name", () => {
  it("returns 204 on successful deletion", async () => {
    const app = createApp();
    const uniqueName = `route-test-delete-${Date.now()}`;
    await request(app).put(`/v1/tools/${uniqueName}`).send(BASE_TOOL);

    const res = await request(app).delete(`/v1/tools/${uniqueName}`);
    expect(res.status).toBe(204);
  });

  it("returns 404 when tool does not exist", async () => {
    const app = createApp();
    const res = await request(app).delete("/v1/tools/nonexistent-xyz-tool-del");
    expect(res.status).toBe(404);
    expect(res.body.error).toBe("Tool not found");
  });

  it("tool is no longer accessible after deletion", async () => {
    const app = createApp();
    const uniqueName = `route-test-gone-${Date.now()}`;
    await request(app).put(`/v1/tools/${uniqueName}`).send(BASE_TOOL);
    await request(app).delete(`/v1/tools/${uniqueName}`);

    const res = await request(app).get(`/v1/tools/${uniqueName}`);
    expect(res.status).toBe(404);
  });
});

describe("stream_input (MVP-8096)", () => {
  const exactError = { error: 'stream_input must be "summary" or "raw"' };

  it.each(["raw", "summary"])("accepts %j: 201 for a new tool, 200 for an update, and GET shows it", async (value) => {
    const app = createApp();
    const n = `route-test-si-${value}-${Date.now()}`;
    const created = await request(app).put(`/v1/tools/${n}`).send({ ...BASE_TOOL, stream_input: value });
    expect(created.status).toBe(201);
    expect(created.body.stream_input).toBe(value);
    const updated = await request(app).put(`/v1/tools/${n}`).send({ ...BASE_TOOL, stream_input: value });
    expect(updated.status).toBe(200);
    expect(updated.body.stream_input).toBe(value);
    expect((await request(app).get(`/v1/tools/${n}`)).body.stream_input).toBe(value);
    const list = await request(app).get("/v1/tools");
    expect(list.body.tools.find((t: { name: string }) => t.name === n).stream_input).toBe(value);
    deleteTool(n);
  });

  it("an omitted field stores summary, also on an update of a raw tool (full replacement)", async () => {
    const app = createApp();
    const n = `route-test-si-omit-${Date.now()}`;
    const created = await request(app).put(`/v1/tools/${n}`).send(BASE_TOOL);
    expect(created.status).toBe(201);
    expect(created.body.stream_input).toBe("summary");
    await request(app).put(`/v1/tools/${n}`).send({ ...BASE_TOOL, stream_input: "raw" });
    const replaced = await request(app).put(`/v1/tools/${n}`).send(BASE_TOOL);
    expect(replaced.status).toBe(200);
    expect(replaced.body.stream_input).toBe("summary");
    expect((await request(app).get(`/v1/tools/${n}`)).body.stream_input).toBe("summary");
    deleteTool(n);
  });

  it.each([["full"], [5], [null], ["RAW"], [true], [[]]])("rejects %j with 400 and the exact envelope, storing nothing", async (value) => {
    const app = createApp();
    const n = `route-test-si-bad-${Date.now()}`;
    const res = await request(app).put(`/v1/tools/${n}`).send({ ...BASE_TOOL, stream_input: value });
    expect(res.status).toBe(400);
    expect(res.body).toEqual(exactError);
    expect((await request(app).get(`/v1/tools/${n}`)).status).toBe(404);
  });

  it("a rejected update leaves the stored raw tool unchanged", async () => {
    const app = createApp();
    const n = `route-test-si-keep-${Date.now()}`;
    await request(app).put(`/v1/tools/${n}`).send({ ...BASE_TOOL, stream_input: "raw", description: "first" });
    const res = await request(app).put(`/v1/tools/${n}`).send({ ...BASE_TOOL, stream_input: "full", description: "second" });
    expect(res.status).toBe(400);
    const got = await request(app).get(`/v1/tools/${n}`);
    expect(got.body.stream_input).toBe("raw");
    expect(got.body.description).toBe("first");
    deleteTool(n);
  });

  it("the existing body validations still answer first", async () => {
    const app = createApp();
    const res = await request(app).put("/v1/tools/si-order").send({ input_schema: { type: "object" }, webhook_url: "https://example.com/h", stream_input: "full" });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/description/);
  });
});
