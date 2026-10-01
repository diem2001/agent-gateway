/**
 * Webhook tool ownership (MVP-7679, tools.ts, routes/tools.ts): every PUT records the authenticated label as the
 * owner and ignores an `owner` in the body; another label's PUT or DELETE of an owned tool is refused with 403
 * TOOL_OWNED_BY_OTHER_CLIENT (fixed text, no owner name); a legacy ownerless entry is claimed by the first label
 * that registers it again; GET shows the owner for the deploy read-back; the registry file keeps its owner across a
 * restart and a malformed owner sets the whole file aside (MVP-7616); the startup line counts ownerless entries.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let dir: string;
let logs: string[];

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "tool-owner-"));
  process.env.TOOLS_PERSIST_PATH = path.join(dir, "tools.json");
  logs = [];
  vi.spyOn(console, "log").mockImplementation((...args) => {
    logs.push(args.map(String).join(" "));
  });
  vi.resetModules();
});

afterEach(async () => {
  vi.restoreAllMocks();
  delete process.env.TOOLS_PERSIST_PATH;
  await new Promise((resolve) => setTimeout(resolve, 150));
  fs.rmSync(dir, { recursive: true, force: true });
});

const BASE = {
  description: "A test tool",
  input_schema: { type: "object", properties: { query: { type: "string" } } },
  webhook_url: "https://example.com/webhook",
};

async function appAs(label: string | undefined): Promise<express.Express> {
  const { default: toolRoutes } = await import("../routes/tools.js");
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.clientLabel = (req.headers["x-test-label"] as string | undefined) ?? label;
    next();
  });
  app.use(toolRoutes);
  return app;
}

const as = (label: string) => ({ "x-test-label": label });

describe("the owner is always the authenticated label", () => {
  it("a new tool records the label; the response and GET show it", async () => {
    const app = await appAs("reqlift");
    const put = await request(app).put("/v1/tools/draft").send(BASE);
    expect(put.status).toBe(201);
    expect(put.body.owner).toBe("reqlift");
    const get = await request(app).get("/v1/tools/draft");
    expect(get.body.owner).toBe("reqlift");
    const list = await request(app).get("/v1/tools");
    expect(list.body.tools).toEqual([expect.objectContaining({ name: "draft", owner: "reqlift" })]);
  });

  it("an `owner` in the body is ignored", async () => {
    const app = await appAs("reqlift");
    const put = await request(app).put("/v1/tools/draft").send({ ...BASE, owner: "diemcrm" });
    expect(put.body.owner).toBe("reqlift");
    const { getTool } = await import("../tools.js");
    expect(getTool("draft")?.owner).toBe("reqlift");
  });

  it("the owner updates its own tool", async () => {
    const app = await appAs("reqlift");
    await request(app).put("/v1/tools/draft").send(BASE);
    const again = await request(app).put("/v1/tools/draft").send({ ...BASE, description: "changed" });
    expect(again.status).toBe(200);
    expect(again.body).toMatchObject({ description: "changed", owner: "reqlift" });
  });
});

describe("another label cannot change or delete an owned tool", () => {
  const FORBIDDEN = { error: { code: "TOOL_OWNED_BY_OTHER_CLIENT", message: "This tool was registered by another client and can only be changed or deleted by that client." } };

  it("PUT by another label: 403 with the fixed text; the tool is unchanged", async () => {
    const app = await appAs("reqlift");
    await request(app).put("/v1/tools/draft").send(BASE);
    const put = await request(app).put("/v1/tools/draft").set(as("diemcrm")).send({ ...BASE, webhook_url: "https://attacker.example/collect" });
    expect(put.status).toBe(403);
    expect(put.body).toEqual(FORBIDDEN);
    // The text does not name the owner.
    expect(JSON.stringify(put.body)).not.toContain("reqlift");
    const { getTool } = await import("../tools.js");
    expect(getTool("draft")).toMatchObject({ webhook_url: "https://example.com/webhook", owner: "reqlift" });
  });

  it("DELETE by another label: 403; the tool stays; the owner can delete it", async () => {
    const app = await appAs("reqlift");
    await request(app).put("/v1/tools/draft").send(BASE);
    const del = await request(app).delete("/v1/tools/draft").set(as("diemcrm"));
    expect(del.status).toBe(403);
    expect(del.body).toEqual(FORBIDDEN);
    expect((await request(app).get("/v1/tools/draft")).status).toBe(200);
    expect((await request(app).delete("/v1/tools/draft")).status).toBe(204);
    expect((await request(app).get("/v1/tools/draft")).status).toBe(404);
  });

  it("deleting an unknown tool is still 404 for every label", async () => {
    const app = await appAs("reqlift");
    expect((await request(app).delete("/v1/tools/nothing").set(as("diemcrm"))).status).toBe(404);
  });
});

describe("legacy entries without an owner", () => {
  function seedLegacy(): void {
    fs.writeFileSync(process.env.TOOLS_PERSIST_PATH!, JSON.stringify([{ name: "old", description: "d", input_schema: { type: "object" }, webhook_url: "https://example.com/old" }]));
  }

  it("the first label that registers the tool again claims it; then the other label is refused", async () => {
    seedLegacy();
    const { loadTools, getTool } = await import("../tools.js");
    loadTools();
    expect(getTool("old")?.owner).toBeUndefined();
    const app = await appAs("reqlift");
    const claim = await request(app).put("/v1/tools/old").set(as("diemcrm")).send(BASE);
    expect(claim.status).toBe(200);
    expect(claim.body.owner).toBe("diemcrm");
    const other = await request(app).put("/v1/tools/old").set(as("reqlift")).send(BASE);
    expect(other.status).toBe(403);
  });

  it("a legacy tool can still be deleted by any label until it is claimed (today's behavior)", async () => {
    seedLegacy();
    const { loadTools } = await import("../tools.js");
    loadTools();
    const app = await appAs("reqlift");
    expect((await request(app).delete("/v1/tools/old").set(as("diemcrm"))).status).toBe(204);
  });

  it("the startup writes one line with the count of ownerless entries, and none when there are none", async () => {
    seedLegacy();
    const { loadTools } = await import("../tools.js");
    loadTools();
    expect(logs.filter((l) => l.includes("tools.legacy.ownerless"))).toEqual(["[audit] tools.legacy.ownerless count=1"]);
    logs.length = 0;
    vi.resetModules();
    fs.writeFileSync(process.env.TOOLS_PERSIST_PATH!, JSON.stringify([{ name: "new", description: "d", input_schema: { type: "object" }, webhook_url: "https://example.com/n", owner: "reqlift" }]));
    const again = await import("../tools.js");
    again.loadTools();
    expect(logs.filter((l) => l.includes("tools.legacy.ownerless"))).toEqual([]);
  });

  it("countOwnerlessTools is the number the deploy read-back needs to reach 0", async () => {
    seedLegacy();
    const { loadTools, countOwnerlessTools } = await import("../tools.js");
    loadTools();
    expect(countOwnerlessTools()).toBe(1);
    const app = await appAs("reqlift");
    await request(app).put("/v1/tools/old").send(BASE);
    expect(countOwnerlessTools()).toBe(0);
  });
});

describe("persistence", () => {
  it("the owner survives a restart", async () => {
    const app = await appAs("reqlift");
    await request(app).put("/v1/tools/draft").send(BASE);
    const { flushTools } = await import("../tools.js");
    expect(flushTools()).toBe(true);
    vi.resetModules();
    const { loadTools, getTool } = await import("../tools.js");
    loadTools();
    expect(getTool("draft")?.owner).toBe("reqlift");
  });

  it.each([
    ["a numeric owner", { owner: 7 }],
    ["an empty owner", { owner: "" }],
    ["an object owner", { owner: { label: "x" } }],
  ])("%s sets the whole file aside instead of loading it (MVP-7616)", async (_label, extra) => {
    fs.writeFileSync(process.env.TOOLS_PERSIST_PATH!, JSON.stringify([{ name: "t", description: "d", input_schema: { type: "object" }, webhook_url: "https://example.com/t", ...extra }]));
    const { loadTools, getAllTools } = await import("../tools.js");
    loadTools();
    expect(getAllTools()).toEqual([]);
    expect(fs.readdirSync(dir).some((f) => f.startsWith("tools.json.corrupt"))).toBe(true);
  });

  it("a request without an authenticated label (unit-test apps) registers an ownerless tool", async () => {
    const app = await appAs(undefined);
    const put = await request(app).put("/v1/tools/draft").send(BASE);
    expect(put.body.owner).toBeUndefined();
  });
});
