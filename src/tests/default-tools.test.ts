import { describe, it, expect } from "vitest";
import { DEFAULT_TOOLS } from "../agent.js";

// MVP-6497: the agent must be allowed to call TodoWrite by default, otherwise the
// Claude Agent SDK's allowedTools filter blocks it, no tool_use:"TodoWrite" event is
// ever emitted, and reqlift's TodoWrite checklist widget (MVP-6298) has nothing to
// render (the model falls back to a prose/markdown todo list).
describe("DEFAULT_TOOLS", () => {
  it("includes TodoWrite so the agent can emit todo lists (MVP-6497)", () => {
    expect(DEFAULT_TOOLS).toContain("TodoWrite");
  });

  it("retains the core built-in tools", () => {
    for (const tool of ["Bash", "Read", "Write", "Edit", "Glob", "Grep", "WebSearch", "WebFetch", "Skill"]) {
      expect(DEFAULT_TOOLS).toContain(tool);
    }
  });
});
