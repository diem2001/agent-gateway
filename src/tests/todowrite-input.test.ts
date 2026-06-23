import { describe, it, expect } from "vitest";
import { toolUseEventInput } from "../agent.js";

// MVP-6497 (follow-up): TodoWrite's tool_use event must carry the STRUCTURED
// { todos: [...] } object, not a stringified/truncated summary. reqlift's
// parseTodos (MVP-6298) requires an object and falls back to the generic tool
// card otherwise — which is why the checklist widget didn't render even after
// TodoWrite was allowed.
describe("toolUseEventInput", () => {
  it("forwards TodoWrite input as the structured todos object (untruncated)", () => {
    const input = {
      todos: [
        { content: "List repos", status: "completed", activeForm: "Listing repos" },
        { content: "Explore skills", status: "in_progress", activeForm: "Exploring skills" },
      ],
    };
    const out = toolUseEventInput("TodoWrite", input);
    expect(typeof out).toBe("object");
    expect(out).toEqual(input);
  });

  it("summarizes non-structured tools to a string (unchanged)", () => {
    expect(typeof toolUseEventInput("Bash", { command: "ls -la" })).toBe("string");
    expect(toolUseEventInput("Bash", { command: "ls -la" })).toBe("ls -la");
  });
});
