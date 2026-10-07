import { describe, it, expect } from "vitest";
import { APPROVED_DEFAULT_SET as DEFAULT_TOOLS } from "../tool-grant.js";

// MVP-6497: the agent must be allowed to call TodoWrite by default, otherwise the
// Claude Agent SDK's allowedTools filter blocks it, no tool_use:"TodoWrite" event is
// ever emitted, and reqlift's TodoWrite checklist widget (MVP-6298) has nothing to
// render (the model falls back to a prose/markdown todo list).
//
// MVP-8088 (DEC-ISO-008): the default is exactly the 12 reviewed tools. The task tools
// (TaskCreate, TaskGet, TaskList, TaskUpdate) are hidden by CLAUDE_CODE_ENABLE_TASKS=false
// so TodoWrite stays offered; none of the tools newer runtimes add belongs to it.
describe("the default tools (APPROVED_DEFAULT_SET)", () => {
  it("is exactly the reviewed default set (DEC-ISO-008)", () => {
    expect([...DEFAULT_TOOLS].sort()).toEqual(["Agent", "Bash", "Edit", "Glob", "Grep", "NotebookEdit", "Read", "Skill", "TodoWrite", "WebFetch", "WebSearch", "Write"]);
  });

  it("includes TodoWrite so the agent can emit todo lists (MVP-6497) and names none of the task tools", () => {
    expect(DEFAULT_TOOLS).toContain("TodoWrite");
    for (const tool of ["TaskCreate", "TaskGet", "TaskUpdate", "TaskList"]) expect(DEFAULT_TOOLS).not.toContain(tool);
  });

  it("retains the core built-in tools", () => {
    for (const tool of ["Bash", "Read", "Write", "Edit", "Glob", "Grep", "WebSearch", "WebFetch", "Skill"]) {
      expect(DEFAULT_TOOLS).toContain(tool);
    }
  });

  it("names none of the tools of the newer runtime that were never reviewed", () => {
    for (const tool of ["CronCreate", "CronDelete", "CronList", "DesignSync", "EnterWorktree", "ExitWorktree", "ListAgents", "Monitor", "PushNotification", "ReportFindings", "ScheduleWakeup", "SendMessage", "TaskStop", "Workflow", "Artifact", "SendUserFile", "ShareOnboardingGuide"]) {
      expect(DEFAULT_TOOLS, tool).not.toContain(tool);
    }
  });
});
