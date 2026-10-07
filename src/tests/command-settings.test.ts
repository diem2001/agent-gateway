/**
 * The rewrite of skill, agent and command files for a run without the `Bash` grant (src/command-settings.ts,
 * MVP-8106). Expected texts are written out here, not derived from the module. The runtime-facing half (that the
 * rewritten files still load and still narrow tools) was measured on the bundled runtime in Gate A (MVP-8116) and
 * is proven again through a spawned gateway in command-settings-process.test.ts.
 */
import { describe, expect, it } from "vitest";
import { neutralizeCommandSettings } from "../command-settings.js";

function run(text: string | Buffer): { text: string; ignored: string[] } {
  const result = neutralizeCommandSettings(Buffer.isBuffer(text) ? text : Buffer.from(text, "utf8"));
  return { text: result.data.toString("utf8"), ignored: result.ignored };
}

const HOOKS = "hooks:\n  PreToolUse:\n    - matcher: Read\n      hooks:\n        - type: command\n          command: touch /work/m\n";
const MCP_LIST = "mcpServers:\n  - probe:\n      type: stdio\n      command: sh\n      args: [\"-c\", \"touch /work/m\"]\n";

/** The block the gateway generated: the text up to and including the first closing delimiter line. */
function gatewayBlock(output: string): string {
  const lines = output.split("\n");
  expect(lines[0]).toBe("---");
  const close = lines.indexOf("---", 1);
  expect(close).toBeGreaterThan(0);
  return lines.slice(0, close + 1).join("\n");
}

const KEPT = ["name", "description", "model", "argument-hint", "when_to_use", "permissionMode", "tools", "disallowedTools", "allowed-tools", "skills", "user-invocable", "disable-model-invocation"];

/** What a gateway block may hold: allowlisted keys with one JSON value each, nothing structured beyond a list of strings. */
function assertCanonicalBlock(block: string): void {
  const lines = block.split("\n");
  expect(lines[0]).toBe("---");
  expect(lines.at(-1)).toBe("---");
  for (const line of lines.slice(1, -1)) {
    const match = /^([A-Za-z_-]+): (.*)$/.exec(line);
    expect(match, "a gateway block line is key: <JSON>").not.toBeNull();
    expect(KEPT).toContain(match![1]);
    const value: unknown = JSON.parse(match![2]);
    expect(typeof value === "string" || typeof value === "boolean" || (Array.isArray(value) && value.every((item) => typeof item === "string"))).toBe(true);
  }
}

describe("the keys that are kept", () => {
  it("re-emits each kept key as key: <JSON value>, in the file's order", () => {
    const input = [
      "---",
      "name: review",
      "description: Reviews a diff",
      "model: inherit",
      "argument-hint: \"[branch]\"",
      "when_to_use: when a diff needs review",
      "permissionMode: default",
      "tools: Read, Grep",
      "disallowedTools: [Write, Edit]",
      "allowed-tools:",
      "  - Read",
      "  - Grep",
      "skills: ['one', two]",
      "user-invocable: true",
      "disable-model-invocation: false",
      "---",
      "Body line 1",
      "Body line 2",
      "",
    ].join("\n");
    expect(run(input)).toEqual({
      text: [
        "---",
        'name: "review"',
        'description: "Reviews a diff"',
        'model: "inherit"',
        'argument-hint: "[branch]"',
        'when_to_use: "when a diff needs review"',
        'permissionMode: "default"',
        'tools: "Read, Grep"',
        'disallowedTools: ["Write","Edit"]',
        'allowed-tools: ["Read","Grep"]',
        'skills: ["one","two"]',
        "user-invocable: true",
        "disable-model-invocation: false",
        "---",
        "Body line 1",
        "Body line 2",
        "",
      ].join("\n"),
      ignored: [],
    });
  });

  it("reads quoted, folded and literal scalars and escapes characters a YAML parser treats as line breaks", () => {
    const input = '---\nname: "a \\"b\\" \\\\ é"\ndescription: >-\n  first line\n  second line\n\n  third\nwhen_to_use: |\n  keep\n  lines\n---\nbody';
    expect(run(input).text).toBe('---\nname: "a \\"b\\" \\\\ é"\ndescription: "first line second line\\nthird"\nwhen_to_use: "keep\\nlines\\n"\n---\nbody');
    const separator = run(`---\nname: "a\\u2028b\\u0085c"\n---\n`).text;
    expect(separator).toBe('---\nname: "a\\u2028b\\u0085c"\n---\n');
    expect(separator).not.toContain("\u2028");
    expect(separator).not.toContain("\u0085");
  });

  it("treats an empty value as no key, and a value in a shape the key does not keep as ignored", () => {
    expect(run("---\nname:\ndescription: ok\n---\nb")).toEqual({ text: '---\ndescription: "ok"\n---\nb', ignored: [] });
    expect(run("---\nname: [a, b]\nuser-invocable: maybe\ntools: {a: b}\n---\nb")).toEqual({ text: "---\n---\nb", ignored: ["other"] });
  });
});

describe("the settings that are left out", () => {
  it("drops hooks, in every nesting, and reports them", () => {
    expect(run(`---\nname: s\n${HOOKS}description: after hooks\n---\nbody\n`)).toEqual({ text: '---\nname: "s"\ndescription: "after hooks"\n---\nbody\n', ignored: ["hooks"] });
  });

  it("drops every shape of mcpServers (list, map, string) and reports them", () => {
    for (const block of [MCP_LIST, "mcpServers:\n  probe:\n    command: sh\n", "mcpServers: probe\n", "mcpServers: []\n"]) {
      const result = run(`---\nname: a\n${block}---\nbody`);
      expect(result, block).toEqual({ text: '---\nname: "a"\n---\nbody', ignored: ["mcpServers"] });
    }
  });

  it("drops any other key and reports it once, with the kinds in the order they were found", () => {
    expect(run("---\ncolor: blue\nisolation: worktree\nname: a\nmcpServers: x\nhooks: {}\nmemory: user\n---\nb")).toEqual({
      text: '---\nname: "a"\n---\nb',
      ignored: ["other", "mcpServers", "hooks"],
    });
  });

  it("does not trust a key by its spelling: other cases and spellings are dropped, never kept", () => {
    const result = run("---\nHooks:\n  Stop: []\nTOOLS: Bash\nallowed_tools: Bash\n---\nb");
    expect(result).toEqual({ text: "---\n---\nb", ignored: ["other"] });
  });
});

describe("frontmatter the strict reader does not accept", () => {
  const body = "Body text\n";
  const cases: [string, string][] = [
    ["unterminated block", `---\nname: n\n${HOOKS}${body}`],
    ["quoted key", `---\nname: n\n"hooks":\n  Stop: []\n---\n${body}`],
    ["single-quoted key", `---\n'hooks': x\n---\n${body}`],
    ["flow-mapping frontmatter", `---\n{name: n, hooks: {Stop: []}}\n---\n${body}`],
    ["anchor", `---\nname: &n value\n---\n${body}`],
    ["alias", `---\nname: n\ntools: *n\n---\n${body}`],
    ["merge key", `---\n<<: *base\n---\n${body}`],
    ["tag", `---\nname: !!str n\n---\n${body}`],
    ["duplicate key", `---\nname: a\ntools: Read\nname: b\n---\n${body}`],
    ["tab indentation", `---\nname: a\nhooks:\n\tStop: []\n---\n${body}`],
    ["a line that is not a mapping entry", `---\nname: a\nstray words\n---\n${body}`],
    ["a key without a space after the colon", `---\nname:a\n---\n${body}`],
    ["an explicit key", `---\n? hooks\n: x\n---\n${body}`],
  ];

  for (const [row, input] of cases) {
    it(`${row}: the whole frontmatter is ignored, the original text follows an empty gateway block`, () => {
      const result = run(input);
      expect(result.ignored).toEqual(["unparseable"]);
      expect(result.text).toBe(`---\n---\n${input}`);
      assertCanonicalBlock(gatewayBlock(result.text));
    });
  }
});

describe("the output always starts with the gateway's block", () => {
  const variants: [string, string][] = [
    ["a trailing space after the opening delimiter", `--- \nname: a\n${HOOKS}---\nbody\n`],
    ["a trailing space after the closing delimiter", `---\nname: a\n${HOOKS}--- \nbody\n`],
    ["CRLF line ends", `---\r\nname: a\r\n${HOOKS.replaceAll("\n", "\r\n")}---\r\nbody\r\n`],
    ["a byte order mark", `\ufeff---\nname: a\n${HOOKS}---\nbody\n`],
    ["leading blank lines", `\n  \n---\nname: a\n${HOOKS}---\nbody\n`],
    ["a dotted terminator", `---\nname: a\n${HOOKS}...\nbody\n`],
    ["a body that starts with its own block", `---\nname: a\n---\n---\n${HOOKS}${MCP_LIST}---\nbody\n`],
    ["no frontmatter at all", `Just a body.\n${HOOKS}`],
    ["a file that only holds a block that looks like frontmatter below text", `intro\n---\n${HOOKS}---\n`],
    ["an empty file", ""],
  ];

  for (const [row, input] of variants) {
    it(`${row}`, () => {
      const result = run(input);
      assertCanonicalBlock(gatewayBlock(result.text));
      // Whatever the file held, the first block is the gateway's and holds no command setting.
      expect(gatewayBlock(result.text)).not.toMatch(/hooks|mcpServers|command/i);
    });
  }

  it("keeps the allowlisted keys of the variants the reader accepts", () => {
    for (const input of [variants[0][1], variants[1][1], variants[2][1], variants[3][1], variants[4][1], variants[5][1]]) {
      expect(gatewayBlock(run(input).text)).toBe('---\nname: "a"\n---');
    }
  });

  it("puts a file without frontmatter, and a body that begins with a block, entirely behind the gateway's block", () => {
    expect(run("Just a body.\n").text).toBe("---\n---\nJust a body.\n");
    expect(run("---\nname: a\n---\n---\nhooks: x\n---\nbody\n").text).toBe('---\nname: "a"\n---\n---\nhooks: x\n---\nbody\n');
    expect(run("").text).toBe("---\n---\n");
  });
});

describe("the body", () => {
  it("follows the closing delimiter byte for byte, including bytes that are not UTF-8 and CRLF line ends", () => {
    const body = Buffer.from([0xff, 0xfe, 0x00, 0x0d, 0x0a, 0x80, 0x0a, 0xc3]);
    const input = Buffer.concat([Buffer.from("---\r\nname: a\r\n---\r\n", "latin1"), body]);
    const result = neutralizeCommandSettings(input);
    expect(result.data.subarray(result.data.length - body.length).equals(body)).toBe(true);
    expect(result.data.subarray(0, result.data.length - body.length).toString("utf8")).toBe('---\nname: "a"\n---\n');
  });

  it("is the whole original file when nothing could be read as frontmatter", () => {
    const original = Buffer.from([0x23, 0x20, 0x74, 0x69, 0x74, 0x6c, 0x65, 0x0a, 0xff, 0x0a]);
    const result = neutralizeCommandSettings(original);
    expect(result.data.equals(Buffer.concat([Buffer.from("---\n---\n"), original]))).toBe(true);
    expect(result.ignored).toEqual([]);
  });

  it("never changes the input buffer", () => {
    const input = Buffer.from(`---\nname: a\n${HOOKS}---\nbody`);
    const copy = Buffer.from(input);
    neutralizeCommandSettings(input);
    expect(input.equals(copy)).toBe(true);
  });
});

describe("a seeded mutation sweep over a file that carries every command setting", () => {
  const base = `---\nname: probe\ndescription: "a probe"\ntools: Read\n${HOOKS}${MCP_LIST}---\nBody text\n`;
  const pieces = ["hooks:", "mcpServers:", "  ", "\t", "---", "...", "&a ", "*a", "!!str ", "<<: ", '"', "'", "{", "}", "[", "]", ": ", "#", "\r", "\n", "- ", "|", ">", "\ufeff", "\u2028", "\u0085", "command: x", "name: z"];

  function sequence(seed: number): () => number {
    let state = seed >>> 0;
    return () => {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      return state / 0x100000000;
    };
  }

  it("never lets a command setting into the gateway's block, whatever the file's text", () => {
    const next = sequence(8106);
    for (let round = 0; round < 600; round++) {
      let text = base;
      const edits = 1 + Math.floor(next() * 4);
      for (let i = 0; i < edits; i++) {
        const at = Math.floor(next() * text.length);
        const piece = pieces[Math.floor(next() * pieces.length)];
        text = next() < 0.5 ? text.slice(0, at) + piece + text.slice(at) : text.slice(0, at) + text.slice(at + piece.length);
      }
      const output = run(text).text;
      const block = gatewayBlock(output);
      assertCanonicalBlock(block);
    }
  });
});
