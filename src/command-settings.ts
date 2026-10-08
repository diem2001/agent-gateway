/**
 * Command settings of skill, agent and command files (MVP-8106).
 *
 * The Claude runtime starts commands on its own from the frontmatter of the markdown files it loads: `hooks` of a
 * skill, agent or command file, and a stdio `mcpServers` entry with a `command` in an agent file. The tool grant
 * only controls which tools the model is offered, so a run whose label is not granted `Bash` must not load those
 * settings. `neutralizeCommandSettings` rewrites one file for such a run; the stored file is never modified.
 *
 * The rewrite is canonical, not a deny-list edit: the output always starts with a block the gateway generated
 * (`---`, the allowlisted keys as `key: <JSON value>`, `---`), followed by the original text. The runtime therefore
 * only ever reads frontmatter this module emitted. A setting cannot get past a difference between this parser and
 * the runtime's YAML parser, because nothing of the original block is copied except values of the allowlisted keys,
 * re-encoded as a JSON string, number, boolean or array of strings. Anything the strict reader below does not
 * understand is dropped; text that looks like frontmatter and sits behind the gateway's block is plain body text
 * (measured on the bundled runtime: only the first block is read).
 *
 * The allowlist is bound by the Gate A measurement of the bundled runtime (MVP-8116): every kept key was measured
 * or only changes how a file is listed, and none of them starts a command or widens the tool set.
 */

/** What was left out of a file. Fixed words only: never a value of the file. */
export type SettingKind = "hooks" | "mcpServers" | "other" | "unparseable";

export interface NeutralizedFile {
  /** The rewritten file: the gateway's block, then the original body. */
  data: Buffer;
  /** The kinds of setting that were ignored, each once, in the order they were found. Empty when nothing was left out. */
  ignored: SettingKind[];
}

type ValueShape = "string" | "list" | "boolean";

/** The frontmatter keys that survive, and the shape each may have. */
const KEPT_KEYS: Readonly<Record<string, ValueShape>> = {
  name: "string",
  description: "string",
  model: "string",
  "argument-hint": "string",
  when_to_use: "string",
  permissionMode: "string",
  tools: "list",
  disallowedTools: "list",
  "allowed-tools": "list",
  skills: "list",
  "user-invocable": "boolean",
  "disable-model-invocation": "boolean",
};

const BOM = "\u00ef\u00bb\u00bf"; // the UTF-8 byte order mark as seen through a latin1 view
const OPENING = /^---[ \t]*$/;
const CLOSING = /^(---|\.\.\.)[ \t]*$/;
const KEY_LINE = /^([A-Za-z][A-Za-z0-9_-]*):(?: (.*))?$/;
const BLOCK_SCALAR = /^([|>])([+-]?)([1-9]?)$/;

interface Located {
  /** The lines of the block between the delimiters (no line terminators). */
  lines: string[];
  /** Offset of the first byte after the closing delimiter line. */
  bodyStart: number;
}

/**
 * Finds the frontmatter block: null when the file has no opening delimiter, `{ unterminated: true }` when it never
 * closes. Offsets are in the latin1 view (one character per byte); the lines of the block are decoded as UTF-8.
 */
function locate(view: string): Located | { unterminated: true } | null {
  let pos = view.startsWith(BOM) ? BOM.length : 0;
  const nextLine = (from: number): { text: string; next: number } | null => {
    if (from >= view.length) return null;
    const newline = view.indexOf("\n", from);
    const end = newline < 0 ? view.length : newline;
    return { text: view.slice(from, end).replace(/\r$/, ""), next: newline < 0 ? view.length : newline + 1 };
  };
  let line = nextLine(pos);
  while (line && line.text.trim() === "") {
    pos = line.next;
    line = nextLine(pos);
  }
  if (!line || !OPENING.test(line.text)) return null;
  const lines: string[] = [];
  let cursor = line.next;
  for (;;) {
    const current = nextLine(cursor);
    if (!current) return { unterminated: true };
    if (CLOSING.test(current.text)) return { lines, bodyStart: current.next };
    lines.push(utf8(current.text));
    cursor = current.next;
  }
}

interface Entry {
  key: string;
  /** The text after `key:` on the key's own line. */
  rest: string;
  /** The following lines of this entry (indented lines and block-sequence dashes at column 0). */
  more: string[];
}

/** The top-level entries of a block, or null when its structure is not the plain `key: value` mapping this reader accepts. */
function readEntries(lines: string[]): Entry[] | null {
  const entries: Entry[] = [];
  const seen = new Set<string>();
  for (const line of lines) {
    if (/^[ ]*\t/.test(line)) return null; // tab indentation
    if (line.trim() === "" || /^\s*#/.test(line)) {
      entries.at(-1)?.more.push(line);
      continue;
    }
    if (/^\s/.test(line)) {
      const entry = entries.at(-1);
      if (!entry) return null;
      entry.more.push(line);
      continue;
    }
    const match = KEY_LINE.exec(line);
    if (match) {
      const key = match[1];
      if (seen.has(key)) return null; // duplicate key
      seen.add(key);
      const rest = (match[2] ?? "").trim();
      // An anchor, an alias or a tag at the start of a value: a construct the runtime's parser may resolve differently.
      if (/^[&*!]/.test(rest)) return null;
      entries.push({ key, rest, more: [] });
      continue;
    }
    if (/^-(?: |$)/.test(line) && entries.length > 0) {
      entries.at(-1)!.more.push(line); // a block sequence written at the key's own indent
      continue;
    }
    return null; // quoted key, merge key, flow mapping, explicit key, a stray line
  }
  return entries;
}

/** The text of a plain scalar without a trailing ` # comment`. */
function stripComment(text: string): string {
  const hash = text.search(/(^|[ \t])#/);
  return (hash < 0 ? text : text.slice(0, hash)).trim();
}

/** A latin1-view string as the UTF-8 text its bytes spell. */
function utf8(view: string): string {
  return Buffer.from(view, "latin1").toString("utf8");
}

/** Reads one quoted scalar at the start of `text`; returns its value and what follows, or null. */
function readQuoted(text: string): { value: string; after: string } | null {
  const quote = text[0];
  if (quote !== '"' && quote !== "'") return null;
  let i = 1;
  if (quote === "'") {
    let value = "";
    while (i < text.length) {
      if (text[i] === "'") {
        if (text[i + 1] === "'") {
          value += "'";
          i += 2;
          continue;
        }
        return { value, after: text.slice(i + 1) };
      }
      value += text[i++];
    }
    return null;
  }
  while (i < text.length) {
    if (text[i] === "\\") {
      i += 2;
      continue;
    }
    if (text[i] === '"') {
      try {
        const value: unknown = JSON.parse(text.slice(0, i + 1));
        return typeof value === "string" ? { value, after: text.slice(i + 1) } : null;
      } catch {
        return null; // an escape JSON does not have
      }
    }
    i++;
  }
  return null;
}

function onlyComment(after: string): boolean {
  const trimmed = after.trim();
  return trimmed === "" || (/^[ \t]/.test(after) && trimmed.startsWith("#"));
}

/**
 * One plain or quoted scalar. `flow` is the context of a `[a, b]` item (no `,[]{}` inside, since the text was split at
 * commas); a block scalar, a block-sequence item or a multi-line plain scalar may hold commas and brackets.
 */
function readScalar(text: string, flow: boolean): string | null {
  const trimmed = text.trim();
  if (trimmed === "") return null;
  if (trimmed[0] === '"' || trimmed[0] === "'") {
    const quoted = readQuoted(trimmed);
    return quoted && onlyComment(quoted.after) ? quoted.value : null;
  }
  if (/^[\[\]{}&*!|>%@`,#]/.test(trimmed) || /^-(?: |$)/.test(trimmed)) return null;
  const plain = stripComment(trimmed);
  if (plain === "" || /: |:$/.test(plain)) return null;
  return flow && /[,\[\]{}]/.test(plain) ? null : plain;
}

function readFlowSequence(text: string): string[] | null {
  const body = stripComment(text);
  if (!body.startsWith("[") || !body.endsWith("]")) return null;
  let rest = body.slice(1, -1).trim();
  const items: string[] = [];
  while (rest.length > 0) {
    let item: string | null;
    if (rest[0] === '"' || rest[0] === "'") {
      const quoted = readQuoted(rest);
      if (!quoted) return null;
      item = quoted.value;
      rest = quoted.after.trimStart();
      if (rest !== "" && rest[0] !== ",") return null;
    } else {
      const comma = rest.indexOf(",");
      item = readScalar(comma < 0 ? rest : rest.slice(0, comma), true);
      rest = comma < 0 ? "" : rest.slice(comma);
    }
    if (item === null) return null;
    items.push(item);
    if (rest.startsWith(",")) {
      rest = rest.slice(1).trimStart();
      if (rest === "") return null; // a trailing comma leaves an empty item
    }
  }
  return items;
}

function readBlockScalar(indicator: RegExpExecArray, more: string[]): string | null {
  const body = more.map((line) => line.replace(/\s+$/, ""));
  const content = body.filter((line) => line !== "");
  if (content.length === 0) return "";
  const indent = Math.min(...content.map((line) => /^ */.exec(line)![0].length));
  if (indent === 0) return null;
  const lines = body.map((line) => line.slice(Math.min(indent, line.length)));
  while (lines.at(-1) === "") lines.pop();
  let text: string;
  if (indicator[1] === "|") {
    text = lines.join("\n");
  } else {
    text = "";
    let previousBlank = true;
    for (const line of lines) {
      if (line === "") {
        text += "\n";
        previousBlank = true;
        continue;
      }
      if (!previousBlank) text += " ";
      text += line;
      previousBlank = false;
    }
  }
  if (indicator[2] === "-") return text;
  return text === "" ? text : `${text}\n`;
}

/**
 * The value of one entry in the shape its key allows: a string, a list of strings (also written as one string) or a
 * boolean. `undefined` is an empty value (the same as no key); null is a value in a shape the rewrite does not keep.
 */
function readValue(entry: Entry, shape: ValueShape): string | string[] | boolean | null | undefined {
  const more = entry.more.filter((line) => line.trim() !== "" && !/^\s*#/.test(line));
  const rest = entry.rest;
  if (shape === "boolean") {
    if (more.length > 0) return null;
    const word = stripComment(rest);
    return word === "true" ? true : word === "false" ? false : null;
  }
  const fit = (value: string | string[] | null): string | string[] | null => (value === null || (Array.isArray(value) && shape !== "list") ? null : value);
  const block = BLOCK_SCALAR.exec(rest);
  if (block) {
    const text = readBlockScalar(block, entry.more);
    return text === "" ? undefined : fit(text);
  }
  if (rest === "" || rest[0] === "#") {
    if (more.length === 0) return undefined;
    if (more.every((line) => /^\s*-(?: |$)/.test(line))) {
      const items = more.map((line) => readScalar(line.replace(/^\s*-/, ""), false));
      return fit(items.every((item) => item !== null) ? (items as string[]) : null);
    }
    const parts = more.map((line) => readScalar(line, false));
    return fit(parts.every((part) => part !== null) ? parts.join(" ") : null);
  }
  if (rest[0] === "[") return more.length > 0 ? null : fit(readFlowSequence(rest));
  if (rest[0] === "{") return null;
  if (rest[0] === '"' || rest[0] === "'") {
    const quoted = readQuoted(rest);
    return quoted && onlyComment(quoted.after) && more.length === 0 ? fit(quoted.value) : null;
  }
  const first = readScalar(rest, false);
  if (first === null) return null;
  const parts = [first];
  for (const line of more) {
    const part = readScalar(line, false);
    if (part === null) return null;
    parts.push(part);
  }
  return fit(parts.join(" "));
}

/** A JSON text that is also a valid YAML double-quoted scalar: the characters YAML treats as line breaks are escaped. */
function encode(value: string | string[] | boolean): string {
  return JSON.stringify(value).replace(/[\u0085\u2028\u2029]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

/**
 * Rewrites one skill, agent or command file for a run without the `Bash` grant. The result always starts with the
 * gateway's own block. Frontmatter that was found is replaced by the allowlisted keys it held; the body after its
 * closing delimiter follows byte for byte. A file without frontmatter, or whose frontmatter cannot be read, keeps
 * its whole original text behind an (empty) gateway block, so nothing it holds is ever read as frontmatter.
 */
export function neutralizeCommandSettings(input: Buffer): NeutralizedFile {
  const view = input.toString("latin1");
  const located = locate(view);
  const ignored: SettingKind[] = [];
  const note = (kind: SettingKind): void => {
    if (!ignored.includes(kind)) ignored.push(kind);
  };
  let header = "---\n---\n";
  let bodyStart = 0;
  if (located && "unterminated" in located) {
    note("unparseable");
  } else if (located) {
    const entries = readEntries(located.lines);
    if (entries === null) {
      note("unparseable");
    } else {
      bodyStart = located.bodyStart;
      const lines: string[] = [];
      for (const entry of entries) {
        if (!Object.hasOwn(KEPT_KEYS, entry.key)) {
          note(entry.key === "hooks" ? "hooks" : entry.key === "mcpServers" ? "mcpServers" : "other");
          continue;
        }
        const value = readValue(entry, KEPT_KEYS[entry.key]);
        if (value === undefined) continue; // an empty value is the same as no key
        if (value === null) {
          note("other");
          continue;
        }
        lines.push(`${entry.key}: ${encode(value)}\n`);
      }
      header = `---\n${lines.join("")}---\n`;
    }
  }
  return { data: Buffer.concat([Buffer.from(header, "utf8"), input.subarray(bodyStart)]), ignored };
}
