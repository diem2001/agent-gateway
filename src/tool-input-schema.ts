// zod is a transitive dependency of @anthropic-ai/claude-agent-sdk (required for ZodRawShape)
import { z } from "zod";
import { log } from "./logging.js";

/* ------------------------------------------------------------------ */
/*  Webhook tool input_schema -> SDK tool shape                         */
/* ------------------------------------------------------------------ */
//
// A registered webhook tool's `input_schema` (JSON Schema) is the single source
// of what the model is told about the tool's arguments and of how the SDK MCP
// server validates them before the handler (and so the webhook) runs.
//
// Supported, closed allowlist: `type` string/number/integer/boolean/object/
// array, `description`, `enum` (string/number literals), `properties`,
// `required`, `items` (one schema). `additionalProperties` is ignored at every
// level. Anything else makes that property alone accept any value, advertised
// with only its description; the rest of the tool stays typed. No defaults, no
// coercion: a valid call reaches the webhook with the model's values unchanged.
// Top-level undeclared keys are stripped by the SDK's own object (as before);
// nested objects keep undeclared keys (loose), as the webhook received them before.

/** Deeper properties fall back to "any value", so a hostile schema cannot exhaust the stack. */
export const MAX_SCHEMA_DEPTH = 32;

type JsonObject = Record<string, unknown>;
type Fragment = Record<string, unknown>;

/** A property's validator (gateway zod) and the JSON Schema fragment advertised for it. */
interface Converted {
  validator: z.ZodType;
  advertised: Fragment;
}

const SUPPORTED_KEYWORDS = new Set(["type", "description", "enum", "properties", "required", "items", "additionalProperties"]);

/**
 * Property names that can never reach the webhook, so they are not advertised:
 * `__proto__` cannot be carried as an own key through object parsing, and a
 * top-level `constructor` is deliberately stripped before the webhook. A
 * nested `constructor` is fine.
 */
const EXCLUDED_TOP_LEVEL_NAMES = new Set(["__proto__", "constructor"]);
const EXCLUDED_NESTED_NAMES = new Set(["__proto__"]);

function isPlainObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function describe(node: unknown): Fragment {
  return isPlainObject(node) && typeof node["description"] === "string" ? { description: node["description"] } : {};
}

/** Any value; a required one must still be present. Advertised with only its description. */
function fallback(node: unknown): Converted {
  return { validator: z.unknown(), advertised: describe(node) };
}

/** The literal values of a valid `enum` for the given `type`, or undefined when the enum is unusable. */
function enumValues(values: unknown, type: unknown): (string | number)[] | undefined {
  if (!Array.isArray(values) || values.length === 0) return undefined;
  if (new Set(values).size !== values.length) return undefined;
  const fits = (value: unknown): boolean => {
    if (type === "string") return typeof value === "string";
    if (type === "number") return typeof value === "number" && Number.isFinite(value);
    if (type === "integer") return Number.isSafeInteger(value);
    if (type === undefined) return typeof value === "string" || (typeof value === "number" && Number.isFinite(value));
    return false;
  };
  return values.every(fits) ? (values as (string | number)[]) : undefined;
}

/** Names listed in a valid `required`, or undefined when `required` is malformed. Absent means none. */
function requiredNames(required: unknown): Set<string> | undefined {
  if (required === undefined) return new Set();
  if (!Array.isArray(required) || !required.every((name) => typeof name === "string")) return undefined;
  return new Set(required as string[]);
}

/** The declared properties in order, without names that cannot be carried; `[]` (PHP's empty object) counts as none. */
function declaredProperties(properties: unknown, toolName: string, excluded: Set<string>): [string, unknown][] | undefined {
  if (properties === undefined || (Array.isArray(properties) && properties.length === 0)) return [];
  if (!isPlainObject(properties)) return undefined;
  const entries: [string, unknown][] = [];
  for (const name of Object.keys(properties)) {
    if (excluded.has(name)) {
      log("tools", `tools.schema.property_excluded tool=${toolName} property=${name}`);
      continue;
    }
    entries.push([name, properties[name]]);
  }
  return entries;
}

/**
 * The validator placed under one property key: optional unless required, and a
 * required property must be present even when it accepts any value.
 */
function propertyValidator(name: string, converted: Converted, required: boolean): z.ZodType {
  let validator: z.ZodType = converted.validator;
  if (required && validator instanceof z.ZodUnknown) {
    // The new MCP SDK's Zod 4 JSON Schema converter cannot serialize a refinement on `unknown`.
    validator = z.custom((value) => value !== undefined, { message: "Invalid input: expected a value, received undefined" });
  }
  if (!required) validator = validator.optional();
  if (Object.hasOwn(Object.prototype, name)) {
    // Object parsing reads input[name]; for an omitted key that is the inherited
    // Object.prototype member (e.g. `toString`), which must count as absent.
    const inherited = (Object.prototype as Record<string, unknown>)[name];
    validator = z.preprocess((value) => (value === inherited ? undefined : value), validator);
    if (!required) validator = validator.optional();
  }
  return validator;
}

/** Converts `properties`/`required` of an object node into a null-prototype shape and advertised fragments. */
function convertProperties(
  node: JsonObject,
  depth: number,
  toolName: string,
): { shape: Record<string, z.ZodType>; properties: Record<string, Fragment>; required: string[] } | undefined {
  const entries = declaredProperties(node["properties"], toolName, EXCLUDED_NESTED_NAMES);
  const names = requiredNames(node["required"]);
  if (!entries || !names) return undefined;
  const shape = Object.create(null) as Record<string, z.ZodType>;
  const properties = Object.create(null) as Record<string, Fragment>;
  const required: string[] = [];
  for (const [name, child] of entries) {
    const converted = convertNode(child, depth + 1, toolName);
    // Dangling `required` names (no matching property) are ignored.
    const isRequired = names.has(name);
    shape[name] = propertyValidator(name, converted, isRequired);
    properties[name] = converted.advertised;
    if (isRequired) required.push(name);
  }
  return { shape, properties, required };
}

function convertNode(node: unknown, depth: number, toolName: string): Converted {
  if (depth > MAX_SCHEMA_DEPTH || !isPlainObject(node)) return fallback(node);
  if (Object.keys(node).some((keyword) => !SUPPORTED_KEYWORDS.has(keyword))) return fallback(node);
  if (node["description"] !== undefined && typeof node["description"] !== "string") return fallback(node);

  const type = node["type"];
  const description = describe(node);

  if (node["enum"] !== undefined) {
    const values = enumValues(node["enum"], type);
    if (!values) return fallback(node);
    const validator = values.every((value) => typeof value === "string") ? z.enum(values as [string, ...string[]]) : z.literal(values);
    return { validator, advertised: { ...(type !== undefined ? { type } : {}), enum: values, ...description } };
  }

  switch (type) {
    case "string":
      return { validator: z.string(), advertised: { type, ...description } };
    case "number":
      return { validator: z.number(), advertised: { type, ...description } };
    case "integer":
      return { validator: z.int(), advertised: { type, ...description } };
    case "boolean":
      return { validator: z.boolean(), advertised: { type, ...description } };
    case "object": {
      const converted = convertProperties(node, depth, toolName);
      if (!converted) return fallback(node);
      const hasProperties = Object.keys(converted.properties).length > 0;
      return {
        validator: z.looseObject(converted.shape),
        advertised: {
          type,
          ...description,
          ...(hasProperties ? { properties: converted.properties } : {}),
          ...(converted.required.length > 0 ? { required: converted.required } : {}),
        },
      };
    }
    case "array": {
      const items = node["items"];
      if (items === undefined) return { validator: z.array(z.unknown()), advertised: { type, ...description } };
      if (!isPlainObject(items)) return fallback(node);
      const item = convertNode(items, depth + 1, toolName);
      return { validator: z.array(item.validator), advertised: { type, ...description, items: item.advertised } };
    }
    default:
      return fallback(node);
  }
}

/**
 * Attaches the advertised fragment as the schema's JSON Schema. The MCP
 * server uses Zod's converter; this preserves the registered descriptions and
 * integer types exactly while Zod still validates calls before the webhook.
 */
function advertise(validator: z.ZodType, fragment: Fragment): z.ZodType {
  const json = JSON.stringify(fragment);
  validator._zod.toJSONSchema = () => JSON.parse(json);
  return validator;
}

/** The previous shape: every declared key accepts any value (and is advertised as required). */
function untypedShape(inputSchema: unknown): Record<string, z.ZodType> {
  const shape = Object.create(null) as Record<string, z.ZodType>;
  try {
    const props = isPlainObject(inputSchema) ? inputSchema["properties"] : undefined;
    if (isPlainObject(props)) {
      for (const key of Object.keys(props)) {
        if (!EXCLUDED_TOP_LEVEL_NAMES.has(key)) shape[key] = z.unknown();
      }
    }
  } catch {
    // An unreadable schema offers no arguments.
  }
  return shape;
}

/**
 * Builds the SDK raw shape for one webhook tool from its registered
 * `input_schema`. Never throws: a schema that cannot be converted falls back to
 * the previous untyped shape for this tool only, so one bad registration cannot
 * break every client's queries.
 */
export function buildToolInputShape(toolName: string, inputSchema: unknown): Record<string, z.ZodType> {
  try {
    const node = isPlainObject(inputSchema) ? inputSchema : {};
    const entries = declaredProperties(node["properties"], toolName, EXCLUDED_TOP_LEVEL_NAMES) ?? [];
    const names = requiredNames(node["required"]);
    if (!names) throw new Error("required must be an array of property names");
    const shape = Object.create(null) as Record<string, z.ZodType>;
    for (const [name, child] of entries) {
      const converted = convertNode(child, 1, toolName);
      shape[name] = advertise(propertyValidator(name, converted, names.has(name)), converted.advertised);
    }
    return shape;
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    log("tools", `tools.schema.untyped_fallback tool=${toolName} reason=${JSON.stringify(msg)}`);
    return untypedShape(inputSchema);
  }
}
