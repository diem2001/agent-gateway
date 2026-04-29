import type { CredentialField, UserCredentialSchema } from "./mcp-registry.js";

export type CredentialFieldValues = Record<string, string | null | undefined>;

export interface CredentialOverride {
  headers?: Record<string, string>;
  env?: Record<string, string>;
}

export type CredentialCompositionErrorCode = "MISSING_CREDENTIAL_FIELD";

export class CredentialCompositionError extends Error {
  constructor(
    public readonly code: CredentialCompositionErrorCode,
    public readonly fieldKey: string,
    public readonly outputKey: string,
  ) {
    super(`Missing credential field "${fieldKey}" for output "${outputKey}"`);
    this.name = "CredentialCompositionError";
  }
}

export function getCredentialTemplateFieldKeys(template: string): string[] {
  return Array.from(template.matchAll(/\{([^}]+)\}/g), (match) => match[1]);
}

export function composeCredentialOverride(
  schema: UserCredentialSchema,
  fieldValues: CredentialFieldValues,
): CredentialOverride {
  const fieldsByKey = new Map(schema.fields.map((field) => [field.key, field]));
  const result: CredentialOverride = {};

  for (const output of schema.outputs) {
    const value = composeOutputValue(
      output.template,
      output.outputKey,
      fieldsByKey,
      fieldValues,
    );
    const bucket =
      output.target === "headers"
        ? (result.headers ??= {})
        : (result.env ??= {});
    bucket[output.outputKey] = value;
  }

  return result;
}

function composeOutputValue(
  template: string,
  outputKey: string,
  fieldsByKey: Map<string, CredentialField>,
  fieldValues: CredentialFieldValues,
): string {
  const basicMatch = /^basic:\{([^}]+)\}:\{([^}]+)\}$/.exec(template);
  if (basicMatch) {
    const user = getFieldValue(basicMatch[1], outputKey, fieldsByKey, fieldValues);
    const token = getFieldValue(basicMatch[2], outputKey, fieldsByKey, fieldValues);
    return `Basic ${Buffer.from(`${user}:${token}`, "utf8").toString("base64")}`;
  }

  return template.replace(/\{([^}]+)\}/g, (_match, fieldKey: string) =>
    getFieldValue(fieldKey, outputKey, fieldsByKey, fieldValues),
  );
}

function getFieldValue(
  fieldKey: string,
  outputKey: string,
  fieldsByKey: Map<string, CredentialField>,
  fieldValues: CredentialFieldValues,
): string {
  const field = fieldsByKey.get(fieldKey);
  const value = fieldValues[fieldKey];
  if (value === undefined || value === null || (field?.required === true && value === "")) {
    throw new CredentialCompositionError("MISSING_CREDENTIAL_FIELD", fieldKey, outputKey);
  }
  return value;
}
