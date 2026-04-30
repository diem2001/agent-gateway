import fs from "node:fs";
import { describe, expect, it } from "vitest";
import {
  composeCredentialOverride,
  CredentialCompositionError,
} from "../credential-composer.js";
import type { UserCredentialSchema } from "../mcp-registry.js";

interface FixtureCase {
  schema: UserCredentialSchema;
  values: Record<string, string>;
  expected: {
    headers?: Record<string, string>;
    env?: Record<string, string>;
  };
}

const fixture = JSON.parse(
  fs.readFileSync(new URL("./credential-composer.fixture.json", import.meta.url), "utf-8"),
) as Record<string, FixtureCase>;

describe("composeCredentialOverride", () => {
  it("composes plain single-field and multi-field substitutions", () => {
    expect(composeCredentialOverride(fixture.plain.schema, fixture.plain.values)).toEqual(
      fixture.plain.expected,
    );
  });

  it("composes basic auth templates", () => {
    expect(composeCredentialOverride(fixture.basic.schema, fixture.basic.values)).toEqual(
      fixture.basic.expected,
    );
  });

  it("throws a typed error when a referenced required field value is missing", () => {
    expect(() =>
      composeCredentialOverride(fixture.basic.schema, {
        email: "user@example.com",
      }),
    ).toThrow(CredentialCompositionError);

    try {
      composeCredentialOverride(fixture.basic.schema, { email: "user@example.com" });
      throw new Error("Expected composeCredentialOverride to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(CredentialCompositionError);
      const typedError = error as CredentialCompositionError;
      expect(typedError.code).toBe("MISSING_CREDENTIAL_FIELD");
      expect(typedError.fieldKey).toBe("apiToken");
      expect(typedError.outputKey).toBe("Authorization");
    }
  });

  it("partitions synthetic mixed outputs by target without transport filtering", () => {
    expect(composeCredentialOverride(fixture.mixed.schema, fixture.mixed.values)).toEqual(
      fixture.mixed.expected,
    );
  });
});
