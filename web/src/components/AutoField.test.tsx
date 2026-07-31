import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { AutoField } from "./AutoField";
import {
  compactListInput,
  parseListInput,
  updateListInputDraft,
  validateBuzzAllowedUsers,
  getBuzzAllowedUsersValidationError,
} from "./autoFieldListInput";

describe("AutoField", () => {
  it("keeps a trailing comma in the draft while committing only complete values", () => {
    const update = updateListInputDraft("first-pubkey,");

    expect(update.draft).toBe("first-pubkey,");
    expect(update.value).toEqual(["first-pubkey"]);
  });

  it("preserves a trailing separator while another list value is being typed", () => {
    const afterSeparator = parseListInput("first-pubkey,");
    expect(afterSeparator).toEqual(["first-pubkey", ""]);

    // AutoField is controlled: parent state is joined back into the input after
    // every keystroke. The separator must survive that round trip.
    const rerendered = afterSeparator.join(", ");
    expect(rerendered).toBe("first-pubkey, ");
    expect(parseListInput(`${rerendered}second-pubkey`)).toEqual([
      "first-pubkey",
      "second-pubkey",
    ]);
    expect(compactListInput(afterSeparator)).toEqual(["first-pubkey"]);
  });
  it("rejects Buzz keys separated only by whitespace", () => {
    const validHex = "a".repeat(64);

    expect(validateBuzzAllowedUsers([`${validHex} ${validHex}`])).toBe(
      "Separate public keys with commas.",
    );
  });

  it("rejects malformed Buzz public keys without echoing their values", () => {
    const invalid = "npub1not-a-valid-key";
    const error = validateBuzzAllowedUsers([invalid]);

    expect(error).toBe("Invalid public key at item 1; use one npub or 64-character hex key.");
    expect(error).not.toContain(invalid);
  });

  it("accepts valid hex and checksum-valid npub keys", () => {
    expect(
      validateBuzzAllowedUsers([
        "a".repeat(64),
        "npub1nl2u0wnd8mezfknc74q7pl9ec58h9nrrakce4tnk434qgaxl4psqe5twr6",
      ]),
    ).toBeNull();
  });

  it("rejects npubs with a bad checksum", () => {
    expect(
      validateBuzzAllowedUsers([
        "npub1nl2u0wnd8mezfknc74q7pl9ec58h9nrrakce4tnk434qgaxl4psqe5twrq",
      ]),
    ).toBe("Invalid public key at item 1; use one npub or 64-character hex key.");
  });

  it("shows an inline error for invalid Buzz allowed users", () => {
    const markup = renderToStaticMarkup(
      <AutoField
        schemaKey="gateway.platforms.buzz.extra.allowed_users"
        schema={{ type: "list" }}
        value={[`${"a".repeat(64)} ${"b".repeat(64)}`]}
        onChange={() => undefined}
      />,
    );

    expect(markup).toContain('role="alert"');
    expect(markup).toContain("Separate public keys with commas.");
    expect(markup).toContain('aria-invalid="true"');
  });

  it("shows the same inline error for the legacy top-level Buzz path", () => {
    const markup = renderToStaticMarkup(
      <AutoField
        schemaKey="buzz.extra.allowed_users"
        schema={{ type: "list" }}
        value={[`${"a".repeat(64)}${"b".repeat(64)}`]}
        onChange={() => undefined}
      />,
    );

    expect(markup).toContain('role="alert"');
    expect(markup).toContain("Invalid public key at item 1");
    expect(markup).toContain('aria-invalid="true"');
  });

  it("finds invalid Buzz keys in the full Dashboard config before save", () => {
    const validHex = "a".repeat(64);
    const config = {
      gateway: {
        platforms: {
          buzz: { extra: { allowed_users: [`${validHex} ${validHex}`] } },
        },
      },
    };

    expect(getBuzzAllowedUsersValidationError(config)).toBe(
      "Separate public keys with commas.",
    );
  });

  it("finds invalid Buzz keys at the legacy top-level config path before save", () => {
    const config = {
      buzz: { extra: { allowed_users: [`${"a".repeat(64)}${"b".repeat(64)}`] } },
    };

    expect(getBuzzAllowedUsersValidationError(config)).toBe(
      "Invalid public key at item 1; use one npub or 64-character hex key.",
    );
  });

  it("names the generated Buzz allow-all switch", () => {
    const markup = renderToStaticMarkup(
      <AutoField
        schemaKey="gateway.platforms.buzz.extra.allow_all_users"
        schema={{ type: "boolean" }}
        value={false}
        onChange={() => undefined}
      />,
    );

    expect(markup).toContain('role="switch"');
    expect(markup).toContain('aria-label="Allow All Users"');
  });

  it("names the generated Buzz allowed-users list", () => {
    const markup = renderToStaticMarkup(
      <AutoField
        schemaKey="gateway.platforms.buzz.extra.allowed_users"
        schema={{ type: "list" }}
        value={[]}
        onChange={() => undefined}
      />,
    );

    expect(markup).toContain('aria-label="Allowed Users"');
    expect(markup).toContain('placeholder="comma-separated values"');
  });
});
