import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { AutoField } from "./AutoField";
import {
  compactListInput,
  parseListInput,
  updateListInputDraft,
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
