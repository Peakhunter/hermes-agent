export function parseListInput(raw: string): string[] {
  // Keep empty segments while the field is focused. Removing the trailing
  // empty item immediately would make a just-typed comma disappear on the
  // controlled re-render, preventing entry of the next value.
  return raw.split(",").map((item) => item.trim());
}

export function compactListInput(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((item): item is string => typeof item === "string")
    .map((item) => item.trim())
    .filter(Boolean);
}

export function updateListInputDraft(raw: string): { draft: string; value: string[] } {
  return {
    draft: raw,
    value: compactListInput(parseListInput(raw)),
  };
}
