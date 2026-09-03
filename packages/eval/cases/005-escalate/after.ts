// Same code — kept stable across before/after for this case. The "edit" is a no-op
// that introduces ambiguity only at the API-naming layer.
export const flat = (arr: unknown[][]) => arr.flatten();
