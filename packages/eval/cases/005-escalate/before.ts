// Ambiguous: Array.prototype.flatten was the original name (renamed to flat in ES2019).
// Agent may have used the deprecated name.
export const flat = (arr: unknown[][]) => arr.flatten();
