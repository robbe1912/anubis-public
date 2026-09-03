const cache: Record<string, number> = {};
cache["foo"] = 1;
if (cache["foo"] !== undefined) {
  // hit
}
