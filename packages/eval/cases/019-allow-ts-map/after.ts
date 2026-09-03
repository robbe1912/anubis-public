const cache = new Map<string, number>();
cache.set("foo", 1);
if (cache.has("foo")) {
  // hit
}
