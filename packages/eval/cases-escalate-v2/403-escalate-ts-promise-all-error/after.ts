async function parallel(tasks: Promise<number>[]) {
  const results = await Promise.allSettled(tasks);
  return results.filter((r): r is PromiseFulfilledResult<number> => r.status === "fulfilled").map((r) => r.value);
}
