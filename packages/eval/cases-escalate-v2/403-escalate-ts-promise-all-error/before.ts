async function parallel(tasks: Promise<number>[]) {
  return Promise.all(tasks);
}
