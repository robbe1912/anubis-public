async function load(url: string, attempts = 3) {
  for (let i = 0; i < attempts; i++) {
    const res = await fetch(url);
    if (res.ok) return res.json();
    await new Promise((r) => setTimeout(r, 1000 * (i + 1)));
  }
  throw new Error("exhausted retries");
}
