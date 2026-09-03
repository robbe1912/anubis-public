// after — HALLUCINATION: fetch does not return a Promise with .jsonSync
const r = await fetch("/api");
const j = r.jsonSync();
