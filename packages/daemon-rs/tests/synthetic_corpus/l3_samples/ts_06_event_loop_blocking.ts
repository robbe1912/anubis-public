// Mutation L3-3: blocking fs in async handler.
// `fs.readFileSync` is synchronous and blocks the Node event loop.
// In an async handler this defeats the purpose of async and degrades
// throughput to single-threaded blocking. The LLM hallucinated that
// sync I/O inside async is fine. Real API is `await fs.promises.readFile`.
// Expected runtime: works but blocks event loop (semantic bug, no API error).
// Expected scanner layer: L3 (semantic — no API hallucination).
import * as fs from "fs";

export async function readConfig(path: string): Promise<string> {
    return fs.readFileSync(path, "utf8");
}
