// Mutation L3-8: unhandled promise rejection.
// The async function returns a Promise that may reject (if value < 0),
// but the caller chain has no `.catch()`. Unhandled rejections crash
// Node 15+ (process exit). The LLM hallucinated try/catch was implicit.
// Expected runtime: UnhandledPromiseRejection in caller (semantic bug).
// Expected scanner layer: L3 (semantic error handling).
export async function computeScore(value: number): Promise<number> {
    if (value < 0) {
        throw new Error("negative input");
    }
    return value * 2;
}

export function run(value: number): void {
    computeScore(value).then((r) => console.log(r));
    // Missing: .catch((err) => console.error(err));
}
