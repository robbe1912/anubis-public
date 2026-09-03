// Mutation M5: method-on-wrong-type. Promise has no `.retry()`.
// Real APIs: `.then()`, `.catch()`, `.finally()`. Retry requires libs
// like `p-retry`, `async-retry`, etc.
// Expected runtime: TypeError: Promise.resolve(...).retry is not a function.
// Expected scanner layer: L2 forge: hallucinated-method.
export function resilient(value: number): Promise<number> {
    return Promise.resolve(value).retry(3);
}
