// Mutation M5: method-on-wrong-type. JS arrays have `.reduce()` not `.sum()`.
// `Array.prototype.sum` does NOT exist (Lodash adds `_.sum`).
// Expected runtime: TypeError: arr.sum is not a function.
// Expected scanner layer: L2 forge: hallucinated-method.
export function total(xs: number[]): number {
    return xs.sum();
}
