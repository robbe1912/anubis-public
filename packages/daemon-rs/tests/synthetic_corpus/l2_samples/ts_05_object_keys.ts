// Mutation M5: method-on-wrong-type. Object.values returns an array of
// values; arrays have no `.unique()` method (use lodash _.uniq or new Set()).
// Expected runtime: TypeError: Object.values(obj).unique is not a function.
// Expected scanner layer: L2 forge: hallucinated-method OR chain-phantom-member.
export function distinctValues(obj: Record<string, unknown>): unknown[] {
    return Object.values(obj).unique();
}
