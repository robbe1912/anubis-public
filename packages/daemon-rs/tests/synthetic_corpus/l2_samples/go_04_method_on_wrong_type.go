// Mutation M5: method-on-wrong-type. `len(s)` returns an int, which has
// no `.String()` method (only fmt.Stringer implementors, *big.Int, etc.).
// Expected compile: len(s).String undefined (type int has no field or method String).
// Expected scanner layer: L2 forge: hallucinated-method OR chain-broken.
package main

func LenString(s string) string {
    return len(s).String()
}
