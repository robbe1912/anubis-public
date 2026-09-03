// Mutation M5: method-on-wrong-type. String::len returns usize directly,
// not Result<usize,_>; calling `.unwrap()` on it is a hallucinated chain.
// Expected compile: E0599 no method named `unwrap` found for type `usize`.
// Expected scanner layer: L2 forge: hallucinated-method OR chain-broken.
pub fn length_or_zero(s: &str) -> usize {
    String::len(&s.to_string()).unwrap_or(0)
}
