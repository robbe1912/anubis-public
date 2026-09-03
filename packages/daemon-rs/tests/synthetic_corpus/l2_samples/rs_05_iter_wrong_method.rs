// Mutation M5: hallucinated iterator adapter. `iter().map_to_string()`
// does not exist; real API is `.map(|x| x.to_string())` or `.map_to(...)`-
// no, that doesn't exist either. The LLM hallucinated a sugar that
// mimics `.map(ToString::to_string)` as a single method call.
// Expected compile: E0599 no method named `map_to_string` found.
// Expected scanner layer: L2 forge: hallucinated-method OR chain-phantom-member.
pub fn strings(xs: Vec<i32>) -> Vec<String> {
    xs.iter().map_to_string().collect::<Vec<String>>()
}
