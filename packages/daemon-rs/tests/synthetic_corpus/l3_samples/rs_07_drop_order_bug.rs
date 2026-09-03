// Mutation L3-7: drop order use-after-free.
// `value` is moved into `Wrapper` before its reference is dereferenced.
// `Wrapper`'s Drop impl runs first (Rust drops fields in declaration
// order), invalidating the `&value` still held in `holder`. The LLM
// hallucinated Rust's drop ordering was lexical (top-down) rather than
// reverse declaration order. Pseudo-bug; real code would fail to compile
// under borrow checker for trivial cases but compiles + UAFs under
// unsafe patterns. Demonstrates a subtle semantic lifetime issue.
// Expected runtime: undefined (compiles but unsound).
// Expected scanner layer: L3 (semantic Drop ordering).
pub struct Holder<'a> {
    inner: &'a str,
}

pub struct Wrapper {
    value: String,
}

impl Drop for Wrapper {
    fn drop(&mut self) {
        // intentionally empty
    }
}

pub fn make_holder() -> Holder<'static> {
    let w = Wrapper { value: String::from("hello") };
    Holder { inner: &w.value }
}
