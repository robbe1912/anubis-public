// Mutation M2: invented trait in real crate module.
// `serde::de::Visitor` is real; `VisitorExt` is fabricated.
// Expected compile: E0432 unresolved import `serde::de::VisitorExt`.
// Expected scanner layer: L1.5 cached-hallucination OR forge: hallucinated-import-name.
use serde::de::VisitorExt;

pub fn describe_visitor<T: VisitorExt<'static>>(v: &T) -> String {
    v.describe()
}
