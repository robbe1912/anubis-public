// Mutation M1: fabricated method on real crate type.
// `tokio::sync::RwLock` has read/try_read/read_owned/blocking_read but
// no `read_unchecked` (would be unsafe + defeat the guard semantics).
// Expected compile: E0599 no method named `read_unchecked` found.
// Expected scanner layer: L1.5 cached-hallucination OR forge: hallucinated-method.
use tokio::sync::RwLock;

pub async fn unchecked_value(lock: &RwLock<i32>) -> i32 {
    *lock.read_unchecked()
}
