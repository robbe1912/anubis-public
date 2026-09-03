// Mutation M4: parameter hallucination on real tokio function.
// `tokio::spawn` signature: `pub fn spawn<F>(future: F) -> JoinHandle<F::Output>`.
// No `name` parameter exists (unlike Go's goroutines or Rayon tasks).
// Expected compile: E0061 wrong number of arguments — `spawn` takes 1, not 2.
// Expected scanner layer: L2 forge: hallucinated-parameter.
pub fn spawn_named<F>(fut: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(fut, "worker");
}
