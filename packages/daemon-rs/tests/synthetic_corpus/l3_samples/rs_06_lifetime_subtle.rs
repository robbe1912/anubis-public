// Mutation L3-2: runtime borrow-panic from nested RefCell borrow.
// `RefCell` enforces borrow rules at RUNTIME, not compile time. Holding
// an immutable `borrow()` while calling `borrow_mut()` panics. The LLM
// hallucinated that RefCell allows overlapping borrows (it doesn't).
// Code compiles clean; runtime panic: "already mutably borrowed".
// Expected runtime: panic at BorrowMutError.
// Expected scanner layer: L3 (semantic runtime reasoning).
use std::cell::RefCell;

pub fn increment_first(cell: &RefCell<Vec<i32>>) {
    let view = cell.borrow();
    let first = view.first().copied().unwrap_or(0);
    cell.borrow_mut().push(first + 1);
}
