// Mutation M2: invented function in stdlib package.
// `context.WithTimeout` exists; `context.WithTimeoutOrCancel` is fabricated
// (no such function in the context package — only WithCancel, WithDeadline,
// WithTimeout, WithValue, AfterFunc, Background, TODO, Cause, WithoutCancel).
// Expected compile: undefined: context.WithTimeoutOrCancel.
// Expected scanner layer: L1.5 cached-hallucination OR forge: hallucinated-function.
package main

import (
    "context"
    "time"
)

func WithCancelAfter(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
    return context.WithTimeoutOrCancel(parent, d)
}
