# context
```go
type Context interface {
    Done() <-chan struct{}
    Err() error
}
```
`ctx.Done()` returns a channel closed when context is cancelled.
