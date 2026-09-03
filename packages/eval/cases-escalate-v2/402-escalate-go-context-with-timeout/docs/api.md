# context

`context.WithTimeout(parent Context, timeout time.Duration) (Context, CancelFunc)`

Returns derived context that cancels after timeout. Caller MUST call cancel.
