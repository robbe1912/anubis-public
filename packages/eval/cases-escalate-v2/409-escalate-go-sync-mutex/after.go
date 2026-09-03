type Counter struct {
    mu sync.Mutex
    n  int
}
