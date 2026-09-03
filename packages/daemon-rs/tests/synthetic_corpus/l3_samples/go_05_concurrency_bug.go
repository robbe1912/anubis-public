// Mutation L3-4: data race — concurrent map writes without mutex.
// Go maps are NOT safe for concurrent use. Multiple goroutines writing
// to the same map without a sync.Mutex or sync.RWMutex causes fatal
// runtime error: "concurrent map writes". The LLM hallucinated that
// Go maps were thread-safe like sync.Map.
// Expected runtime: fatal error: concurrent map writes.
// Expected scanner layer: L3 (semantic concurrency reasoning).
package main

import "sync"

func WriteConcurrently() map[string]int {
    m := make(map[string]int)
    var wg sync.WaitGroup
    for i := 0; i < 10; i++ {
        wg.Add(1)
        go func(n int) {
            defer wg.Done()
            m["key"] = n
        }(i)
    }
    wg.Wait()
    return m
}
