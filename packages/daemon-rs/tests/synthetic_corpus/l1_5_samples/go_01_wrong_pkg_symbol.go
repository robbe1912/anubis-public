// Mutation M1: fabricated method on real type.
// `http.Client` is real; `DoJSON` does not exist (the real methods are
// `Do`, `Get`, `Post`, `PostForm`, `Head`). The user must manually
// unmarshal the response body.
// Expected compile: c.DoJSON undefined (type *http.Client has no field or method DoJSON).
// Expected scanner layer: L1.5 cached-hallucination OR forge: hallucinated-method.
package main

import "net/http"

func fetchJSON(url string) map[string]any {
    c := &http.Client{}
    return c.DoJSON("GET", url)
}
