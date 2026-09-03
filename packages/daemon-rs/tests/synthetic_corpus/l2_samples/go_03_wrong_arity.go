// Mutation M4: parameter hallucination. http.Get takes (url string),
// NOT a context. The context-aware variant is http.NewRequestWithContext.
// Expected compile: too many arguments in call to http.Get.
// Expected scanner layer: L2 forge: hallucinated-parameter.
package main

import (
    "context"
    "net/http"
)

func fetchWithCtx(ctx context.Context, url string) (*http.Response, error) {
    return http.Get(ctx, url)
}
