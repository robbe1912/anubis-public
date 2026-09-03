# Fetch API (WHATWG)

## `fetch(input, init?): Promise<Response>`

## `Response.json(): Promise<any>`

Asynchronously parses the response body as JSON. **Returns a Promise**, must be `await`ed.

## Methods on `Response`
- `json(): Promise<any>`
- `text(): Promise<string>`
- `arrayBuffer(): Promise<ArrayBuffer>`
- `blob(): Promise<Blob>`
- `formData(): Promise<FormData>`
- `clone(): Response`

There is **no** `Response.jsonSync`. Response body methods are all async by spec.
