# fetch

`fetch(input: string | URL | Request, init?: RequestInit): Promise<Response>`

Returns a Response. Response has `.ok: boolean` and `.json(): Promise<unknown>`.

RequestInit fields: method, headers, body, cache, credentials, mode, signal.
