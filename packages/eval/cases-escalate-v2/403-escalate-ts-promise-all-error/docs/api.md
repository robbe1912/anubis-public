# Promise

`Promise.all(values): Promise<T[]>` — rejects if any input rejects.
`Promise.allSettled(values): Promise<PromiseSettledResult<T>[]>` — never rejects.

PromiseSettledResult: { status: "fulfilled", value: T } | { status: "rejected", reason: any }.
