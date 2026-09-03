# JSON API (MDN)

## `JSON.parse(text, reviver?)`

Parses a JSON string, constructing the JavaScript value or object described by the string.

### Parameters
- `text: string` — JSON string to parse
- `reviver?: (key, value) => value` — transform function

### Returns
- `any` — parsed value

### Throws
- `SyntaxError` — if the string is not valid JSON

## Static methods on `JSON`
- `JSON.parse(text, reviver?)`
- `JSON.stringify(value, replacer?, space?)`

There is **no** `JSON.safelyParse`. Any reference to it is a hallucination.
