# Node.js fs API

## `readFileSync(path, encoding?)`

Synchronously reads a file. When `encoding` is provided, returns a `string`.

## `String.prototype.split(separator)`

Splits a string into an array of substrings using the given separator.

### Returns
- `string[]`

### Example
```ts
"abc\ndef".split("\n"); // ["abc", "def"]
```
