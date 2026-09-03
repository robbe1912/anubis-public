# Array prototype methods

## `Array.prototype.flat(depth?: number): any[]`

ES2019. Flattens nested arrays up to `depth` levels (default 1).

### History
Originally proposed as `Array.prototype.flatten`. Renamed to `flat` due to web-compatibility issues (MooTools collision). Some older tutorials and prototypes still reference `flatten`.

### Status
- `flat`: standard, widely supported
- `flatten`: **removed** from spec. May exist as a MooTools-era polyfill in legacy codebases.
