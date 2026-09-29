# Vendored libraries

The UI's virtual DOM. The files are the libraries' own ES module builds,
copied unchanged from the npm packages, except for two edits:

- `preact-hooks.js` imports `./preact.js` instead of `preact` (there is no
  import map: the CSP allows no inline script).
- The `sourceMappingURL` comments are removed.

| File | Package | Version | License |
| --- | --- | --- | --- |
| `preact.js` | `preact` `dist/preact.mjs` | 10.29.8 | MIT, `LICENSE-preact.txt` |
| `preact-hooks.js` | `preact` `hooks/dist/hooks.mjs` | 10.29.8 | MIT, `LICENSE-preact.txt` |
| `htm.js` | `htm` `dist/htm.mjs` | 3.1.1 | Apache 2.0, `LICENSE-htm.txt` |

To update: `npm pack preact htm`, copy the three files again and make the two
edits above.
