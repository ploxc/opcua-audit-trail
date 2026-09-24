// The `html` template tag and its helpers: every page is rendered with them.
//
// Every interpolated value is escaped unless it is itself `html` output (an
// `Html` object), so data from the server can never inject markup. Arrays are
// joined, so `${rows.map((r) => html`<tr>…</tr>`)}` just works.

/** Markup that is already safe: produced by `html`, or trusted literal SVG. */
export class Html {
  constructor(s) {
    this.s = s;
  }
  toString() {
    return this.s;
  }
}

const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

/** Escapes text for use in markup, in element content as well as in attribute values. */
export const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ESC[c]);

// One interpolated value: safe markup as is, arrays joined, anything else escaped.
const fmt = (v) => (v instanceof Html ? v.s : Array.isArray(v) ? v.map(fmt).join("") : esc(v));

/** Tagged template that escapes its values and returns `Html`. */
export function html(strings, ...values) {
  let out = "";
  strings.forEach((s, i) => {
    out += s + (i < values.length ? fmt(values[i]) : "");
  });
  return new Html(out);
}

/**
 * `then` when `cond` holds, else `otherwise`. `then` may be a function, so
 * branches that dereference optional data are only evaluated when the
 * condition holds.
 */
export const when = (cond, then, otherwise = "") =>
  cond ? (typeof then === "function" ? then() : then) : otherwise;

/** A bare attribute such as `checked` or `disabled`, present only when `cond` holds. */
export const flag = (cond, name) => new Html(cond ? name : "");
