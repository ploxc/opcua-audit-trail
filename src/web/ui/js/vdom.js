// Preact, which draws the UI: the `html` tag that builds it, the hooks, and
// the helpers for event handlers.
//
// `html` is htm bound to Preact's `h`: a template builds a virtual DOM, which
// Preact diffs into the page. So a redraw keeps the focus, what is typed and
// the scroll positions by itself, and the text of every interpolated value is
// escaped by the DOM. The library is vendored, unchanged, in `vendor/` (see
// LICENSES.md there): no build step and no npm at runtime.
//
// Things htm does differently from HTML (like JSX):
// - Every element is closed: `<input />`, `<br />`.
// - An inline element at the start or the end of a line loses the space next
//   to it: write `${" "}` there, or keep it mid-line.
// - Entities such as `&lt;` are not decoded: interpolate the text instead.
// - `${n && html`…`}` shows a 0: write `${n > 0 && …}` or `${n ? … : null}`.
//
// Form fields that are not controlled by a component's state get their
// start value with `defaultValue`, `defaultChecked` or an option's
// `selected`: a redraw then leaves what the user typed alone (`value` and
// `checked` would put the start value back).

import { h, render } from "./vendor/preact.js";
import { useEffect, useState } from "./vendor/preact-hooks.js";
import htm from "./vendor/htm.js";
import { fail } from "./state.js";

export const html = htm.bind(h);
export { h, render, useEffect, useState };

/**
 * An event handler for a request: a failure is shown as a toast (a 401
 * shows the login), instead of an unhandled rejection.
 */
export const safe = (handler) => async (event) => {
  try {
    await handler(event);
  } catch (e) {
    fail(e);
  }
};

/**
 * A form's submit handler: `handler(form)` runs instead of the browser's
 * submit, with the submit button disabled while it runs; a failure is shown
 * as a toast.
 */
export const submit = (handler) => async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector("button[type=submit]");
  if (button) button.disabled = true;
  try {
    await handler(form);
  } catch (e) {
    fail(e);
  } finally {
    if (button) button.disabled = false;
  }
};
