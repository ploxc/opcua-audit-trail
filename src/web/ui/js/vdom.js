// Preact for the pages that are written as components: the `html` tag that
// builds them, the hooks, and the few helpers that tie them to the rest of
// the UI.
//
// This `html` is not the one in html.js. That one builds strings for the
// pages that are not converted yet; this one (htm, bound to Preact's `h`)
// builds a virtual DOM, which Preact diffs into the page. So a redraw keeps
// the focus, what is typed and the scroll positions by itself, and the text of
// every interpolated value is escaped by the DOM.
//
// The library is vendored, unchanged, in `vendor/` (see LICENSES.md there):
// still no build step and no npm at runtime.

import { h, render } from "./vendor/preact.js";
import { useState } from "./vendor/preact-hooks.js";
import htm from "./vendor/htm.js";
import { Html } from "./html.js";
import { fail, renderPage, state } from "./state.js";

export const html = htm.bind(h);
export { h, render, useState };

/**
 * Markup from the string `html` tag of html.js, for a part of a component
 * that is not converted yet. Its `data-action` handlers keep working (they
 * are delegated); the markup is only replaced when it changes.
 */
export const Raw = ({ markup }) =>
  h("span", {
    class: "raw",
    dangerouslySetInnerHTML: { __html: markup instanceof Html ? markup.s : String(markup ?? "") },
  });

/**
 * An event handler for a request: a failure is shown like a failed
 * `data-action` (a toast; a 401 shows the login), instead of an unhandled
 * rejection.
 */
export const safe = (handler) => async (event) => {
  try {
    await handler(event);
  } catch (e) {
    fail(e);
  }
};

/**
 * A section of a card that opens on click, closed unless opened. Which
 * folds are open is kept in `state.open` by `id`, the same set the string
 * `fold` of components.js uses, so the folds of one card behave alike.
 */
export function Fold({ id, title, summary, children }) {
  const open = state.open?.has(id);
  const toggle = () => {
    state.open ||= new Set();
    if (open) state.open.delete(id);
    else state.open.add(id);
    renderPage();
  };
  return html`<div class="fold">
    <button type="button" class="fold-head" onClick=${toggle}>
      <span class="chevron">${open ? "▾" : "▸"}</span>
      <h3>${title}</h3>
      <span class="fold-summary">${summary}</span>
    </button>
    ${open && children}
  </div>`;
}
