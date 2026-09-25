// Building blocks shared by the pages: icons and logos, the header buttons,
// status badges, foldable sections, dialogs, toasts and form helpers.

import { Html, html, when } from "./html.js";
import { CHANGE_EVENTS, ERROR_EVENTS, EVENT_LABELS, WARNING_EVENTS } from "./format.js";
import { state } from "./state.js";

// ---------- icons and logos ----------

// Material icons (filled, Apache 2.0), the set Modbux uses.
const ICON_PATHS = {
  dashboard: '<path d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z"/>',
  audit:
    '<path d="M19.5 3.5 18 2l-1.5 1.5L15 2l-1.5 1.5L12 2l-1.5 1.5L9 2 7.5 3.5 6 2v14H3v3c0 1.66 1.34 3 3 3h12c1.66 0 3-1.34 3-3V2l-1.5 1.5zM19 19c0 .55-.45 1-1 1s-1-.45-1-1v-3H8V5h11v14z"/><path d="M9 7h6v2H9zm7 0h2v2h-2zm-7 3h6v2H9zm7 0h2v2h-2z"/>',
  targets: '<path d="M13 22h8v-7h-3v-4h-5V9h3V2H8v7h3v2H6v4H3v7h8v-7H8v-2h8v2h-3z"/>',
  certificates:
    '<path d="M12 1 3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/>',
  browser: '<path d="M22 11V3h-7v3H9V3H2v8h7V8h2v10h4v3h7v-8h-7v3h-2V8h2v3z"/>',
  users:
    '<path d="M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5c-1.66 0-3 1.34-3 3s1.34 3 3 3zm-8 0c1.66 0 2.99-1.34 2.99-3S9.66 5 8 5C6.34 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5zm8 0c-.29 0-.62.02-.97.05 1.16.84 1.97 1.97 1.97 3.45V19h6v-2.5c0-2.33-4.67-3.5-7-3.5z"/>',
  account:
    '<circle cx="10" cy="8" r="4"/><path d="M10.67 13.02c-.22-.01-.44-.02-.67-.02-2.42 0-4.68.67-6.61 1.82-.88.52-1.39 1.5-1.39 2.53V20h9.26a6.963 6.963 0 0 1-.59-6.98zM20.75 16c0-.22-.03-.42-.06-.63l1.14-1.01-1-1.73-1.45.49c-.32-.27-.68-.48-1.08-.63L18 11h-2l-.3 1.49c-.4.15-.76.36-1.08.63l-1.45-.49-1 1.73 1.14 1.01c-.03.21-.06.41-.06.63s.03.42.06.63l-1.14 1.01 1 1.73 1.45-.49c.32.27.68.48 1.08.63L16 21h2l.3-1.49c.4-.15.76-.36 1.08-.63l1.45.49 1-1.73-1.14-1.01c.03-.21.06-.41.06-.63zM17 18c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z"/>',
  dark: '<path d="M12 3a9 9 0 1 0 9 9c0-.46-.04-.92-.1-1.36a5.389 5.389 0 0 1-4.4 2.26 5.403 5.403 0 0 1-3.14-9.8c-.44-.06-.9-.1-1.36-.1z"/>',
  light:
    '<path d="M12 7c-2.76 0-5 2.24-5 5s2.24 5 5 5 5-2.24 5-5-2.24-5-5-5zM2 13h2c.55 0 1-.45 1-1s-.45-1-1-1H2c-.55 0-1 .45-1 1s.45 1 1 1zm18 0h2c.55 0 1-.45 1-1s-.45-1-1-1h-2c-.55 0-1 .45-1 1s.45 1 1 1zM11 2v2c0 .55.45 1 1 1s1-.45 1-1V2c0-.55-.45-1-1-1s-1 .45-1 1zm0 18v2c0 .55.45 1 1 1s1-.45 1-1v-2c0-.55-.45-1-1-1s-1 .45-1 1zM5.99 4.58a.996.996 0 0 0-1.41 0 .996.996 0 0 0 0 1.41l1.06 1.06c.39.39 1.03.39 1.41 0s.39-1.03 0-1.41L5.99 4.58zm12.37 12.37a.996.996 0 0 0-1.41 0 .996.996 0 0 0 0 1.41l1.06 1.06c.39.39 1.03.39 1.41 0a.996.996 0 0 0 0-1.41l-1.06-1.06zm1.06-10.96a.996.996 0 0 0 0-1.41.996.996 0 0 0-1.41 0l-1.06 1.06c-.39.39-.39 1.03 0 1.41s1.03.39 1.41 0l1.06-1.06zM7.05 18.36a.996.996 0 0 0 0-1.41.996.996 0 0 0-1.41 0l-1.06 1.06c-.39.39-.39 1.03 0 1.41s1.03.39 1.41 0l1.06-1.06z"/>',
  menu: '<path d="M3 18h18v-2H3v2zm0-5h18v-2H3v2zm0-7v2h18V6H3z"/>',
  settings:
    '<path d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58a.49.49 0 0 0 .12-.61l-1.92-3.32a.488.488 0 0 0-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54a.484.484 0 0 0-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58a.49.49 0 0 0-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z"/>',
  logout:
    '<path d="m17 7-1.41 1.41L18.17 11H8v2h10.17l-2.58 2.58L17 17l5-5zM4 5h8V3H4c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h8v-2H4V5z"/>',
};

/** An inline SVG icon by name (see ICON_PATHS). */
export const icon = (name, cls = "") =>
  new Html(
    `<svg class="icon ${cls}" viewBox="0 0 24 24" aria-hidden="true">${ICON_PATHS[name]}</svg>`,
  );

const LOGO_PATH =
  "m 107.60293,0.64220653 c -35.769829,0 -65.039135,29.45982647 -65.039135,65.27483247 V 94.927484 L 30.45287,82.757639 7.3579379,105.74314 32.676186,131.18345 7.3579379,156.5017 30.214018,179.35778 55.477552,154.09425 80.619032,179.35778 103.71607,156.37227 75.147546,127.66697 V 65.917039 c 0,-18.289883 14.380372,-32.691083 32.455384,-32.691083 18.07499,0 32.45538,14.4012 32.45538,32.691083 0,18.275197 -14.35769,32.665875 -32.41224,32.68897 l -16.215592,-0.09996 -0.124161,32.583751 16.296613,0.1 v 0.002 c 35.7698,0 65.03913,-29.45983 65.03913,-65.274832 0,-35.815005 -29.26933,-65.27483198 -65.03913,-65.27483198 z";

/** The Ploxc logo. */
export const logo = (cls = "") =>
  new Html(
    `<svg class="logo ${cls}" viewBox="0 0 180 180" aria-hidden="true">` +
      `<circle class="dot" cx="107.599" cy="65.927" r="16.292"/>` +
      `<path class="mark" d="${LOGO_PATH}"/>` +
      `</svg>`,
  );

// The gateway's own mark: traffic enters on the left and leaves through the
// gateway (the ring) towards the target and the audit trail.
export const gatewayLogo = (cls = "") =>
  new Html(
    `<svg class="logo gateway-logo ${cls}" viewBox="0 0 512 512" aria-hidden="true">` +
      `<g class="mark-line" fill="none" stroke-width="75.1" stroke-linecap="round">` +
      `<line x1="143.3" y1="256" x2="37.6" y2="256"/>` +
      `<line x1="342.3" y1="183.6" x2="423.3" y2="115.6"/>` +
      `<line x1="342.3" y1="328.4" x2="423.3" y2="396.4"/>` +
      `<circle cx="256" cy="256" r="112.7"/>` +
      `</g>` +
      `<circle class="dot" cx="256" cy="256" r="37.6"/>` +
      `</svg>`,
  );

// ---------- header buttons and links ----------

/** Opens the sidebar on narrow screens (hidden on wide ones). */
export const menuButton = new Html(
  `<button class="icon-button menu-button" data-action="menu" aria-label="Menu">` +
    `${icon("menu").s}</button>`,
);

/** The localStorage key of the light or dark mode the user picked. */
export const THEME_KEY = "ploxc-color-mode";

// Both icons are rendered; the stylesheet shows the one for the other mode.
export const themeButton = () =>
  html`<button
    class="icon-button"
    data-action="theme"
    title="Light or dark mode"
    aria-label="Toggle light or dark mode"
  >${icon("light", "icon-sun")}${icon("dark", "icon-moon")}</button>`;

export const ploxcLink = () =>
  html`<a class="ploxc-link" href="https://ploxc.com" target="_blank" rel="noopener">${logo()}Ploxc</a>`;

// ---------- badges ----------

/** An OPC UA status code, coloured by its severity (Good, Uncertain, Bad). */
export const statusBadge = (status) => {
  if (!status) return "";
  const kind = status.startsWith("Good") ? "ok" : status.startsWith("Uncertain") ? "warn" : "bad";
  return html`<span class="badge plain ${kind}">${status}</span>`;
};

/** Whether a target is reachable. */
export const stateBadge = (s) => {
  const map = {
    // Discovery reaches the target; whether clients can connect securely is
    // the trust shown next to it.
    available: ["ok", "Reachable"],
    unavailable: ["bad", "Unreachable"],
    unknown: ["neutral", "Checking…"],
  };
  const [kind, label] = map[s] || map.unknown;
  return html`<span class="badge ${kind}">${label}</span>`;
};

/** An audit event type: errors red, warnings orange, changes green. */
export const eventBadge = (type) => {
  const kind = ERROR_EVENTS.has(type)
    ? "bad"
    : WARNING_EVENTS.has(type)
      ? "warn"
      : CHANGE_EVENTS.has(type)
        ? "accent"
        : "neutral";
  return html`<span class="badge plain ${kind}">${EVENT_LABELS[type] || type}</span>`;
};

// ---------- foldable section ----------

/**
 * A section of a card that opens on click; closed unless opened. Which folds
 * are open is kept in `state.open` (by `key`), so it survives the periodic
 * refresh. `body` may be a function, only called when open.
 */
export function fold(key, title, summary, body) {
  const open = state.open?.has(key);
  return html`<div class="fold">
    <button type="button" class="fold-head" data-action="fold" data-key="${key}">
      <span class="chevron">${open ? "▾" : "▸"}</span>
      <h3>${title}</h3>
      <span class="fold-summary">${summary}</span>
    </button>
    ${when(open, body)}
  </div>`;
}

// ---------- dialog and toast ----------

/**
 * A dialog in the page, instead of the browser's confirm() and prompt().
 * Resolves with the form's fields when confirmed, or null when cancelled.
 */
export function dialog({ title, body = "", confirm = "OK", danger = false }) {
  return new Promise((resolve) => {
    const d = document.createElement("dialog");
    d.className = "dialog";
    d.innerHTML = html`<form method="dialog">
      <h2>${title}</h2>
      <div class="dialog-body">${body}</div>
      <div class="dialog-actions">
        <button type="submit" value="" formnovalidate>Cancel</button>
        <button type="submit" value="ok" class="${danger ? "danger" : "primary"}">${confirm}</button>
      </div>
    </form>`.s;
    document.body.append(d);
    d.addEventListener("close", () => {
      const data =
        d.returnValue === "ok" ? Object.fromEntries(new FormData(d.querySelector("form"))) : null;
      d.remove();
      resolve(data);
    });
    d.showModal();
    d.querySelector(
      ".dialog-body input:not([type=radio]), .dialog-actions button[value=ok]",
    )?.focus();
  });
}

/** A short message in the corner; `kind` "bad" for errors, which stay longer. */
export function toast(message, kind = "") {
  let host = document.querySelector(".toast-host");
  if (!host) {
    host = document.createElement("div");
    host.className = "toast-host";
    document.body.append(host);
  }
  // The same message again (e.g. a failing refresh) keeps the one shown
  // and restarts its timer instead of stacking another.
  let t = [...host.children].find(
    (x) => x.textContent === message && x.className === "toast " + kind,
  );
  if (!t) {
    t = document.createElement("div");
    t.className = "toast " + kind;
    t.textContent = message;
    host.append(t);
  }
  clearTimeout(t.timer);
  t.timer = setTimeout(() => t.remove(), kind === "bad" ? 7000 : 3500);
}

// ---------- form helpers ----------

/** A form's fields as an object (checkboxes only when checked). */
export const formData = (form) => Object.fromEntries(new FormData(form).entries());

/** A file's content as base64. */
export const readFile = (file) =>
  new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(r.result.split(",")[1]);
    r.onerror = reject;
    r.readAsDataURL(file);
  });
