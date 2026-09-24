// Warnings and errors that nobody acknowledged yet: the counts next to
// "Audit trail" in the sidebar, refreshed on every page.

import { html, when } from "./html.js";
import { get } from "./api.js";
import { plural } from "./format.js";
import { state } from "./state.js";

/** The last /alarms answer for one severity ("error" or "warning"). */
export const alarm = (severity) => (state.alarms || []).find((a) => a.severity === severity);

/** How many records of a severity are not acknowledged. */
export const unacked = (severity) => alarm(severity)?.unacknowledged || 0;

/** The red and orange counts in the sidebar. */
export function alarmCounts() {
  const e = unacked("error"),
    w = unacked("warning");
  return html`${when(
    e,
    html`<span class="count bad" title="${plural(e, "error")} not acknowledged">${e}</span>`,
  )}${when(
    w,
    html`<span class="count warn" title="${plural(w, "warning")} not acknowledged">${w}</span>`,
  )}`;
}

/** Fetches the counts and updates the sidebar in place (no full redraw). */
export async function refreshAlarms() {
  if (!state.user || state.user.must_change_password) return;
  try {
    state.alarms = await get("/alarms");
  } catch {
    return;
  }
  const el = document.querySelector(".alarm-counts");
  if (el) el.innerHTML = alarmCounts().s;
}
