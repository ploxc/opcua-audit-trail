// Warnings and errors that nobody acknowledged yet: the counts next to
// "Audit trail" in the sidebar, refreshed on every page.

import { html } from "./vdom.js";
import { get } from "./api.js";
import { plural } from "./format.js";
import { redraw, state } from "./state.js";

/** The last /alarms answer for one severity ("error" or "warning"). */
export const alarm = (severity) => (state.alarms || []).find((a) => a.severity === severity);

/** How many records of a severity are not acknowledged. */
export const unacked = (severity) => alarm(severity)?.unacknowledged || 0;

/** The red and orange counts in the sidebar. */
export function AlarmCounts() {
  const count = (n, kind, word) =>
    n > 0 &&
    html`<span class="count ${kind}" title="${plural(n, word)} not acknowledged">${n}</span>`;
  return html`<span class="alarm-counts"
    >${count(unacked("error"), "bad", "error")}${count(unacked("warning"), "warn", "warning")}</span
  >`;
}

/** Fetches the counts and redraws. */
export async function refreshAlarms() {
  if (!state.user || state.user.must_change_password) return;
  try {
    state.alarms = await get("/alarms");
  } catch {
    return;
  }
  redraw();
}
