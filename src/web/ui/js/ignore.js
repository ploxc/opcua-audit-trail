// Summarised ("ignored") nodes: a node written constantly, such as a life bit
// or a clock, can be summarised per target: one record per interval instead
// of one per write. The audit trail, the targets page and the browser all
// show and change this, so it lives here with its two actions.

import { Html, esc, html, when } from "./html.js";
import { get, post } from "./api.js";
import { dialog, toast } from "./components.js";
import { can, renderPage, state } from "./state.js";

/** A target of the last /status answer, by name. */
export const targetOf = (name) => (state.status?.targets || []).find((t) => t.name === name);

// The ignore rules of a target for one node (one per client, or one for all).
const ignoreRules = (target, nodeId) =>
  (targetOf(target)?.ignore || []).filter((r) => r.node_id === nodeId);

// What an ignore rule for one client names: its application URI, else its address.
const clientKey = (client) =>
  client?.application_uri ||
  (client?.remote_addr || "").replace(/:\d+$/, "").replace(/^\[|\]$/g, "");

/** How often a summary is recorded, e.g. "1 h". */
export function summaryEvery() {
  const s = state.status?.ignored_summary_secs || 3600;
  return s % 3600 === 0 ? `${s / 3600} h` : s % 60 === 0 ? `${s / 60} min` : `${s} s`;
}

const isSummarised = (target, nodeId) => ignoreRules(target, nodeId).length > 0;

/** A "summarised" badge next to a node that is summarised on its target. */
export const summarisedBadge = (target, nodeId) =>
  when(
    isSummarised(target, nodeId),
    () =>
      html`<span
        class="badge plain neutral"
        title="Writes to this node are recorded as one summary every ${summaryEvery()}"
      >summarised</span>`,
  );

// How the summarise dialog names a client: its application, and its address
// when the rule would name the application URI.
const clientLabel = (client) =>
  client
    ? [
        client.application_name,
        clientKey(client) === client.application_uri
          ? (client.remote_addr || "").replace(/:\d+$/, "")
          : "",
      ]
        .filter(Boolean)
        .join(" ") || clientKey(client)
    : "";

/**
 * Whether writes to a node are summarised, and the button to change that.
 * `node` is { target, node_id, name, client }. `compact` gives just a badge
 * or a button, for a table row.
 */
export function ignoreControls(node, { compact = false } = {}) {
  const { target, node_id: nodeId } = node;
  if (!target || !nodeId || !targetOf(target)) return "";
  const rules = ignoreRules(target, nodeId);
  const data = (r) =>
    new Html(
      `data-target="${esc(target)}" data-node="${esc(nodeId)}" data-client="${esc(r?.client || "")}"`,
    );

  // Summarised already: say from whom, and offer to record every write again.
  if (rules.length) {
    const recordAgain = when(can("admin"), () =>
      rules.map(
        (r) =>
          html`<button class="small" data-action="unignore" ${data(r)}>
            Record every write again
          </button>`,
      ),
    );
    const who = rules.map((r) => (r.client ? `from ${r.client}` : "from every client")).join(", ");
    if (compact)
      return html`<span class="badge plain neutral" title="Summarised ${who}">summarised</span>`;
    return html`<div class="alert info small">
      <b>Summarised.</b> Writes to this node ${who} are not recorded one by one: every
      ${summaryEvery()} one record says how many there were, from whom, and the last value.
      <div class="button-row">${recordAgain}</div>
    </div>`;
  }

  // Not summarised: admins may summarise it.
  if (!can("admin")) return "";
  const button = html`<button
    class="small"
    data-action="ignore"
    ${data(null)}
    data-name="${node.name || ""}"
    data-client-key="${clientKey(node.client)}"
    data-client-label="${clientLabel(node.client)}"
  >${compact ? "Summarise…" : "Summarise writes…"}</button>`;
  if (compact) return button;
  return html`<div class="ignore-box">
    <p class="small muted">
      Is this node written constantly, like a life bit or a clock? Its writes can be summarised
      instead of recorded one by one.
    </p>
    <div class="button-row">${button}</div>
  </div>`;
}

export const actions = {
  /** Asks from which clients to summarise a node's writes, then does it. */
  async ignore(el) {
    const { target, node, name, clientKey: key, clientLabel: label } = el.dataset;
    const title = name || node;
    const choice = await dialog({
      title: `Summarise writes to ${title}?`,
      body: html`<p>
          Now every write to <b>${title}</b> <span class="mono muted">${node}</span> on target
          <b>${target}</b> becomes its own record. A node that is written constantly, like a life
          bit or a clock, buries the writes that matter.
        </p>
        <p>
          Summarised, its writes are counted instead: every ${summaryEvery()} one record says how
          many writes there were (and how many failed), from which clients, and the last value.
        </p>
        <fieldset class="choice">
          <legend>Which writes?</legend>
          <label><input type="radio" name="scope" value="" checked> From every client</label>
          ${when(
            key,
            () =>
              html`<label>
                <input type="radio" name="scope" value="${key}"> Only from ${label || key}
                <span class="muted small">
                  Writes to this node by any other client stay recorded one by one.
                </span>
              </label>`,
          )}
        </fieldset>
        <p class="muted small">
          Method calls and writes to other nodes are always recorded. You can undo this at any
          time (on the target's page, or here).
        </p>`,
      confirm: "Summarise writes",
    });
    if (!choice) return;
    await post(`/targets/${encodeURIComponent(target)}/ignore`, {
      node_id: node,
      client: choice.scope || null,
      name: name || null,
    });
    state.status = await get("/status");
    toast(`Writes to ${title} are now summarised`);
    renderPage();
  },

  /** Records every write to a node again. */
  async unignore(el) {
    const { target, node, client } = el.dataset;
    await post(`/targets/${encodeURIComponent(target)}/ignore/remove`, {
      node_id: node,
      client: client || null,
    });
    state.status = await get("/status");
    toast("Every write to this node is recorded again");
    renderPage();
  },
};
