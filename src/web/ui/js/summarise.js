// Summarised nodes: a node written constantly, such as a life bit or a clock,
// can be summarised per target: one record per interval instead of one per
// write. A target keeps them in groups (e.g. "HMI line 1"), each for one
// client or for every client. The audit trail, the targets page and the
// browser all show and change this, so it lives here with its actions.

import { Html, esc, html, when } from "./html.js";
import { del, get, post, put } from "./api.js";
import { dialog, fold, toast } from "./components.js";
import { plural } from "./format.js";
import { can, renderPage, state } from "./state.js";

/** A target of the last /status answer, by name. */
export const targetOf = (name) => (state.status?.targets || []).find((t) => t.name === name);

// A target's summarise groups, each with its position (the API addresses it by that).
const groupsOf = (target) => (targetOf(target)?.summarise || []).map((g, i) => ({ ...g, i }));

// The groups that have a node.
const groupsWith = (target, nodeId) => groupsOf(target).filter((g) => g.nodes.includes(nodeId));

// A client's address without its port.
const clientIp = (client) =>
  (client?.remote_addr || "").replace(/:\d+$/, "").replace(/^\[|\]$/g, "");

// What a group for one client names: its application URI, else its address.
const clientKey = (client) => client?.application_uri || clientIp(client);

// Whether a group applies to writes from `client` (every group, without a client).
const fitsClient = (g, client) =>
  !g.client || (!!client && (g.client === clientIp(client) || g.client === client.application_uri));

const groupName = (g) => g.name || "Unnamed group";
const groupFrom = (g) => (g.client ? `from ${g.client}` : "from every client");
const api = (target, rest = "") => `/targets/${encodeURIComponent(target)}/summarise${rest}`;

// A group by its position, with the group shown to the user: the gateway
// refuses the change if the list changed meanwhile (another admin), instead
// of changing another group.
const groupApi = (target, index, rest = "") => {
  const g = groupsOf(target)[index] || {};
  const q = new URLSearchParams({ check: "true" });
  if (g.name) q.set("name", g.name);
  if (g.client) q.set("client", g.client);
  return api(target, `/${index}${rest}?${q}`);
};

async function refresh(message) {
  state.status = await get("/status");
  toast(message);
  renderPage();
}

/** How often a summary is recorded, e.g. "1 h". */
export function summaryEvery() {
  const s = state.status?.ignored_summary_secs || 3600;
  return s % 3600 === 0 ? `${s / 3600} h` : s % 60 === 0 ? `${s / 60} min` : `${s} s`;
}

/** A "summarised" badge next to a node that is summarised on its target. */
export const summarisedBadge = (target, nodeId) =>
  when(
    groupsWith(target, nodeId).length > 0,
    () =>
      html`<span
        class="badge plain neutral"
        title="Writes to this node are recorded as one summary every ${summaryEvery()}"
      >summarised</span>`,
  );

// How the summarise dialog names a client: its application, and its address
// when a group would name the application URI.
const clientLabel = (client) =>
  client
    ? [
        client.application_name,
        clientKey(client) === client.application_uri ? clientIp(client) : "",
      ]
        .filter(Boolean)
        .join(" ") || clientKey(client)
    : "";

/**
 * Whether writes to a node are summarised, and the buttons to change that.
 * `node` is { target, node_id, name, client }. `compact` gives just a badge
 * or a button, for a table row.
 */
export function summariseControls(node, { compact = false } = {}) {
  const { target, node_id: nodeId } = node;
  if (!target || !nodeId || !targetOf(target)) return "";
  const groups = groupsWith(target, nodeId);
  const who = groups.map((g) => `${groupName(g)} (${groupFrom(g)})`).join(", ");
  const button = when(
    can("admin"),
    () => html`<button
      class="small"
      data-action="summarise"
      data-target="${target}"
      data-node="${nodeId}"
      data-name="${node.name || ""}"
      data-client-key="${clientKey(node.client)}"
      data-client-label="${clientLabel(node.client)}"
    >${compact ? "Summarise…" : groups.length ? "Add to another group…" : "Summarise writes…"}</button>`,
  );

  if (compact) {
    return groups.length
      ? html`<span class="badge plain neutral" title="Summarised in ${who}">summarised</span>`
      : button;
  }
  if (groups.length) {
    const remove = when(can("admin"), () =>
      groups.map(
        (g) => html`<button
          class="small"
          data-action="unsummarise-node"
          data-target="${target}"
          data-group="${g.i}"
          data-node="${nodeId}"
        >Remove from ${groupName(g)}</button>`,
      ),
    );
    return html`<div class="alert info small">
      <b>Summarised</b> in ${who}. Writes to this node are not recorded one by one: every
      ${summaryEvery()} one record says how many there were, from whom, and the last value.
      <div class="button-row">${remove}${button}</div>
    </div>`;
  }
  if (!can("admin")) return "";
  return html`<div class="ignore-box">
    <p class="small muted">
      Is this node written constantly, like a life bit or a clock? Its writes can be summarised
      instead of recorded one by one.
    </p>
    <div class="button-row">${button}</div>
  </div>`;
}

// ---------- the groups on the targets page ----------

// Nodes shown per group before "Show all".
const SHOWN = 20;

/** A target's summarise groups, in a fold on its card. */
export function summariseSection(t) {
  const groups = groupsOf(t.name);
  const count = groups.reduce((n, g) => n + g.nodes.length, 0);
  const shown = (state.targets.showAllNodes ||= {});
  const data = (g) => new Html(`data-target="${esc(t.name)}" data-group="${g.i}"`);
  const card = (g) => {
    const key = `${t.name}:${g.i}`;
    const nodes = shown[key] ? g.nodes : g.nodes.slice(0, SHOWN);
    const row = (id) => html`<tr>
      <td>
        ${g.names?.[id] || id}${when(g.names?.[id], () => html`<div class="muted mono small">${id}</div>`)}
      </td>
      <td class="num">
        ${when(
          can("admin"),
          () => html`<button class="small" data-action="unsummarise-node" ${data(g)} data-node="${id}"
            title="Record every write to this node again">Remove</button>`,
        )}
      </td>
    </tr>`;
    return html`<div class="summarise-group">
      <div class="card-head">
        <div>
          <b>${groupName(g)}</b> <span class="muted small">${groupFrom(g)} ·
          ${plural(g.nodes.length, "node")}</span>
        </div>
        ${when(
          can("admin"),
          () => html`<div class="inline">
            <button class="small" data-action="add-summarised-nodes" ${data(g)}>Add nodes…</button>
            <button class="small" data-action="rename-summarise-group" ${data(g)}>Rename</button>
            <button class="small danger" data-action="delete-summarise-group" ${data(g)}>
              Remove group
            </button>
          </div>`,
        )}
      </div>
      ${
        g.nodes.length
          ? html`<div class="table-wrap">
              <table>
                <tbody>${nodes.map(row)}</tbody>
              </table>
            </div>`
          : html`<p class="muted small">No nodes yet.</p>`
      }
      ${when(
        g.nodes.length > SHOWN,
        () => html`<button class="small" data-action="toggle-group-nodes" data-key="${key}">
          ${shown[key] ? "Show fewer" : `Show all ${g.nodes.length}`}
        </button>`,
      )}
    </div>`;
  };
  return fold(
    `${t.name}:summarised`,
    "Summarised nodes",
    count ? `${plural(count, "node")} in ${plural(groups.length, "group")}` : "none",
    () => html`
      <p class="section-note">
        Writes to these nodes are not recorded one by one: every ${summaryEvery()} one record per
        node says how many there were, from whom, and the last value. A group is for one client or
        for every client. Add nodes here, from <a href="#/audit">Audit trail → Most written</a>, a
        write's details, or the <a href="#/browser">Browser</a>.
      </p>
      ${groups.length ? groups.map(card) : html`<p class="muted small">None: every write is recorded.</p>`}
      ${when(
        can("admin"),
        () => html`<div class="button-row">
          <button class="small" data-action="new-summarise-group" data-target="${t.name}">
            New group…
          </button>
        </div>`,
      )}`,
  );
}

// The fields of a new group: its name and, optionally, its client.
const newGroupFields = (client = true) => html`<label>Name
    <input name="name" maxlength="100" placeholder="e.g. HMI line 1">
  </label>
  ${when(
    client,
    () => html`<label>Only writes from (IP address or application URI; empty: every client)
      <input name="client" maxlength="256" placeholder="e.g. 192.168.1.20">
    </label>`,
  )}`;

// Node ids pasted one per line.
const pasted = (text) =>
  (text || "")
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);

export const actions = {
  /** Asks to which group a node is added (or a new one), then adds it. */
  async summarise(el) {
    const { target, node, name, clientKey: key, clientLabel: label } = el.dataset;
    const title = name || node;
    const client = key ? { remote_addr: key, application_uri: key } : null;
    const fits = groupsOf(target).filter((g) => fitsClient(g, client) && !g.nodes.includes(node));
    const option = (value, text, note, checked) => html`<label>
      <input type="radio" name="to" value="${value}" ${checked ? "checked" : ""}> ${text}
      ${when(note, () => html`<span class="muted small">${note}</span>`)}
    </label>`;
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
          <legend>Add to</legend>
          ${fits.map((g, n) => option(`g${g.i}`, `${groupName(g)} (${groupFrom(g)})`, "", n === 0))}
          ${when(key, () =>
            option(
              "client",
              `A new group for ${label || key}`,
              "Writes to this node by any other client stay recorded one by one.",
              !fits.length,
            ),
          )}
          ${option("all", "A new group for every client", "", !fits.length && !key)}
        </fieldset>
        <label>Name of a new group <input name="name" maxlength="100" placeholder="e.g. HMI line 1"></label>
        <p class="muted small">
          Method calls and writes to other nodes are always recorded. You can undo this at any
          time (on the target's page, or here).
        </p>`,
      confirm: "Summarise writes",
    });
    if (!choice?.to) return;
    const nodes = [{ node_id: node, name: name || null }];
    if (choice.to.startsWith("g")) {
      await post(groupApi(target, choice.to.slice(1), "/add"), nodes);
    } else {
      await post(api(target), {
        name: choice.name || null,
        client: choice.to === "client" ? key : null,
        nodes,
      });
    }
    await refresh(`Writes to ${title} are now summarised`);
  },

  /** Removes a node from a group: its writes are recorded again. */
  async "unsummarise-node"(el) {
    const { target, group, node } = el.dataset;
    await post(groupApi(target, group, "/remove"), { nodes: [node] });
    await refresh("Removed from the group");
  },

  async "new-summarise-group"(el) {
    const { target } = el.dataset;
    const d = await dialog({
      title: `New group on ${target}`,
      body: newGroupFields(),
      confirm: "Create group",
    });
    if (!d) return;
    await post(api(target), { name: d.name || null, client: d.client || null });
    await refresh("Group created");
  },

  /** Adds nodes: picked from the most written, or pasted one per line. */
  async "add-summarised-nodes"(el) {
    const { target, group } = el.dataset;
    const g = groupsOf(target)[group];
    if (!g) return;
    const q = new URLSearchParams({ hours: 24, limit: 100, target });
    if (g.client) q.set("client", g.client);
    const top = await get(`/audit/most-written?${q}`);
    const pick = (n, i) => {
      const inGroup = g.nodes.includes(n.node_id);
      return html`<label>
        <input type="checkbox" name="pick${i}" value="${i}" ${inGroup ? "checked disabled" : ""}>
        <span>${n.display_name || n.node_id}
          ${when(n.display_name, () => html`<span class="muted mono small">${n.node_id}</span>`)}
          <span class="muted small">· ${n.count} writes${inGroup ? " · in this group" : ""}</span>
        </span>
      </label>`;
    };
    const d = await dialog({
      title: `Add nodes to ${groupName(g)}`,
      body: html`<p class="muted small">Writes ${groupFrom(g)}.</p>
        <fieldset class="choice pick-list">
          <legend>Most written, last 24 hours${g.client ? ` (by ${g.client})` : ""}</legend>
          ${top.length ? top.map(pick) : html`<p class="muted small">No writes recorded.</p>`}
        </fieldset>
        <label>Or paste node ids, one per line
          <textarea name="paste" rows="5" class="mono" placeholder='ns=3;s="DB1"."Life"'></textarea>
        </label>
        <p class="muted small">Nodes already in the group are skipped.</p>`,
      confirm: "Add nodes",
    });
    if (!d) return;
    const nodes = Object.keys(d)
      .filter((k) => k.startsWith("pick"))
      .map((k) => top[Number(d[k])])
      .map((n) => ({ node_id: n.node_id, name: n.display_name || null }))
      .concat(pasted(d.paste).map((id) => ({ node_id: id })));
    if (!nodes.length) return;
    const r = await post(groupApi(target, group, "/add"), nodes);
    await refresh(`${plural(r.changed, "node")} added`);
  },

  async "rename-summarise-group"(el) {
    const { target, group } = el.dataset;
    const g = groupsOf(target)[group];
    if (!g) return;
    const d = await dialog({
      title: "Rename group",
      body: html`<label>Name
        <input name="name" maxlength="100" value="${g.name || ""}" placeholder="e.g. HMI line 1">
      </label>`,
      confirm: "Rename",
    });
    if (!d) return;
    await put(groupApi(target, group), { name: d.name || null });
    await refresh("Group renamed");
  },

  async "delete-summarise-group"(el) {
    const { target, group } = el.dataset;
    const g = groupsOf(target)[group];
    if (!g) return;
    const ok = await dialog({
      title: `Remove ${groupName(g)}?`,
      body: html`<p>
        Every write to its ${plural(g.nodes.length, "node")} ${groupFrom(g)} is recorded one by one
        again (unless another group has the node).
      </p>`,
      confirm: "Remove group",
      danger: true,
    });
    if (!ok) return;
    await del(groupApi(target, group));
    await refresh("Group removed");
  },

  "toggle-group-nodes"(el) {
    const shown = (state.targets.showAllNodes ||= {});
    shown[el.dataset.key] = !shown[el.dataset.key];
    renderPage();
  },
};
