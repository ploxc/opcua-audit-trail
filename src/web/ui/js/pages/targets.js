// Targets page: one card per target (an OPC UA server behind the gateway)
// with its security (endpoints, logins, certificates) and summarised nodes,
// and the form to add or edit a target.
//
// Written as Preact components (vdom.js). What is being edited lives in the
// page's own `useState`, not in the shared `state`: the form's fields are
// controlled by it, so the periodic refresh can redraw the page without
// touching what the user typed.
//
// In a template, an inline element at the start or the end of a line loses
// the space next to it (like JSX): write `${" "}` there, or keep it mid-line.

import { Fold, Raw, html, safe, useEffect, useState } from "../vdom.js";
import { html as markup } from "../html.js";
import { del, get, post, put } from "../api.js";
import { dialog, menuButton, stateBadge, toast } from "../components.js";
import { clientUrl } from "../format.js";
import { summariseSection } from "../summarise.js";
import { can, fail, load, renderPage, state } from "../state.js";

// How secure an endpoint is, and the minimum a target asks, on one scale.
const MODE_RANK = { None: 0, Sign: 1, SignAndEncrypt: 2 };
const MIN_RANK = { none: 0, sign: 1, sign_and_encrypt: 2 };
const MIN_SECURITY = {
  none: "Follow the target (incl. None)",
  sign: "Sign or better",
  sign_and_encrypt: "Sign & encrypt only",
};

// Whether the gateway can pass a login of this kind on to the target.
const relayed = (u) => u.token_type !== "Certificate" && u.token_type !== "IssuedToken";

// ---------- security ----------

// The target's endpoints, and which of them clients are offered.
function endpointsTable(endpoints, minSecurity) {
  if (!endpoints?.length) {
    return html`<p class="muted small">No endpoints known yet: press Discover.</p>`;
  }
  const min = MIN_RANK[minSecurity || "none"];
  const row = (e) => {
    const offered = (MODE_RANK[e.security_mode] ?? 0) >= min;
    const token = (u) => html`<span
        class="badge plain ${relayed(u) ? "accent" : "neutral"}"
        title=${relayed(u) ? "Passed on to the target" : "Cannot be passed on by the gateway"}
      >${u.token_type}</span>${" "}`;
    return html`<tr class=${offered ? "" : "dimmed"}>
      <td>${e.security_policy}</td>
      <td>${e.security_mode}</td>
      <td>${e.user_tokens.map(token)}</td>
      <td>
        ${
          offered
            ? html`<span class="badge ok">offered</span>`
            : html`<span class="badge plain neutral" title="Below the minimum security">hidden</span>`
        }
      </td>
    </tr>`;
  };
  return html`<div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Security policy</th>
          <th>Mode</th>
          <th>Logins</th>
          <th>For clients</th>
        </tr>
      </thead>
      <tbody>${endpoints.map(row)}</tbody>
    </table>
  </div>`;
}

// The trust problem that stops secure client connections, for the card's
// head: both sides must trust each other's certificate.
function trustBadge(g) {
  switch (g?.state) {
    case "target_not_trusted":
      return html`<span class="badge bad" title="The gateway does not trust the target's certificate">
        Target not trusted</span>`;
    case "refused":
      return html`<span class="badge bad" title="The target does not trust the gateway's certificate">
        Refuses the gateway</span>`;
    case "failed":
      return html`<span class="badge warn" title=${g.detail}>Trust not checked</span>`;
    default:
      return "";
  }
}

// Whether the target accepts the gateway's certificate (checked by the
// gateway with a secure channel, before any client needs it).
function gatewayTrust(g) {
  switch (g?.state) {
    case "trusted":
      return html`<div class="alert ok small">
        The target accepts the gateway (checked with ${g.policy}).
      </div>`;
    case "refused":
      return html`<div class="alert bad small">
        <b>The target refuses the gateway.</b> It does not trust this certificate yet, so no client
        can connect securely. Download it below and trust it on the target: add it to the target's
        OPC UA trust list. Many servers keep refused certificates in a${" "}
        <span class="mono">rejected</span> folder; moving it to the${" "}
        <span class="mono">trusted</span> folder does it (e.g.${" "}
        <span class="mono">pki/rejected/certs</span> → <span class="mono">pki/trusted/certs</span>).
        Then press Discover to check again.
      </div>`;
    case "target_not_trusted":
      return html`<div class="alert bad small">
        <b>Secure connections do not work yet.</b> Two steps are needed: (1) the gateway trusts the
        target's certificate (Trust… above), then (2) the target trusts the gateway's certificate
        (below). Whether the target accepts the gateway can only be checked after step 1.
      </div>`;
    case "no_secure_endpoint":
      return html`<div class="muted small">
        The target offers no secure endpoint, so it needs no certificate from the gateway.
      </div>`;
    case "failed":
      return html`<div class="alert warn small">Could not check: ${g.detail}</div>`;
    default:
      return html`<div class="muted small">Checking whether the target accepts the gateway…</div>`;
  }
}

/**
 * Everything about security for one target: endpoints, logins, certificates.
 * Folded away on the target's card; open in the form, where `onMinSecurity`
 * is given and the minimum security is chosen.
 */
function Security({ t, endpoints, onMinSecurity }) {
  const editing = !!onMinSecurity;
  const trusted = new Set((state.certificates?.trusted || []).map((c) => c.thumbprint));
  const cert = endpoints?.find((e) => e.server_certificate)?.server_certificate;
  const own = state.status?.certificate;
  const min = t.min_security || "none";
  const offered = (endpoints || []).filter(
    (e) => (MODE_RANK[e.security_mode] ?? 0) >= MIN_RANK[min],
  ).length;
  const g = t.status?.gateway_trust?.state;

  // The line on the closed fold.
  const endpointCount = endpoints?.length
    ? `${offered} of ${endpoints.length} endpoints offered`
    : "not discovered yet";
  const targetBadge =
    cert &&
    (trusted.has(cert.thumbprint)
      ? html`<span class="badge plain ok">target trusted</span>`
      : html`<span class="badge plain bad">target not trusted</span>`);
  const gatewayBadge =
    g === "trusted"
      ? html`<span class="badge plain ok">accepts the gateway</span>`
      : g === "refused"
        ? html`<span class="badge plain bad">refuses the gateway</span>`
        : g === "target_not_trusted"
          ? html`<span class="badge plain neutral">gateway acceptance not checked yet</span>`
          : "";
  const summary = html`${endpointCount} · ${targetBadge} ${gatewayBadge}`;

  // Endpoints: which ones clients get, from the minimum security up.
  const minimum = editing
    ? html`<div class="inline-input mb">
        <label for="min_security">Minimum security</label>
        <select
          id="min_security"
          name="min_security"
          value=${min}
          onChange=${(e) => onMinSecurity(e.target.value)}
        >
          ${Object.entries(MIN_SECURITY).map(([k, v]) => html`<option value=${k}>${v}</option>`)}
        </select>
      </div>`
    : html`<p class="small">Minimum security: <b>${MIN_SECURITY[min]}</b></p>`;

  // The target's certificate, and a button to trust it.
  const trustServer = safe(async () => {
    const shown = cert;
    const confirmed = await dialog({
      title: "Trust this server certificate?",
      confirm: "Trust",
      body: markup`<p><b>${shown.subject}</b></p>
        <p>Thumbprint <span class="mono">${shown.thumbprint}</span></p>
        <p>Compare the thumbprint with the one shown on the PLC first.</p>`,
    });
    if (!confirmed) return;
    // The thumbprint makes sure the certificate trusted is the one shown.
    const trustedCert = await post(`/targets/${encodeURIComponent(t.name)}/trust-server`, {
      thumbprint: shown.thumbprint,
    });
    toast(`Trusted ${trustedCert.subject}`);
    state.certificates = await get("/certificates");
    renderPage();
  });
  const targetCert = cert
    ? html`${cert.subject}${" "}
        ${
          trusted.has(cert.thumbprint)
            ? html`<span class="badge ok">trusted</span>`
            : html`<span class="badge bad">not trusted</span>${" "}
                ${
                  can("admin") &&
                  !editing &&
                  html`<button type="button" class="small" onClick=${trustServer}>Trust…</button>`
                }`
        }
        <div class="mono muted">${cert.thumbprint}</div>
        ${
          !trusted.has(cert.thumbprint) &&
          html`<div class="muted">
          The gateway only makes encrypted connections to a target it trusts.
        </div>`
        }`
    : html`<span class="muted">Unknown: discover the target first.</span>`;

  const body = html`<div class="security-block">
      <h4>Endpoints</h4>
      <p class="help">
        Clients choose one of the offered endpoints themselves; the gateway offers what the target
        offers, from the minimum security up.
      </p>
      ${minimum} ${endpointsTable(endpoints, min)}
    </div>
    <div class="security-block">
      <h4>Logins</h4>
      <p class="help">
        There is no login to set here: each client logs in itself (anonymous or user name and
        password, as the target allows), and the gateway passes that login on to the target. So the
        target's own user rights apply, per user, and the audit trail shows who it was. Certificate
        logins cannot be passed on and are refused. The <a href="#/browser">Browser</a> asks for a
        login when it connects.
      </p>
    </div>
    <div class="security-block">
      <h4>Certificates</h4>
      <dl class="kv small">
        <dt>Target's certificate</dt>
        <dd>${targetCert}</dd>
        <dt>Gateway's certificate</dt>
        <dd>
          ${own && html`${own.subject}<div class="mono muted">${own.thumbprint}</div>`}
          ${gatewayTrust(t.status?.gateway_trust)}
          <div class="muted">
            The target must trust this one (add it to the target's trust list), and should trust
            only this one, so no client can bypass the gateway. The same certificate for all
            targets: see <a href="#/certificates">Certificates</a>.
          </div>
          <a class="button small mt-xs" href="/api/certificates/own/cert.der">Download</a>
        </dd>
        <dt>Client certificates</dt>
        <dd class="muted">
          Clients connecting securely are accepted on the <a href="#/certificates">Certificates</a> page${state.status?.rejected_certificates ? html` (<b>${state.status.rejected_certificates} waiting</b>)` : ""}.
        </dd>
      </dl>
    </div>`;

  return editing
    ? html`<h3 class="mt">Security</h3>
        ${body}`
    : html`<${Fold} id="${t.name}:security" title="Security" summary=${summary}>${body}<//>`;
}

// ---------- the page ----------

const newTarget = () => ({
  original: null,
  name: "",
  listen: "0.0.0.0:4841",
  endpoint_url: "opc.tcp://",
  discovery_interval_secs: 60,
  min_security: "none",
});

const editTarget = (t) => ({
  original: t.name,
  name: t.name,
  listen: t.listen,
  endpoint_url: t.endpoint_url,
  discovery_interval_secs: t.discovery_interval_secs,
  min_security: t.min_security || "none",
});

export function TargetsPage() {
  // The target being added or edited (`original`: its saved name, null for a
  // new one), with what has been typed; null when none is.
  const [editing, setEditing] = useState(null);
  const s = state.status;

  // The target being edited was deleted or renamed meanwhile (another admin,
  // an AI assistant): drop the edit, or the form would vanish while the Add
  // and Edit buttons stay hidden.
  const gone =
    !!s && editing?.original != null && !s.targets.some((t) => t.name === editing.original);
  useEffect(() => {
    if (!gone) return;
    toast(
      `Target ${editing.original} was changed or deleted meanwhile: the edit is dropped`,
      "warn",
    );
    setEditing(null);
  }, [gone]);

  if (!s) return html`<p class="muted">Loading…</p>`;
  return html`
    <div class="page-head">
      <div class="inline"><${Raw} markup=${menuButton} /><h1>Targets</h1></div>
      ${
        can("admin") &&
        !editing &&
        html`<div class="actions">
        <button class="primary" onClick=${() => setEditing(newTarget())}>Add target</button>
      </div>`
      }
    </div>
    <p class="section-note">
      Each target is an OPC UA server (a PLC) behind the gateway. Clients (HMI, SCADA) connect to
      the gateway instead of the target. The gateway keeps no session of its own on the target: for
      every client, it opens a connection to the target with the gateway's certificate and passes
      that client's requests and login on, recording every change.
    </p>
    ${
      editing?.original === null &&
      html`<${TargetForm} key="new" editing=${editing} setEditing=${setEditing} />`
    }
    ${s.targets.map((t) =>
      editing?.original === t.name
        ? html`<${TargetForm} key=${t.name} editing=${editing} setEditing=${setEditing} current=${t} />`
        : html`<${TargetCard} key=${t.name} t=${t} editing=${editing} setEditing=${setEditing} />`,
    )}`;
}

// A saved target, with its buttons.
function TargetCard({ t, editing, setEditing }) {
  const [checking, setChecking] = useState(false);

  /** "Check now": discovers the target again and checks whether it accepts
   * the gateway, instead of waiting for the next interval. */
  const check = safe(async () => {
    setChecking(true);
    try {
      state.targets.discovery[t.name] = await post(
        `/targets/${encodeURIComponent(t.name)}/discover`,
      );
    } finally {
      setChecking(false);
      // Also after a failure: the card shows why. If the status cannot be
      // read, the periodic refresh tries again; the check's own error is shown.
      state.status = await get("/status").catch(() => state.status);
      renderPage();
    }
    const now = state.status.targets.find((x) => x.name === t.name);
    const trust = now?.status?.gateway_trust?.state;
    if (trust === "refused") toast("The target refuses the gateway's certificate", "bad");
    else if (trust === "target_not_trusted")
      toast("Reachable, but the gateway does not trust the target's certificate yet", "bad");
    else if (trust === "failed")
      toast(`Reachable, but the trust check failed: ${now.status.gateway_trust.detail}`, "warn");
    else if (trust === "trusted") toast("Target reachable and accepts the gateway");
    else toast("Check done");
  });

  const remove = safe(async () => {
    const confirmed = await dialog({
      title: `Delete target ${t.name}?`,
      body: "Its clients are disconnected. The audit trail keeps its records.",
      confirm: "Delete",
      danger: true,
    });
    if (!confirmed) return;
    await del(`/targets/${encodeURIComponent(t.name)}`);
    toast("Target deleted");
    await load();
  });

  return html`<div class="card">
    <div class="card-head">
      <div class="inline">
        <h2>${t.name}</h2>
        <${Raw} markup=${stateBadge(t.status?.state)} />
        ${trustBadge(t.status?.gateway_trust)}
      </div>
      <div class="inline">
        ${
          can("operator") &&
          html`<button
          class="small"
          disabled=${checking}
          onClick=${check}
          title="Check the target, its endpoints and whether it accepts the gateway now"
        >
          Check now
        </button>`
        }
        ${
          can("admin") &&
          !editing &&
          html`<button class="small" onClick=${() => setEditing(editTarget(t))}>Edit</button>${" "}
          <button class="small danger" onClick=${remove}>Delete</button>`
        }
      </div>
    </div>
    <dl class="kv">
      <dt>Clients connect to</dt>
      <dd class="mono">${clientUrl(t.listen)} <span class="muted">(listening on ${t.listen})</span></dd>
      <dt>Target server</dt>
      <dd class="mono">${t.endpoint_url}</dd>
      <dt>Discovery every</dt>
      <dd>${t.discovery_interval_secs} s</dd>
      ${
        t.status?.last_error &&
        html`<dt>Error</dt>
        <dd class="small">${t.status.last_error}</dd>`
      }
    </dl>
    <${Security} t=${t} endpoints=${state.targets.discovery[t.name] || t.status?.endpoints} />
    <${Raw} markup=${summariseSection(t)} />
  </div>`;
}

// Adding a target, or editing one in its own card (`current` is the saved target).
function TargetForm({ editing, setEditing, current = null }) {
  const [saving, setSaving] = useState(false);
  const isNew = editing.original === null;
  const endpoints =
    editing.endpoints ||
    (current && (state.targets.discovery[current.name] || current.status?.endpoints));

  // The field's new value goes into `editing`; the input shows it from there.
  const set = (field) => (event) => {
    const value = event.target.value;
    setEditing((cur) => ({ ...cur, [field]: value }));
  };

  /** Discovers the endpoints of the URL in the form. */
  const discover = safe(async () => {
    const found = await post("/discover", { endpoint_url: editing.endpoint_url });
    setEditing((cur) => ({ ...cur, endpoints: found }));
  });

  /** Adds or saves the target. */
  const save = async (event) => {
    event.preventDefault();
    setSaving(true);
    const body = {
      name: editing.name,
      listen: editing.listen,
      endpoint_url: editing.endpoint_url,
      discovery_interval_secs: Number(editing.discovery_interval_secs) || 60,
      min_security: editing.min_security || "none",
    };
    try {
      if (isNew) await post("/targets", body);
      else await put(`/targets/${encodeURIComponent(editing.original)}`, body);
    } catch (e) {
      setSaving(false);
      return fail(e);
    }
    toast(isNew ? "Target added" : "Target saved");
    setEditing(null);
    await load();
  };

  return html`<form class="card" onSubmit=${save}>
    <div class="card-head">
      <h2>${isNew ? "Add target" : html`Edit ${editing.original}`}</h2>
      <div class="inline">
        <button type="button" class="small" onClick=${() => setEditing(null)}>Cancel</button>
        <button class="primary small" type="submit" disabled=${saving}>
          ${isNew ? "Add" : "Save"}
        </button>
      </div>
    </div>
    <div class="form-grid">
      <div>
        <label>Name</label>
        <input
          name="name"
          value=${editing.name}
          onInput=${set("name")}
          required
          pattern="[A-Za-z0-9._\\-]+"
          title="letters, digits, . _ -"
        />
      </div>
      <div>
        <label>Listen address (for clients)</label>
        <input
          name="listen"
          value=${editing.listen}
          onInput=${set("listen")}
          required
          placeholder="0.0.0.0:4841"
        />
      </div>
      <div>
        <label>Target endpoint URL</label>
        <input
          name="endpoint_url"
          value=${editing.endpoint_url}
          onInput=${set("endpoint_url")}
          required
          placeholder="opc.tcp://192.168.0.10:4840"
        />
      </div>
      <div>
        <label>Discovery every (s)</label>
        <input
          name="discovery_interval_secs"
          type="number"
          min="1"
          value=${editing.discovery_interval_secs}
          onInput=${set("discovery_interval_secs")}
        />
      </div>
      <div><button type="button" onClick=${discover}>Discover endpoints</button></div>
    </div>
    <p class="hint">
      On the PLC itself, use another port than the PLC's own server (e.g. 4841) and let the PLC's
      server accept only the gateway.
    </p>
    <${Security}
      t=${{ ...current, ...editing, name: editing.original || editing.name }}
      endpoints=${endpoints}
      onMinSecurity=${(min) => setEditing((cur) => ({ ...cur, min_security: min }))}
    />
  </form>`;
}
