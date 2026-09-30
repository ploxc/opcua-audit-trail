// Login and password pages: the login screen, the forced password change
// after a password someone else chose, and the Account page.

import { html, safe, submit, useEffect, useState } from "../vdom.js";
import { del, get, post } from "../api.js";
import {
  MenuButton,
  PloxcLink,
  ThemeButton,
  dialog,
  formData,
  gatewayLogo,
  logout,
  toast,
} from "../components.js";
import { time } from "../format.js";
import { can, load, redraw, state } from "../state.js";
import { SCOPE_LABELS, scopeRole } from "./settings.js";

// Puts the cursor in the first field of a login screen when it opens.
const useFocus = (selector) => useEffect(() => document.querySelector(selector)?.focus(), []);

export function LoginPage() {
  const [error, setError] = useState(null);
  useFocus(".login input[name=username]");

  /** Logs in; a wrong password is shown in the form, not as a toast. */
  const login = submit(async (form) => {
    try {
      state.user = await post("/login", formData(form));
    } catch (e) {
      return setError(e.message);
    }
    redraw();
    await load();
  });

  return html`<div class="login">
    <form class="card" onSubmit=${login}>
      <div class="brand">${gatewayLogo()}<div>Audit Gateway<small>OPC UA</small></div></div>
      <div class="field">
        <label for="u">User name</label>
        <input id="u" name="username" autocomplete="username" required />
      </div>
      <div class="field">
        <label for="p">Password</label>
        <input id="p" name="password" type="password" autocomplete="current-password" required />
      </div>
      <div class="alert bad ${error ? "" : "hidden"}">${error}</div>
      <button class="primary" type="submit">Sign in</button>
    </form>
    <div class="login-foot"><${PloxcLink} /><span class="version">${state.version}</span></div>
    <div class="login-theme"><${ThemeButton} /></div>
  </div>`;
}

/** Changes the own password (the forced change and the Account page). */
const changePassword = submit(async (form) => {
  const wasForced = state.user.must_change_password;
  const { repeat, ...body } = formData(form);
  if (body.new !== repeat) throw new Error("The new passwords do not match");
  await post("/me/password", body);
  form.reset();
  toast("Password changed");
  state.user = await get("/me");
  redraw();
  // After the forced change, the gateway opens: show the dashboard.
  if (wasForced) await load();
});

/**
 * A password someone else chose (first start, reset by an admin) is
 * replaced before anything else.
 */
export function MustChangePage() {
  useFocus(".login input[name=new]");
  return html`<div class="login">
    <form class="card" onSubmit=${changePassword}>
      <div class="brand">
        ${gatewayLogo()}
        <div>Choose a new password<small>${state.user.username}</small></div>
      </div>
      <p class="section-note">Your password was set by someone else. Choose your own to continue.</p>
      <div class="field">
        <label for="n">New password (min. 8)</label>
        <input
          id="n"
          name="new"
          type="password"
          minlength="8"
          required
          autocomplete="new-password"
        />
      </div>
      <div class="field">
        <label for="r">Repeat new password</label>
        <input
          id="r"
          name="repeat"
          type="password"
          minlength="8"
          required
          autocomplete="new-password"
        />
      </div>
      <button class="primary" type="submit">Continue</button>
      <p class="mt"><button type="button" class="link small" onClick=${logout}>Log out</button></p>
    </form>
  </div>`;
}

export function AccountPage() {
  return html`<div class="page-head">
      <div class="inline"><${MenuButton} /><h1>Account</h1></div>
    </div>
    <form class="card" onSubmit=${changePassword}>
      <h2>Change password</h2>
      <div class="form-grid">
        <div>
          <label>Current password</label>
          <input name="current" type="password" required autocomplete="current-password" />
        </div>
        <div>
          <label>New password (min. 8)</label>
          <input name="new" type="password" minlength="8" required autocomplete="new-password" />
        </div>
        <div>
          <label>Repeat new password</label>
          <input
            name="repeat"
            type="password"
            minlength="8"
            required
            autocomplete="new-password"
          />
        </div>
        <div><button class="primary" type="submit">Change</button></div>
      </div>
    </form>
    ${tokensCard()}`;
}

/** Where AI assistants connect: this page's address plus /mcp. */
const mcpUrl = () => `${location.origin}/mcp`;

const deleteToken = (t) =>
  safe(async () => {
    const ok = await dialog({
      title: "Delete token",
      body: `Assistants that use "${t.name}" can no longer connect.`,
      confirm: "Delete",
      danger: true,
    });
    if (!ok) return;
    await del(`/me/tokens/${encodeURIComponent(t.id)}`);
    state.account.tokens = await get("/me/tokens");
    toast("Token deleted");
    redraw();
  });

/** Creates an API token and shows its secret once. */
const createToken = submit(async (form) => {
  const scopes = [...form.querySelectorAll("input[name=scopes]:checked")].map((i) => i.value);
  state.account.newToken = await post("/me/tokens", { name: formData(form).name, scopes });
  state.account.tokens = await get("/me/tokens");
  form.reset();
  redraw();
});

// API tokens: an AI assistant (Claude Desktop, Claude Code, …) reads the
// audit trail and the status through /mcp with one of these.
function tokensCard() {
  const { tokens, newToken, mcp } = state.account;
  // Off: existing tokens can still be deleted, new ones are not offered.
  const on = mcp?.enabled && mcp?.transport_ok;
  const scopes = on ? mcp.scopes.filter((scope) => can(scopeRole(scope))) : [];
  return html`<div class="card">
    <h2>API tokens for AI assistants (MCP)</h2>
    ${
      on
        ? html`<p class="section-note">
          An AI assistant can search the audit trail and read the gateway's status at${" "}
          <span class="mono">${mcpUrl()}</span>, with a token that acts as you. A token only reads,
          unless an administrator gives it permission to change something. Everything it does is
          recorded in the trail.
        </p>`
        : mcp?.enabled
          ? html`<p class="section-note">
              The MCP endpoint is on but needs HTTPS: an administrator sets${" "}
              <span class="mono">tls = true</span> under <span class="mono">[web]</span> in the
              config file and restarts the gateway.
            </p>`
          : html`<p class="section-note">
              The MCP endpoint is off: an administrator can turn it on on the${" "}
              <a href="#/settings">Settings</a> page.
            </p>`
    }
    ${on && newToken && newTokenBox(newToken)}
    ${
      tokens.length > 0 &&
      html`<table class="mt">
      <thead>
        <tr>
          <th>Name</th>
          <th>May change</th>
          <th>Created</th>
          <th>Last used</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        ${tokens.map(
          (t) => html`<tr key=${t.id}>
            <td>${t.name} <span class="muted mono">${t.id}</span></td>
            <td>
              ${
                t.scopes.length
                  ? t.scopes.map((x) => SCOPE_LABELS[x]?.[0] || x).join(", ")
                  : html`<span class="muted">nothing (read only)</span>`
              }
            </td>
            <td class="nowrap">${time(t.created_at)}</td>
            <td class="nowrap">
              ${t.last_used ? time(t.last_used) : html`<span class="muted">never</span>`}
            </td>
            <td class="actions-cell">
              <button class="small danger" onClick=${deleteToken(t)}>Delete</button>
            </td>
          </tr>`,
        )}
      </tbody>
    </table>`
    }
    ${
      on &&
      html`<form class="token-form mt" onSubmit=${createToken}>
      <h3>New token</h3>
      <div>
        <label for="token-name">Name</label>
        <input
          id="token-name"
          name="name"
          required
          maxlength="64"
          placeholder="e.g. Claude Desktop on my laptop"
        />
      </div>
      ${
        scopes.length > 0 &&
        html`<fieldset class="choice">
          <legend>May also change (nothing ticked: read only)</legend>
          ${scopes.map(
            (scope) => html`<label>
              <input type="checkbox" name="scopes" value=${scope} />
              <span>${SCOPE_LABELS[scope]?.[0] || scope}</span>
              <span class="small muted">${SCOPE_LABELS[scope]?.[1] || ""}</span>
            </label>`,
          )}
        </fieldset>
        <p class="help small">
          Give a token only what it needs, and delete it when the work is done.
        </p>`
      }
      <div><button class="primary" type="submit">Create token</button></div>
    </form>`
    }
  </div>`;
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast("Copied");
  } catch {
    toast("Copying is not allowed here: select the text and copy it.", "bad");
  }
}

/** The secret of a token just created, with how to use it. Shown once. */
function newTokenBox(t) {
  const command =
    `claude mcp add --transport http opcua-audit ${mcpUrl()} ` +
    `--header "Authorization: Bearer ${t.secret}"`;
  return html`<div class="alert ok">
    <p><b>Copy the token now:</b> it is not shown again.</p>
    <div class="inline mt">
      <code class="mono token-secret">${t.secret}</code>
      <button class="small" onClick=${() => copy(t.secret)}>Copy</button>
    </div>
    <p class="mt small">Claude Code:</p>
    <div class="inline">
      <code class="mono token-secret">${command}</code>
      <button class="small" onClick=${() => copy(command)}>Copy</button>
    </div>
    <p class="mt small">
      Other MCP clients: server URL <span class="mono">${mcpUrl()}</span> (Streamable HTTP),
      header <span class="mono">${"Authorization: Bearer <token>"}</span>.
    </p>
    ${
      location.protocol === "https:" &&
      html`<p class="mt small muted">
      With the web UI's self-signed certificate, the assistant must trust it: download the .pem on
      the <a href="#/certificates">Certificates</a> page (Web UI certificate) and start the assistant with${" "}
      <span class="mono">NODE_EXTRA_CA_CERTS=/path/to/opcua-audit-gateway-web.pem</span>.
    </p>`
    }
  </div>`;
}
