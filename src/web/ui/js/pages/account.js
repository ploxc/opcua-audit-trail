// Login and password pages: the login screen, the forced password change
// after a password someone else chose, and the Account page.

import { html, when } from "../html.js";
import { del, get, post } from "../api.js";
import {
  dialog,
  formData,
  gatewayLogo,
  menuButton,
  ploxcLink,
  themeButton,
  toast,
} from "../components.js";
import { time } from "../format.js";
import { load, render, renderPage, state } from "../state.js";

export function loginView() {
  return html`<div class="login">
    <form class="card" data-form="login">
      <div class="brand">${gatewayLogo()}<div>Audit Gateway<small>OPC UA</small></div></div>
      <div class="field">
        <label for="u">User name</label>
        <input id="u" name="username" autocomplete="username" required>
      </div>
      <div class="field">
        <label for="p">Password</label>
        <input id="p" name="password" type="password" autocomplete="current-password" required>
      </div>
      <div id="login-error" class="alert bad hidden"></div>
      <button class="primary" type="submit">Sign in</button>
    </form>
    <div class="login-foot">${ploxcLink()}<span class="version">${state.version}</span></div>
    <div class="login-theme">${themeButton()}</div>
  </div>`;
}

/**
 * A password someone else chose (first start, reset by an admin) is
 * replaced before anything else.
 */
export function mustChangeView() {
  return html`<div class="login">
    <form class="card" data-form="password">
      <div class="brand">
        ${gatewayLogo()}<div>Choose a new password<small>${state.user.username}</small></div>
      </div>
      <p class="section-note">Your password was set by someone else. Choose your own to continue.</p>
      <div class="field">
        <label for="n">New password (min. 8)</label>
        <input id="n" name="new" type="password" minlength="8" required autocomplete="new-password">
      </div>
      <div class="field">
        <label for="r">Repeat new password</label>
        <input id="r" name="repeat" type="password" minlength="8" required autocomplete="new-password">
      </div>
      <button class="primary" type="submit">Continue</button>
      <p class="mt"><button type="button" class="link small" data-action="logout">Log out</button></p>
    </form>
  </div>`;
}

export function accountView() {
  return html`<div class="page-head">
      <div class="inline">${menuButton}<h1>Account</h1></div>
    </div>
    <form class="card" data-form="password">
      <h2>Change password</h2>
      <div class="form-grid">
        <div>
          <label>Current password</label>
          <input name="current" type="password" required autocomplete="current-password">
        </div>
        <div>
          <label>New password (min. 8)</label>
          <input name="new" type="password" minlength="8" required autocomplete="new-password">
        </div>
        <div>
          <label>Repeat new password</label>
          <input name="repeat" type="password" minlength="8" required autocomplete="new-password">
        </div>
        <div><button class="primary" type="submit">Change</button></div>
      </div>
    </form>
    ${tokensCard()}`;
}

/** Where AI assistants connect: this page's address plus /mcp. */
const mcpUrl = () => `${location.origin}/mcp`;

// API tokens: an AI assistant (Claude Desktop, Claude Code, …) reads the
// audit trail and the status through /mcp with one of these.
function tokensCard() {
  const { tokens, newToken, mcp } = state.account;
  // Off: existing tokens can still be deleted, new ones are not offered.
  const on = mcp?.enabled && mcp?.transport_ok;
  return html`<div class="card">
    <h2>API tokens for AI assistants (MCP)</h2>
    ${
      on
        ? html`<p class="section-note">
            An AI assistant can search the audit trail and read the gateway's status
            at <span class="mono">${mcpUrl()}</span>, with a token that acts as you.
            It can only read, and every question it asks is recorded in the trail.
          </p>`
        : html`<p class="section-note">
            The MCP endpoint is ${mcp?.enabled ? "on but needs HTTPS" : "off"}: an administrator
            can change that on the <a href="#/settings">Settings</a> page.
          </p>`
    }
    ${when(on && newToken, () => newTokenBox(newToken))}
    ${when(
      tokens.length,
      () => html`<table class="mt">
        <thead><tr><th>Name</th><th>Created</th><th>Last used</th><th></th></tr></thead>
        <tbody>
          ${tokens.map(
            (t) => html`<tr>
              <td>${t.name} <span class="muted mono">${t.id}</span></td>
              <td class="nowrap">${time(t.created_at)}</td>
              <td class="nowrap">${t.last_used ? time(t.last_used) : html`<span class="muted">never</span>`}</td>
              <td class="actions-cell">
                <button class="small danger" data-action="delete-token" data-id="${t.id}"
                  data-name="${t.name}">Delete</button>
              </td>
            </tr>`,
          )}
        </tbody>
      </table>`,
    )}
    ${when(
      on,
      () => html`<form data-form="token" class="form-grid mt">
        <div>
          <label>New token</label>
          <input name="name" required maxlength="64" placeholder="e.g. Claude Desktop on my laptop">
        </div>
        <div><button class="primary" type="submit">Create token</button></div>
      </form>`,
    )}
  </div>`;
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
      <button class="small" data-action="copy-text" data-text="${t.secret}">Copy</button>
    </div>
    <p class="mt small">Claude Code:</p>
    <div class="inline">
      <code class="mono token-secret">${command}</code>
      <button class="small" data-action="copy-text" data-text="${command}">Copy</button>
    </div>
    <p class="mt small">
      Other MCP clients: server URL <span class="mono">${mcpUrl()}</span> (Streamable HTTP),
      header <span class="mono">Authorization: Bearer &lt;token&gt;</span>.
    </p>
    ${when(
      location.protocol === "https:",
      html`<p class="mt small muted">
        With the gateway's own certificate, the assistant must trust it: download it on the
        <a href="#/certificates">Certificates</a> page, convert it to PEM
        (<span class="mono">openssl x509 -inform der -in cert.der -out gateway.pem</span>) and
        start the assistant with <span class="mono">NODE_EXTRA_CA_CERTS=gateway.pem</span>.
      </p>`,
    )}
  </div>`;
}

export const actions = {
  async "delete-token"(el) {
    const ok = await dialog({
      title: "Delete token",
      body: `Assistants that use "${el.dataset.name}" can no longer connect.`,
      confirm: "Delete",
      danger: true,
    });
    if (!ok) return;
    await del(`/me/tokens/${encodeURIComponent(el.dataset.id)}`);
    state.account.tokens = await get("/me/tokens");
    toast("Token deleted");
    renderPage();
  },

  async "copy-text"(el) {
    try {
      await navigator.clipboard.writeText(el.dataset.text);
      toast("Copied");
    } catch {
      toast("Copying is not allowed here: select the text and copy it.", "bad");
    }
  },
};

export const forms = {
  /** Creates an API token and shows its secret once. */
  async token(form) {
    state.account.newToken = await post("/me/tokens", formData(form));
    state.account.tokens = await get("/me/tokens");
    form.reset();
    renderPage();
  },

  /** Logs in; a wrong password is shown in the form, not as a toast. */
  async login(form) {
    const err = form.querySelector("#login-error");
    try {
      state.user = await post("/login", formData(form));
      render();
      await load();
    } catch (e) {
      err.textContent = e.message;
      err.classList.remove("hidden");
    }
  },

  /** Changes the own password (the forced change and the Account page). */
  async password(form) {
    const wasForced = state.user.must_change_password;
    const { repeat, ...body } = formData(form);
    if (body.new !== repeat) throw new Error("The new passwords do not match");
    await post("/me/password", body);
    form.reset();
    toast("Password changed");
    state.user = await get("/me");
    // After the forced change, the gateway opens: show the dashboard.
    if (wasForced) {
      render();
      await load();
    }
  },
};
