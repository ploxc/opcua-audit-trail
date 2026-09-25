// Users page (admins only): the users with their roles, and adding,
// resetting and deleting users; every user's API tokens, to revoke them.

import { flag, html, when } from "../html.js";
import { del, post, put } from "../api.js";
import { dialog, formData, menuButton, toast } from "../components.js";
import { time } from "../format.js";
import { load, state } from "../state.js";
import { SCOPE_LABELS } from "./settings.js";

export function usersView() {
  // The last admin stays: without one, nobody can manage the gateway.
  const admins = state.users.filter((u) => u.role === "admin").length;
  const row = (u) => {
    const last = u.role === "admin" && admins === 1;
    const why = last ? "The last admin cannot be removed or demoted: add another admin first." : "";
    return html`<tr>
      <td>${u.username}</td>
      <td>
        <select
          name="role-${u.username}"
          data-action="set-role"
          data-user="${u.username}"
          title="${why}"
          ${flag(last, "disabled")}
        >
          ${["auditor", "operator", "admin"].map(
            (r) => html`<option ${flag(u.role === r, "selected")}>${r}</option>`,
          )}
        </select>
      </td>
      <td class="small nowrap">${time(u.created_at)}</td>
      <td class="actions-cell">
        <button class="small" data-action="reset-password" data-user="${u.username}">
          Reset password
        </button>
        <button
          class="small danger"
          data-action="delete-user"
          data-user="${u.username}"
          title="${why}"
          ${flag(last, "disabled")}
        >Delete</button>
      </td>
    </tr>`;
  };
  return html`<div class="page-head">
      <div class="inline">${menuButton}<h1>Users</h1></div>
    </div>
    <div class="card">
      <div class="table-wrap">
        <table class="middle">
          <thead>
            <tr>
              <th>User</th>
              <th>Role</th>
              <th>Created</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            ${state.users.map(row)}
          </tbody>
        </table>
      </div>
      ${when(
        admins === 1,
        html`<p class="hint">
          There must always be an admin, so the last one cannot be deleted or demoted.
        </p>`,
      )}
    </div>
    ${tokensCard()}
    <form class="card" data-form="new-user">
      <h2>Add user</h2>
      <div class="form-grid">
        <div>
          <label>User name</label>
          <input name="username" required>
        </div>
        <div>
          <label>Password (min. 8)</label>
          <input name="password" type="password" minlength="8" required autocomplete="new-password">
        </div>
        <div>
          <label>Role</label>
          <select name="role">
            <option>auditor</option>
            <option>operator</option>
            <option>admin</option>
          </select>
        </div>
        <div><button class="primary" type="submit">Add</button></div>
      </div>
      <p class="hint">
        Auditor: dashboard and audit trail. Operator: also the browser. Admin: also targets,
        certificates and users.
      </p>
    </form>`;
}

// Every user's API tokens for the MCP endpoint: an admin revokes one here,
// e.g. when an account may be compromised.
function tokensCard() {
  const tokens = state.userTokens;
  return html`<div class="card">
    <h2>API tokens</h2>
    ${
      tokens.length
        ? html`<div class="table-wrap">
            <table class="middle">
              <thead>
                <tr>
                  <th>User</th>
                  <th>Token</th>
                  <th>May change</th>
                  <th>Last used</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                ${tokens.map(
                  (t) => html`<tr>
                    <td>${t.username}</td>
                    <td>${t.name} <span class="muted mono">${t.id}</span></td>
                    <td class="small">
                      ${
                        t.scopes.length
                          ? t.scopes.map((x) => SCOPE_LABELS[x]?.[0] || x).join(", ")
                          : html`<span class="muted">read only</span>`
                      }
                    </td>
                    <td class="small nowrap">
                      ${t.last_used ? time(t.last_used) : html`<span class="muted">never</span>`}
                    </td>
                    <td class="actions-cell">
                      <button
                        class="small danger"
                        data-action="revoke-token"
                        data-user="${t.username}"
                        data-id="${t.id}"
                        data-name="${t.name}"
                      >Revoke</button>
                    </td>
                  </tr>`,
                )}
              </tbody>
            </table>
          </div>`
        : html`<p class="empty">No API tokens.</p>`
    }
    <p class="hint">
      Users create their own tokens on their Account page. Resetting a user's password also deletes
      their tokens.
    </p>
  </div>`;
}

export const actions = {
  async "revoke-token"(el) {
    const { user, id, name } = el.dataset;
    const confirmed = await dialog({
      title: `Revoke token "${name}" of ${user}?`,
      body: "Assistants that use it can no longer connect.",
      confirm: "Revoke",
      danger: true,
    });
    if (!confirmed) return;
    await del(`/users/${encodeURIComponent(user)}/tokens/${encodeURIComponent(id)}`);
    toast("Token revoked");
    await load();
  },

  async "set-role"(el) {
    await put(`/users/${encodeURIComponent(el.dataset.user)}`, { role: el.value });
    toast("Role changed");
    await load();
  },

  /** Sets a password the user must replace at the next login. */
  async "reset-password"(el) {
    const input = await dialog({
      title: `New password for ${el.dataset.user}`,
      confirm: "Set password",
      body: html`<div class="field">
          <label for="new-password">Password (min. 8 characters)</label>
          <input
            id="new-password"
            name="password"
            type="password"
            minlength="8"
            required
            autocomplete="new-password"
          >
        </div>
        <p class="muted small">
          The user's sessions and API tokens end; they log in with the new password.
        </p>`,
    });
    if (!input) return;
    await put(`/users/${encodeURIComponent(el.dataset.user)}`, { password: input.password });
    toast("Password reset");
    await load();
  },

  async "delete-user"(el) {
    const confirmed = await dialog({
      title: `Delete user ${el.dataset.user}?`,
      body: "Their sessions end at once. The audit trail keeps their records.",
      confirm: "Delete",
      danger: true,
    });
    if (!confirmed) return;
    await del(`/users/${encodeURIComponent(el.dataset.user)}`);
    await load();
  },
};

export const forms = {
  async "new-user"(form) {
    await post("/users", formData(form));
    form.reset();
    toast("User added");
    await load();
  },
};
