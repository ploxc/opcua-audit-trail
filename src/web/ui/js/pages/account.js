// Login and password pages: the login screen, the forced password change
// after a password someone else chose, and the Account page.

import { html } from "../html.js";
import { get, post } from "../api.js";
import { formData, gatewayLogo, menuButton, ploxcLink, themeButton, toast } from "../components.js";
import { load, render, state } from "../state.js";

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
    </form>`;
}

export const forms = {
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
