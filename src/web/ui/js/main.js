// OPC UA Audit Gateway web UI: start-up, routing, rendering, periodic
// refresh and event handling. No build step, no dependencies.
//
// Rendering uses the `html` template tag (html.js): every interpolated value
// is escaped unless it is itself `html` output, so server data can never
// inject markup. Events are handled by delegation on `data-action` and
// `data-form` attributes (the Content-Security-Policy forbids inline
// handlers): each page module exports its `actions` and `forms`, merged below.

import { html, when } from "./html.js";
import { get, post } from "./api.js";
import { alarmCounts, refreshAlarms } from "./alarms.js";
import { THEME_KEY, gatewayLogo, icon, ploxcLink, themeButton, toast } from "./components.js";
import * as ignore from "./ignore.js";
import { BROWSER_EMPTY, can, setHooks, state } from "./state.js";
import * as account from "./pages/account.js";
import * as audit from "./pages/audit.js";
import * as browser from "./pages/browser.js";
import * as certificates from "./pages/certificates.js";
import * as dashboard from "./pages/dashboard.js";
import * as settings from "./pages/settings.js";
import * as targets from "./pages/targets.js";
import * as users from "./pages/users.js";

// ---------- routing ----------

// The pages in the sidebar, in order, with the least role that sees them.
const PAGES = [
  {
    id: "dashboard",
    label: "Dashboard",
    role: "auditor",
    icon: "dashboard",
    view: dashboard.dashboardView,
  },
  { id: "audit", label: "Audit trail", role: "auditor", icon: "audit", view: audit.auditView },
  { id: "targets", label: "Targets", role: "auditor", icon: "targets", view: targets.targetsView },
  {
    id: "certificates",
    label: "Certificates",
    role: "auditor",
    icon: "certificates",
    view: certificates.certificatesView,
  },
  { id: "browser", label: "Browser", role: "operator", icon: "browser", view: browser.browserView },
  { id: "users", label: "Users", role: "admin", icon: "users", view: users.usersView },
  {
    id: "settings",
    label: "Settings",
    role: "auditor",
    icon: "settings",
    view: settings.settingsView,
  },
  {
    id: "account",
    label: "Account",
    role: "auditor",
    icon: "account",
    hidden: true,
    view: account.accountView,
  },
];

/** The page in the URL (#/audit), or the dashboard when unknown or not allowed. */
const currentPage = () => {
  const id = location.hash.replace(/^#\/?/, "").split("?")[0] || "dashboard";
  const page = PAGES.find((p) => p.id === id);
  return page && can(page.role) ? page : PAGES[0];
};

// ---------- rendering ----------

const app = document.getElementById("app");
let refreshTimer = null;

/** Draws everything: the login or password screen, or the sidebar and the current page. */
function render() {
  if (state.user === undefined) return;
  if (!state.user) {
    app.innerHTML = account.loginView().s;
    app.querySelector("input[name=username]")?.focus();
    return;
  }
  if (state.user.must_change_password) {
    app.innerHTML = account.mustChangeView().s;
    app.querySelector("input[name=new]")?.focus();
    return;
  }
  const page = currentPage();
  app.innerHTML = html`<div class="shell">
    ${sidebar(page)}
    <main class="main" id="page">${page.view()}</main>
  </div>`.s;
}

// A dot next to "Targets" when a target is down or refuses the gateway
// (red), or does not accept it for another reason (amber).
function targetsDot() {
  const targets = state.status?.targets || [];
  const down = targets.filter(
    (t) =>
      t.status?.state === "unavailable" ||
      ["refused", "target_not_trusted"].includes(t.status?.gateway_trust?.state),
  );
  const other = targets.filter(
    (t) => !down.includes(t) && t.status?.gateway_trust?.state === "failed",
  );
  const list = down.length ? down : other;
  if (!list.length) return "";
  const title = `Needs attention: ${list.map((t) => t.name).join(", ")}`;
  return html`<span class="nav-dot ${down.length ? "bad" : "warn"}" title="${title}"
    aria-label="${title}"></span>`;
}

// The sidebar is not redrawn with the page: update the dot in place.
function updateTargetsDot() {
  const el = document.querySelector(".targets-dot");
  if (el) el.innerHTML = html`${targetsDot()}`.s;
}

// The sidebar: brand, navigation with counts, the user and their buttons.
function sidebar(page) {
  const rejected = state.status?.rejected_certificates || 0;
  const link = (p) => html`<a href="#/${p.id}" class="${p.id === page.id ? "active" : ""}">
    ${icon(p.icon)}${p.label}
    ${when(
      p.id === "certificates" && rejected,
      html`<span class="count" title="Certificates waiting for a decision">${rejected}</span>`,
    )}
    ${when(p.id === "audit", () => html`<span class="alarm-counts">${alarmCounts()}</span>`)}
    ${when(p.id === "targets", () => html`<span class="targets-dot">${targetsDot()}</span>`)}
  </a>`;
  return html`<aside class="sidebar">
    <div class="brand">${gatewayLogo()}<div>Audit Gateway<small>OPC UA</small></div></div>
    <nav class="nav">
      ${PAGES.filter((p) => !p.hidden && can(p.role)).map(link)}
    </nav>
    <div class="sidebar-foot">
      <div class="user-row">
        <div class="who">${state.user.username}<small>${state.user.role}</small></div>
        <div class="tools">
          <a href="#/account" class="button icon-button" title="Account" aria-label="Account">
            ${icon("account")}
          </a>
          ${themeButton()}
          <button class="icon-button" data-action="logout" title="Log out" aria-label="Log out">
            ${icon("logout")}
          </button>
        </div>
      </div>
      <div class="made-by">${ploxcLink()}<span class="version">${state.version}</span></div>
    </div>
  </aside>`;
}

/**
 * Redraws the current page only. A periodic refresh must not wipe what the
 * user is typing: the values of the form that has focus, the focus itself and
 * the scroll positions inside the page (e.g. the browser tree) are kept.
 */
function renderPage() {
  const el = document.getElementById("page");
  if (!el) return render();
  updateTargetsDot();

  // Remember the form being typed in, and scroll positions.
  const active = document.activeElement;
  const typing =
    active &&
    el.contains(active) &&
    /^(INPUT|SELECT|TEXTAREA)$/.test(active.tagName) &&
    active.type !== "file";
  const form = typing ? active.closest("form[data-form]") : null;
  const kept = form
    ? [...form.elements]
        .filter((e) => e.name && e.type !== "file")
        .map((e) => [e.name, e.type === "checkbox" ? e.checked : e.value])
    : [];
  const focusName = typing ? active.name : null;
  const scrolls = [...el.querySelectorAll("[data-keep-scroll]")].map((e) => [
    e.dataset.keepScroll,
    e.scrollTop,
    e.scrollLeft,
  ]);

  el.innerHTML = currentPage().view().s;

  // Put them back.
  for (const [key, top, left] of scrolls) {
    const again = el.querySelector(`[data-keep-scroll="${key}"]`);
    if (again) {
      again.scrollTop = top;
      again.scrollLeft = left;
    }
  }
  if (form) {
    const again = el.querySelector(`form[data-form="${form.dataset.form}"]`);
    for (const [name, value] of kept) {
      const input = again?.elements.namedItem(name);
      if (!input || input instanceof RadioNodeList) continue;
      if (input.type === "checkbox") input.checked = value;
      else input.value = value;
    }
    again?.elements.namedItem(focusName)?.focus?.();
  }
}

// ---------- errors ----------

/** Shows a failed action or refresh as a toast (a 401 already shows the login). */
const fail = (e) => {
  // 409 from the browser API: its session on the target is gone.
  if (e.status === 409 && state.browser.connection) return browserLost();
  if (e.status !== 401) toast(e.message, "bad");
};

// The browser session ended (idle timeout, gateway restart, target down):
// back to the connect form, with one message instead of one per refresh.
function browserLost() {
  Object.assign(state.browser, BROWSER_EMPTY());
  toast("The browser session on the target has ended. Connect again to continue.", "bad");
  renderPage();
  schedule(currentPage().id);
}

// ---------- data loading and refresh ----------

/** Loads what the current page shows, draws it and starts its refresh. */
async function load() {
  // Nothing loads until a forced password change is done.
  if (!state.user || state.user.must_change_password) return;
  refreshAlarms();
  const page = currentPage();
  try {
    switch (page.id) {
      case "dashboard":
        await dashboard.refreshDashboard();
        break;
      case "audit":
        state.status ||= await get("/status");
        await audit.loadAudit();
        break;
      case "targets":
        state.status = await get("/status");
        state.certificates = await get("/certificates");
        break;
      case "certificates":
        state.certificates = await get("/certificates");
        state.status = await get("/status");
        break;
      case "browser":
        state.status ||= await get("/status");
        break;
      case "users":
        state.users = await get("/users");
        break;
      case "account":
        // A new token's secret is shown once: not again after navigating.
        state.account.newToken = null;
        state.account.tokens = await get("/me/tokens");
        state.account.mcp = (await get("/settings")).mcp;
        break;
      case "settings":
        state.settings = await get("/settings");
        state.status = await get("/status");
        break;
    }
  } catch (e) {
    fail(e);
  }
  renderPage();
  schedule(page.id);
}

/** (Re)starts the periodic refresh of a page; one timer at a time. */
function schedule(pageId) {
  clearInterval(refreshTimer);
  refreshTimer = null;
  // Calls `fn` every `ms` and redraws, unless it returns false.
  const every = (ms, fn) => {
    refreshTimer = setInterval(async () => {
      if (!state.user) return;
      try {
        if ((await fn()) !== false) renderPage();
      } catch (e) {
        fail(e);
      }
    }, ms);
  };
  if (pageId === "dashboard") every(5000, dashboard.refreshDashboard);
  // Target status (a new target starts as "Checking…"), but not while a
  // target is being edited: that would redraw the form.
  if (pageId === "targets") {
    every(5000, async () => {
      if (state.targets.editing) return false;
      state.status = await get("/status");
    });
  }
  if (pageId === "audit" && state.audit.live) every(3000, () => audit.loadAudit());
  if (pageId === "browser" && state.browser.connection && state.browser.watch.length) {
    every(1000, browser.pollWatch);
  }
}

setHooks({ render, renderPage, load, schedule });

// The sidebar's warning and error counts and the targets dot stay current
// on every page.
setInterval(async () => {
  refreshAlarms();
  if (!state.user || state.user.must_change_password) return;
  try {
    state.status = await get("/status");
  } catch {
    return;
  }
  updateTargetsDot();
}, 10000);

// ---------- actions and forms ----------

// Actions that belong to no page: the header buttons and the folds.
const shellActions = {
  async logout() {
    await post("/logout");
    // Start from a clean page: nothing of this user's session stays behind.
    location.hash = "";
    location.reload();
  },
  theme() {
    // Like ploxc.com: follow the system until the user picks a mode.
    const root = document.documentElement;
    const dark = root.dataset.theme
      ? root.dataset.theme === "dark"
      : matchMedia("(prefers-color-scheme: dark)").matches;
    root.dataset.theme = dark ? "light" : "dark";
    try {
      localStorage.setItem(THEME_KEY, root.dataset.theme);
    } catch {}
  },
  menu() {
    document.querySelector(".shell")?.classList.toggle("nav-open");
  },
  // Opens or closes a foldable section (components.js `fold`).
  fold(el) {
    state.open ||= new Set();
    const key = el.dataset.key;
    if (state.open.has(key)) state.open.delete(key);
    else state.open.add(key);
    renderPage();
  },
};

// `data-action` name → handler(element, event).
const actions = {
  ...shellActions,
  ...ignore.actions,
  ...audit.actions,
  ...targets.actions,
  ...certificates.actions,
  ...browser.actions,
  ...users.actions,
  ...account.actions,
  ...settings.actions,
};

// `data-form` name → handler(form).
const forms = {
  ...account.forms,
  ...audit.forms,
  ...targets.forms,
  ...certificates.forms,
  ...browser.forms,
  ...users.forms,
  ...settings.forms,
};

// ---------- event delegation ----------

// Clicks on buttons and links with a `data-action`. Selects and checkboxes
// act on "change" instead (below).
document.addEventListener("click", async (event) => {
  const el = event.target.closest("[data-action]");
  if (!el || el.tagName === "SELECT" || (el.tagName === "INPUT" && el.type === "checkbox")) return;
  const action = actions[el.dataset.action];
  if (!action) return;
  event.preventDefault();
  try {
    await action(el, event);
  } catch (e) {
    fail(e);
  }
});

document.addEventListener("change", async (event) => {
  const el = event.target.closest("select[data-action], input[type=checkbox][data-action]");
  if (!el) return;
  try {
    await actions[el.dataset.action]?.(el, event);
  } catch (e) {
    fail(e);
  }
});

// Form submits: the submit button is disabled while the request runs.
document.addEventListener("submit", async (event) => {
  const form = event.target.closest("form[data-form]");
  if (!form) return;
  event.preventDefault();
  const button = form.querySelector("button[type=submit]");
  if (button) button.disabled = true;
  try {
    await forms[form.dataset.form](form);
  } catch (e) {
    fail(e);
  } finally {
    if (button) button.disabled = false;
  }
});

window.addEventListener("hashchange", () => {
  document.querySelector(".shell")?.classList.remove("nav-open");
  render();
  load();
});

// ---------- start ----------

// The light or dark mode the user picked earlier, if any.
try {
  const theme = localStorage.getItem(THEME_KEY);
  if (theme === "light" || theme === "dark") document.documentElement.dataset.theme = theme;
} catch {}

(async () => {
  try {
    state.version = (await get("/health")).version;
  } catch {}
  try {
    state.user = await get("/me");
  } catch {
    state.user = null;
  }
  render();
  if (state.user) await load();
})();
