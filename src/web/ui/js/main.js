// OPC UA Audit Gateway web UI: start-up, routing, drawing, periodic refresh.
// No build step.
//
// The whole UI is one Preact component tree (see vdom.js), drawn from the
// shared `state` (state.js). After a change, `redraw()` diffs the tree into
// the page again: only what changed is touched, so what is typed, the focus
// and scroll positions stay. Every template escapes what it interpolates, so
// server data can never inject markup.

import { h, html, render } from "./vdom.js";
import { get } from "./api.js";
import { AlarmCounts, refreshAlarms } from "./alarms.js";
import {
  THEME_KEY,
  PloxcLink,
  ThemeButton,
  gatewayLogo,
  icon,
  logout,
  toast,
} from "./components.js";
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
    component: dashboard.DashboardPage,
  },
  {
    id: "audit",
    label: "Audit trail",
    role: "auditor",
    icon: "audit",
    component: audit.AuditPage,
  },
  {
    id: "targets",
    label: "Targets",
    role: "auditor",
    icon: "targets",
    component: targets.TargetsPage,
  },
  {
    id: "certificates",
    label: "Certificates",
    role: "auditor",
    icon: "certificates",
    component: certificates.CertificatesPage,
  },
  {
    id: "browser",
    label: "Browser",
    role: "operator",
    icon: "browser",
    component: browser.BrowserPage,
  },
  { id: "users", label: "Users", role: "admin", icon: "users", component: users.UsersPage },
  {
    id: "settings",
    label: "Settings",
    role: "auditor",
    icon: "settings",
    component: settings.SettingsPage,
  },
  {
    id: "account",
    label: "Account",
    role: "auditor",
    icon: "account",
    hidden: true,
    component: account.AccountPage,
  },
];

/** The page in the URL (#/audit), or the dashboard when unknown or not allowed. */
const currentPage = () => {
  const id = location.hash.replace(/^#\/?/, "").split("?")[0] || "dashboard";
  const page = PAGES.find((p) => p.id === id);
  return page && can(page.role) ? page : PAGES[0];
};

// ---------- drawing ----------

const app = document.getElementById("app");

/** Draws the UI from `state`: the login or password screen, or the sidebar and the page. */
function App() {
  if (state.user === undefined) return html`<div class="boot">Loading…</div>`;
  if (!state.user) return html`<${account.LoginPage} />`;
  if (state.user.must_change_password) return html`<${account.MustChangePage} />`;
  const page = currentPage();
  // The key starts a page afresh when it is opened: what it edited is gone.
  return html`<div class="shell ${state.navOpen ? "nav-open" : ""}">
    <${Sidebar} page=${page} />
    <main class="main" id="page"><${page.component} key=${page.id} /></main>
  </div>`;
}

const redraw = () => render(h(App), app);

// The start-up screen of index.html is replaced, not reused by the diff.
app.textContent = "";
redraw();

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
  if (!list.length) return null;
  const title = `Needs attention: ${list.map((t) => t.name).join(", ")}`;
  return html`<span
    class="nav-dot ${down.length ? "bad" : "warn"}"
    title=${title}
    aria-label=${title}
  ></span>`;
}

// The sidebar: brand, navigation with counts, the user and their buttons.
function Sidebar({ page }) {
  const rejected = state.status?.rejected_certificates || 0;
  const link = (p) => html`<a href="#/${p.id}" class=${p.id === page.id ? "active" : ""}>
    ${icon(p.icon)}${p.label}
    ${
      p.id === "certificates" &&
      rejected > 0 &&
      html`<span class="count" title="Certificates waiting for a decision">${rejected}</span>`
    }
    ${p.id === "audit" && html`<${AlarmCounts} />`}
    ${p.id === "targets" && html`<span class="targets-dot">${targetsDot()}</span>`}
  </a>`;
  return html`<aside class="sidebar">
    <div class="brand">${gatewayLogo()}<div>Audit Gateway<small>OPC UA</small></div></div>
    <nav class="nav">${PAGES.filter((p) => !p.hidden && can(p.role)).map(link)}</nav>
    <div class="sidebar-foot">
      <div class="user-row">
        <div class="who">${state.user.username}<small>${state.user.role}</small></div>
        <div class="tools">
          <a href="#/account" class="button icon-button" title="Account" aria-label="Account">
            ${icon("account")}
          </a>
          <${ThemeButton} />
          <button class="icon-button" onClick=${logout} title="Log out" aria-label="Log out">
            ${icon("logout")}
          </button>
        </div>
      </div>
      <div class="made-by"><${PloxcLink} /><span class="version">${state.version}</span></div>
    </div>
  </aside>`;
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
  redraw();
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
        state.settings = await get("/settings");
        state.status = await get("/status");
        break;
      case "browser":
        state.status ||= await get("/status");
        break;
      case "users":
        state.users = await get("/users");
        state.userTokens = await get("/tokens");
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
  redraw();
  schedule(page.id);
}

let refreshTimer = null;

/** (Re)starts the periodic refresh of a page; one timer at a time. */
function schedule(pageId) {
  clearInterval(refreshTimer);
  refreshTimer = null;
  // Calls `fn` every `ms` and redraws, unless it returns false.
  const every = (ms, fn) => {
    refreshTimer = setInterval(async () => {
      if (!state.user) return;
      try {
        if ((await fn()) !== false) redraw();
      } catch (e) {
        fail(e);
      }
    }, ms);
  };
  if (pageId === "dashboard") every(5000, dashboard.refreshDashboard);
  // Target status (a new target starts as "Checking…").
  if (pageId === "targets") {
    every(5000, async () => {
      state.status = await get("/status");
    });
  }
  if (pageId === "audit" && state.audit.live) every(3000, () => audit.loadAudit());
  if (pageId === "browser" && state.browser.connection && state.browser.watch.length) {
    every(1000, browser.pollWatch);
  }
}

setHooks({ redraw, load, schedule, fail });

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
  reloadIfUpgraded();
  redraw();
}, 10000);

// This page's UI version: the hash in the URL main.js was loaded from
// (/js/<hash>/main.js). After an upgrade the gateway reports another one;
// the page then reloads itself, but not while something is being typed or
// a dialog is open (it tries again at the next check).
const OWN_UI_VERSION = new URL(import.meta.url).pathname.split("/")[2];

function reloadIfUpgraded() {
  const current = state.status?.ui_version;
  if (!current || !OWN_UI_VERSION || OWN_UI_VERSION === "main.js") return;
  if (current === OWN_UI_VERSION) return;
  const active = document.activeElement;
  const typing =
    active?.matches?.("input, textarea, select") &&
    active.value !== "" &&
    active.type !== "checkbox";
  if (typing || document.querySelector("dialog[open], .dialog-backdrop")) return;
  location.reload();
}

window.addEventListener("hashchange", () => {
  state.navOpen = false;
  redraw();
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
  redraw();
  if (state.user) await load();
})();
