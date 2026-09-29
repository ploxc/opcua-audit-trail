// The UI's shared state, the role check, and the hooks through which any
// module can redraw or reload the page.
//
// What the gateway sent lives in the one `state` object: components read it
// when they are drawn, handlers change it and then redraw. What only one
// component needs while it is shown (a form being edited) is its own
// `useState`. The hooks keep the import graph free of cycles: page modules
// call `redraw()` or `load()` from here, and main.js, which imports the
// pages, supplies the implementations with `setHooks`.

const ROLE_LEVEL = { auditor: 0, operator: 1, admin: 2 };

/** A browser page without a session on a target (the target choice stays). */
export const BROWSER_EMPTY = () => ({
  connection: null,
  tree: {},
  expanded: new Set(),
  selected: null,
  attributes: [],
  watch: [],
  values: {},
  watchError: null,
});

// Also set later, by the page that needs them: `dashboardChanges` and
// `changesToday` (dashboard), `alarms` (sidebar counts), `open` (the folds
// that are open), `navOpen` (the sidebar on a narrow screen), `settings`
// (settings page).
export const state = {
  // undefined: not known yet (starting up); null: not logged in.
  user: undefined,
  status: null,
  audit: {
    rows: [],
    filters: {},
    selected: null,
    // `cursor`: the page shown starts before this record (null: the newest);
    // `back`: the cursors of the newer pages, to go back to.
    cursor: null,
    back: [],
    olderAvailable: false,
    live: false,
  },
  targets: { discovery: {} },
  certificates: null,
  browser: { target: "", ...BROWSER_EMPTY() },
  users: [],
  // Every user's API tokens (Users page, admins).
  userTokens: [],
  // API tokens of the logged-in user; `newToken` holds a secret just created
  // (shown once, until the page is left).
  account: { tokens: [], newToken: null },
  version: "",
};

/** Whether the logged-in user has at least `role`. */
export const can = (role) => state.user && ROLE_LEVEL[state.user.role] >= ROLE_LEVEL[role];

// ---------- redraw and reload hooks (implemented in main.js) ----------

const hooks = {};

/** Called once by main.js with its `redraw`, `load`, `schedule` and `fail`. */
export function setHooks(implementations) {
  Object.assign(hooks, implementations);
}

/** Draws the UI again from `state` (a diff: what is typed stays). */
export const redraw = () => hooks.redraw();
/** Loads the data of the current page, redraws it and restarts its refresh timer. */
export const load = () => hooks.load();
/** Restarts the periodic refresh for a page. */
export const schedule = (pageId) => hooks.schedule(pageId);
/** Shows a failed request (a toast; a 401 already shows the login). */
export const fail = (error) => hooks.fail(error);
