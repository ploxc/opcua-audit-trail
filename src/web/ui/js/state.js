// The UI's shared state, the role check, and the hooks through which any
// module can redraw or reload the page.
//
// Everything the pages show lives in the one `state` object; views read it,
// actions change it and then redraw. The hooks keep the import graph free of
// cycles: page modules call `render()` or `load()` from here, and main.js,
// which imports the pages, supplies the implementations with `setHooks`.

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
// that are open), `showImport` (certificates), `settings` (settings page).
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
  targets: { editing: null, discovery: {} },
  certificates: null,
  browser: { target: "", ...BROWSER_EMPTY() },
  users: [],
  // API tokens of the logged-in user; `newToken` holds a secret just created
  // (shown once, until the page is left).
  account: { tokens: [], newToken: null },
  version: "",
};

/** Whether the logged-in user has at least `role`. */
export const can = (role) => state.user && ROLE_LEVEL[state.user.role] >= ROLE_LEVEL[role];

// ---------- redraw and reload hooks (implemented in main.js) ----------

const hooks = {};

/** Called once by main.js with its `render`, `renderPage`, `load` and `schedule`. */
export function setHooks(implementations) {
  Object.assign(hooks, implementations);
}

/** Redraws everything: the login screen, or the sidebar and the current page. */
export const render = () => hooks.render();
/** Redraws the current page only, keeping what the user is typing. */
export const renderPage = () => hooks.renderPage();
/** Loads the data of the current page, redraws it and restarts its refresh timer. */
export const load = () => hooks.load();
/** Restarts the periodic refresh for a page. */
export const schedule = (pageId) => hooks.schedule(pageId);
