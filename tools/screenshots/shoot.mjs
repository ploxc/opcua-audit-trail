// Makes the README screenshots (docs/screenshots/*-light.png and *-dark.png):
// a fresh gateway in a temporary directory, the demo PLC and two demo clients
// writing through it, then Chrome (headless) on each page in light and dark.
//
//   cd tools/screenshots && npm install && npm run shoot
//
// Needs Rust (it builds the gateway and the examples) and Google Chrome. Uses
// ports 14840 (PLC), 14841 (target) and 18080 (web UI), so a gateway already
// running on the usual ports is not disturbed.

import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { chromium } from "playwright-core";

const ROOT = resolve(import.meta.dirname, "../..");
const OUT = join(ROOT, "docs/screenshots");
const RELEASE = join(ROOT, "target/release");
const WEB = "http://127.0.0.1:18080";
const FIRST_PASSWORD = "screenshot-first-password";
const PASSWORD = "screenshot-password";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const children = [];

function start(cmd, args, options = {}) {
  const child = spawn(cmd, args, { stdio: "ignore", ...options });
  children.push(child);
  return child;
}

function stopAll() {
  for (const c of children) c.kill();
}

/** The web API, with the session cookie of the last login. */
let cookie = "";
async function api(method, path, body) {
  const response = await fetch(WEB + "/api" + path, {
    method,
    headers: {
      "x-requested-with": "opcua-audit-gateway",
      "content-type": "application/json",
      cookie,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const set = response.headers.get("set-cookie");
  if (set) cookie = set.split(";")[0];
  const text = await response.text();
  if (!response.ok) throw new Error(`${method} ${path}: ${response.status} ${text}`);
  return text ? JSON.parse(text) : null;
}

async function waitFor(what, check) {
  for (let i = 0; i < 60; i++) {
    try {
      if (await check()) return;
    } catch {
      // not yet
    }
    await sleep(500);
  }
  throw new Error(`timed out waiting for ${what}`);
}

async function setUp(dir) {
  console.log("building the gateway and the examples…");
  execFileSync(
    "cargo",
    ["build", "--release", "--locked", "--bin", "opcua-audit-gateway",
      "--example", "demo_plc", "--example", "demo_client"],
    { cwd: ROOT, stdio: "inherit" },
  );

  start(join(RELEASE, "examples/demo_plc"), ["127.0.0.1", "14840"], { cwd: dir });

  const config = join(dir, "config.toml");
  execFileSync(join(RELEASE, "opcua-audit-gateway"), ["--config", config, "init"], { cwd: dir });
  const text = readFileSync(config, "utf8").replace(
    'listen = "127.0.0.1:8080"',
    'listen = "127.0.0.1:18080"',
  );
  writeFileSync(
    config,
    text +
      '\n[[targets]]\nname = "line1"\nlisten = "0.0.0.0:14841"\n' +
      'endpoint_url = "opc.tcp://127.0.0.1:14840/"\n',
  );
  start(join(RELEASE, "opcua-audit-gateway"), ["--config", config, "run"], {
    cwd: dir,
    env: { ...process.env, OPCUA_GATEWAY_ADMIN_PASSWORD: FIRST_PASSWORD },
  });
  await waitFor("the web UI", async () => (await fetch(WEB + "/api/health")).ok);

  console.log("setting up the target…");
  await api("POST", "/login", { username: "admin", password: FIRST_PASSWORD });
  await api("POST", "/me/password", { new: PASSWORD });
  // The gateway trusts the demo PLC (which trusts every client).
  const endpoints = await api("POST", "/targets/line1/discover");
  const cert = endpoints.find((e) => e.server_certificate)?.server_certificate;
  await api("POST", "/targets/line1/trust-server", { thumbprint: cert.thumbprint });
  // "Target not trusted" was true until a moment ago: seen, not a problem.
  await sleep(2000);
  await api("POST", "/alarms/acknowledge", { severity: "error" });
  // A group of summarised nodes, and summaries often enough to see one.
  await api("POST", "/targets/line1/summarise", {
    name: "HMI life bits",
    client: null,
    nodes: [{ node_id: "ns=2;s=Line1.Running", name: "Running" }],
  });
  const settings = await api("GET", "/settings");
  await api("PUT", "/settings/audit", {
    retention_days: settings.audit.retention_days,
    // Fail-closed (the default) adds a change_intent record before every
    // write; open keeps the screenshot to the writes themselves.
    fail_mode: "open",
    record_old_value: settings.audit.record_old_value,
    ignored_summary_secs: 15,
  });

  console.log("two clients write for 25 s…");
  const client = join(RELEASE, "examples/demo_client");
  start(client, ["opc.tcp://127.0.0.1:14841/"], { cwd: dir });
  start(client, ["opc.tcp://127.0.0.1:14841/", "operator", "operator"], { cwd: dir });
  await sleep(25_000);
}

async function shoot(browser, scheme) {
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    colorScheme: scheme,
    locale: "en-US",
  });
  const page = await context.newPage();
  await page.goto(WEB + "/");
  await page.fill("input[name=username]", "admin");
  await page.fill("input[name=password]", PASSWORD);
  await page.click("button[type=submit]");
  await page.waitForSelector(".sidebar");

  const snap = async (name) => {
    await sleep(800);
    await page.screenshot({ path: join(OUT, `${name}-${scheme}.png`) });
    console.log(`  ${name}-${scheme}.png`);
  };

  await page.goto(WEB + "/#/audit");
  await page.waitForSelector("table");
  await snap("audit-trail");

  await page.goto(WEB + "/#/dashboard");
  await page.waitForSelector(".card");
  await snap("dashboard");

  await page.goto(WEB + "/#/targets");
  await page.click("[data-action=fold]");
  await snap("targets");

  await page.goto(WEB + "/#/browser");
  await page.click("form[data-form=browser-connect] button[type=submit]");
  const node = (name) => page.locator(".node", { hasText: name }).first();
  // The tree starts with the Objects folder's children.
  await node("Line1").locator("[data-action=toggle-node]").click();
  await node("Setpoint").click();
  await page.click("[data-action=watch]");
  // The watch list shows the value after its first refresh (every second).
  await page
    .locator(".card", { hasText: "Watch list" })
    .locator("td.mono", { hasText: /\d/ })
    .waitFor();
  await snap("browser");

  await context.close();
}

const dir = mkdtempSync(join(tmpdir(), "gateway-screenshots-"));
try {
  await setUp(dir);
  const browser = await chromium.launch({ channel: "chrome" });
  for (const scheme of ["light", "dark"]) await shoot(browser, scheme);
  await browser.close();
  console.log(`done: ${OUT}`);
} finally {
  stopAll();
  rmSync(dir, { recursive: true, force: true });
}
