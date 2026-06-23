#!/usr/bin/env node
/*
 * playwright-login.js — headed stealth Chromium login + session capture.
 *
 * Backs agent/skills/browser-automation/SKILL.md and
 * agent/references/web/browser-automation-playwright.md.
 *
 * Headed + stealth-hardened Chromium beats headless and beats curl for
 * bot-defended (Akamai/Cloudflare) login flows. Two capture modes:
 *   Mode A (through-proxy): set PROXY=http://127.0.0.1:8080 (vigil mitmproxy)
 *           — proxy addon auto-captures the session into the engagement.
 *   Mode B (direct + cookie-dump): leave PROXY unset — go direct on the
 *           residential IP and dump context.cookies() to a Netscape jar.
 *           Use this the moment the proxied browser hits a bot-manager
 *           "system unavailable" block that the direct browser does not.
 *
 * No hardcoded secrets — everything comes from env:
 *   TARGET_URL  (required)  login page URL
 *   USERNAME    (required)
 *   PASSWORD    (required)
 *   PROXY       (optional)  e.g. http://127.0.0.1:8080 -> Mode A
 *   OTP         (optional)  one-time code if a step-up field appears
 *   JAR         (optional)  Netscape cookie-jar output path (default ./cookies.txt)
 *   SHOTS_DIR   (optional)  screenshot dir (default ./login-shots)
 *   UA          (optional)  override user-agent
 *   LOCALE      (optional)  default en-US
 *   TZ_ID       (optional)  default America/Chicago
 *   SUCCESS_SEL (optional)  selector that proves authenticated state
 *   HEADLESS    (optional)  set to 1 to force headless (NOT recommended)
 *
 * Install once:  npm i playwright && npx playwright install chromium
 * Run:           node playwright-login.js
 */
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const env = process.env;
const TARGET_URL = req('TARGET_URL');
const USERNAME = req('USERNAME');
const PASSWORD = req('PASSWORD');
const PROXY = env.PROXY || null;
const OTP = env.OTP || null;
const JAR = env.JAR || 'cookies.txt';
const SHOTS_DIR = env.SHOTS_DIR || 'login-shots';
const LOCALE = env.LOCALE || 'en-US';
const TZ_ID = env.TZ_ID || 'America/Chicago';
const HEADLESS = env.HEADLESS === '1';
const SUCCESS_SEL = env.SUCCESS_SEL || null;
// Program-mandated attribution headers (e.g. {"X-Bug-Bounty":"<handle>"}) for
// engagements created with `--program`/`--header`. Attached to EVERY browser
// request so navigations + form posts match what the Kali CLI probes send and
// the program's traffic rules are honoured. Export REQUIRED_HEADERS as a JSON
// object; e.g. REQUIRED_HEADERS="$(jq -c .required_headers <eng>/scope.json)".
const REQUIRED_HEADERS = (() => {
  const raw = env.REQUIRED_HEADERS;
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch {
    console.error('[warn] REQUIRED_HEADERS is not valid JSON; ignoring');
    return null;
  }
})();
const UA = env.UA ||
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ' +
  '(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';

// Multi-selector candidates — first visible+editable wins.
const USER_SELECTORS = [
  'input[name="username"]', 'input[name="userId"]', 'input[name="email"]',
  'input[type="email"]', '#username', '#userId', '#email',
  'input[autocomplete="username"]', 'input[aria-label*="ser" i]',
];
const PASS_SELECTORS = [
  'input[name="password"]', 'input[type="password"]', '#password',
  'input[autocomplete="current-password"]', 'input[aria-label*="assword" i]',
];
const SUBMIT_SELECTORS = [
  'button[type="submit"]', 'input[type="submit"]', 'button[name="submit"]',
  'button:has-text("Log on")', 'button:has-text("Log in")',
  'button:has-text("Sign in")', 'button:has-text("Continue")',
  'button:has-text("Next")',
];
const OTP_SELECTORS = [
  'input[name*="otp" i]', 'input[name*="code" i]', 'input[name*="token" i]',
  'input[autocomplete="one-time-code"]', 'input[inputmode="numeric"]',
];
// Bot-manager / unavailable-system block fingerprints.
const BLOCK_TEXTS = [
  'unable to complete your request', 'system is currently unavailable',
  'system currently unavailable', 'access denied', 'reference #',
];

function req(name) {
  const v = process.env[name];
  if (!v) { console.error(`FATAL: env ${name} is required`); process.exit(2); }
  return v;
}

function stamp() { return new Date().toISOString().replace(/[:.]/g, '-'); }

async function shot(page, label) {
  try {
    fs.mkdirSync(SHOTS_DIR, { recursive: true });
    const p = path.join(SHOTS_DIR, `${stamp()}_${label}.png`);
    await page.screenshot({ path: p, fullPage: true });
    console.error(`[shot] ${label} -> ${p}`);
  } catch (e) { console.error(`[shot] ${label} failed: ${e.message}`); }
}

async function firstVisible(page, selectors, timeout = 15000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    for (const sel of selectors) {
      const loc = page.locator(sel).first();
      try {
        if (await loc.isVisible() && await loc.isEditable())
          return loc;
      } catch (_) { /* selector not present yet */ }
    }
    await page.waitForTimeout(300);
  }
  return null;
}

async function clickFirst(page, selectors) {
  for (const sel of selectors) {
    const loc = page.locator(sel).first();
    try {
      if (await loc.isVisible()) { await loc.click(); return true; }
    } catch (_) { /* try next */ }
  }
  // Fall back to Enter on the active element.
  await page.keyboard.press('Enter');
  return false;
}

async function pageBlocked(page) {
  let txt = '';
  try { txt = (await page.locator('body').innerText({ timeout: 3000 })).toLowerCase(); }
  catch (_) { return false; }
  return BLOCK_TEXTS.some(t => txt.includes(t));
}

// Stealth: applied before any page script runs.
const STEALTH = () => {
  Object.defineProperty(navigator, 'webdriver', { get: () => false });
  Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
  Object.defineProperty(navigator, 'plugins', {
    get: () => [1, 2, 3, 4, 5].map(i => ({ name: `Plugin ${i}` })),
  });
  Object.defineProperty(navigator, 'mimeTypes', { get: () => [1, 2].map(i => ({ type: `t${i}` })) });
  window.chrome = window.chrome || { runtime: {} };
  const origQuery = window.navigator.permissions && window.navigator.permissions.query;
  if (origQuery) {
    window.navigator.permissions.query = (p) =>
      p && p.name === 'notifications'
        ? Promise.resolve({ state: Notification.permission })
        : origQuery(p);
  }
  // WebGL vendor/renderer spoof.
  try {
    const gp = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function (p) {
      if (p === 37445) return 'Intel Inc.';           // UNMASKED_VENDOR_WEBGL
      if (p === 37446) return 'Intel Iris OpenGL Engine'; // UNMASKED_RENDERER_WEBGL
      return gp.call(this, p);
    };
  } catch (_) { /* no webgl */ }
};

function writeJar(cookies, jarPath) {
  const lines = ['# Netscape HTTP Cookie File'];
  for (const c of cookies) {
    const domain = c.domain.startsWith('.') ? c.domain : '.' + c.domain;
    const flag = 'TRUE';
    const cpath = c.path || '/';
    const secure = c.secure ? 'TRUE' : 'FALSE';
    const expiry = Math.floor(
      c.expires && c.expires > 0 ? c.expires : Date.now() / 1000 + 3600);
    lines.push([domain, flag, cpath, secure, expiry, c.name, c.value].join('\t'));
  }
  fs.mkdirSync(path.dirname(path.resolve(jarPath)), { recursive: true });
  fs.writeFileSync(jarPath, lines.join('\n') + '\n');
  console.error(`[jar] wrote ${cookies.length} cookies -> ${jarPath}`);
}

(async () => {
  const launchArgs = ['--disable-blink-features=AutomationControlled', '--no-first-run'];
  const launchOpts = { headless: HEADLESS, args: launchArgs };
  if (PROXY) { launchOpts.proxy = { server: PROXY }; console.error(`[mode] A (through-proxy) ${PROXY}`); }
  else { console.error('[mode] B (direct + cookie-dump)'); }

  const browser = await chromium.launch(launchOpts);
  const context = await browser.newContext({
    userAgent: UA,
    locale: LOCALE,
    timezoneId: TZ_ID,
    viewport: { width: 1280, height: 800 },
    deviceScaleFactor: 1,
    hasTouch: false,
    ignoreHTTPSErrors: !!PROXY, // Mode A: trust the mitmproxy CA the easy way
    // Program attribution headers ride on every request in both modes (direct
    // and through-proxy) — the proxy addon only observes traffic, it does not
    // inject these.
    ...(REQUIRED_HEADERS ? { extraHTTPHeaders: REQUIRED_HEADERS } : {}),
  });
  if (REQUIRED_HEADERS) {
    console.error(`[headers] attaching ${Object.keys(REQUIRED_HEADERS).join(', ')} to all requests`);
  }
  await context.addInitScript(STEALTH);
  const page = await context.newPage();

  let ok = false;
  try {
    await page.goto(TARGET_URL, { waitUntil: 'domcontentloaded', timeout: 45000 });
    await shot(page, '00_landing');
    if (await pageBlocked(page)) throw new Error('BOT-MANAGER BLOCK at landing — switch to Mode B / residential IP');

    // --- username ---
    const userField = await firstVisible(page, USER_SELECTORS);
    if (!userField) throw new Error('username field not found (selectors exhausted)');
    await userField.fill(USERNAME);
    await shot(page, '01_username_filled');
    await clickFirst(page, SUBMIT_SELECTORS);
    await page.waitForLoadState('domcontentloaded').catch(() => {});
    await page.waitForTimeout(1500); // let two-step IdP render the password view
    await shot(page, '02_after_username_submit');
    if (await pageBlocked(page)) throw new Error('BOT-MANAGER BLOCK after username — switch to Mode B');

    // --- password (may be on a second view; two-step username->password) ---
    const passField = await firstVisible(page, PASS_SELECTORS, 20000);
    if (!passField) throw new Error('password field not found (two-step flow may have changed)');
    await passField.fill(PASSWORD);
    await shot(page, '03_password_filled');
    await clickFirst(page, SUBMIT_SELECTORS);
    await page.waitForLoadState('networkidle', { timeout: 30000 }).catch(() => {});
    await shot(page, '04_after_password_submit');
    if (await pageBlocked(page)) throw new Error('BOT-MANAGER BLOCK after password — switch to Mode B');

    // --- optional OTP / email step-up ---
    const otpField = await firstVisible(page, OTP_SELECTORS, 6000);
    if (otpField) {
      if (!OTP) throw new Error('OTP step-up present but no OTP env supplied — ask the operator for the code');
      await otpField.fill(OTP);
      await clickFirst(page, SUBMIT_SELECTORS);
      await page.waitForLoadState('networkidle', { timeout: 30000 }).catch(() => {});
      await shot(page, '05_after_otp');
    }

    // --- success check ---
    if (SUCCESS_SEL) {
      await page.waitForSelector(SUCCESS_SEL, { timeout: 30000 });
    } else {
      // Heuristic: we left the login URL and the page is not a block page.
      await page.waitForTimeout(2000);
      if (await pageBlocked(page)) throw new Error('ended on a block/error page');
    }
    await shot(page, '06_authenticated');
    ok = true;
    console.error(`[ok] authenticated — final URL: ${page.url()}`);

    // --- session extraction (Mode B and useful in Mode A too) ---
    const cookies = await context.cookies();
    writeJar(cookies, JAR);
  } catch (e) {
    console.error(`[fail] ${e.message}`);
    await shot(page, 'ERROR');
  } finally {
    // Keep cookies even on partial success in Mode B.
    if (!ok) { try { writeJar(await context.cookies(), JAR); } catch (_) {} }
    await browser.close();
  }
  process.exit(ok ? 0 : 1);
})();
