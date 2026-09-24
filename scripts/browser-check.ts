/**
 * Real-browser test (development only): drives the installed Microsoft Edge (or Chrome) through the
 * Test Console exactly like a person - clicks, typing, real cookies, real Origin / Referrer headers.
 *
 *   npm start            # service on :4000
 *   npm run console      # console on :5170
 *   npm run test:browser [-- --headed]
 *
 * Complements the HTTP-level e2e suite: it catches what only a browser does (e.g. which Origin a
 * form POST carries, cookie SameSite handling, the client-side script).
 */
import { chromium, type Page } from 'playwright-core';
import { Pool } from 'pg';
import { loadDotEnv } from '../src/config/env';

loadDotEnv();
if (process.env.NODE_ENV === 'production') throw new Error('development only');

const CONSOLE = `http://localhost:${process.env.CONSOLE_PORT ?? 5170}`;
const headed = process.argv.includes('--headed');
let failures = 0;
const check = (name: string, ok: boolean, detail = '') => {
  if (!ok) failures++;
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? `  -> ${detail}` : ''}`);
};

async function state() {
  return (await (await fetch(`${CONSOLE}/api/state`)).json()) as {
    apps: { key: string; session: { claims: Record<string, unknown> } | null; lastError: string | null }[];
    outbox: { code: string; at: string }[];
    members: { itsId: string; password: string }[];
  };
}

async function latestCodeAfter(since: number): Promise<string> {
  for (let i = 0; i < 40; i++) {
    const o = (await state()).outbox.find((x) => Date.parse(x.at) >= since - 1000);
    if (o) return o.code;
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error('no code arrived');
}

/** Clicks an app button on the console and completes whatever Core shows (login / MFA). */
async function signIn(page: Page, appKey: string, button: string, itsId: string, password: string) {
  await page.goto(`${CONSOLE}/`);
  await page.locator(`#${appKey}`).getByRole('link', { name: button, exact: true }).click();
  const seen: string[] = [];
  for (let i = 0; i < 4; i++) {
    await page.waitForLoadState('load');
    if (page.url().startsWith(CONSOLE)) break;
    const text = await page.locator('body').innerText();
    if (await page.locator('#its_id').count()) {
      seen.push('login');
      if (seen.filter((s) => s === 'login').length > 1) throw new Error(`login rejected: ${await alertText(page)}`);
      await page.fill('#its_id', itsId);
      await page.fill('#password', password);
      const since = Date.now();
      await Promise.all([page.waitForLoadState('load'), page.click('button[data-submit]')]);
      (page as unknown as { __since: number }).__since = since;
    } else if (await page.locator('#code').count()) {
      seen.push('mfa');
      if (seen.filter((s) => s === 'mfa').length > 1) throw new Error(`MFA rejected: ${await alertText(page)}`);
      const code = await latestCodeAfter((page as unknown as { __since?: number }).__since ?? Date.now() - 10_000);
      await page.fill('#code', code);
      await Promise.all([page.waitForURL((u) => u.toString().startsWith(CONSOLE) || u.toString().includes('/interaction/'), { timeout: 15_000 }), page.click('button[data-submit]')]);
    } else {
      throw new Error(`unexpected page: ${text.slice(0, 200)}`);
    }
  }
  await page.waitForURL((u) => u.toString().startsWith(CONSOLE), { timeout: 15_000 });
  const app = (await state()).apps.find((a) => a.key === appKey)!;
  return { seen, claims: app.session?.claims ?? null, error: app.lastError };
}

async function waitFor<T>(fn: () => Promise<T | null>, timeoutMs = 10_000): Promise<T | null> {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    const v = await fn();
    if (v) return v;
    await new Promise((r) => setTimeout(r, 300));
  }
  return null;
}

/** The registration UI test owns exactly this client row (callbacks and handoff paths cascade). */
const UI_CLIENT = 'console-ui-check';
async function dbQuery(sql: string, params: unknown[]): Promise<unknown[]> {
  const pool = new Pool({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT),
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    options: `-c search_path=${process.env.DB_SCHEMA}`,
  });
  try {
    return (await pool.query(sql, params)).rows;
  } finally {
    await pool.end();
  }
}
async function deleteUiClient() {
  await dbQuery('DELETE FROM auth_clients WHERE client_id = $1', [UI_CLIENT]);
}

async function alertText(page: Page) {
  return (await page.locator('.alert').first().innerText().catch(() => '')).trim();
}

async function main() {
  const members = (await state()).members;
  const pw = (id: string) => members.find((m) => m.itsId === id)!.password;
  for (const key of ['rms-admin', 'ams-admin', 'rms-mumin']) await fetch(`${CONSOLE}/api/clear?app=${key}`);

  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL ?? 'msedge', headless: !headed });
  try {
    const page = await (await browser.newContext()).newPage();

    console.log('\n=== Real browser: login + MFA, SSO, realm isolation');
    const r1 = await signIn(page, 'rms-admin', 'Sign in + MFA (AAL2)', '10110101', pw('10110101'));
    check('RMS Admin: login page -> MFA page -> back on console', r1.seen.join(',') === 'login,mfa', r1.seen.join(',') + ' ' + (r1.error ?? ''));
    check('RMS Admin: ITS 10110101, ADMIN, aal:2', r1.claims?.sub === '10110101' && r1.claims?.auth_realm === 'ADMIN' && r1.claims?.acr === 'urn:miqaat:aal:2');
    const r2 = await signIn(page, 'ams-admin', 'Sign in + MFA (AAL2)', '10110101', pw('10110101'));
    check('AMS Admin: silent SSO (no pages), same sid', r2.seen.length === 0 && r2.claims?.sid === r1.claims?.sid, r2.seen.join(','));
    const r3 = await signIn(page, 'rms-mumin', 'Sign in + MFA (AAL2)', '10110101', pw('10110101'));
    check('RMS Mumin: login + MFA again, realm MUMIN, other sid', r3.seen.join(',') === 'login,mfa' && r3.claims?.auth_realm === 'MUMIN' && r3.claims?.sid !== r1.claims?.sid);

    console.log('\n=== Real browser: form behaviour');
    const fresh = await (await browser.newContext()).newPage();
    await fresh.goto(`${CONSOLE}/`);
    await fresh.locator('#rms-admin').getByRole('link', { name: 'Sign in (AAL1)', exact: true }).click();
    await fresh.waitForSelector('#its_id');
    check('Login button disabled until both fields are filled', await fresh.isDisabled('button[data-submit]'));
    await fresh.fill('#its_id', '10110101');
    await fresh.fill('#password', 'wrong-password');
    check('Login button enabled when filled', await fresh.isEnabled('button[data-submit]'));
    await fresh.click('button[data-reveal]');
    check('Eye button shows the password', (await fresh.getAttribute('#password', 'type')) === 'text');
    await Promise.all([fresh.waitForLoadState('load'), fresh.click('button[data-submit]')]);
    const wrong = await alertText(fresh);
    check('Wrong password -> "Incorrect ITS ID or password." (no CSRF / expired-form error)', wrong === 'Incorrect ITS ID or password.', wrong);
    await fresh.fill('#password', pw('10110101'));
    await Promise.all([fresh.waitForURL((u) => u.toString().startsWith(CONSOLE), { timeout: 15_000 }), fresh.click('button[data-submit]')]);
    const aal1 = (await state()).apps.find((a) => a.key === 'rms-admin')!.session?.claims;
    check('Retry with the right password on the same form -> signed in (AAL1)', aal1?.acr === 'urn:miqaat:aal:1');

    const mfaPage = await (await browser.newContext()).newPage();
    await mfaPage.goto(`${CONSOLE}/`);
    await mfaPage.locator('#rms-admin').getByRole('link', { name: 'Sign in + MFA (AAL2)', exact: true }).click();
    await mfaPage.fill('#its_id', '10110101');
    await mfaPage.fill('#password', pw('10110101'));
    await Promise.all([mfaPage.waitForSelector('#code'), mfaPage.click('button[data-submit]')]);
    await mfaPage.fill('#code', '000000');
    await Promise.all([mfaPage.waitForLoadState('load'), mfaPage.click('button[data-submit]')]);
    const wrongCode = await alertText(mfaPage);
    check('Wrong MFA code -> "Incorrect code. 4 attempts left."', wrongCode === 'Incorrect code. 4 attempts left.', wrongCode);
    await Promise.all([mfaPage.waitForLoadState('load'), mfaPage.getByRole('button', { name: /Use SMS/ }).click()]);
    check('"Use SMS instead" switches the page to SMS', (await mfaPage.locator('.subtitle').innerText()).includes('SMS'));
    await Promise.all([mfaPage.waitForLoadState('load'), mfaPage.getByRole('button', { name: 'Cancel sign-in' }).click()]);
    await mfaPage.waitForURL((u) => u.toString().startsWith(CONSOLE));
    const cancelled = (await state()).apps.find((a) => a.key === 'rms-admin')!.lastError ?? '';
    check('Cancel -> app receives access_denied', cancelled.startsWith('access_denied'), cancelled);

    // ---- logout ------------------------------------------------------------------------------
    console.log('\n=== Real browser: realm-wide logout');
    for (const key of ['rms-admin', 'ams-admin', 'rms-mumin']) await fetch(`${CONSOLE}/api/clear?app=${key}`);
    const lb = await (await browser.newContext()).newPage();
    const a1 = await signIn(lb, 'rms-admin', 'Sign in + MFA (AAL2)', '10110101', pw('10110101'));
    const a2 = await signIn(lb, 'ams-admin', 'Sign in + MFA (AAL2)', '10110101', pw('10110101'));
    const m1 = await signIn(lb, 'rms-mumin', 'Sign in (AAL1)', '10110101', pw('10110101'));
    check('Signed in to RMS Admin, AMS Admin (SSO) and RMS Mumin', Boolean(a1.claims && a2.claims && m1.claims) && a2.seen.length === 0);

    await lb.goto(`${CONSOLE}/`);
    await Promise.all([lb.waitForURL((u) => u.toString().startsWith(CONSOLE), { timeout: 15_000 }), lb.locator('#rms-admin').getByRole('link', { name: /^Logout/ }).click()]);
    check('Logout on RMS Admin returns straight to the console (id_token_hint -> no confirmation)', lb.url().startsWith(CONSOLE));
    const afterLogout = await waitFor(async () => {
      const s = await state();
      const ams = s.apps.find((a) => a.key === 'ams-admin')!;
      return ams.session ? null : s;
    });
    const apps = afterLogout?.apps ?? (await state()).apps;
    check('RMS Admin signed out (local session ended before Core)', !apps.find((a) => a.key === 'rms-admin')!.session);
    check('AMS Admin signed out by Core back-channel logout (verified JWS)', !apps.find((a) => a.key === 'ams-admin')!.session);
    check('RMS Mumin still signed in (MUMIN realm untouched)', Boolean(apps.find((a) => a.key === 'rms-mumin')!.session));
    // The BU may clear its session a moment before Core records the 200, so wait for the final status.
    const deliveries =
      (await waitFor(async () => {
        const l = ((await (await fetch(`${CONSOLE}/api/state`)).json()) as { logout: { client_id: string; status: string }[] }).logout;
        return ['rms-admin-dev', 'ams-admin-dev'].every((c) => l.some((d) => d.client_id === c && d.status === 'SUCCEEDED')) ? l : null;
      })) ?? ((await (await fetch(`${CONSOLE}/api/state`)).json()) as { logout: { client_id: string; status: string }[] }).logout;
    check('Deliveries: RMS Admin + AMS Admin SUCCEEDED, none to MUMIN',
      ['rms-admin-dev', 'ams-admin-dev'].every((c) => deliveries.some((d) => d.client_id === c && d.status === 'SUCCEEDED')) && !deliveries.some((d) => d.client_id === 'rms-mumin-dev'),
      JSON.stringify(deliveries.slice(0, 3)));
    const again = await signIn(lb, 'ams-admin', 'Sign in (AAL1)', '10110101', pw('10110101'));
    check('After logout, AMS Admin asks for the password again (no SSO)', again.seen[0] === 'login', again.seen.join(','));
    const mumin = await signIn(lb, 'rms-mumin', 'Sign in (AAL1)', '10110101', pw('10110101'));
    check('RMS Mumin still signs in silently', mumin.seen.length === 0, mumin.seen.join(','));

    // Logout with no local session -> Core asks to confirm.
    await fetch(`${CONSOLE}/api/clear?app=ams-admin`);
    await lb.goto(`${CONSOLE}/`);
    await lb.locator('#ams-admin').getByRole('link', { name: /^Logout/ }).click();
    await lb.waitForSelector('text=Sign out?');
    check('Logout without id_token_hint shows the Core "Sign out?" confirmation', (await lb.locator('h1').innerText()).includes('Sign out'));
    await Promise.all([lb.waitForURL((u) => u.toString().startsWith(CONSOLE), { timeout: 15_000 }), lb.getByRole('button', { name: 'Sign out' }).click()]);
    const confirmed = await signIn(lb, 'rms-admin', 'Sign in (AAL1)', '10110101', pw('10110101'));
    check('After confirming, the ADMIN session is gone', confirmed.seen[0] === 'login', confirmed.seen.join(','));

    // Back-channel endpoint down -> Core retries until it is back.
    const rb = await (await browser.newContext()).newPage();
    for (const key of ['rms-admin', 'ams-admin']) await fetch(`${CONSOLE}/api/clear?app=${key}`);
    await signIn(rb, 'rms-admin', 'Sign in (AAL1)', '10110101', pw('10110101'));
    await signIn(rb, 'ams-admin', 'Sign in (AAL1)', '10110101', pw('10110101'));
    await fetch(`${CONSOLE}/api/backchannel?app=ams-admin&down=1`);
    await rb.goto(`${CONSOLE}/`);
    await Promise.all([rb.waitForURL((u) => u.toString().startsWith(CONSOLE), { timeout: 15_000 }), rb.locator('#rms-admin').getByRole('link', { name: /^Logout/ }).click()]);
    const retrying = await waitFor(async () => {
      const l = ((await (await fetch(`${CONSOLE}/api/state`)).json()) as { logout: { client_id: string; status: string }[] }).logout;
      return l.find((d) => d.client_id === 'ams-admin-dev' && d.status === 'RETRY') ?? null;
    });
    check('AMS endpoint down (503) -> delivery marked RETRY', Boolean(retrying));
    await fetch(`${CONSOLE}/api/backchannel?app=ams-admin&down=0`);
    const recovered = await waitFor(async () => {
      const l = ((await (await fetch(`${CONSOLE}/api/state`)).json()) as { logout: { client_id: string; status: string; attempt_count: number }[] }).logout;
      const d = l.find((x) => x.client_id === 'ams-admin-dev');
      return d && d.status === 'SUCCEEDED' ? d : null;
    }, 20_000);
    check('Endpoint back up -> next retry SUCCEEDED and AMS signed out', Boolean(recovered) && !(await state()).apps.find((a) => a.key === 'ams-admin')!.session, recovered ? `attempts ${recovered.attempt_count}` : 'no success');

    // ---- trusted handoff ---------------------------------------------------------------------
    console.log('\n=== Real browser: trusted handoff (RMS Admin -> AMS Admin)');
    for (const key of ['rms-admin', 'ams-admin', 'rms-mumin']) await fetch(`${CONSOLE}/api/clear?app=${key}`);
    const hb = await (await browser.newContext()).newPage();
    const src = await signIn(hb, 'rms-admin', 'Sign in (AAL1)', '10110101', pw('10110101'));
    let assertion = '';
    hb.on('request', (r) => {
      if (r.method() === 'POST' && r.url().endsWith('/auth/core/handoff')) assertion = new URLSearchParams(r.postData() ?? '').get('assertion') ?? '';
    });
    const handoff = async (target: string, path: string) => {
      await hb.goto(`${CONSOLE}/`);
      const form = hb.locator('#rms-admin form.handoff');
      await form.locator('select[name="target"]').selectOption(target);
      await form.locator('select[name="path"]').selectOption(path);
      await Promise.all([hb.waitForLoadState('load'), form.getByRole('button', { name: 'Open via handoff' }).click()]);
      await hb.waitForURL((u) => !u.toString().startsWith('http://localhost:4000'), { timeout: 15_000 });
    };
    await handoff('ams-admin', '/events/123');
    check('Handoff lands on AMS Admin /events/123 (no login page, auto-POST)', hb.url() === 'http://localhost:5174/events/123', hb.url());
    check('Landing page says it arrived by trusted handoff', (await hb.locator('main').innerText()).includes('trusted handoff'));
    const ams = (await state()).apps.find((a) => a.key === 'ams-admin')!.session?.claims;
    check('AMS Admin local session: same ITS ID and Core sid as RMS Admin', ams?.sub === '10110101' && ams?.sid === src.claims?.sid && ams?.source_client_id === 'rms-admin-dev');
    const replay = await fetch('http://localhost:5174/auth/core/handoff', { method: 'POST', body: new URLSearchParams({ assertion }), redirect: 'manual' });
    check('Replaying the captured assertion -> 400 HANDOFF_REPLAYED', replay.status === 400 && (await replay.text()).includes('HANDOFF_REPLAYED'));
    const [h, p, s] = assertion.split('.');
    const forged = `${h}.${Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(p, 'base64url').toString()), sub: '10110102' })).toString('base64url')}.${s}`;
    const tampered = await fetch('http://localhost:5174/auth/core/handoff', { method: 'POST', body: new URLSearchParams({ assertion: forged }), redirect: 'manual' });
    check('Tampered assertion (sub changed) -> 400 HANDOFF_SIGNATURE_INVALID', tampered.status === 400 && (await tampered.text()).includes('HANDOFF_SIGNATURE_INVALID'));
    await handoff('ams-admin', '/admin/users');
    check('Handoff to /admin/users: target authorization denies it (403 page)', (await hb.locator('h2').innerText()).includes('Access denied'));
    await handoff('rms-mumin', '/events/123');
    const events = ((await (await fetch(`${CONSOLE}/api/state`)).json()) as { apps: { key: string; events: { text: string }[] }[] }).apps.find((a) => a.key === 'rms-admin')!.events;
    check('ADMIN -> MUMIN handoff refused by Core (REALM_MISMATCH), browser back on console', hb.url().startsWith(CONSOLE) && events.some((e) => e.text.includes('REALM_MISMATCH')), events[0]?.text);

    // ---- a client registered in the UI, tested end to end through the console test app ----------
    console.log('\n=== Real browser: register a new client in the UI and test everything with it');
    await deleteUiClient();
    for (const key of ['rms-admin', 'ams-admin', 'rms-mumin']) await fetch(`${CONSOLE}/api/clear?app=${key}`);
    const cp = await (await browser.newContext()).newPage();
    cp.on('dialog', (d) => void d.accept());
    const USER = '10110105';
    const TEST_APP = `${CONSOLE}/try?client_id=${UI_CLIENT}`;
    const main = async () => (await cp.locator('main').innerText()).replace(/\s+/g, ' ');
    /** Completes whatever Core shows (login / MFA) until the browser leaves Core; returns the pages seen. */
    const throughCore = async () => {
      const seen: string[] = [];
      let since = Date.now() - 2000;
      for (let i = 0; i < 4; i++) {
        await cp.waitForLoadState('load');
        if (!cp.url().startsWith('http://localhost:4000')) break;
        if (await cp.locator('#its_id').count()) {
          seen.push('login');
          await cp.fill('#its_id', USER);
          await cp.fill('#password', pw(USER));
          since = Date.now();
          await Promise.all([cp.waitForLoadState('load'), cp.click('button[data-submit]')]);
        } else if (await cp.locator('#code').count()) {
          seen.push('mfa');
          await cp.fill('#code', await latestCodeAfter(since));
          await Promise.all([cp.waitForURL((u) => !u.toString().includes('/mfa'), { timeout: 15_000 }).catch(() => undefined), cp.click('button[data-submit]')]);
        } else break;
      }
      await cp.waitForLoadState('load');
      return seen;
    };
    const click = async (name: string) => {
      await Promise.all([cp.waitForLoadState('load'), cp.getByRole('link', { name, exact: true }).first().click()]);
    };

    // 1. Register through the form.
    await cp.goto(`${CONSOLE}/#clients`);
    await cp.waitForFunction(`document.querySelector('#regform textarea[name="redirectUris"]').value.includes('/try/callback')`);
    const form = cp.locator('#regform');
    await form.locator('input[name="clientId"]').fill(UI_CLIENT);
    await form.locator('input[name="name"]').fill('Console UI check');
    await form.locator('select[name="realm"]').selectOption('ADMIN');
    await form.locator('input[name="businessUnit"]').fill('QA');
    await form.getByRole('button', { name: 'Use console test URLs' }).click();
    const bcUri = await form.locator('input[name="backchannelLogoutUri"]').inputValue();
    const hoUri = await form.locator('input[name="handoffCallbackUri"]').inputValue();
    check('"Use console test URLs" fills redirect, post-logout, back-channel and handoff URIs for this client', bcUri.endsWith(`/try/backchannel/${UI_CLIENT}`) && hoUri.endsWith(`/try/handoff/${UI_CLIENT}`) && (await form.locator('input[name="inbound"]').isChecked()));
    await form.getByRole('button', { name: 'Register client' }).click();
    await cp.waitForSelector('#newsecret');
    const secret1 = (await cp.locator('#newsecret').innerText()).trim();
    const result = await cp.locator('#regresult').innerText();
    check('Register -> 64-hex secret shown once + the Authorization: Basic header', /^[0-9a-f]{64}$/.test(secret1) && result.includes('Authorization: Basic '));
    await cp.waitForSelector(`#clientrows tr:has-text("${UI_CLIENT}")`);
    const row = (await cp.locator(`#clientrows tr:has-text("${UI_CLIENT}")`).innerText()).replace(/\s+/g, ' ');
    check('Listed: ADMIN, client_secret_basic, ACTIVE, handoff out+in, usable', row.includes('ADMIN') && row.includes('client_secret_basic') && row.includes('ACTIVE') && row.includes('out in') && /\byes\b/.test(row), row);
    const [dbRow] = (await dbQuery('SELECT client_secret_enc, token_endpoint_auth_method, status FROM auth_clients WHERE client_id = $1', [UI_CLIENT])) as { client_secret_enc: string; token_endpoint_auth_method: string; status: string }[];
    check('Stored in auth_clients: encrypted secret (not the plain one), client_secret_basic, ACTIVE', Boolean(dbRow) && !dbRow.client_secret_enc.includes(secret1) && dbRow.token_endpoint_auth_method === 'client_secret_basic' && dbRow.status === 'ACTIVE');

    // 2. Open the test app and sign in at AAL1.
    await Promise.all([cp.waitForLoadState('load'), cp.locator('#regresult').getByRole('link', { name: 'Open test app' }).click()]);
    check('Test app opens: not signed in yet', (await main()).includes('Not signed in'));
    await click('Sign in (AAL1)');
    const s1 = await throughCore();
    let m = await main();
    check('Sign in (AAL1): Core login page -> back signed in, aal:1, amr ["pwd"]', s1.join(',') === 'login' && m.includes(`Signed in as ITS ${USER}`) && m.includes('aal:1') && m.includes('["pwd"]'), `${s1.join(',')} | ${m.slice(0, 200)}`);
    check('Code exchanged at /token with Authorization: Basic and ID token verified (aud = new client)', m.includes('Authorization: Basic') && m.includes(`"aud": "${UI_CLIENT}"`));
    const sid1 = /sid ([0-9a-f]{8})/.exec(m)?.[1];

    // 3. /me.
    await click('Call /me');
    m = await main();
    check('Call /me with the access token -> 200', m.includes('/me with the access token -> 200'));

    // 4. Step-up to AAL2: MFA only.
    await click('Sign in + MFA (AAL2)');
    const s2 = await throughCore();
    m = await main();
    check('Sign in + MFA: only the MFA page (password skipped), aal:2, amr has otp, same sid', s2.join(',') === 'mfa' && m.includes('aal:2') && m.includes('"otp"') && m.includes(`sid ${sid1}`), `${s2.join(',')} | ${m.slice(0, 200)}`);

    // 5. SSO into a demo app of the same realm.
    const amsSso = await signIn(cp, 'ams-admin', 'Sign in (AAL1)', USER, pw(USER));
    check('SSO: AMS Admin signs in silently with the same Core session', amsSso.seen.length === 0 && String(amsSso.claims?.sid).startsWith(sid1 ?? '-'), amsSso.seen.join(','));

    // 6. Handoff OUT: new client -> AMS Admin.
    await cp.goto(TEST_APP);
    await cp.locator('form[action="/try/handoff-out"] select[name="target"]').selectOption('ams-admin-dev');
    await cp.locator('form[action="/try/handoff-out"] select[name="path"]').selectOption('/events/123');
    await Promise.all([cp.waitForURL((u) => u.toString().startsWith('http://localhost:5174/'), { timeout: 15_000 }), cp.getByRole('button', { name: 'Open via handoff' }).click()]);
    const landed = (await cp.locator('main').innerText()).replace(/\s+/g, ' ');
    check('Handoff out: lands on AMS Admin /events/123, arrived from the new client, no login', cp.url() === 'http://localhost:5174/events/123' && landed.includes(UI_CLIENT) && landed.includes('trusted handoff'), `${cp.url()} ${landed.slice(0, 160)}`);

    // 7. Handoff IN: RMS Admin -> new client.
    await cp.goto(TEST_APP);
    await Promise.all([cp.waitForURL((u) => u.toString().startsWith(TEST_APP), { timeout: 15_000 }), cp.getByRole('link', { name: 'RMS Admin', exact: true }).click()]);
    m = await main();
    check('Handoff in: RMS Admin opens /dashboard of the new client, assertion verified, no password', m.includes('Handoff from rms-admin-dev verified') && m.includes('via handoff from rms-admin-dev'), m.slice(0, 300));

    // 8. Handoff to the other realm is refused.
    await cp.locator('form[action="/try/handoff-out"] select[name="target"]').selectOption('rms-mumin-dev');
    await Promise.all([cp.waitForURL((u) => u.toString().startsWith(TEST_APP), { timeout: 15_000 }), cp.getByRole('button', { name: 'Open via handoff' }).click()]);
    check('Handoff to a MUMIN app -> refused by Core (REALM_MISMATCH)', (await main()).includes('REALM_MISMATCH'));

    // 9. Logout from the new client: realm-wide, back-channel to the new client and AMS Admin.
    await click('Logout');
    await cp.waitForURL((u) => u.toString().startsWith(TEST_APP), { timeout: 15_000 });
    m = await main();
    check('Logout (id_token_hint) -> back from Core, local session ended', m.includes('Back from Core /logout') && m.includes('Not signed in'));
    const bcOk = await waitFor(async () => {
      await cp.goto(TEST_APP);
      return (await main()).includes('Back-channel logout from Core verified') ? true : null;
    }, 15_000);
    check('New client receives and verifies its back-channel logout (signed miqaat-logout+jwt)', Boolean(bcOk));
    const amsGone = await waitFor(async () => ((await state()).apps.find((a) => a.key === 'ams-admin')!.session ? null : true), 10_000);
    check('AMS Admin signed out too (realm-wide logout, back-channel)', Boolean(amsGone));
    const uiDeliveries = (await dbQuery(
      `SELECT d.client_id, d.status FROM logout_deliveries d JOIN logout_jobs j ON j.id = d.job_id WHERE j.initiated_by_client = $1 ORDER BY j.created_at DESC LIMIT 5`,
      [UI_CLIENT],
    ).catch(() => [])) as { client_id: string; status: string }[];
    check('Core logout deliveries: new client + AMS Admin SUCCEEDED', uiDeliveries.some((d) => d.client_id === UI_CLIENT && d.status === 'SUCCEEDED') && uiDeliveries.some((d) => d.client_id === 'ams-admin-dev' && d.status === 'SUCCEEDED'), JSON.stringify(uiDeliveries));
    await click('Sign in (AAL1)');
    const s3 = await throughCore();
    check('After logout, sign-in asks for the password again', s3[0] === 'login' && (await main()).includes(`Signed in as ITS ${USER}`), s3.join(','));

    // 10. Duplicate registration, secret rotation, suspend / activate.
    await cp.goto(`${CONSOLE}/#clients`);
    await cp.waitForSelector(`#clientrows tr:has-text("${UI_CLIENT}")`);
    await form.locator('input[name="clientId"]').fill(UI_CLIENT);
    await form.getByRole('button', { name: 'Register client' }).click();
    await cp.waitForSelector('#regresult .box.bad');
    check('Registering the same client ID again -> "already exists" in the page', (await cp.locator('#regresult').innerText()).includes('already exists'));
    await cp.locator(`#clientrows tr:has-text("${UI_CLIENT}")`).getByRole('button', { name: 'New secret' }).click();
    await cp.waitForFunction(`(document.getElementById('newsecret')?.textContent ?? '${secret1}') !== '${secret1}'`);
    const secret2 = (await cp.locator('#newsecret').innerText()).trim();
    const tokenWith = async (secret: string) =>
      (await fetch('http://localhost:4000/token', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${Buffer.from(`${UI_CLIENT}:${secret}`).toString('base64')}` },
        body: new URLSearchParams({ grant_type: 'authorization_code', code: 'not-a-code', redirect_uri: `${CONSOLE}/try/callback`, code_verifier: 'x'.repeat(43) }),
      }).then((r) => r.json())) as { error?: string };
    check('New secret: old secret -> invalid_client, new secret authenticates (invalid_grant for a fake code)', (await tokenWith(secret1)).error === 'invalid_client' && (await tokenWith(secret2)).error === 'invalid_grant');
    await cp.goto(TEST_APP);
    await click('Sign in (AAL1)');
    await throughCore();
    check('Sign-in with the new secret works (silent SSO)', (await main()).includes(`Signed in as ITS ${USER}`));

    await cp.goto(`${CONSOLE}/#clients`);
    await cp.waitForSelector(`#clientrows tr:has-text("${UI_CLIENT}")`);
    await cp.locator(`#clientrows tr:has-text("${UI_CLIENT}")`).getByRole('button', { name: 'Suspend' }).click();
    await cp.waitForSelector(`#clientrows tr:has-text("${UI_CLIENT}") >> text=SUSPENDED`);
    await cp.goto(`${CONSOLE}/try/login?client_id=${UI_CLIENT}`);
    await cp.waitForLoadState('load');
    check('Suspended -> Core refuses the client (stays on a Core error page)', cp.url().startsWith('http://localhost:4000') && !(await cp.locator('body').innerText()).includes('Signed in'), cp.url());
    check('Suspended -> the secret no longer authenticates at /token', (await tokenWith(secret2)).error === 'invalid_client');
    await cp.goto(`${CONSOLE}/#clients`);
    await cp.waitForSelector(`#clientrows tr:has-text("${UI_CLIENT}")`);
    await cp.locator(`#clientrows tr:has-text("${UI_CLIENT}")`).getByRole('button', { name: 'Activate' }).click();
    await cp.waitForSelector(`#clientrows tr:has-text("${UI_CLIENT}") >> text=ACTIVE`);
    await cp.goto(TEST_APP);
    await click('Sign in (AAL1)');
    await throughCore();
    check('Activate -> signs in again', (await main()).includes(`Signed in as ITS ${USER}`));
    const crossSite = await fetch(`${CONSOLE}/api/clients`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-test-console': '1', origin: 'https://evil.example' }, body: '{}' });
    check('Registration API refuses requests from another origin (403)', crossSite.status === 403);
    await deleteUiClient();
  } finally {
    await browser.close();
  }
  for (const key of ['rms-admin', 'ams-admin', 'rms-mumin']) await fetch(`${CONSOLE}/api/clear?app=${key}`);
  console.log(`\nRESULT: ${failures === 0 ? 'all browser checks passed' : `${failures} failed`}`);
  process.exit(failures ? 1 : 0);
}

main().catch((e) => {
  console.error(`browser check aborted: ${e instanceof Error ? e.message : e}`);
  process.exit(2);
});
