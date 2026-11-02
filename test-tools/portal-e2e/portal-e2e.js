// Phase 134: the REAL portal in Chromium against the HttpHarness (real AdminController/Dtos/services/PostgreSQL).
const { chromium } = require('playwright');
const { call, tokens, activate, newDevice, B } = require('./lib');
let pass = 0, fail = 0; const ok = (c, m) => { if (c) { pass++; console.log('PASS', m); } else { fail++; console.log('FAIL', m); } };
(async () => {
  const br = await chromium.launch(); const ctx = await br.newContext(); const pg = await ctx.newPage();
  const bad = [], reqs = []; pg.on('console', m => { if (/Content Security Policy|Refused to/i.test(m.text())) bad.push(m.text()); }); pg.on('pageerror', e => bad.push('PAGEERROR ' + e.message)); pg.on('request', r => reqs.push(r.url()));
  const login = async (tok) => { await pg.goto(B + '/admin'); await pg.fill('#token', tok); await pg.click('#login-btn'); };
  // wrong token
  await login('nope'); await pg.waitForSelector('#login-error:not([hidden])'); ok(/not accepted/.test(await pg.textContent('#login-error')), 'real API: wrong token refused on the sign-in screen');
  // reader: dashboard counts yes, activity unavailable; history unavailable; issue refused
  await login(tokens.reader); await pg.waitForSelector('#stats .cards');
  ok(/Unavailable/.test(await pg.textContent('#stats')), 'read-only token: activity shown as unavailable by the real API');
  await pg.click('button[data-view=issue]'); await pg.fill('#i-email', 'ro@example.com'); await pg.check('#i-paid'); await pg.click('#issue-form button[type=submit]'); await pg.click('#issue-confirm');
  await pg.waitForSelector('#review-error:not([hidden])'); ok(/not allowed/.test(await pg.textContent('#review-error')), 'read-only token: issuing shows the 403 as a clear message');
  ok((await call(tokens.full, 'GET', '/api/v1/admin/stats')).json.licenses.total === 0, 'the refused issuance created nothing');
  await pg.click('#signout');
  // full admin
  await login(tokens.full); await pg.waitForSelector('#stats .cards');
  ok(/real zero/.test(await pg.textContent('#stats')), 'empty database: dashboard says real zeros');
  const st = await pg.evaluate(() => ({ l: localStorage.length, s: sessionStorage.length, c: document.cookie }));
  ok(st.l === 0 && st.s === 0 && st.c === '' && !pg.url().includes('token'), 'no token in storage, cookies or URL');
  // opening/reviewing/declining creates nothing
  await pg.click('button[data-view=issue]'); await pg.fill('#i-email', 'Review.Only@Example.com'); await pg.check('#i-paid'); await pg.click('#issue-form button[type=submit]');
  ok(await pg.locator('#issue-review').isVisible(), 'review step shown'); await pg.click('#issue-back'); await pg.click('button[data-view=dashboard]'); await pg.click('button[data-view=issue]');
  ok((await call(tokens.full, 'GET', '/api/v1/admin/stats')).json.licenses.total === 0, 'opening, reviewing and declining created no record');
  // issue (double click on confirm)
  await pg.fill('#i-email', 'Buyer@Example.com'); await pg.fill('#i-ref', 'bank-0042'); await pg.check('#i-paid'); await pg.click('#issue-form button[type=submit]'); await pg.dblclick('#issue-confirm');
  await pg.waitForSelector('#issue-done:not([hidden])'); const code = await pg.textContent('#key-value');
  ok(/^[A-Z0-9-]{20,}$/.test(code), 'the real API returned an activation key shown once: ' + code.replace(/./g, '*').slice(0, 4) + '…');
  const lst = (await call(tokens.full, 'GET', '/api/v1/admin/licenses/search?q=buyer@')).json; ok(lst.items.length === 1, 'double click created exactly one license in PostgreSQL');
  const id = lst.items[0].id;
  ok(!(await call(tokens.full, 'GET', '/api/v1/admin/licenses/' + id)).text.includes(code), 'the key is not retrievable afterwards');
  await pg.click('#done-close'); ok((await pg.textContent('#key-value')) === '' && !(await pg.content()).includes(code), 'key wiped from the page');
  // activate the license as a desktop device, then manage it from the portal
  const dev = newDevice(); const act = await activate(dev, 'buyer@example.com', code); ok(act.status === 200, 'the issued key activates a device (real client endpoint)');
  await pg.click('button[data-view=licenses]'); await pg.waitForSelector('#results tbody tr');
  ok((await pg.textContent('#results tbody')).includes('buyer@example.com') && (await pg.textContent('#results tbody')).includes('1 / 1'), 'list shows email and device count 1 / 1');
  await pg.fill('#s-q', 'BUY'); await pg.selectOption('#s-status', 'ACTIVE'); await pg.click('#search-form button[type=submit]'); await pg.waitForTimeout(300);
  ok((await pg.locator('#results tbody tr').count()) === 1, 'case-insensitive search + effective-status filter through PostgreSQL');
  await pg.locator('#results tbody tr').first().click(); await pg.waitForSelector('#detail h2');
  const d = await pg.textContent('#detail'); ok(/Activated/.test(d) && /1 of 1/.test(d), 'detail: activation and devices');
  await pg.waitForFunction(() => document.querySelector('#history').textContent.includes('LICENSE_ISSUED'));
  ok((await pg.textContent('#history')).includes('DEVICE_BOUND'), 'history from the real audit trail (issue, activation, device bound)');
  await pg.click('#detail-actions button:has-text("Suspend")'); await pg.fill('#c-reason', 'e2e'); await pg.click('#confirm-ok');
  await pg.waitForFunction(() => document.querySelector('#detail').textContent.includes('SUSPENDED'));
  ok((await call(tokens.full, 'GET', '/api/v1/admin/licenses/' + id)).json.effectiveStatus === 'SUSPENDED', 'suspend reached the database');
  // renew while suspended (exact date), stays suspended
  await pg.click('#detail-actions button:has-text("Renew")'); await pg.check('input[name=c-mode][value=SET_END]');
  const endDate = new Date(Date.now() + 200 * 864e5).toISOString().slice(0, 10); await pg.fill('#c-date', endDate); await pg.click('#confirm-ok');
  await pg.waitForFunction(d => document.querySelector('#detail').textContent.includes(d), endDate);
  const mid = (await call(tokens.full, 'GET', '/api/v1/admin/licenses/' + id)).json; ok(mid.effectiveStatus === 'SUSPENDED' && mid.expiresAt.startsWith(endDate) && mid.activeDeviceCount === 1, 'renewal via the portal: exact date stored, still suspended, device still bound');
  await pg.click('#detail-actions button:has-text("Reinstate")'); await pg.click('#confirm-ok');
  await pg.waitForFunction(() => document.querySelector('#detail-actions').textContent.includes('Suspend')); ok(true, 'reinstated');
  await pg.click('#detail-actions button:has-text("Renew")'); await pg.fill('#c-days', '10'); await pg.click('#confirm-ok');
  await pg.waitForFunction(() => document.querySelector('#history').textContent.includes('mode=EXTEND_DAYS'));
  ok(true, 'extend-by-days renewal recorded in the history');
  await pg.click('#detail-actions button:has-text("Revoke")'); await pg.click('#confirm-ok'); await pg.waitForFunction(() => document.querySelector('#detail').textContent.includes('REVOKED'));
  ok((await pg.locator('#detail-actions button').count()) === 0, 'revoked: no actions offered');
  // the server-side refusal surfaces in the UI even if the page were driven manually
  const direct = await call(tokens.full, 'POST', '/api/v1/admin/licenses/' + id + '/renew', { mode: 'EXTEND_DAYS', days: 5 }); ok(direct.status === 409, 'a revoked license refuses renewal server-side');
  // fixed end date license via the UI
  await pg.click('button[data-view=issue]'); await pg.fill('#i-email', 'dated@example.com'); await pg.check('input[name=i-dur][value=date]');
  const fixed = new Date(Date.now() + 40 * 864e5).toISOString().slice(0, 10); await pg.fill('#i-date', fixed); await pg.check('#i-paid'); await pg.click('#issue-form button[type=submit]'); await pg.click('#issue-confirm'); await pg.waitForSelector('#issue-done:not([hidden])');
  const fx = (await call(tokens.full, 'GET', '/api/v1/admin/licenses/search?q=dated@')).json.items[0]; ok(fx.expiresAt === fixed + 'T23:59:59Z' && fx.validityDays === null, 'fixed end date stored exactly (' + fx.expiresAt + ')');
  await pg.click('#done-close');
  // dashboard against real numbers
  await pg.click('button[data-view=dashboard]'); await pg.waitForSelector('#stats .cards'); const dash = await pg.textContent('#stats');
  const real = (await call(tokens.full, 'GET', '/api/v1/admin/stats')).json; ok(real.licenses.total === 2 && real.licenses.revoked === 1 && real.licenses.pending === 1, 'dashboard source numbers: ' + JSON.stringify(real.licenses));
  ok(/Total/.test(dash) && /Revoked/.test(dash) && /Activations OK/.test(dash), 'dashboard renders the real response');
  await pg.click('button[data-view=audit]'); await pg.waitForSelector('#audit-list li'); ok((await pg.locator('#audit-list li').count()) >= 8, 'global audit view lists real events');
  // 401 mid-session: stop trusting the token -> back to sign-in. (simulate with a token the server does not know)
  await pg.evaluate(() => { }); 
  ok(bad.length === 0, 'no CSP violations or page errors: ' + bad.join('|'));
  ok(reqs.every(u => u.startsWith(B)), 'every request is same-origin');
  await pg.screenshot({ path: 'portal-real.png' });
  const m = await (await br.newContext({ viewport: { width: 375, height: 740 } })).newPage(); await m.goto(B + '/admin'); await m.fill('#token', tokens.full); await m.click('#login-btn'); await m.waitForSelector('#stats .cards');
  for (const v of ['dashboard', 'issue', 'licenses', 'audit']) { await m.click('button[data-view=' + v + ']'); await m.waitForTimeout(250); const w = await m.evaluate(() => [document.documentElement.scrollWidth, innerWidth]); ok(w[0] <= w[1], '375px real data: no horizontal scroll on ' + v); }
  await br.close(); console.log(`\n${pass} passed, ${fail} failed`); process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
