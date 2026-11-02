// Phase 134 HTTP contract checks of the admin API (real AdminController/Dtos/services/PostgreSQL behind HttpHarness).
const { call, tokens, activate, newDevice, B } = require('./lib');
let pass = 0, fail = 0; const ok = (c, m) => { if (c) { pass++; console.log('PASS', m); } else { fail++; console.log('FAIL', m); } };
const policy = { deviceLimit: 1, validityDays: 30, rights: ['LIVE', 'DSA'], activationWindowDays: 30 };
const issueBody = (email, extra = {}) => ({ customerEmail: email, paymentVerified: true, paymentReference: 'ref-1', policy, ...extra });
const key = () => require('crypto').randomUUID().replace(/-/g, '');
(async () => {
  // --- static portal
  let r = await call(null, 'GET', '/admin');
  ok(r.status === 200 && /text\/html/.test(r.headers.get('content-type')), '/admin loads');
  const csp = r.headers.get('content-security-policy');
  ok(/script-src 'self'/.test(csp) && !/unsafe-inline|unsafe-eval/.test(csp) && /frame-ancestors 'none'/.test(csp) && /form-action 'none'/.test(csp), 'portal CSP strict: ' + csp);
  for (const a of ['portal.css', 'portal.js']) { const x = await call(null, 'GET', '/admin/' + a); ok(x.status === 200 && x.headers.get('content-security-policy') === csp && x.headers.get('cache-control') === 'no-store', a + ' served with the same CSP and no-store'); }
  r = await call(null, 'GET', '/admin/../application.yml'); ok(r.status === 404, 'no path beyond the three fixed files');
  r = await call(null, 'GET', '/api/v1/entitlement-keys'); ok(r.status === 200 && /default-src 'none'/.test(r.headers.get('content-security-policy')), 'API responses keep the blanket CSP');
  // --- unauthenticated: every admin route refuses
  const routes = [['GET', '/api/v1/admin/stats'], ['GET', '/api/v1/admin/licenses/search'], ['GET', '/api/v1/admin/licenses?customerEmail=a@b.c'], ['GET', '/api/v1/admin/audit'],
    ['POST', '/api/v1/admin/licenses', issueBody('x@example.com')], ['GET', '/api/v1/admin/licenses/00000000-0000-4000-8000-000000000000'],
    ['POST', '/api/v1/admin/licenses/00000000-0000-4000-8000-000000000000/revoke', {}], ['POST', '/api/v1/admin/licenses/00000000-0000-4000-8000-000000000000/renew', { mode: 'EXTEND_DAYS', days: 1 }]];
  let allow = true;
  for (const [m, p, b] of routes) { const x = await call(null, m, p, b, { 'Idempotency-Key': key() }); if (x.status !== 401 || (x.json && x.json.code) !== 'UNAUTHENTICATED') allow = false; }
  ok(allow, 'no token -> 401 UNAUTHENTICATED on every admin route (read and mutate)');
  r = await call('wrong-token', 'GET', '/api/v1/admin/stats'); ok(r.status === 401 && !/wrong-token/.test(r.text), 'wrong token -> 401, token not echoed');
  r = await call(null, 'GET', '/api/v1/admin/stats', undefined, { Authorization: 'Basic ' + tokens.full }); ok(r.status === 401, 'non-Bearer scheme refused');
  const lic = await call(null, 'GET', '/api/v1/admin/licenses'); ok(lic.status === 401, 'admin list refused without a token');
  const nothing = await call(tokens.full, 'GET', '/api/v1/admin/stats'); ok(nothing.json.licenses.total === 0, 'refused calls created no data (total=' + nothing.json.licenses.total + ')');
  // --- issue + response shape
  const k1 = key(); const body = issueBody('Customer@Example.com');
  r = await call(tokens.full, 'POST', '/api/v1/admin/licenses', body, { 'Idempotency-Key': k1 });
  ok(r.status === 201 && r.json.activationCode && r.json.replayed === false, 'issue -> 201 with the activation key once');
  const code = r.json.activationCode, id = r.json.license.id;
  const L = r.json.license; const want = ['id', 'customerEmail', 'status', 'effectiveStatus', 'deviceLimit', 'activeDeviceCount', 'validityDays', 'rights', 'createdAt', 'activationDeadline', 'activatedAt', 'expiresAt', 'suspendedAt', 'revokedAt'];
  ok(want.every(k => k in L), 'license JSON has every field the portal reads');
  ok(L.customerEmail === 'customer@example.com' && L.status === 'PENDING' && L.activeDeviceCount === 0, 'email normalised, PENDING, no devices');
  ok(!/codeHash|code_hash|pepper|password|secret/i.test(r.text), 'no credential hash or secret in the issue response');
  // --- idempotency
  const r2 = await call(tokens.full, 'POST', '/api/v1/admin/licenses', body, { 'Idempotency-Key': k1 });
  ok(r2.status === 200 && r2.json.replayed === true && r2.json.activationCode === null && r2.json.license.id === id, 'same key again -> same license, replayed, no key');
  const dup = await Promise.all(Array.from({ length: 8 }, () => call(tokens.full, 'POST', '/api/v1/admin/licenses', issueBody('race@example.com'), { 'Idempotency-Key': 'race' + '0'.repeat(20) })));
  const created = dup.filter(x => x.status === 201).length, withKey = dup.filter(x => x.json && x.json.activationCode).length;
  const sr = await call(tokens.full, 'GET', '/api/v1/admin/licenses/search?q=race@'); ok(created === 1 && withKey === 1 && sr.json.items.length === 1 && dup.every(x => x.status === 200 || x.status === 201), `8 concurrent identical submissions -> 1 license, 1 key (created=${created}, rows=${sr.json.items.length})`);
  r = await call(tokens.full, 'POST', '/api/v1/admin/licenses', issueBody('other@example.com'), { 'Idempotency-Key': k1 });
  ok(r.status === 409 && r.json.code === 'IDEMPOTENCY_KEY_REUSED', 'same key, different request -> 409');
  // --- the key never comes back
  const reads = [await call(tokens.full, 'GET', '/api/v1/admin/licenses/' + id), await call(tokens.full, 'GET', '/api/v1/admin/licenses/search'), await call(tokens.full, 'GET', '/api/v1/admin/licenses?customerEmail=customer@example.com'),
    await call(tokens.full, 'GET', '/api/v1/admin/licenses/' + id + '/audit'), await call(tokens.full, 'GET', '/api/v1/admin/audit'), await call(tokens.full, 'GET', '/api/v1/admin/stats')];
  ok(reads.every(x => x.status === 200 && !x.text.includes(code) && !x.text.includes(code.replace(/-/g, ''))), 'the raw key is in no read response after issuance');
  // --- validation
  const bad = [[{ ...body, customerEmail: '' }, 'blank email'], [{ ...body, paymentVerified: null }, 'missing payment flag'], [{ ...body, policy: { ...policy, deviceLimit: 0 } }, 'deviceLimit 0'], [{ ...body, policy: { ...policy, deviceLimit: 11 } }, 'deviceLimit 11'],
    [{ ...body, policy: { ...policy, validityDays: 0 } }, 'validityDays 0'], [{ ...body, policy: { ...policy, validityDays: 3651 } }, 'validityDays 3651'], [{ ...body, policy: { ...policy, rights: [] } }, 'no rights'],
    [{ ...body, policy: { ...policy, rights: ['ADMIN'] } }, 'unknown right'], [{ ...body, customerEmail: 'x'.repeat(300) }, 'huge email'], [{ ...body, paymentReference: 'x'.repeat(65) }, 'long reference'],
    [{ ...body, policy: null }, 'no policy'], [{ ...body, expiresAt: '2020-01-01T00:00:00Z' }, 'past end date'], [{ ...body, expiresAt: new Date(Date.now() + 864e5).toISOString() }, 'days AND end date'],
    [{ ...body, policy: { ...policy, validityDays: null }, expiresAt: 'not-a-date' }, 'bad date']];
  let allBad = true; for (const [b, n] of bad) { const x = await call(tokens.full, 'POST', '/api/v1/admin/licenses', b, { 'Idempotency-Key': key() }); if (x.status !== 400 || x.json.code !== 'VALIDATION_FAILED') { allBad = false; console.log('  not refused as 400:', n, x.status, x.text.slice(0, 80)); } }
  ok(allBad, 'invalid issue requests -> 400 VALIDATION_FAILED');
  r = await call(tokens.full, 'POST', '/api/v1/admin/licenses', { ...body, paymentVerified: false }, { 'Idempotency-Key': key() }); ok(r.status === 400 && r.json.code === 'PAYMENT_NOT_CONFIRMED', 'payment not confirmed -> 400 PAYMENT_NOT_CONFIRMED');
  r = await call(tokens.full, 'POST', '/api/v1/admin/licenses', body, { 'Idempotency-Key': 'short' }); ok(r.status === 400, 'bad idempotency key refused');
  r = await call(tokens.full, 'POST', '/api/v1/admin/licenses', body, {}); ok(r.status === 400, 'missing idempotency key refused');
  r = await call(tokens.full, 'POST', '/api/v1/admin/licenses', '{not json', { 'Idempotency-Key': key() }, true); ok(r.status === 400 && r.json.code === 'VALIDATION_FAILED' && !/Unexpected|line|column|Jackson/i.test(r.text), 'malformed JSON -> safe 400');
  r = await call(tokens.full, 'POST', '/api/v1/admin/licenses', 'x=1', { 'Idempotency-Key': key(), 'Content-Type': 'text/plain' }, true); ok(r.status === 415, 'wrong content type -> 415');
  r = await call(tokens.full, 'POST', '/api/v1/admin/licenses', 'x'.repeat(20000), { 'Idempotency-Key': key() }, true); ok(r.status === 413, 'oversize body -> 413');
  r = await call(tokens.full, 'GET', '/api/v1/admin/nonexistent'); ok(r.status === 404 && r.json.code, 'unknown route -> 404 JSON');
  r = await call(tokens.full, 'GET', '/api/v1/admin/licenses/not-a-uuid'); ok(r.status === 400, 'bad id -> 400');
  r = await call(tokens.full, 'GET', '/api/v1/admin/licenses/00000000-0000-4000-8000-000000000000'); ok(r.status === 404 && r.json.code === 'LICENSE_NOT_FOUND', 'unknown license -> 404');
  r = await call(tokens.full, 'GET', '/api/v1/admin/licenses/search?status=BOGUS'); ok(r.status === 400, 'unknown status filter -> 400');
  r = await call(tokens.full, 'GET', '/api/v1/admin/licenses/search?limit=100000'); ok(r.status === 200 && r.json.items.length <= 100, 'search limit is capped');
  r = await call(tokens.full, 'GET', '/api/v1/admin/licenses/search?offset=-5'); ok(r.status === 400, 'negative offset refused');
  r = await call(tokens.full, 'GET', "/api/v1/admin/licenses/search?q=" + encodeURIComponent("x'; DROP TABLE license; --")); ok(r.status === 200 && r.json.items.length === 0, 'SQL metacharacters are inert in search');
  r = await call(tokens.full, 'POST', '/api/v1/admin/licenses/' + id + '/renew', { mode: 'NOPE', days: 5 }); ok(r.status === 400, 'unknown renew mode -> 400');
  r = await call(tokens.full, 'POST', '/api/v1/admin/licenses/' + id + '/renew', { mode: 'EXTEND_DAYS', days: 5 }); ok(r.status === 409 && r.json.code === 'ILLEGAL_TRANSITION', 'renewing a never-activated license -> 409');
  r = await call(tokens.full, 'POST', '/api/v1/admin/licenses/' + id + '/renew', { mode: 'EXTEND_DAYS', days: 0 }); ok(r.status === 400, 'renew days 0 -> 400');
  r = await call(tokens.full, 'POST', '/api/v1/admin/licenses/' + id + '/suspend', { reason: 'x'.repeat(201) }); ok(r.status === 400, 'reason > 200 chars refused');
  // --- error safety
  const errs = [await call(tokens.full, 'GET', '/api/v1/admin/licenses/not-a-uuid'), await call(tokens.full, 'POST', '/api/v1/admin/licenses', '{bad', { 'Idempotency-Key': key() }, true), await call(tokens.full, 'GET', '/api/v1/admin/zzz')];
  ok(errs.every(x => x.json && Object.keys(x.json).sort().join() === 'code,message' && !/postgres|jdbc|sql|exception|at com\.|stack|org\.|java\./i.test(x.text)), 'error bodies are {code,message} only, no SQL/stack/class names');
  // --- scopes
  const only = async (who, m, p, b) => call(tokens[who], m, p, b, { 'Idempotency-Key': key() });
  r = await only('reader', 'POST', '/api/v1/admin/licenses', body); ok(r.status === 403, 'read-only credential cannot issue (403)');
  r = await only('reader', 'POST', '/api/v1/admin/licenses/' + id + '/suspend', {}); ok(r.status === 403, 'read-only credential cannot suspend');
  r = await only('reader', 'POST', '/api/v1/admin/licenses/' + id + '/revoke', {}); ok(r.status === 403, 'read-only credential cannot revoke');
  r = await only('reader', 'POST', '/api/v1/admin/licenses/' + id + '/renew', { mode: 'EXTEND_DAYS', days: 5 }); ok(r.status === 403, 'read-only credential cannot renew');
  r = await only('reader', 'GET', '/api/v1/admin/licenses/' + id + '/audit'); ok(r.status === 403, 'read-only credential cannot read history');
  r = await only('reader', 'GET', '/api/v1/admin/audit'); ok(r.status === 403, 'read-only credential cannot read the audit trail');
  r = await only('reader', 'GET', '/api/v1/admin/stats'); ok(r.status === 200 && r.json.activityAvailable === false && r.json.last30Days === null && r.json.recent === null && r.json.licenses.total >= 2, 'read-only credential: counts yes, activity unavailable (null, not zero)');
  r = await only('reader', 'GET', '/api/v1/admin/licenses/search'); ok(r.status === 200, 'read-only credential can search');
  r = await only('lifecycle', 'POST', '/api/v1/admin/licenses', body); ok(r.status === 403, 'lifecycle credential cannot issue');
  r = await only('lifecycle', 'GET', '/api/v1/admin/audit'); ok(r.status === 403, 'lifecycle credential cannot read the audit trail');
  r = await only('issuer', 'GET', '/api/v1/admin/licenses/' + id); ok(r.status === 403, 'issue-only credential cannot read licenses');
  r = await only('issuer', 'POST', '/api/v1/admin/licenses', issueBody('issuer-only@example.com')); ok(r.status === 201, 'issue-only credential can issue');
  const before = (await only('full', 'GET', '/api/v1/admin/licenses/' + id)).json;
  await only('reader', 'POST', '/api/v1/admin/licenses/' + id + '/revoke', {});
  const after = (await only('full', 'GET', '/api/v1/admin/licenses/' + id)).json; ok(before.status === after.status && after.status === 'PENDING', 'refused scope calls changed nothing');
  // --- lifecycle over HTTP with a real device
  const dev = newDevice(); const act = await activate(dev, 'customer@example.com', code); ok(act.status === 200 && act.json.entitlement && act.json.status === 'ACTIVE', 'device activates with the issued key');
  r = await only('full', 'GET', '/api/v1/admin/licenses/' + id); ok(r.json.status === 'ACTIVE' && r.json.activeDeviceCount === 1 && r.json.activatedAt, 'detail shows activation and device count');
  r = await only('full', 'POST', '/api/v1/admin/licenses/' + id + '/suspend', { reason: 'review' }); ok(r.status === 200 && r.json.effectiveStatus === 'SUSPENDED', 'suspend');
  r = await only('full', 'POST', '/api/v1/admin/licenses/' + id + '/suspend', {}); ok(r.status === 409 && r.json.code === 'ILLEGAL_TRANSITION', 'suspending twice -> 409, nothing changed');
  r = await only('full', 'POST', '/api/v1/admin/licenses/' + id + '/renew', { mode: 'SET_END', endsAt: new Date(Date.now() + 90 * 864e5).toISOString() }); ok(r.status === 200 && r.json.effectiveStatus === 'SUSPENDED' && r.json.activeDeviceCount === 1, 'renew keeps it suspended and keeps the device bound');
  r = await only('full', 'POST', '/api/v1/admin/licenses/' + id + '/reinstate', {}); ok(r.status === 200 && r.json.effectiveStatus === 'ACTIVE', 'reinstate');
  r = await only('full', 'POST', '/api/v1/admin/licenses/' + id + '/renew', { mode: 'EXTEND_DAYS', days: 10 }); ok(r.status === 200 && r.json.activeDeviceCount === 1, 'extend by days');
  r = await only('full', 'POST', '/api/v1/admin/licenses/' + id + '/revoke', { reason: 'refund' }); ok(r.status === 200 && r.json.effectiveStatus === 'REVOKED', 'revoke');
  r = await only('full', 'POST', '/api/v1/admin/licenses/' + id + '/reinstate', {}); ok(r.status === 409, 'a revoked license cannot be reinstated');
  r = await only('full', 'GET', '/api/v1/admin/licenses/' + id + '/audit?limit=100');
  const acts = r.json.events.map(e => e.action);
  ok(['LICENSE_ISSUED', 'ACTIVATION', 'DEVICE_BOUND', 'ENTITLEMENT_ISSUED', 'LICENSE_SUSPENDED', 'LICENSE_RENEWED', 'LICENSE_REINSTATED', 'LICENSE_REVOKED'].every(a => acts.includes(a)), 'audit has every expected event: ' + [...new Set(acts)].join(','));
  ok(r.json.events.filter(e => e.action === 'LICENSE_RENEWED' && e.outcome === 'SUCCESS').every(e => /expiresFrom=/.test(e.detail) && /expiresTo=/.test(e.detail)), 'renewal audit records old and new end');
  ok(!r.text.includes(code) && !/entitlement.{0,3}eyJ/.test(r.text) && !JSON.stringify(r.json).includes(act.json.entitlement), 'audit holds neither the key nor the token');
  const post = await call(null, 'POST', '/api/v1/client/validate', undefined); ok(post.status >= 400, 'client endpoint without a body is refused');
  console.log(`\n${pass} passed, ${fail} failed`); process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
