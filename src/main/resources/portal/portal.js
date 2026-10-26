(function () {
  'use strict';
  /* Administrator portal. The token lives only in this closure; nothing is written to storage, cookies or URLs.
     All server text is rendered with textContent, never as HTML. */
  var API = '/api/v1/admin';
  var token = null;
  var RIGHTS = ['LIVE', 'AI_LIVE', 'DSA', 'SCREEN_QUESTION'];
  var PRESETS = [30, 90, 180, 365];
  var PAGE = 25;
  var $ = function (id) { return document.getElementById(id); };

  function el(tag, attrs) {
    var e = document.createElement(tag);
    if (attrs) { Object.keys(attrs).forEach(function (k) { if (k === 'text') e.textContent = attrs[k]; else e.setAttribute(k, attrs[k]); }); }
    for (var i = 2; i < arguments.length; i++) { var c = arguments[i]; if (c != null) e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); }
    return e;
  }
  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }
  function show(n, on) { if (on) n.removeAttribute('hidden'); else n.setAttribute('hidden', ''); }
  function fmt(iso) { return iso ? new Date(iso).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC').replace(/:\d\d UTC$/, ' UTC') : '—'; }
  function say(node, msg) { node.textContent = msg || ''; show(node, !!msg); }
  function banner(msg) { say($('banner'), msg); }

  // ---------------------------------------------------------------- API
  function ApiFailure(status, code, message, retryAfter) { this.status = status; this.code = code; this.message = message; this.retryAfter = retryAfter; }
  function api(method, path, body, headers) {
    var init = { method: method, cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer',
      headers: Object.assign({ 'Authorization': 'Bearer ' + token, 'Accept': 'application/json' }, headers || {}) };
    if (body !== undefined) { init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(body); }
    return fetch(API + path, init).then(function (r) {
      return r.text().then(function (t) {
        var data = null; try { data = t ? JSON.parse(t) : null; } catch (e) { data = null; }
        if (r.ok) return data;
        if (r.status === 401) { signOut('Your session is not valid. Sign in again.'); }
        throw new ApiFailure(r.status, data && data.code, (data && data.message) || ('The server answered ' + r.status + '.'), r.headers.get('Retry-After'));
      });
    }, function () { throw new ApiFailure(0, 'NETWORK', 'The server could not be reached. Nothing was changed by this attempt unless you retry and see a result.'); });
  }
  function explain(e) {
    if (e instanceof ApiFailure) {
      if (e.status === 429) return 'Too many attempts. Try again in ' + (e.retryAfter || 'a minute') + ' seconds.';
      if (e.status === 403) return 'This credential is not allowed to do that (' + e.message + ').';
      return e.message;
    }
    return 'Unexpected error in the page.';
  }

  // ---------------------------------------------------------------- views
  var VIEWS = ['dashboard', 'issue', 'licenses', 'audit'];
  var currentView = null;
  function showView(name) {
    wipeKey();
    currentView = name;
    banner('');
    ['login'].concat(VIEWS).forEach(function (v) { show($('view-' + v), v === name); });
    Array.prototype.forEach.call(document.querySelectorAll('button.tab'), function (b) {
      if (b.getAttribute('data-view') === name) b.setAttribute('aria-current', 'true'); else b.removeAttribute('aria-current');
    });
    if (name === 'dashboard') loadStats();
    if (name === 'issue') resetIssue();
    if (name === 'licenses') { show($('list-wrap'), true); show($('detail-wrap'), false); if (!listLoaded) runSearch(0); }
    if (name === 'audit') loadAudit(true);
  }
  function signOut(msg) {
    token = null; listLoaded = false; wipeKey();
    $('token').value = '';
    show($('nav'), false);
    clear($('stats')); clear($('detail')); clear($('history')); clear($('audit-list')); clear($('results').tBodies[0]);
    showView('login');
    say($('login-error'), msg || '');
  }

  // ---------------------------------------------------------------- sign in
  $('login-form').addEventListener('submit', function (ev) {
    ev.preventDefault();
    var t = $('token').value.trim();
    if (!t) return;
    token = t; $('token').value = '';
    $('login-btn').disabled = true;
    api('GET', '/stats').then(function () { show($('nav'), true); say($('login-error'), ''); showView('dashboard'); },
      function (e) {
        if (e instanceof ApiFailure && e.status === 403) { token = null; say($('login-error'), 'This token is valid but lacks the license-read permission needed for the portal.'); }
        else if (e instanceof ApiFailure && e.status === 401) { token = null; say($('login-error'), 'That token was not accepted.'); }
        else { token = null; say($('login-error'), explain(e)); }
      }).then(function () { $('login-btn').disabled = false; });
  });
  $('signout').addEventListener('click', function () { signOut('Signed out.'); });
  Array.prototype.forEach.call(document.querySelectorAll('button.tab'), function (b) {
    b.addEventListener('click', function () { showView(b.getAttribute('data-view')); });
  });

  // ---------------------------------------------------------------- dashboard
  function statCard(label, value, note) {
    return el('div', { 'class': 'stat' }, el('b', { text: String(value) }), el('span', { text: label }), note ? el('div', { 'class': 'muted', text: note }) : null);
  }
  function loadStats() {
    var box = $('stats'); clear(box); box.appendChild(el('p', { 'class': 'muted', text: 'Loading…' }));
    api('GET', '/stats').then(function (s) {
      clear(box);
      var c = s.licenses;
      box.appendChild(el('p', { 'class': 'muted', text: 'Counted from the database at ' + fmt(s.generatedAt) + '. Expired = activated and past its end date; lapsed = never activated in time.' }));
      box.appendChild(el('div', { 'class': 'cards' }, statCard('Total', c.total), statCard('Active', c.active), statCard('Awaiting activation', c.pending),
        statCard('Expired', c.expiredAfterActivation), statCard('Lapsed, never activated', c.lapsedUnactivated), statCard('Suspended', c.suspended), statCard('Revoked', c.revoked)));
      if (!s.activityAvailable) {
        box.appendChild(el('div', { 'class': 'card' }, el('h3', { text: 'Activity' }), el('p', { 'class': 'warn', text: 'Unavailable: this credential has no audit-read permission, so activity figures cannot be shown. This is not zero.' })));
        return;
      }
      var w = s.last30Days, a = s.allRecorded;
      box.appendChild(el('div', { 'class': 'card' }, el('h3', { text: 'Activity (from the audit trail)' }),
        el('p', { 'class': 'muted', text: s.activityRecordedSince ? 'Events have been recorded since ' + fmt(s.activityRecordedSince) + '.' : 'No events have been recorded yet, so every figure below is a real zero.' }),
        el('div', { 'class': 'cards' },
          statCard('Activations OK (30 days)', w.activationSuccesses, 'all recorded: ' + a.activationSuccesses),
          statCard('Activations failed (30 days)', w.activationFailures, 'all recorded: ' + a.activationFailures),
          statCard('Licenses issued (30 days)', w.licensesIssued, 'all recorded: ' + a.licensesIssued),
          statCard('Validations refused (30 days)', w.validationRejections, 'all recorded: ' + a.validationRejections))));
      var ol = el('ol', { 'class': 'history' });
      s.recent.forEach(function (ev) { ol.appendChild(eventItem(ev, true)); });
      if (!s.recent.length) ol.appendChild(el('li', { 'class': 'muted', text: 'No recent events.' }));
      box.appendChild(el('div', { 'class': 'card' }, el('h3', { text: 'Recent activity' }), ol));
    }, function (e) { clear(box); box.appendChild(el('p', { 'class': 'error', text: 'Could not load the figures: ' + explain(e) })); });
  }
  $('refresh-stats').addEventListener('click', loadStats);

  // ---------------------------------------------------------------- issuance
  var issueState = null;   // { body, key, summary }
  function buildIssueControls() {
    var p = $('i-presets'); clear(p);
    PRESETS.forEach(function (d, i) {
      p.appendChild(el('label', null, el('input', { type: 'radio', name: 'i-dur', value: String(d) }), d + ' days'));
    });
    var r = $('i-rights'); clear(r);
    RIGHTS.forEach(function (x) { r.appendChild(el('label', null, el('input', { type: 'checkbox', 'data-right': x, checked: 'checked' }), x)); });
  }
  buildIssueControls();
  function resetIssue() {
    issueState = null;
    $('issue-form').reset(); buildIssueControls();
    var first = document.querySelector('input[name=i-dur][value="365"]'); if (first) first.checked = true;
    show($('issue-form-wrap'), true); show($('issue-review'), false); show($('issue-done'), false);
    say($('issue-error'), ''); say($('review-error'), '');
  }
  function duration() {
    var chosen = document.querySelector('input[name=i-dur]:checked');
    if (!chosen) return { error: 'Choose a duration.' };
    if (chosen.value === 'custom') {
      var n = Number($('i-days').value);
      if (!Number.isInteger(n) || n < 1 || n > 3650) return { error: 'Custom days must be a whole number from 1 to 3650.' };
      return { days: n, text: n + ' days from activation' };
    }
    if (chosen.value === 'date') {
      var d = $('i-date').value;
      if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) return { error: 'Choose the end date.' };
      var end = new Date(d + 'T23:59:59Z');
      if (!(end.getTime() > Date.now())) return { error: 'The end date must be in the future.' };
      return { expiresAt: end.toISOString().replace(/\.\d+Z$/, 'Z'), text: 'ends ' + fmt(end.toISOString()) };
    }
    if (chosen.value === 'none') return { none: true, text: 'no end date' };
    return { days: Number(chosen.value), text: chosen.value + ' days from activation' };
  }
  $('issue-form').addEventListener('submit', function (ev) {
    ev.preventDefault();
    var email = $('i-email').value.trim();
    if (!email || !$('i-email').checkValidity()) return say($('issue-error'), 'Enter a valid customer email.');
    var dur = duration(); if (dur.error) return say($('issue-error'), dur.error);
    var rights = []; Array.prototype.forEach.call(document.querySelectorAll('#i-rights input'), function (c) { if (c.checked) rights.push(c.getAttribute('data-right')); });
    if (!rights.length) return say($('issue-error'), 'Choose at least one right.');
    var dev = Number($('i-devices').value), win = Number($('i-window').value);
    if (!Number.isInteger(dev) || dev < 1 || dev > 10) return say($('issue-error'), 'Device limit must be 1 to 10.');
    if (!Number.isInteger(win) || win < 1 || win > 365) return say($('issue-error'), 'Activation window must be 1 to 365 days.');
    if (!$('i-paid').checked) return say($('issue-error'), 'Confirm that you verified the payment before issuing.');
    say($('issue-error'), '');
    var body = { customerEmail: email, paymentVerified: true, paymentReference: $('i-ref').value.trim() || null,
      policy: { deviceLimit: dev, validityDays: dur.days || null, rights: rights, activationWindowDays: win } };
    if (dur.expiresAt) body.expiresAt = dur.expiresAt;
    var key = (window.crypto && crypto.randomUUID ? crypto.randomUUID() : String(Date.now()) + Math.random().toString(16).slice(2)).replace(/[^A-Za-z0-9]/g, '');
    if (key.length < 16) key = (key + '0123456789abcdef').slice(0, 32);
    issueState = { body: body, key: key, sent: false };
    var l = $('review-list'); clear(l);
    [['Customer', email], ['Term', dur.text], ['Devices', String(dev)], ['Rights', rights.join(', ')],
     ['Activation window', win + ' days from now'], ['Payment reference', body.paymentReference || '—'],
     ['Payment', 'You confirm it was verified outside this application']].forEach(function (r) { l.appendChild(el('dt', { text: r[0] })); l.appendChild(el('dd', { text: r[1] })); });
    show($('issue-form-wrap'), false); show($('issue-review'), true); say($('review-error'), '');
    $('issue-confirm').disabled = false;
  });
  $('issue-back').addEventListener('click', function () { issueState = null; show($('issue-review'), false); show($('issue-form-wrap'), true); });
  var issued = null;
  $('issue-confirm').addEventListener('click', function () {
    if (!issueState || $('issue-confirm').disabled) return;
    $('issue-confirm').disabled = true; $('issue-back').disabled = true; say($('review-error'), '');
    // The same Idempotency-Key is reused if this attempt must be retried, so a double click or a network retry cannot create two licenses.
    api('POST', '/licenses', issueState.body, { 'Idempotency-Key': issueState.key }).then(function (r) {
      issued = r.license;
      show($('issue-review'), false); show($('issue-done'), true);
      if (r.activationCode) {
        $('key-value').textContent = r.activationCode; $('key-copy').disabled = false;
        say($('copy-note'), '');
      } else {
        $('key-value').textContent = '(not available)'; $('key-copy').disabled = true;
        say($('copy-note'), 'This request had already been completed earlier, so the key cannot be shown again. If the key was lost, revoke this license and issue a new one.');
      }
      var d = $('done-list'); clear(d);
      [['License', r.license.id], ['Customer', r.license.customerEmail], ['Status', r.license.effectiveStatus],
       ['Activate by', fmt(r.license.activationDeadline)], ['Ends', r.license.expiresAt ? fmt(r.license.expiresAt) : r.license.validityDays ? r.license.validityDays + ' days after activation' : 'never']]
        .forEach(function (x) { d.appendChild(el('dt', { text: x[0] })); d.appendChild(el('dd', { text: x[1] })); });
      issueState = null;
    }, function (e) {
      say($('review-error'), explain(e) + (e instanceof ApiFailure && e.status === 0 ? ' You can press Confirm again: it will not create a duplicate.' : ''));
      $('issue-confirm').disabled = false; $('issue-back').disabled = false;
    });
  });
  function wipeKey() { $('key-value').textContent = ''; say($('copy-note'), ''); issued = null; }
  $('key-copy').addEventListener('click', function () {
    var v = $('key-value').textContent;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(v).then(function () { say($('copy-note'), 'Copied. Paste it into your private message now.'); },
        function () { say($('copy-note'), 'Copy was blocked by the browser. Select the key and copy it manually.'); });
    } else { say($('copy-note'), 'Copy is not available here. Select the key and copy it manually.'); }
  });
  $('done-close').addEventListener('click', function () { wipeKey(); resetIssue(); });
  $('done-open').addEventListener('click', function () { var id = issued && issued.id; wipeKey(); if (id) { showView('licenses'); openDetail(id); } });

  // ---------------------------------------------------------------- list
  var listLoaded = false, offset = 0, lastQuery = { q: '', status: '' };
  function qs(o) { return Object.keys(o).filter(function (k) { return o[k] !== '' && o[k] != null; }).map(function (k) { return encodeURIComponent(k) + '=' + encodeURIComponent(o[k]); }).join('&'); }
  function badge(s) { return el('span', { 'class': 'badge', text: s }); }
  function runSearch(off) {
    offset = off; listLoaded = true;
    var tb = $('results').tBodies[0]; clear(tb);
    api('GET', '/licenses/search?' + qs({ q: lastQuery.q, status: lastQuery.status, limit: PAGE, offset: off })).then(function (r) {
      r.items.forEach(function (l) {
        var tr = el('tr', { tabindex: '0' },
          el('td', { text: l.customerEmail }), el('td', null, badge(l.effectiveStatus)), el('td', { text: fmt(l.createdAt) }),
          el('td', { text: l.expiresAt ? fmt(l.expiresAt) : l.validityDays ? l.validityDays + ' d after activation' : 'never' }),
          el('td', { text: l.activatedAt ? 'Activated' : 'Not activated' }), el('td', { text: l.activeDeviceCount + ' / ' + l.deviceLimit }));
        tr.addEventListener('click', function () { openDetail(l.id); });
        tr.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') openDetail(l.id); });
        tb.appendChild(tr);
      });
      $('prev').disabled = off === 0; $('next').disabled = !r.hasMore;
      $('page-note').textContent = r.items.length ? 'Showing ' + (off + 1) + '–' + (off + r.items.length) : 'No licenses match.';
    }, function (e) { $('page-note').textContent = 'Could not load: ' + explain(e); });
  }
  $('search-form').addEventListener('submit', function (ev) { ev.preventDefault(); lastQuery = { q: $('s-q').value.trim(), status: $('s-status').value }; runSearch(0); });
  $('prev').addEventListener('click', function () { runSearch(Math.max(0, offset - PAGE)); });
  $('next').addEventListener('click', function () { runSearch(offset + PAGE); });
  $('back-list').addEventListener('click', function () { show($('detail-wrap'), false); show($('list-wrap'), true); runSearch(offset); });

  // ---------------------------------------------------------------- detail
  var open = null, historyNext = null;
  function openDetail(id) {
    show($('list-wrap'), false); show($('detail-wrap'), true); banner('');
    api('GET', '/licenses/' + encodeURIComponent(id)).then(function (l) { open = l; renderDetail(l); loadHistory(l.id, true); },
      function (e) { banner('Could not load the license: ' + explain(e)); show($('detail-wrap'), false); show($('list-wrap'), true); });
  }
  function renderDetail(l) {
    var d = $('detail'); clear(d);
    d.appendChild(el('h2', { text: l.customerEmail }));
    var dl = el('dl');
    [['License id', l.id], ['Status', l.effectiveStatus + (l.status !== l.effectiveStatus ? ' (stored: ' + l.status + ')' : '')],
     ['Issued', fmt(l.createdAt)], ['Duration', l.validityDays ? l.validityDays + ' days from activation' : l.expiresAt ? 'fixed end date' : 'no end date'],
     ['Expires', l.expiresAt ? fmt(l.expiresAt) : 'not set until activation'], ['Activation', l.activatedAt ? 'Activated ' + fmt(l.activatedAt) : 'Not activated; activate by ' + fmt(l.activationDeadline)],
     ['Devices', l.activeDeviceCount + ' of ' + l.deviceLimit], ['Rights', l.rights.join(', ')],
     ['Suspended', l.suspendedAt ? fmt(l.suspendedAt) : '—'], ['Revoked', l.revokedAt ? fmt(l.revokedAt) : '—'],
     ['Last activity', 'see the newest history entry below']].forEach(function (r) { dl.appendChild(el('dt', { text: r[0] })); dl.appendChild(el('dd', { text: r[1] })); });
    d.appendChild(dl);
    var a = $('detail-actions'); clear(a);
    var s = l.effectiveStatus;
    function act(label, cls, fn) { var b = el('button', { type: 'button', 'class': cls || '', text: label }); b.addEventListener('click', fn); a.appendChild(b); }
    if (s === 'ACTIVE' || s === 'PENDING') act('Suspend', 'ghost', function () { lifecycle('suspend', l, 'Suspend this license?', 'The customer will lose access at their next check. You can reinstate it later.'); });
    if (s === 'SUSPENDED') act('Reinstate', '', function () { lifecycle('reinstate', l, 'Reinstate this license?', 'Access returns at the customer\'s next check.'); });
    if (l.activatedAt && s !== 'REVOKED') act('Renew', '', function () { renewDialog(l); });
    if (s !== 'REVOKED') act('Revoke', 'danger', function () { lifecycle('revoke', l, 'Revoke this license permanently?', 'This cannot be undone. The customer loses access and the license can never be renewed.'); });
    if (!a.firstChild) a.appendChild(el('span', { 'class': 'muted', text: 'No actions are available for this license.' }));
  }
  function loadHistory(id, fresh) {
    var ol = $('history');
    if (fresh) { clear(ol); historyNext = null; }
    api('GET', '/licenses/' + encodeURIComponent(id) + '/audit?limit=50' + (historyNext ? '&beforeId=' + historyNext : '')).then(function (p) {
      p.events.forEach(function (ev) { ol.appendChild(eventItem(ev, false)); });
      if (!ol.firstChild) ol.appendChild(el('li', { 'class': 'muted', text: 'No history recorded.' }));
      historyNext = p.nextBeforeId; show($('history-more'), historyNext != null);
    }, function (e) { ol.appendChild(el('li', { 'class': 'muted', text: e instanceof ApiFailure && e.status === 403 ? 'History is unavailable: this credential has no audit-read permission.' : 'History could not be loaded: ' + explain(e) })); show($('history-more'), false); });
  }
  $('history-more').addEventListener('click', function () { if (open) loadHistory(open.id, false); });
  function eventItem(ev, withLicense) {
    var t = fmt(ev.occurredAt) + ' · ' + ev.action + ' · ' + ev.outcome + ' · ' + ev.actor;
    return el('li', null, el('div', { text: t }), ev.detail ? el('div', { 'class': 'muted', text: ev.detail }) : null);
  }
  var auditNext = null;
  function loadAudit(fresh) {
    var ol = $('audit-list'); if (fresh) { clear(ol); auditNext = null; }
    api('GET', '/audit?limit=50' + (auditNext ? '&beforeId=' + auditNext : '')).then(function (p) {
      p.events.forEach(function (ev) { ol.appendChild(eventItem(ev, true)); });
      if (!ol.firstChild) ol.appendChild(el('li', { 'class': 'muted', text: 'No events recorded.' }));
      auditNext = p.nextBeforeId; show($('audit-more'), auditNext != null);
    }, function (e) { ol.appendChild(el('li', { 'class': 'error', text: e instanceof ApiFailure && e.status === 403 ? 'The audit trail is unavailable: this credential has no audit-read permission.' : explain(e) })); show($('audit-more'), false); });
  }
  $('audit-more').addEventListener('click', function () { loadAudit(false); });

  // ---------------------------------------------------------------- consequential actions
  var dlg = $('confirm'), pending = null;
  function ask(title, text, okLabel, danger, fields, onOk) {
    $('confirm-title').textContent = title; $('confirm-text').textContent = text;
    var f = $('confirm-fields'); clear(f); (fields || []).forEach(function (n) { f.appendChild(n); });
    var ok = $('confirm-ok'); ok.textContent = okLabel; ok.className = danger ? 'danger' : ''; ok.disabled = false;
    pending = onOk;
    if (dlg.showModal) dlg.showModal(); else dlg.setAttribute('open', '');
  }
  $('confirm-cancel').addEventListener('click', function () { pending = null; dlg.close(); });
  $('confirm-form').addEventListener('submit', function (ev) {
    ev.preventDefault();
    var fn = pending; if (!fn) return;
    var ok = $('confirm-ok'); if (ok.disabled) return; ok.disabled = true;   // duplicate-submission guard
    fn().then(function (err) { if (err) { $('confirm-text').textContent = err; ok.disabled = false; } else { pending = null; dlg.close(); } });
  });
  function reasonField() { return el('label', null, 'Reason (optional, recorded in the audit trail)', el('input', { id: 'c-reason', maxlength: '200' })); }
  function lifecycle(action, l, title, text) {
    ask(title, l.customerEmail + ': ' + text, action.charAt(0).toUpperCase() + action.slice(1), action === 'revoke', [reasonField()], function () {
      return api('POST', '/licenses/' + encodeURIComponent(l.id) + '/' + action, { reason: $('c-reason').value.trim() || null }).then(function (r) {
        open = r; renderDetail(r); loadHistory(r.id, true); return null;
      }, function (e) { return explain(e); });
    });
  }
  function renewDialog(l) {
    var r1 = el('input', { type: 'radio', name: 'c-mode', value: 'EXTEND_DAYS', checked: 'checked' }), r2 = el('input', { type: 'radio', name: 'c-mode', value: 'SET_END' });
    var days = el('input', { id: 'c-days', type: 'number', min: '1', max: '3650', value: '365', 'class': 'short' }), date = el('input', { id: 'c-date', type: 'date' });
    var fields = [el('label', { 'class': 'inline' }, r1, 'Extend by days', days), el('label', { 'class': 'inline' }, r2, 'Set exact end date (UTC, end of day)', date), reasonField()];
    ask('Renew subscription', l.customerEmail + ': renewing changes only the end date. Devices stay bound; a suspended license stays suspended. The payment for the renewal is verified outside this application.', 'Renew', false, fields, function () {
      var body = { reason: $('c-reason').value.trim() || null };
      if (r2.checked) {
        if (!/^\d{4}-\d{2}-\d{2}$/.test(date.value)) return Promise.resolve('Choose the end date.');
        body.mode = 'SET_END'; body.endsAt = new Date(date.value + 'T23:59:59Z').toISOString().replace(/\.\d+Z$/, 'Z');
      } else {
        var n = Number(days.value); if (!Number.isInteger(n) || n < 1 || n > 3650) return Promise.resolve('Days must be 1 to 3650.');
        body.mode = 'EXTEND_DAYS'; body.days = n;
      }
      return api('POST', '/licenses/' + encodeURIComponent(l.id) + '/renew', body).then(function (r) { open = r; renderDetail(r); loadHistory(r.id, true); return null; }, function (e) { return explain(e); });
    });
  }

  showView('login');
})();
