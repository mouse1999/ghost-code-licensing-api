// Shared helpers: talk to the Phase 134 HttpHarness (real controllers/services/PostgreSQL) and act as a desktop device.
const crypto = require('crypto');
const b64u = b => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
exports.B = process.env.BASE || 'http://127.0.0.1:8181';
exports.tokens = JSON.parse(require('fs').readFileSync(process.env.HOUT || '/tmp/claude-0/-home-claude/a665147f-a271-5996-96ed-3fad231d1db4/scratchpad/hout/harness.json'));
exports.call = async (token, method, path, body, headers = {}, raw = false) => {
  const h = { ...headers }; if (token) h.Authorization = 'Bearer ' + token;
  if (body !== undefined && !h['Content-Type']) h['Content-Type'] = 'application/json';
  const r = await fetch(exports.B + path, { method, headers: h, body: body === undefined ? undefined : (raw ? body : JSON.stringify(body)) });
  const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch (e) {}
  return { status: r.status, text, json, headers: r.headers };
};
exports.newDevice = () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  return { privateKey, pub: b64u(spki), thumb: crypto.createHash('sha256').update(spki).digest('hex') };
};
exports.activate = async (d, email, code) => {
  const ts = Math.floor(Date.now() / 1000) + Number(process.env.SKEW || 0), nonce = b64u(crypto.randomBytes(16));
  const msg = `ia-license-v1\nactivate\n${email.toLowerCase()}\n${d.thumb}\n${ts}\n${nonce}`;
  const sig = b64u(crypto.sign(null, Buffer.from(msg), d.privateKey));
  return exports.call(null, 'POST', '/api/v1/client/activate', { email, activationCode: code, devicePublicKey: d.pub, proofTimestamp: ts, proofNonce: nonce, proofSignature: sig, deviceLabel: 'e2e' });
};
exports.skewNow = async () => (await exports.call(null, 'GET', '/__now')).json.now;
