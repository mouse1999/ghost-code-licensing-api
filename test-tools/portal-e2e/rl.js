const { call, tokens } = require('./lib'); (async () => {
  let s = []; for (let i = 0; i < 12; i++) s.push((await call('bad' + i, 'GET', '/api/v1/admin/stats')).status);
  const ok = await call(tokens.full, 'GET', '/api/v1/admin/stats');
  console.log('statuses', s.join(','), 'then valid token ->', ok.status, ok.headers.get('retry-after'));
  const noLeak = s.slice(10).every(x => x === 429) && ok.status === 429; console.log(noLeak ? 'PASS rate limit locks the client after 10 failures (also the valid token from the same address, as documented)' : 'FAIL'); process.exit(noLeak ? 0 : 1); })();
