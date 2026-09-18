// Offline tests: every DoH response is a fixture served by a fake fetch, so the
// suite never touches the network and runs the same everywhere.
'use strict';
const lib = require('../doh-compare.js');

let pass = 0, fail = 0;
function eq(name, got, want) {
  const g = JSON.stringify(got), w = JSON.stringify(want);
  if (g === w) { pass++; } else { fail++; console.log('FAIL ' + name + '\n  got  ' + g + '\n  want ' + w); }
}

const CODE = { A: 1, AAAA: 28, CNAME: 5, MX: 15, NS: 2, TXT: 16, SOA: 6, CAA: 257 };
const ans = (type, ...data) => data.map(d => ({ name: 'example.test.', type: CODE[type], TTL: 300, data: d }));
const ok = (answers, extra) => Object.assign({ Status: 0, AD: false, Answer: answers }, extra || {});

// fixtures[resolver][type] = JSON body | 'http500' | 'throw' | 'badjson'
function fakeFetch(fixtures) {
  return function (url) {
    const u = new URL(url);
    const resolver = u.hostname === 'dns.google' ? 'google' : 'cloudflare';
    const code = Number(u.searchParams.get('type'));
    const type = Object.keys(CODE).find(k => CODE[k] === code);
    const f = (fixtures[resolver] || {})[type];
    if (f === 'throw') return Promise.reject(new TypeError('network down'));
    if (f === 'http500') return Promise.resolve({ ok: false, status: 500, json: () => Promise.resolve({}) });
    if (f === 'badjson') return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ nope: 1 }) });
    const body = f === undefined ? ok([]) : f;
    return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });
  };
}
const run = (fixtures, types) => lib.compare('example.test', { types, fetch: fakeFetch(fixtures) });

(async () => {
  // --- normalize / sameRecords ---
  eq('quoted vs unquoted TXT', lib.normalize('"v=spf1 -all"'), lib.normalize('v=spf1 -all'));
  eq('split TXT chunks', lib.normalize('"v=DKIM1; k=rsa; p=MIGf" "MA0GCSqG"'), 'v=dkim1; k=rsa; p=migfma0gcsqg');
  eq('trailing dot + case', lib.normalize('NS1.Example.TEST.'), 'ns1.example.test');
  eq('order-insensitive', lib.sameRecords(ans('NS', 'b.test.', 'a.test.'), ans('NS', 'a.test', 'B.test')), true);
  eq('really different', lib.sameRecords(ans('MX', '10 a.test.'), ans('MX', '10 b.test.')), false);

  // --- cleanName ---
  eq('cleanName url', lib.cleanName('https://Www.Example.com:443/path?q=1'), 'www.example.com');
  eq('cleanName dot', lib.cleanName(' example.com. '), 'example.com');

  // --- dohUrl ---
  eq('google url', lib.dohUrl('google', 'example.com', 'MX'), 'https://dns.google/resolve?name=example.com&type=15');
  eq('cloudflare url', lib.dohUrl('cloudflare', 'example.com', 'TXT'), 'https://cloudflare-dns.com/dns-query?name=example.com&type=16');

  // --- consistent, despite Cloudflare quoting TXT ---
  let r = await run({
    google:     { A: ok(ans('A', '93.184.215.14')), TXT: ok(ans('TXT', 'v=spf1 -all')) },
    cloudflare: { A: ok(ans('A', '93.184.215.14')), TXT: ok(ans('TXT', '"v=spf1 -all"')) }
  }, ['A', 'TXT']);
  eq('TXT quoting is not a difference', r.verdict, 'consistent');
  eq('states', r.records.map(x => x.state), ['agree', 'agree']);

  // --- A differs only: geographic DNS, not an error ---
  r = await run({
    google:     { A: ok(ans('A', '104.16.1.1')), MX: ok(ans('MX', '10 mx.example.test.')) },
    cloudflare: { A: ok(ans('A', '104.16.2.2')), MX: ok(ans('MX', '10 mx.example.test.')) }
  }, ['A', 'MX']);
  eq('A-only difference is geo', r.verdict, 'geo');
  eq('geo list', r.differs.geo, ['A']);

  // --- MX differs: a real inconsistency ---
  r = await run({
    google:     { MX: ok(ans('MX', '10 old-mx.example.test.')) },
    cloudflare: { MX: ok(ans('MX', '10 new-mx.example.test.')) }
  }, ['MX']);
  eq('MX difference is inconsistent', r.verdict, 'inconsistent');
  eq('real list', r.differs.real, ['MX']);

  // --- one resolver has records, the other none ---
  r = await run({ google: { TXT: ok(ans('TXT', 'v=spf1 -all')) }, cloudflare: { TXT: ok([]) } }, ['TXT']);
  eq('missing on one side', r.verdict, 'inconsistent');
  eq('missing list', r.differs.missing, ['TXT']);

  // --- a resolver that fails is "unreachable", never "missing" ---
  r = await run({ google: { MX: ok(ans('MX', '10 mx.example.test.')) }, cloudflare: { MX: 'throw' } }, ['MX']);
  eq('failure is not a difference', r.verdict, 'consistent');
  eq('failure state', r.records[0].state, 'partial');
  eq('failure listed', r.unreachable, ['MX']);
  eq('cloudflare null', r.records[0].cloudflare, null);

  r = await run({ google: { A: 'http500' }, cloudflare: { A: 'badjson' } }, ['A']);
  eq('both fail -> unreachable', r.verdict, 'unreachable');

  // --- NXDOMAIN and SERVFAIL ---
  r = await run({ google: { A: ok([], { Status: 3 }) }, cloudflare: { A: ok([], { Status: 3 }) } }, ['A']);
  eq('nxdomain', r.verdict, 'nxdomain');
  r = await run({ google: { A: ok([], { Status: 2 }) }, cloudflare: { A: ok([], { Status: 2 }) } }, ['A']);
  eq('servfail', r.verdict, 'servfail');

  // --- no records at all but the name exists ---
  r = await run({}, ['CAA']);
  eq('no records, NOERROR', r.verdict, 'consistent');
  eq('none state', r.records[0].state, 'none');

  // --- DNSSEC AD flag, and CNAME chain only returned alongside A ---
  r = await run({
    google:     { A: ok(ans('CNAME', 'cdn.example.test.').concat(ans('A', '1.2.3.4')), { AD: true }) },
    cloudflare: { A: ok(ans('CNAME', 'cdn.example.test.').concat(ans('A', '1.2.3.4')), { AD: true }) }
  }, ['A']);
  eq('dnssec', r.dnssec, true);
  eq('cname not counted as A', r.records[0].google.map(x => x.data), ['1.2.3.4']);
  eq('chain kept', r.records[0].chain.map(x => x.data), ['cdn.example.test.']);

  // --- input validation ---
  let err = '';
  try { await lib.compare('localhost', { fetch: fakeFetch({}) }); } catch (e) { err = e.message; }
  eq('rejects non-domain', /Not a domain/.test(err), true);
  err = '';
  try { await lib.compare('example.test', { types: ['PTR'], fetch: fakeFetch({}) }); } catch (e) { err = e.message; }
  eq('rejects unsupported type', /Unsupported/.test(err), true);

  // --- TXT labels ---
  eq('spf label', /^SPF/.test(lib.txtLabel('"v=spf1 include:_spf.example.test -all"')), true);
  eq('dmarc label', /^DMARC/.test(lib.txtLabel('v=DMARC1; p=reject')), true);
  eq('no label', lib.txtLabel('hello'), '');

  console.log(`${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
