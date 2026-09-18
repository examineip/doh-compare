/*!
 * doh-compare — ask Google and Cloudflare the same DNS question over DNS-over-HTTPS
 * and tell you whether the answers really differ.
 *
 * Works in browsers and in Node 18+ (global fetch). No dependencies.
 * MIT License — https://github.com/examineip/doh-compare
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.dohCompare = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var RESOLVERS = {
    google:     { label: 'Google (8.8.8.8)',     url: 'https://dns.google/resolve' },
    cloudflare: { label: 'Cloudflare (1.1.1.1)', url: 'https://cloudflare-dns.com/dns-query' }
  };

  /* Record types, their numeric codes, and whether their answers may legitimately
   * vary with the location of whoever asks (CDNs and GeoDNS answer A/AAAA with the
   * nearest server, so two resolvers in different places often get different IPs). */
  var TYPES = {
    A:     { code: 1,   geo: true },
    AAAA:  { code: 28,  geo: true },
    CNAME: { code: 5,   geo: false },
    MX:    { code: 15,  geo: false },
    NS:    { code: 2,   geo: false },
    TXT:   { code: 16,  geo: false },
    SOA:   { code: 6,   geo: false },
    CAA:   { code: 257, geo: false }
  };
  var DEFAULT_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA'];

  var RCODE = { NOERROR: 0, SERVFAIL: 2, NXDOMAIN: 3 };

  function dohUrl(resolver, name, type) {
    var r = RESOLVERS[resolver];
    if (!r) throw new Error('Unknown resolver: ' + resolver);
    var t = TYPES[type];
    if (!t) throw new Error('Unsupported record type: ' + type);
    var u = new URL(r.url);
    u.searchParams.set('name', name);
    u.searchParams.set('type', String(t.code));
    return u.toString();
  }

  /**
   * One DoH JSON query. Resolves to
   *   { ok: true, status, ad, answers: [{name, type, TTL, data}] }
   * or { ok: false, error } when the resolver could not be reached or replied badly.
   * A failed query is reported as a failure — never as "no records".
   */
  function query(resolver, name, type, opts) {
    opts = opts || {};
    var f = opts.fetch || (typeof fetch === 'function' ? fetch : null);
    if (!f) return Promise.reject(new Error('No fetch available (Node 18+ or a browser is required)'));
    var timeout = opts.timeout || 8000;
    var ctrl = typeof AbortController === 'function' ? new AbortController() : null;
    var timer = ctrl ? setTimeout(function () { ctrl.abort(); }, timeout) : null;

    return f(dohUrl(resolver, name, type), {
      headers: { Accept: 'application/dns-json' },
      cache: 'no-store',
      signal: ctrl ? ctrl.signal : undefined
    }).then(function (r) {
      if (!r.ok) return { ok: false, error: 'HTTP ' + r.status };
      return r.json().then(function (j) {
        if (!j || typeof j.Status !== 'number') return { ok: false, error: 'Malformed response' };
        var code = TYPES[type].code;
        var all = Array.isArray(j.Answer) ? j.Answer : [];
        return {
          ok: true,
          status: j.Status,
          ad: !!j.AD,
          answers: all.filter(function (a) { return a.type === code; }),
          chain: all.filter(function (a) { return a.type === 5 && code !== 5; })
        };
      });
    }).catch(function (e) {
      return { ok: false, error: e && e.name === 'AbortError' ? 'Timed out' : String(e && e.message || e) };
    }).then(function (res) {
      if (timer) clearTimeout(timer);
      return res;
    });
  }

  /* The two resolvers format identical records differently: Cloudflare wraps TXT
   * values in quotes and Google does not, long TXT records arrive split into quoted
   * chunks, and trailing dots and letter case on names vary. Comparing raw strings
   * reports a "difference" for almost every domain with a TXT record, so normalise
   * first. */
  function normalize(value) {
    return String(value).trim()
      .replace(/"\s+"/g, '')
      .replace(/^"|"$/g, '')
      .replace(/\s+/g, ' ')
      .replace(/\.$/, '')
      .toLowerCase();
  }

  function values(answers) {
    return answers.map(function (a) { return normalize(a.data); }).sort();
  }

  function sameRecords(a, b) {
    return values(a).join('\n') === values(b).join('\n');
  }

  /**
   * Pure classification of two resolvers' results for a set of types. Exposed so
   * it can be tested without the network.
   *   results: { TYPE: { google: queryResult, cloudflare: queryResult } }
   */
  function classify(results) {
    var records = [];
    var geo = [], real = [], missing = [], unreachable = [];
    var anyAnswer = false, nx = 0, servfail = 0, reached = 0;
    var dnssec = false;

    Object.keys(results).forEach(function (type) {
      var g = results[type].google, c = results[type].cloudflare;
      [g, c].forEach(function (r) {
        if (!r || !r.ok) return;
        reached++;
        if (r.status === RCODE.NXDOMAIN) nx++;
        if (r.status === RCODE.SERVFAIL) servfail++;
        if (r.ad) dnssec = true;
      });

      var gOk = !!(g && g.ok), cOk = !!(c && c.ok);
      var ga = gOk ? g.answers : [], ca = cOk ? c.answers : [];
      if (ga.length || ca.length) anyAnswer = true;

      var state;
      if (!gOk && !cOk) { state = 'unreachable'; unreachable.push(type); }
      else if (!gOk || !cOk) { state = 'partial'; unreachable.push(type); }
      else if (!ga.length && !ca.length) state = 'none';
      else if (sameRecords(ga, ca)) state = 'agree';
      else if (!ga.length || !ca.length) { state = 'missing'; missing.push(type); }
      else if (TYPES[type] && TYPES[type].geo) { state = 'geo'; geo.push(type); }
      else { state = 'differ'; real.push(type); }

      records.push({
        type: type,
        state: state,
        google: gOk ? ga.map(function (a) { return { data: a.data, ttl: a.TTL }; }) : null,
        cloudflare: cOk ? ca.map(function (a) { return { data: a.data, ttl: a.TTL }; }) : null,
        chain: (gOk ? g.chain : cOk ? c.chain : null) || []
      });
    });

    var verdict;
    if (!reached) verdict = 'unreachable';
    else if (!anyAnswer && nx) verdict = 'nxdomain';
    else if (!anyAnswer && servfail) verdict = 'servfail';
    else if (missing.length || real.length) verdict = 'inconsistent';
    else if (geo.length) verdict = 'geo';
    else verdict = 'consistent';

    return {
      verdict: verdict,
      dnssec: dnssec,
      differs: { real: real, geo: geo, missing: missing },
      unreachable: unreachable,
      records: records
    };
  }

  var SUMMARY = {
    consistent: 'Both resolvers returned the same records for every type checked.',
    geo: 'Only location-dependent records (A/AAAA) differ. That is normal for CDNs and GeoDNS: each resolver gets the server nearest to it.',
    inconsistent: 'Records that should not vary by location differ, or one resolver has records the other lacks. A change may still be propagating, or two sets of nameservers are serving different data.',
    nxdomain: 'NXDOMAIN: the name does not exist (not registered, or its zone is gone). That is different from a domain with no records.',
    servfail: 'SERVFAIL: the nameservers are unreachable or misconfigured, or DNSSEC validation failed.',
    unreachable: 'Neither resolver could be reached, so nothing can be concluded.'
  };

  function cleanName(input) {
    return String(input || '').trim().toLowerCase()
      .replace(/^[a-z][a-z0-9+.-]*:\/\//, '')
      .replace(/[\/?#].*$/, '')
      .replace(/:\d+$/, '')
      .replace(/\.$/, '');
  }

  /**
   * Compare every requested type across both resolvers.
   * opts: { types: ['A','MX',...], fetch, timeout }
   */
  function compare(name, opts) {
    opts = opts || {};
    var domain = cleanName(name);
    if (!domain || domain.indexOf('.') < 1) {
      return Promise.reject(new Error('Not a domain name: ' + name));
    }
    var types = (opts.types || DEFAULT_TYPES).map(function (t) { return String(t).toUpperCase(); });
    types.forEach(function (t) { if (!TYPES[t]) throw new Error('Unsupported record type: ' + t); });

    var jobs = [];
    types.forEach(function (t) {
      jobs.push(query('google', domain, t, opts));
      jobs.push(query('cloudflare', domain, t, opts));
    });
    return Promise.all(jobs).then(function (res) {
      var results = {};
      types.forEach(function (t, i) { results[t] = { google: res[i * 2], cloudflare: res[i * 2 + 1] }; });
      var out = classify(results);
      out.name = domain;
      out.summary = SUMMARY[out.verdict];
      return out;
    });
  }

  /* Plain-English labels for the TXT records people actually look for. */
  function txtLabel(value) {
    var s = normalize(value);
    if (/^v=spf1/.test(s)) return 'SPF: which servers may send mail for this domain';
    if (/^v=dmarc1/.test(s)) return 'DMARC: what to do with mail that fails authentication';
    if (/^v=dkim1/.test(s)) return 'DKIM: public key used to verify signed mail';
    if (/^google-site-verification=/.test(s)) return 'Google ownership verification';
    if (/^ms=/.test(s)) return 'Microsoft ownership verification';
    return '';
  }

  return {
    RESOLVERS: RESOLVERS,
    TYPES: TYPES,
    DEFAULT_TYPES: DEFAULT_TYPES,
    SUMMARY: SUMMARY,
    dohUrl: dohUrl,
    query: query,
    normalize: normalize,
    sameRecords: sameRecords,
    classify: classify,
    compare: compare,
    cleanName: cleanName,
    txtLabel: txtLabel
  };
});

/* ---------- CLI: node doh-compare.js example.com [MX TXT ...] [--json] ---------- */
if (typeof require === 'function' && typeof module === 'object' && require.main === module) {
  (function () {
    var lib = module.exports;
    var args = process.argv.slice(2);
    var json = args.indexOf('--json') !== -1;
    args = args.filter(function (a) { return a !== '--json'; });
    if (!args.length || args[0] === '-h' || args[0] === '--help') {
      console.log('Usage: node doh-compare.js <domain> [TYPE ...] [--json]\n' +
        'Types: ' + Object.keys(lib.TYPES).join(' ') + '  (default: ' + lib.DEFAULT_TYPES.join(' ') + ')');
      process.exit(args.length ? 0 : 1);
    }
    var name = args[0];
    var types = args.slice(1).length ? args.slice(1) : undefined;
    lib.compare(name, { types: types }).then(function (r) {
      if (json) { console.log(JSON.stringify(r, null, 2)); return; }
      console.log(r.name + ' — ' + r.verdict.toUpperCase() + (r.dnssec ? ' (DNSSEC validated)' : ''));
      console.log(r.summary + '\n');
      r.records.forEach(function (rec) {
        console.log(rec.type + ' [' + rec.state + ']');
        var g = rec.google, c = rec.cloudflare;
        if (rec.state === 'agree') {
          g.forEach(function (a) {
            var label = rec.type === 'TXT' ? lib.txtLabel(a.data) : '';
            console.log('  ' + a.data + (label ? '   <- ' + label : ''));
          });
        } else if (rec.state !== 'none') {
          console.log('  Google:     ' + (g ? (g.map(function (a) { return a.data; }).join(', ') || '(none)') : '(unreachable)'));
          console.log('  Cloudflare: ' + (c ? (c.map(function (a) { return a.data; }).join(', ') || '(none)') : '(unreachable)'));
        }
      });
      process.exitCode = r.verdict === 'inconsistent' ? 2 : (r.verdict === 'consistent' || r.verdict === 'geo') ? 0 : 1;
    }).catch(function (e) {
      console.error(String(e.message || e));
      process.exitCode = 1;
    });
  })();
}
