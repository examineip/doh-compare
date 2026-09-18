# doh-compare

Ask **Google** and **Cloudflare** the same DNS question over DNS-over-HTTPS, then tell you whether
the answers *really* differ — or only look different.

One dependency-free file. Works in the browser and in Node 18+. It powers the
[DNS Checker on ExamineIP](https://tools.examineip.com/dns-checker/).

```
$ node doh-compare.js example.com MX TXT

example.com — CONSISTENT (DNSSEC validated)
Both resolvers returned the same records for every type checked.

MX [agree]
  0 .
TXT [agree]
  v=spf1 -all   <- SPF: which servers may send mail for this domain
  _k2n1y4vw3qtb4skdx9e7dxt97qrmmq9
```

---

## Why

Comparing two resolvers sounds trivial: query both, diff the strings. Done naively, it reports a
"difference" for most domains on the internet:

| Looks different | Why it isn't | What doh-compare does |
|---|---|---|
| TXT records | Cloudflare wraps TXT values in quotes, Google doesn't | Normalises quoting before comparing |
| Long TXT (DKIM, SPF) | Values over 255 bytes arrive as several quoted chunks | Joins the chunks |
| Names | Trailing dots and letter case vary | Strips the dot, lower-cases |
| Record order | Resolvers return round-robin sets in any order | Compares sorted sets |
| A / AAAA | CDNs and GeoDNS answer with the server nearest the *resolver* | Reports **geo**, not an error |
| A resolver timing out | A failed query has no answers | Reports **unreachable** — never "missing records" |

What's left after that is a real signal: records that shouldn't vary by location (MX, NS, TXT, SOA,
CNAME, CAA) disagreeing, or one resolver having records the other doesn't — usually a change
still propagating, or two sets of nameservers serving different data.

---

## Use it

**Command line** (Node 18+)

```
node doh-compare.js <domain> [TYPE ...] [--json]
```

Default types: `A AAAA CNAME MX NS TXT SOA` (`CAA` is available too). Exit code: `0` consistent or geo,
`2` inconsistent, `1` anything else (NXDOMAIN, SERVFAIL, unreachable, bad input).

**Node**

```js
const { compare } = require('./doh-compare');

const r = await compare('example.com', { types: ['MX', 'TXT'] });
r.verdict;   // 'consistent' | 'geo' | 'inconsistent' | 'nxdomain' | 'servfail' | 'unreachable'
r.records;   // [{ type, state, google: [{data, ttl}], cloudflare: [...], chain }]
```

**Browser**

```html
<script src="doh-compare.js"></script>
<script>
  dohCompare.compare('example.com').then(r => console.log(r.verdict, r.summary));
</script>
```

Both resolvers send CORS headers, so it runs from any page with no server of your own.

---

## Result

`compare(name, { types, timeout, fetch })` resolves to:

| Field | Meaning |
|---|---|
| `verdict` | Overall result — see below |
| `summary` | One plain-English sentence explaining the verdict |
| `dnssec` | `true` if either resolver validated the answer (AD flag) |
| `differs` | `{ real, geo, missing }` — which types fell into each bucket |
| `unreachable` | Types where one or both resolvers failed to answer |
| `records[]` | Per type: `state`, both answer sets (or `null` if that resolver failed), and any CNAME `chain` |

Per-type `state`: `agree`, `none` (no records, both agree), `geo`, `differ`, `missing`, `partial`
(one resolver failed), `unreachable` (both failed).

| Verdict | Meaning |
|---|---|
| `consistent` | Every type checked matched |
| `geo` | Only A/AAAA differ — normal for CDNs and GeoDNS |
| `inconsistent` | A location-independent type differs, or is missing on one side |
| `nxdomain` | The name doesn't exist |
| `servfail` | The nameservers failed or DNSSEC validation failed |
| `unreachable` | Neither resolver could be reached |

Lower-level helpers are exported too: `query`, `classify` (pure — no network), `normalize`,
`sameRecords`, `dohUrl`, `cleanName`, `txtLabel`.

---

## What it can't tell you

- **Two resolvers are not "global propagation".** Google and Cloudflare are anycast networks; you see
  what their nearest nodes have cached. A change can match on both and still be stale somewhere else
  until the old record's TTL runs out.
- **Cached answers.** A difference right after a change may just be one resolver holding an older
  record for its remaining TTL. The TTL is included for each answer.
- **Your own resolver.** Your ISP or router may answer differently from both. This tool doesn't see it.

---

## Tests

```
node tests/run.js
```

The suite is fully offline: every DoH response comes from a fixture served by a fake `fetch`, covering
quoted and chunked TXT, geo differences, real mismatches, missing records, resolver failures, NXDOMAIN,
SERVFAIL, DNSSEC and CNAME chains. CI runs it on Node 18, 20 and 22.

---

## Licence

MIT — see [LICENSE](LICENSE).

Built by [ExamineIP](https://examineip.com/). Try it in the browser at the
[DNS Checker](https://tools.examineip.com/dns-checker/), or read
[how DNS works](https://examineip.com/what-is-dns-and-how-does-it-work/) in plain English.
