<p align="center">
  <img src="https://github.com/colocohen/dnssec-server/raw/main/dnssec-server.svg" width="100%" alt="dnssec-server"/>
</p>

<h1 align="center">dnssec-server</h1>

<p align="center">
  <em>📡 Authoritative DNS server with real-time DNSSEC for Node.js</em>
</p>

<p align="center" style="max-width: 720px; margin: auto;">
  <strong>dnssec-server</strong> brings modern, flexible DNS to the Node.js ecosystem.  
  Instead of managing static zone files or running heavyweight daemons like BIND, you compute DNS answers directly in JavaScript.  
  Every response can be signed at runtime with DNSSEC, records can be generated dynamically (Geo-LB, canary, service discovery), and modern RR types are supported out of the box.  
  The protocol details the standards require — authoritative flags, negative answers, proofs of non-existence, client-subnet scope — are completed for you, and every one of them can be taken over by hand.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/dnssec-server">
    <img src="https://img.shields.io/npm/v/dnssec-server?color=blue" alt="npm">
  </a>
  <img src="https://img.shields.io/badge/status-in%20development-yellow" alt="status">
  <img src="https://img.shields.io/github/license/colocohen/dnssec-server?color=brightgreen" alt="license">
</p>


# Table of Contents

- [✨ Why this library?](#-why-this-library)
- [📦 Install](#-install)
- [🚀 Quick Start](#-quick-start)
- [⚙️ API](#️-api)
  - [`createServer(options, handler)`](#createserveroptions-handler)
  - [Request (`req`) object](#request-req-object)
  - [Response (`res`) object](#response-res-object)
  - [What `res.send()` completes for you](#what-ressend-completes-for-you)
  - [`encodeMessage` / `decodeMessage`](#-encodemessage--decodemessage)
- [🚫 Negative answers (NODATA / NXDOMAIN)](#-negative-answers-nodata--nxdomain)
- [🔐 Enabling DNSSEC](#-enabling-dnssec)
  - [1. Generate keys](#1-generate-keys-with-builddnssecmaterial)
  - [2. Keep the keys stable](#2-keep-the-keys-stable-across-restarts)
  - [3. Wire DNSSEC into the server](#3-wire-dnssec-into-the-server)
  - [4. Add the DS at your registrar](#4-add-the-ds-at-your-registrar)
  - [5. Verify](#5-verify)
  - [6. Signature validity and caching](#6-signature-validity-and-caching)
  - [7. Doing it by hand](#7-doing-it-by-hand)
  - [8. CDS / CDNSKEY — DS updates without the registrar](#8-cds--cdnskey--ds-updates-without-the-registrar)
- [🔎 ECS (EDNS Client Subnet)](#-ecs-edns-client-subnet)
- [🛡️ Admission: `accept` and DNS Cookies](#-admission-accept-and-dns-cookies)
- [🔒 Encrypted transports (DoT, DoQ)](#-encrypted-transports-dot-doq)
- [🌐 DNS-over-HTTPS (DoH)](#-dns-over-https-doh)
- [📦 Migrating from Zone Files](#-migrating-from-zone-files)
- [🧩 Dynamic DNS Recipes](#-dynamic-dns-recipes)
- [📜 Supported Record Types](#-supported-record-types-specaligned)
- [Performance Notes](#performance-notes)
- [🗺️ Roadmap](#️-roadmap)
- [Troubleshooting FAQ](#troubleshooting-faq)
- [Support the Project](#support-the-project)
- [License](#license)
- [References](#references)


# ✨ Why this library?

Running DNS in production is usually associated with **heavyweight software** such as BIND, NSD or PowerDNS.  
These are robust and widely used, but they come with trade-offs:  
- Zone files are static and cumbersome to manage when your infrastructure changes frequently.  
- Rolling out new records or policies often requires reloads, manual key management, or external tooling.  
- Enabling DNSSEC usually means a separate signing pipeline, cron jobs, or custom scripts.  

For modern stacks that are **API-driven, containerized, and globally distributed**, this is painful and slow.

`dnssec-server` takes a different approach: it is a **pure JavaScript authoritative DNS server** designed to live *inside your Node.js application* and give you **DNS as code**.  

- 🛡️ **DNSSEC at runtime** — responses are signed on the fly (RRSIG), DNSKEY is served for you, and negative answers carry a signed proof of non-existence (compact NSEC, RFC 9824). No offline signer, no cron jobs, no external toolchain.  
- ⚡ **Dynamic zones** — answers are computed from logic you write in JavaScript. Use the client subnet (ECS) to return the nearest PoP, shift traffic with weighted canaries, or implement feature-flagged DNS in seconds.  
- 📐 **Standards filled in** — AA on authoritative answers, the negative-answer TTL rules of RFC 2308, the ECS scope of RFC 7871. You write the records; `res.send()` adds what the RFCs require.  
- 🌍 **Modern record support** — from `SVCB/HTTPS` for service discovery, to `TLSA` for DANE, `CAA` for certificate policy, and `URI` for service endpoints.  
- 🔒 **Encrypted transports** — DNS-over-TLS and DNS-over-QUIC, with certificates chosen per connection through an `SNICallback`; DNS-over-HTTPS through your own HTTP server.  
- 🧩 **Simple API surface** — one request/response handler where you push records and call `res.send()`. No zone file syntax to learn.  

This makes **dnssec-server** especially useful when:
- You want DNS decisions tied directly to application logic (load balancing, canaries, failover).  
- You need DNSSEC but don't want to manage signing infrastructure.  
- You're building modern protocols (`HTTPS`/`SVCB`, `ECH`, `DoT`, `DoQ`) and need a flexible testbed.  
- You want to prototype quickly without carrying the weight of BIND/NSD.  


# 📦 Install

```bash
npm i dnssec-server
```

The package is an ES module and is loaded straight from its source — there is no build step.

```js
// ESM
import DNSServer from 'dnssec-server';
import { createServer, buildDnssecMaterial } from 'dnssec-server';

// CommonJS — through require(esm), Node.js 20.19+ / 22.12+
const DNSServer = require('dnssec-server');
```

Dependencies: [`lemon-tls`](https://github.com/colocohen/lemon-tls) and [`quico`](https://github.com/colocohen/quico), used by the encrypted transports (DoT, DoQ).


# 🚀 Quick Start

A minimal authoritative server for `example.com.` on UDP and TCP port 53. It answers an `A` record for the apex; for every other name in the zone it returns NXDOMAIN with the zone's SOA, as a negative answer must.

```js
import DNSServer from 'dnssec-server';

const SOA = {
  name: 'example.com.', type: 'SOA', class: 'IN', ttl: 300,
  data: {
    mname: 'ns1.example.com.', rname: 'hostmaster.example.com.',
    serial: 2025081001, refresh: 3600, retry: 600, expire: 604800, minimum: 300
  }
};

DNSServer.createServer({}, function (req, res) {
  console.log(`[${req.transport}] ${req.remoteAddress}  q=${req.name} ${req.type}  DO=${req.flag_do}  ECS=${req.ecsAddress || '-'}`);

  // Not our zone: refuse. (REFUSED claims no authority — AA stays off.)
  if (req.name !== 'example.com.' && !req.name.endsWith('.example.com.')) {
    res.header.rcode = 5;
    return res.send();
  }

  if (req.name === 'example.com.' && req.type === 'A') {
    res.answers.push({ name: 'example.com.', type: 'A', class: 'IN', ttl: 300, data: { address: '203.0.113.10' } });
    return res.send();
  }

  if (req.name !== 'example.com.') res.header.rcode = 3;   // NXDOMAIN: no such name
  // else: NODATA — the name exists, the type does not (rcode stays 0)
  res.authority.push(SOA);                                  // required on every negative answer
  res.send();
});
```

Running on port 53 needs the privilege to bind it. For development, pick other ports: `{ udp: { port: 5353 }, tcp: { port: 5353 } }`.


# ⚙️ API

## `createServer(options, handler)`

Creates and starts an authoritative DNS server.

### Transports

| Option | Default | Shape |
|---|---|---|
| `udp` | UDP on `0.0.0.0:53` and `[::]:53` | `false`, or `{ port, host }` — a `host` binds only its own family (`'127.0.0.1'` → IPv4 only, `'::1'` → IPv6 only); no `host` binds both — or `{ udp4: { host, port }, udp6: { host, port } }` |
| `tcp` | TCP on `[::]:53` | `false`, or `{ port, host, idleMs }`. `idleMs` closes a connection after that long without a whole message in either direction (default 30000, RFC 7766 §6.2.3). A client that sends `edns-tcp-keepalive` is told this value (RFC 7828). |
| `tls` | off | `{ port: 853, host, SNICallback, key, cert, ALPNProtocols, maxConnections, idleMs }` — DNS-over-TLS (RFC 7858) |
| `quic` | off | `{ port: 853, host, SNICallback, key, cert, alpn, maxConnections, maxOpenStreams }` — DNS-over-QUIC (RFC 9250) |

See [Encrypted transports](#-encrypted-transports-dot-doq) for the TLS / QUIC certificate options.

### Behavior

| Option | Default | Meaning |
|---|---|---|
| `aa` | `true` | Set the Authoritative Answer flag on NOERROR / NXDOMAIN responses. `false` leaves it off unless a handler sets `res.header.aa`. |
| `always_ra` | `false` | Set Recursion Available. An authoritative server should not. |
| `ecsDefaultScope` | the query's source prefix | ECS scope returned when the handler does not set `res.ecsScope`. A number overrides it. See [ECS](#-ecs-edns-client-subnet). |
| `onError` | ignored | `function (err, transport)` — socket errors, signing errors, and standards warnings (such as a negative answer without an SOA). |
| `cookies` | on, with a random secret | DNS Cookies (RFC 7873, RFC 9018). `{ secret, previousSecret }` sets the secret: 16 bytes, as a `Uint8Array` or 32 hex characters. `false` turns cookies off. See [Admission](#-admission-accept-and-dns-cookies). |

### DNSSEC

`dnssec` *(optional)* — see [Enabling DNSSEC](#-enabling-dnssec).

| Option | Default | Meaning |
|---|---|---|
| `keyCallback` | — | `function (name, cb)` — called for queries with DO=1; `cb(null, material)` signs with that material, `cb(null, null)` leaves the answer unsigned. |
| `cache` | none | `true` for the built-in LRU signature cache, or `{ get, set }` for your own. |
| `cacheMax` | `10000` | Entries in the built-in cache. |
| `signatureValidity` | 7 days | Lifetime of a new RRSIG, in seconds. |
| `dnskeyValidity` | 30 days | Lifetime of the RRSIG over DNSKEY, in seconds. |
| `autoDenial` | `true` | Add the NSEC proving a negative answer. `false` leaves negative answers without one. |
| `autoDnskey` | `true` | Answer DNSKEY queries at the zone apex from the material. `false` passes them to the handler. |
| `autoCds` | `true` | Answer CDS and CDNSKEY queries at the apex from the material. See [CDS / CDNSKEY](#8-cds--cdnskey--ds-updates-without-the-registrar). |

### `handler(req, res)`

Your request handler. Populate `res.answers` / `res.authority` / `res.additionals`, then call `res.send()` — once.

### Returns

| Member | |
|---|---|
| `on('accept', fn)` | The server is an `EventEmitter`. `'accept'` decides, for every query, whether to answer it. See [Admission](#-admission-accept-and-dns-cookies). |
| `close(cb)` | Stop every transport and drop open TCP/TLS connections. |
| `handleMessage(bytes, peer, cb)` | Answer one DNS message from a transport you run — see [DoH](#-dns-over-https-doh). |
| `connectionCount()` | Open TCP/TLS connections. |
| `clearRrsigCache()` | Flush the built-in signature cache (e.g. after a key change). |
| `rrsigCacheSize()` | Entries in the built-in cache. |
| `context` | Internal server context (advanced use). |


## Request (`req`) object

- `id` *(number)* — message ID.
- `transport` *('udp4' | 'udp6' | 'tcp' | 'tls' | 'quic')* — which transport delivered the query.
- `remoteAddress` *(string)*, `remotePort` *(number)* — the socket peer: usually the **resolver**, not the end user. See [ECS](#-ecs-edns-client-subnet).
- `client` *({ address, port, family })* — the same, with `'IPv4'` / `'IPv6'`.
- `name` *(FQDN, lowercase, with trailing dot)* — qname, e.g. `example.com.`
- `type` *(string)* — qtype, e.g. `A`, `AAAA`, `TXT`, …
- `class` *(string)* — typically `IN`.
- `flag_qr` / `flag_aa` / `flag_tc` / `flag_rd` / `flag_ra` / `flag_ad` / `flag_cd` *(booleans)* — header flags.
- `flag_do` *(boolean)* — DO bit (DNSSEC OK).
- `edns` *(object | undefined)* — parsed EDNS(0): `udpSize`, `do`, `z`, `options`, `optionsStructured`, …
- `edns_udp_size` *(number | undefined)* — advertised UDP payload size.
- `ednsOptions` *(array | undefined)* — raw EDNS options.
- `ecs` *(object | undefined)* — the EDNS Client Subnet option: `{ family, sourcePrefixLength, scopePrefixLength, addressBytes }`.
- `ecsAddress` *(string | undefined)* — the client subnet address, e.g. `200.118.80.0`.
- `ecsSourcePrefixLength` / `ecsScopePrefixLength` *(number | undefined)*.
- `tls` *(object | undefined)* — `{ authorized, alpn }` on encrypted transports.
- `addressVerified` *(boolean)* — whether `remoteAddress` is proven. It is true over TCP, DoT, DoQ and DoH, because the handshake proved it. Over UDP it is true only with a valid server cookie. Otherwise a UDP source address can be forged.
- `raw` *(Uint8Array)* — original wire bytes.
- `message` *(object)* — the full decoded query.


## Response (`res`) object

| Member | |
|---|---|
| `header` | Flags and rcode. `res.header.rcode` — 0 NOERROR, 2 SERVFAIL, 3 NXDOMAIN, 5 REFUSED, … `res.header.aa` — leave it unset and it is decided for you (below). |
| `answers`, `authority`, `additionals` | Arrays of RRs: `{ name, type, class: 'IN', ttl, data }` — see [Supported Record Types](#-supported-record-types-specaligned). |
| `types` | *(optional)* On a negative answer: the types that **do** exist at the name, e.g. `['A', 'MX']`. Makes the DNSSEC proof exact. See [Negative answers](#-negative-answers-nodata--nxdomain). |
| `ecsScope` | *(optional)* For a query with ECS: how wide a subnet this answer is good for. `0` = everyone. See [ECS](#-ecs-edns-client-subnet). |
| `edns` | The response's EDNS(0) record, present when the query had one. |
| `send()` | Complete and transmit the response. Call it once per query. |


## What is answered before your handler

Some queries have an answer fixed by the standards. The server sends it itself, on every transport (UDP, TCP, DoT, DoQ, and `handleMessage`), and your handler is not called. These queries still go through the [`'accept'`](#-admission-accept-and-dns-cookies) listener first.

| Query | Answer | Standard |
|---|---|---|
| A response (QR set) | Nothing | — (avoids loops and reflection) |
| Shorter than a header (12 octets) | Nothing | — |
| Cannot be decoded | FORMERR with the query's ID. Over TCP and DoT the connection stays open. | RFC 1035, RFC 7766 §8 |
| More than one OPT RR, an OPT outside the additional section, or not owned by the root | FORMERR | RFC 6891 §6.1.1–6.1.2 |
| EDNS version other than 0 | BADVERS (16): header RCODE 0, OPT extended RCODE 1, version 0 | RFC 6891 §6.1.3 |
| Opcode other than QUERY | NOTIMP | RFC 8906 §3.1.4 |
| QUERY with no question, or more than one | FORMERR | RFC 9619 |
| A COOKIE option of a forbidden length | FORMERR | RFC 7873 §5.2.2 |

`res.header.rcode` takes the full 12-bit RCODE (for example 16). `encodeMessage` splits it between the header and the OPT RR, and `decodeMessage` joins it back.

## What `res.send()` completes for you

You write the records; `send()` adds what the standards require on top. Each step is skipped when you did it yourself.

| Step | When | Standard |
|---|---|---|
| **AA flag** — on for NOERROR / NXDOMAIN, off for REFUSED / SERVFAIL / FORMERR | `res.header.aa` was left unset and `aa` is not `false` | RFC 1035 §4.1.1 |
| **Negative TTL** — the SOA in a negative answer gets `min(SOA TTL, SOA minimum)` | No answers, rcode 0 or 3, SOA in authority | RFC 2308 §5 |
| **ECS scope** — the ECS option is echoed with a scope | The query carried ECS and you did not add an ECS option yourself | RFC 7871 §7.2.1 |
| **RRSIG** — every RRset in answers and authority is signed | DO=1, `keyCallback` returned material, and no RRSIG is in the response already | RFC 4034, 4035 |
| **NSEC** — the proof of a negative answer | Signing, `autoDenial` not `false`, no NSEC/NSEC3 in authority | RFC 9824, 9077 |
| **NXNAME** — a signed NXDOMAIN becomes NOERROR + NXNAME, unless the resolver set CO | As above, rcode 3 | RFC 9824 §5.1 |
| **Warning** — `onError` reports a negative answer without an SOA | No answers, no SOA, and no NS (not a referral) | RFC 2308 §3 |
| **OPT size** — the response OPT advertises this server's own UDP size (1232), not the client's | The query had an OPT | RFC 6891 §6.2.3 |
| **UDP size** — the response fits the client's EDNS size (512 without EDNS). Whole RRsets are dropped from the end. TC is set only when an answer or authority RRset, or a referral's glue, was dropped; dropped additional data alone does not set it. | UDP only. DoQ, TCP and DoT are never cut to the EDNS size. | RFC 6891 §7, RFC 2181 §9, RFC 9471 |
| **COOKIE** — the client's cookie and a server cookie for it | The query carried a COOKIE option, cookies are on, and the answer is not BADVERS | RFC 7873 §5.2, RFC 9018 |
| **edns-tcp-keepalive** — the idle timeout, in units of 100 ms | TCP and DoT, when the query carried the option | RFC 7828 §3.3.2 |
| **Padding** — the response is padded to a multiple of 468 octets | DoT, DoQ and DoH only, when the query carried the Padding option, and you did not add one | RFC 7830, RFC 8467 §4.1 |


## 🔧 `encodeMessage` / `decodeMessage`

Low-level primitives to **parse** and **serialize** raw DNS messages — for your own transports, middleboxes, or tests.

```js
import { encodeMessage, decodeMessage } from 'dnssec-server';

const query = decodeMessage(rawBuffer);
query.answers.push({ name: 'example.com.', type: 'A', class: 'IN', ttl: 60, data: { address: '203.0.113.10' } });
const wire = encodeMessage(query);
```


# 🚫 Negative answers (NODATA / NXDOMAIN)

A negative answer is one with no records of the asked type. There are two kinds:

- **NODATA** — the name exists, the type does not (`AAAA` for a name with only `A`). `rcode` stays 0, answers are empty.
- **NXDOMAIN** — the name does not exist at all. `rcode = 3`.

Either way **the zone's SOA goes in `res.authority`** (RFC 2308 §3). Resolvers use it to know how long to remember the "no" — without it they cannot cache it, and some treat the answer as broken. Push the SOA as you would any record; its TTL is capped for you. Leave it out and `onError` tells you.

```js
// NODATA: www.example.com has an A record, but no AAAA
res.authority.push(SOA);
res.types = ['A'];          // optional: the types that do exist here
res.send();
```

### With DNSSEC

A signed zone must also **prove** a negative answer — otherwise a validating resolver cannot tell a real "no" from an attacker deleting records, and answers SERVFAIL. `res.send()` adds the proof: one NSEC record in the compact form of RFC 9824, signed online.

- Its owner is the query name and its *next name* is the immediate successor (`\000.<name>`), so it covers exactly one name and **the zone cannot be walked**.
- **NODATA:** the NSEC lists the types that exist at the name. Give them as `res.types` for an exact proof. Without it, a broad list of common types is used, minus the asked type — always safe, since claiming a type that is absent only makes the resolver ask for it, while omitting one that exists would let a resolver deny it from cache (RFC 8198). At the apex, `DNSKEY` is added for you.
- **NXDOMAIN:** the NSEC lists only `NXNAME` (RFC 9824). The response goes out as NOERROR — what resolvers that predate compact denial expect — unless the resolver set the *Compact Answers OK* (CO) flag, in which case it keeps NXDOMAIN and gets CO back.

`answerFromZone()` returns `types` for NODATA results, so zone-file setups need nothing extra: `res.types = result.types`.


# 🔐 Enabling DNSSEC

## 1. Generate keys with `buildDnssecMaterial`

```js
import { buildDnssecMaterial } from 'dnssec-server';

// New random keys
const material = buildDnssecMaterial({ signersName: 'example.com.' });

// Or your existing private keys (base64 string or Uint8Array, P-256)
const material = buildDnssecMaterial({
  signersName: 'example.com.',
  ksk: { privateKey: 'BASE64-P256-PRIVATE-KEY' },
  zsk: { privateKey: 'BASE64-P256-PRIVATE-KEY' }
});
```

Output:

```js
{
  signersName: 'example.com.',
  ds: 'example.com. IN DS 14257 13 2 A1B2C3D4E5F6...',   // ready for the registrar
  ksk: { keyTag: 14257, privateKey: '...', publicKey: '...', algorithm: 13, digestType: 2, digest: 'A1B2C3D4E5F6...' },
  zsk: { keyTag: 27179, privateKey: '...', publicKey: '...', algorithm: 13 }
}
```

Algorithm 13 (ECDSA P-256 / SHA-256) and digest type 2 (SHA-256) — the modern defaults every validating resolver supports.


## 2. Keep the keys stable across restarts

> ⚠️ **This is the step that breaks domains.** Once the parent zone holds a DS for your KSK, a different KSK means every validating resolver (Google, Cloudflare, most ISPs) answers **SERVFAIL for your whole domain** until the DS is updated and caches expire — hours.

`buildDnssecMaterial()` without keys makes new random ones every call. Store the private keys (`material.ksk.privateKey`, `material.zsk.privateKey`) and pass them back on every start:

```js
import fs from 'node:fs';

function loadMaterial(zone, file) {
  let saved = null;
  try { saved = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) {}
  if (saved) return buildDnssecMaterial({ signersName: zone, ksk: { privateKey: saved.ksk }, zsk: { privateKey: saved.zsk } });

  const m = buildDnssecMaterial({ signersName: zone });
  fs.writeFileSync(file, JSON.stringify({ ksk: m.ksk.privateKey, zsk: m.zsk.privateKey }), { mode: 0o600 });
  return m;
}
```

The file holds private keys: keep it out of version control and out of anything served publicly.


## 3. Wire DNSSEC into the server

Return the material from `keyCallback`. The server serves DNSKEY at the apex, signs every answer, and proves negative answers.

```js
const material = loadMaterial('example.com.', './dnssec-example.com.json');

DNSServer.createServer({
  dnssec: {
    keyCallback: function (name, cb) {
      // Several zones: return each one's material by suffix.
      if (name === 'example.com.' || name.endsWith('.example.com.')) cb(null, material);
      else cb(null, null);                  // not ours — no signing
    },
    cache: true
  }
}, handler);
```

`keyCallback` may answer asynchronously — read keys from a database, a KMS, or another process.


## 4. Add the DS at your registrar

Copy `material.ds` (it is also printed by the example above — log it once). Registrars ask for its four fields:

| Key Tag | Algorithm | Digest Type | Digest |
| ------- | --------- | ----------- | ------ |
| 14257   | 13        | 2           | A1B2C3D4E5F6... |

Only the **KSK** produces a DS. Add it **after** step 2 is in place and you have restarted once and seen the same key tag.


## 5. Verify

```bash
dig +dnssec example.com DNSKEY @your-server
dig +dnssec example.com A @your-server
dig +dnssec example.com AAAA @your-server     # a negative answer: SOA + NSEC + RRSIGs in AUTHORITY
```

Then [dnsviz.net](https://dnsviz.net) or [dnssec-debugger.verisignlabs.com](https://dnssec-debugger.verisignlabs.com) for the whole chain.


## 6. Signature validity and caching

A signature is a proof anyone can replay until it expires. Signing online makes short windows free, so new RRSIGs are valid for **7 days** (`signatureValidity`), and **30 days** over DNSKEY (`dnskeyValidity`). A cached signature is replaced once three quarters of its window is spent, so no resolver is handed one that is about to expire.

ECDSA P-256 signing costs about 1–5 ms per RRset. With `cache`, identical RRsets reuse their signature.

```js
// Built-in in-memory LRU
dnssec: { keyCallback, cache: true, cacheMax: 5000 }

// Your own backend (Redis, …)
dnssec: {
  keyCallback,
  cache: {
    get(params, cb) {                // params: { name, type, class, keyTag, hash }
      redis.get(params.hash + ':' + params.keyTag, (err, raw) => cb(err, raw ? JSON.parse(raw) : null));
    },
    set(params, value, cb) {         // value: { rrsig, expiration, inception }
      const ttl = value.expiration - Math.floor(Date.now() / 1000);
      redis.setex(params.hash + ':' + params.keyTag, ttl, JSON.stringify(value), cb);
    }
  }
}
```

`hash` is the SHA-256 of the canonical RRset bytes — it changes whenever the records do, so a changed answer is never served an old signature. `server.clearRrsigCache()` flushes the built-in cache, e.g. after a key change.


## 7. Doing it by hand

Every automatic step can be taken over:

| You want | Do |
|---|---|
| Your own signatures | Put RRSIG records in the response — nothing is signed for you then. |
| Your own denial proof (NSEC3, a different NSEC) | Put it in `res.authority` — no NSEC is added. Or `dnssec.autoDenial: false`. |
| To answer DNSKEY yourself | `dnssec.autoDnskey: false`, and answer it in the handler. |
| To answer CDS / CDNSKEY yourself (or not at all) | `dnssec.autoCds: false`. |
| Your own AA decision | Set `res.header.aa`. Or `aa: false` server-wide. |
| Your own ECS option | Add it to `res.edns.options` — it is left as is. |
| No DNSSEC at all | Don't pass `dnssec`. |


## 8. CDS / CDNSKEY — DS updates without the registrar

The DS lives at the parent, and normally a person types it into the registrar's page — at the start, and again after every KSK change. Forget it once after a key change and the domain goes dark.

**CDS** and **CDNSKEY** (RFC 7344, RFC 8078) are your zone's own copy of "the DS I want my parent to hold": CDS in DS form, CDNSKEY as the key itself. They sit at your apex, signed with the KSK. A registry that scans for them:

- **with a DS already in place** — accepts a change only if the new CDS is signed by the key the current DS points at, so only the key holder can change it; then updates the DS itself;
- **with no DS yet** — applies its own acceptance policy (typically: seen unchanged for some days, from every name server) and installs it;
- **CDS `0 0 0 00`** — the zone asks for DNSSEC to be turned off.

The server answers both at the apex, from the material `keyCallback` returns — always matching the KSK it signs with, signed with that KSK, TTL 3600. The apex NSEC lists them. Support depends on the registry of your TLD (many ccTLDs scan; check yours) — where nobody scans, the records are simply never asked for. `dnssec.autoCds: false` turns them off.


# 🔎 ECS (EDNS Client Subnet)

The query does not come from the user. It comes from their **resolver** — an ISP's, or a public one like Google (8.8.8.8). So `req.remoteAddress` is the resolver's address.

Some resolvers add the **EDNS Client Subnet** option: a prefix of the user's address (never all of it), e.g. `200.118.80.0/24`. It is exposed as `req.ecsAddress` and `req.ecsSourcePrefixLength`.

### The scope — who the answer is good for

A resolver serves millions of users from its cache. If your answer depends on where the user is, the resolver must not hand it to everyone — so the reply says **for how wide a subnet it holds**: the ECS *scope prefix*.

| Scope | The resolver |
|---|---|
| `24` (= the source prefix) | keeps the answer for `200.118.80.0/24` only, and asks you again for every other /24 |
| `16` | keeps it for `200.118.x.x` — e.g. when you decide by country |
| `0` | keeps one answer for everyone |

By default the reply carries the **source prefix the resolver sent** — the safe choice: the resolver asks you for every subnet, and your handler decides each time. Set `res.ecsScope` per answer when you know better:

```js
res.ecsScope = 0;     // this answer is the same for everyone — one cache entry at the resolver
res.ecsScope = 16;    // decided by a /16
```

`ecsDefaultScope` changes the default server-wide. A query without ECS gets no ECS in the reply; a client that opted out (source `/0`) always gets scope 0.

Not every resolver sends ECS — Cloudflare's 1.1.1.1 never does. Location logic should fall back to `req.remoteAddress`.


# 🛡️ Admission: `accept` and DNS Cookies

For every query, the server asks its `'accept'` listener whether to answer at all. The question comes before anything else, including the answers the server gives on its own (DNSKEY / CDS / CDNSKEY at the apex) and those the standards fix (FORMERR, BADVERS, NOTIMP). Rate limiting and load shedding live outside the library, in your own code:

```js
const server = DNSServer.createServer(options, handler);

server.on('accept', function (req, cb) {
  // A forged UDP address must not cost its real owner anything elsewhere:
  // an unproven one is counted under a key of its own.
  const key = req.addressVerified ? req.remoteAddress : 'dns:' + req.remoteAddress;
  myRateLimiter.charge(key, function (err, ok) { cb(!!err || ok); });
});
```

`cb(true)` answers the query. `cb(false)` turns it away, and the server chooses the answer so that nothing is worth forging an address for:

| The query came… | Answer |
|---|---|
| over UDP, unproven, with a client cookie | **BADCOOKIE** (23) with a fresh server cookie. The client asks again at once, cookie in hand (RFC 7873 §5.2.3). |
| over UDP, unproven, without a cookie | **TC**, empty. A real resolver retries over TCP, which a forged address cannot complete. This is the "slip" of Response Rate Limiting. REFUSED here would cut the forged address's real owner (often a public resolver) off your zones. |
| over TCP, DoT, DoQ or DoH, or over UDP with a valid cookie | **REFUSED** |

The callback may come later (an asynchronous limiter). It is called once; any later call is ignored. Without an `'accept'` listener, every query is answered.

**DNS Cookies** (RFC 7873) prove a UDP address. A client sends a cookie of its own; the server answers with a server cookie, a keyed hash (SipHash-2-4, the interoperable format of RFC 9018) of the client's cookie, its address and the time. A client that sends it back is at that address: `req.addressVerified` is true. Cookies are on by default:

- The server adds its cookie to every answer whose query carried one. It renews a cookie that is more than half an hour old, and accepts one up to an hour old.
- A COOKIE option of a forbidden length is answered FORMERR (RFC 7873 §5.2.2).
- A wrong or expired server cookie is not an error. The query is answered, unverified, with a new cookie.
- With the default random secret, each restart starts a new secret. Clients just learn a new cookie.
- Several servers behind one address (anycast) must share one secret: `cookies: { secret: '<32 hex>' }`. To change the secret, put the old one in `previousSecret` for an hour.

# 🔒 Encrypted transports (DoT, DoQ)

Both run on [`lemon-tls`](https://github.com/colocohen/lemon-tls) (DoT through `quico`'s TCP listener, DoQ through `quico`), so one certificate source serves both.

```js
import lemonTls from 'lemon-tls';

const ctx = lemonTls.createSecureContext({ key: fs.readFileSync('key.pem'), cert: fs.readFileSync('cert.pem') });

DNSServer.createServer({
  tls:  { port: 853, SNICallback: (servername, cb, info) => cb(null, ctx) },
  quic: { port: 853, SNICallback: (servername, cb) => cb(null, ctx) }
}, handler);
```

- The `SNICallback` returns a **lemon-tls** context (`lemonTls.createSecureContext`) — not a `node:tls` one.
- It is called for **every** connection, including clients that send no server name. DNS clients are usually configured by IP, and an IP is never sent as SNI (RFC 6066 §3) — for DoT, the third argument `info` carries the local address the connection arrived on, so you can pick a certificate by it.
- DoT and DoQ use the same port number, 853, on different protocols (TCP and UDP).
- DoQ follows RFC 9250 strictly. Each query arrives on its own client bidirectional stream, and the answer is sent on that stream, followed by FIN. The server closes the connection with `DOQ_PROTOCOL_ERROR` (0x2) when a client:
  - sends a Message ID other than 0;
  - sends more than one message on a stream;
  - finishes a stream before the whole message arrives;
  - opens a unidirectional stream;
  - sends the `edns-tcp-keepalive` option.

  More open queries than `maxOpenStreams` close the connection with `DOQ_EXCESSIVE_LOAD` (0x4). A query the client cancels with STOP_SENDING or RESET_STREAM gets no answer, and its stream is reset with `DOQ_REQUEST_CANCELLED` (0x3).


# 🌐 DNS-over-HTTPS (DoH)

The library serves no HTTP. DoH (RFC 8484) is wired through the HTTP server you already run, with `server.handleMessage(bytes, peer, cb)`: hand it the DNS message from the request, send back what it returns. The query goes through exactly the same path as UDP or TCP — key sets, your handler, signing, negative answers.

```js
import http from 'node:http';

const dns = DNSServer.createServer({ /* … */ }, handler);

http.createServer((req, res) => {
  if (!req.url.startsWith('/dns-query')) { res.writeHead(404); return res.end(); }

  const answer = (bytes) => dns.handleMessage(bytes, { address: req.socket.remoteAddress, transport: 'https' }, (err, wire, info) => {
    if (err) { res.writeHead(400); return res.end(); }          // not a DNS message
    res.writeHead(200, {
      'content-type': 'application/dns-message',
      'cache-control': typeof info.ttl === 'number' ? 'max-age=' + info.ttl : 'no-store'   // RFC 8484 §5.1
    });
    res.end(Buffer.from(wire));
  });

  if (req.method === 'POST') {                                  // body: application/dns-message
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => answer(new Uint8Array(Buffer.concat(chunks))));
  } else {                                                      // GET /dns-query?dns=<base64url>
    const m = /[?&]dns=([A-Za-z0-9_-]+)/.exec(req.url);
    if (!m) { res.writeHead(400); return res.end(); }
    answer(new Uint8Array(Buffer.from(m[1], 'base64url')));
  }
}).listen(8443);
```

- `peer` — `{ address, port, transport, tls }`; `transport` is what `req.transport` shows the handler (`'https'` here).
- `cb(err, responseBytes, info)` — `err` when the bytes are not a DNS message (answer HTTP 400); `info.ttl` is the smallest TTL in the response, for `max-age`, `undefined` when it carries no records.
- Run it behind HTTPS in production; DoH over plain HTTP exists only for testing.

Who uses DoH against an authoritative server? Mostly no one yet — browsers speak DoH to their resolver, and resolvers reach authoritative servers over port 53, DoT or DoQ. It is here for completeness and for tools that only speak DoH.


# 📦 Migrating from Zone Files

Already running BIND with zone files? Load them with `parseZone()` and answer with `answerFromZone()`.

- `$ORIGIN` and `$TTL` are honored (or pass `parseZone(text, { origin: 'example.com.' })`).
- A, AAAA, NS, CNAME, PTR, MX, TXT, SRV, CAA, NAPTR, DNSKEY, DS, RRSIG, NSEC, NSEC3PARAM.
- **SVCB/HTTPS** in the RFC 9460 presentation format: every key — `mandatory`, `alpn`, `no-default-alpn`, `port`, `ipv4hint`, `ech`, `ipv6hint`, `dohpath`, `ohttp`, `tls-supported-groups` and `keyNNNNN` — quoted or not, with escapes (`alpn="h3,h2"`, `alpn=h2\,x`). AliasMode (priority 0) takes no keys; a repeated key, or a `mandatory` naming a key that is absent, is an error with the line number. `ech` is checked to be a well-formed ECHConfigList. A/AAAA from the hints are added to `additionals`.
- **CAA** (`0 issue "letsencrypt.org"`), and text escapes as RFC 1035 §5.1 defines them: `\065` is decimal (`A`), `\"` and `\\` are the character.
- **Any type in the RFC 3597 generic form** — `\# 4 c0000201` — for a type this library does not know, or one written that way by another tool.

```
@   IN HTTPS 1 . alpn="h3,h2" ipv4hint=192.0.2.10 ipv6hint=2001:db8::10 ech="AEX+DQBB…"
_dns IN SVCB 1 dns.example.com. alpn=dot,doq port=853 mandatory=alpn,port
@   IN CAA   0 issue "letsencrypt.org"
```
- Glue for MX/SRV/NS and SVCB/HTTPS targets present in the zone; CNAME chains inside the zone are followed; wildcards are synthesized.
- Negative answers come back with the SOA, a correct NXDOMAIN / NODATA, and the `types` at the name — so DNSSEC proofs are exact with no extra work.

```js
import fs from 'node:fs';
import DNSServer from 'dnssec-server';

const zones = {
  'example.com.': DNSServer.parseZone(fs.readFileSync('example.com.zone', 'utf8')),
  'example.net.': DNSServer.parseZone(fs.readFileSync('example.net.zone', 'utf8'))
};

// Longest-suffix match
function pickZone(qname) {
  let best = null;
  for (const origin of Object.keys(zones)) {
    if ((qname === origin || qname.endsWith('.' + origin)) && (!best || origin.length > best.length)) best = origin;
  }
  return best ? zones[best] : null;
}

DNSServer.createServer({}, (req, res) => {
  const zone = pickZone(req.name);
  if (!zone) { res.header.rcode = 5; return res.send(); }   // not ours: REFUSED

  const r = DNSServer.answerFromZone(zone, req.name, req.type, req.class);

  // 👇 the place to adjust: TTLs, ECS-based answers, extra records…

  res.header.rcode = r.rcode;
  res.answers.push(...r.answers);
  res.authority.push(...r.authority);
  res.additionals.push(...r.additionals);
  if (r.types) res.types = r.types;
  res.send();
});
```


# 🧩 Dynamic DNS Recipes

## Geo Load Balancer by client subnet

Return the nearest PoP by the client's subnet (ECS) when the resolver sends it, by the resolver's address otherwise.

```js
function pickRegion(ip) {
  // toy example: replace with a GeoIP database or your own CIDR map
  if (ip.startsWith('200.10.')) return 'sa-east';
  if (ip.startsWith('192.0.2.')) return 'us-east';
  return 'eu-west';
}

const POPS = { 'sa-east': '200.10.10.1', 'us-east': '198.51.100.7', 'eu-west': '203.0.113.42' };

function handler(req, res) {
  const region = pickRegion(req.ecsAddress || req.remoteAddress || '');
  res.answers.push({ name: req.name, type: 'A', class: 'IN', ttl: 30, data: { address: POPS[region] } });
  // The answer depends on the client subnet. The default ECS scope (the
  // source prefix) already keeps resolvers from sharing it across subnets;
  // a coarser decision can say so:
  // res.ecsScope = 16;
  res.send();
}
```

Keep TTLs short for agility.


## Blue/Green & Canary releases

```js
function canaryA(req, res) {
  const canary = Math.random() * 100 < 5;   // 5% canary
  res.answers.push({ name: req.name, type: 'A', class: 'IN', ttl: 20, data: { address: canary ? '203.0.113.77' : '203.0.113.10' } });
  res.send();
}
```


## Service discovery with `SVCB`/`HTTPS`

Advertise ALPNs, ports, address hints and ECH config (RFC 9460/9461).

```js
res.answers.push({
  name: 'example.com.', type: 'HTTPS', class: 'IN', ttl: 300,
  data: {
    priority: 1,
    targetName: '.',
    paramsStructured: { alpn: ['h3', 'h2'], ipv4hint: ['192.0.2.10', '192.0.2.11'] }
  }
});
```


## Regional failover

Synthesize answers from upstream health checks; switch A/AAAA sets when a region is down. Pair with short TTLs — the 7-day signature window does not hold a changed answer back, since a changed RRset is signed anew.


# 📜 Supported Record Types (spec‑aligned)

General RR structure in this library:

```js
{
  type: 'A' | 'AAAA' | 'MX' | ...,
  name: 'example.com',
  class: 'IN',
  ttl: 300,
  data: { ... } // record-specific fields
}
```

The following record types are supported. Each example shows the `data` object expected during `encodeMessage` (and returned during `decodeMessage`).


## Address

### `A`
```js
{ data: { address: '127.0.0.1' } }
```

### `AAAA`
```js
{ data: { address: '2001:db8::1' } }   // or a 16-byte Uint8Array
```


## Name-based

### `NS`, `CNAME`, `PTR`, `DNAME`
```js
{ data: { name: 'ns1.example.net.' } }
```

### Obsolete name-only: `MD`, `MF`, `MB`, `MG`, `MR`, `NSAP_PTR`, `MAILA`, `MAILB`
```js
{ data: { name: 'old-target.example.' } }
```


## Core / Basics

### `SOA`
```js
{ 
  data: {
    mname: 'ns1.example.',
    rname: 'hostmaster.example.',
    serial: 2025082601, 
    refresh: 3600, 
    retry: 600, 
    expire: 1209600, 
    minimum: 300
  }
}
```

### `MX`
```js
{ 
  data: { 
    preference: 10, 
    exchange: 'mail.example.' 
  } 
}
```

### `TXT`
```js
{ data: { texts: ['hello', 'world'] } }
```

### `HINFO`
```js
{ data: { cpu: 'Intel', 
os: 'Linux' } }
```

### `MINFO`
```js
{ 
  data: { 
    rmailbx: 'r.mail.example.', 
    emailbx: 'e.mail.example.' 
  } 
}
```

### `RP`
```js
{ 
  data: { 
    mbox: 'admin.example.', 
    txt: 'info.example.' 
  } 
}
```

### `AFSDB`
```js
{ 
  data: { 
    subtype: 1, 
    hostname: 'afsdb.example.' 
  } 
}
```

### `X25`
```js
{ data: { address: '311061700956' } }
```

### `ISDN`
```js
{ data: { address: '150862028003217', 
sa: '004' } }
```

### `RT`
```js
{ data: { 
  preference: 10, 
  host: 'intermediate.example.' 
} }
```

### `NSAP`
```js
{ data: { address: Uint8Array([...]) } }
```

### `PX`
```js
{ data: { 
  preference: 10, 
  MAP822: 'user.example.', 
  MAPX400: 'x400.example.' 
} }
```

### `GPOS`
```js
{ 
  data: { 
    latitude: '48 51 29.0 N', 
    longitude: '2 17 40.0 E', 
    altitude: '0.00' 
  } 
}
```

### `WKS`
```js
{ 
  data: { 
    address: '192.0.2.1', 
    protocol: 6, 
    bitmap: Uint8Array([...]) 
  } 
}
```

### `NULL`
```js
{ data: { raw: Uint8Array([ ... ]) } }
```


## SRV / NAPTR / URI

### `SRV`
```js
{ 
  data: { 
    priority: 10, 
    weight: 5, 
    port: 443, 
    target: 'svc.example.' 
  } 
}
```

### `NAPTR`
```js
{ 
  data: { 
    order: 100, 
    preference: 10, 
    flags: 'U', 
    services: 'SIP+D2T',
    regexp: '!^.*$!sip:service@example.com!', 
    replacement: '.' 
  } 
}
```

### `URI`
```js
{ 
  data: { 
    priority: 1, 
    weight: 10, 
    target: 'https://api.example/v1' 
  } 
}
```


## EDNS(0)

### `OPT`
```js
{ 
  type: 'OPT', 
  name: '.', 
  udpPayloadSize: 4096,
  data: {
    options: [
      { 
        code: 12, 
        data: Uint8Array(31) 
      }
    ]
  }
}
```


## Modern service mapping

### `SVCB` / `HTTPS`
```js
{ 
  data: {
    priority: 1,
    targetName: 'svc.example.',
    paramsStructured: {
      alpn: ['h3','h2','http/1.1'],
      noDefaultAlpn: true,
      port: 8443,
      ipv4hint: ['192.0.2.10','192.0.2.11'],
      ech: Uint8Array([...]),
      dohpath: '/dns-query{?dns}',
      ohttp: true,                     // a flag: present or absent (RFC 9540)
      tlsSupportedGroups: [29,23],
      mandatory: ['alpn', 'port']      // names or key numbers
    }
  }
}
```

Keys go on the wire in increasing order, as RFC 9460 §2.2 requires; a `mandatory` naming itself or an absent key, or an `ech` that is not a well-formed ECHConfigList, throws when the record is encoded rather than going out broken. `ipv4hint` / `ipv6hint` take address strings.


## DNSSEC & Security

### `DNSKEY` / `CDNSKEY`
```js
{ 
  data: { 
    flags: 257, 
    protocol: 3, 
    algorithm: 8, 
    key: Uint8Array([...]) 
  } 
}
```

### `KEY`
```js
{ 
  data: { 
    flags: 256, 
    protocol: 3, 
    algorithm: 5, 
    key: Uint8Array([...]) 
  } 
}
```

### `DS` / `CDS` / `DLV` / `TA`
```js
{ 
  data: { 
    keyTag: 12345, 
    algorithm: 8, 
    digestType: 2, 
    digest: Uint8Array([...]) 
  } 
}
```

### `RRSIG` / `SIG`
```js
{ 
  data: {
    typeCovered: 1, 
    algorithm: 8, 
    labels: 1,
    originalTTL: 300, 
    expiration: 1735689600, 
    inception: 1735603200,
    keyTag: 12345, 
    signersName: 'example.',
    signature: Uint8Array([...])
  }
}
```

### `NSEC`
```js
{ 
  data: { 
    nextDomainName: 'b.example.', 
    types: ['A','TXT','RRSIG'] 
  } 
}
```

### `NSEC3`
```js
{ 
  data: { 
    hashAlgorithm: 1, 
    flags: 0, 
    iterations: 10,
    salt: Uint8Array([0xde,0xad]), 
    nextHashedOwnerName: Uint8Array([...]),
    types: ['A','AAAA','RRSIG'] 
  } 
}
```

### `NSEC3PARAM`
```js
{ 
  data: { 
    hashAlgorithm: 1, 
    flags: 0, 
    iterations: 10, 
    salt: Uint8Array([0xde,0xad]) 
  } 
}
```

### `DHCID`
```js
{ data: { data: Uint8Array([...]) } }
```

### `TLSA` / `SMIMEA`
```js
{ 
  data: { 
    usage: 3, 
    selector: 1, 
    matchingType: 1, 
    certificate: Uint8Array([...]) 
  } 
}
```

### `CERT`
```js
{ data: { 
    certType: 1, 
    keyTag: 12345, 
    algorithm: 8, 
    certificate: Uint8Array([...]) 
  }
}
```

### `SSHFP`
```js
{ 
  data: { 
    algorithm: 1, 
    hash: 2, 
    fingerprint: Uint8Array([...]) 
  } 
}
```

### `IPSECKEY`
```js
{ 
  data: { 
    precedence: 10, 
    gatewayType: 3, 
    algorithm: 1,
    gateway: 'gw.example.', 
    publicKey: Uint8Array([...]) 
  } 
}
```


## Location / Topology / Misc

### `LOC`
```js
{ 
  data: { 
    version: 0, 
    size: { 
      mant:0, 
      exp:0 
    }, 
    horizontal:{ 
      mant:0, 
      exp:0 
    },
    vertical:{ 
      mant:0, 
      exp:0 
    }, 
    latitude: 0, 
    longitude: 0, 
    altitude: 0 
  }
}
```

### `APL`
```js
{ data: { items: [ { family: 1, 
prefix: 24, 
neg: false, 
address: Uint8Array([192,0,2]) } ] } }
```

### `HIP`
```js
{ 
  data: { 
    algorithm: 1, 
    hit: Uint8Array([...]), 
    publicKey: Uint8Array([...]),
    servers: ['rendezvous1.example.'] 
  } 
}
```

### `NID`
```js
{ 
  data: { 
    preference: 10, 
    nodeIdHigh: 0x01234567, 
    nodeIdLow: 0x89abcdef 
  } 
}
```

### `L32`
```js
{ 
  data: { 
    preference: 10, 
    locator32: '192.0.2.55' 
  } 
}
```

### `L64`
```js
{ 
  data: { 
    preference: 10, 
    locator64High: 0x01234567, 
    locator64Low: 0x89abcdef 
  } 
}
```

### `LP`
```js
{ 
  data: { 
    preference: 10, 
    fqdn: 'locator.example.' 
  } 
}
```

### `EUI48` / `EUI64`
```js
{ data: { address: Uint8Array([0x00,0x1A,0x2B,0x3C,0x4D,0x5E]) } }  // EUI48
{ data: { address: Uint8Array(8) } }                                  // EUI64
```

### `OPENPGPKEY`
```js
{ data: { key: Uint8Array([...]) } }
```

### `ZONEMD`
```js
{ 
  data: { 
    scheme: 1, 
    hashAlgorithm: 1, 
    digest: Uint8Array([...]) 
  } 
}
```


## Transfer / Meta

### `TKEY`
```js
{ 
  data: { 
    algorithm: 'hmac-sha256.', 
    inception: 1710000000, 
    expiration: 1710003600,
    mode: 3, 
    error: 0, 
    key: Uint8Array([...]), 
    other: Uint8Array([]) 
  } 
}
```

### `TSIG`
```js
{ 
  data: { 
    algorithm: 'hmac-sha256.', 
    timeSignedHigh: 0, 
    timeSignedLow: 1710000123,
    fudge: 300, 
    mac: Uint8Array([...]), 
    originalId: 0x1234, 
    error: 0, 
    otherData: Uint8Array([]) 
  } 
}
```

### `IXFR`, `AXFR`, `ANY`
```js
{ data: { 
    raw: Uint8Array([]) 
  } 
}
```


## Raw passthrough

Types preserved as raw (round-trip only): `EID`, `NIMLOC`, `ATMA`, `SINK`, `NINFO`, `RKEY`, `TALINK`.
```js
{ data: { raw: Uint8Array([ ... ]) } }
```



# Performance Notes

- Keep **RRset TTLs** aligned with how often your dynamic decisions change.
- Turn on the signature **cache** (`dnssec.cache`) — identical RRsets are then signed once per validity window instead of once per query.
- A negative answer to a DNSSEC query costs one extra signature (the NSEC); giving `res.types` costs nothing extra.
- The default ECS scope makes resolvers cache per client subnet, so they ask more often. Set `res.ecsScope = 0` on answers that are the same for everyone.
- If you accept high QPS, consider sharding instances per region and delegating via NS.


# 🗺️ Roadmap

- 🛡️ **DNSSEC**
  - Key rollover helpers (ZSK/KSK) with automated timing — today one KSK and one ZSK per zone. CDS/CDNSKEY already carry a new KSK to the parent; what remains is publishing old and new keys side by side through the change.
- 📦 **Operational**
  - Built-in response rate limiting (today: through the `'accept'` event).
  - Minimal responses to `ANY` (RFC 8482).
  - Metrics and logging hooks.
- 🔧 **Developer experience**
  - TypeScript definitions.
- 🚀 **Future**
  - AXFR/IXFR secondary support with TSIG.

💡 *Want something added? Open a [discussion](https://github.com/colocohen/dnssec-server/discussions) or file an issue with the tag `roadmap`.*


# Troubleshooting FAQ

**Q: My domain returns SERVFAIL after enabling DNSSEC.**  
A: The DS at your registrar must match your current KSK (key tag, algorithm, digest type, digest — or simply `material.ds`). The usual cause is keys that changed on restart: see [Keep the keys stable](#2-keep-the-keys-stable-across-restarts). Check the chain with [dnsviz.net](https://dnsviz.net).

**Q: `onError` says "negative answer … has no SOA in authority".**  
A: A response with no answers must carry the zone's SOA in `res.authority` (RFC 2308). Push it in every branch that answers "no".

**Q: Geo routing seems off.**  
A: Many resolvers don't send ECS — fall back to `req.remoteAddress`. If answers leak across regions, check that you did not set `res.ecsScope = 0` on location-dependent answers.

**Q: How do I serve both IPv4 and IPv6?**  
A: Push parallel `A` and `AAAA` answers. A name with no AAAA should answer NODATA (SOA in authority), not NXDOMAIN — the name exists.

**Q: Responses to other domains have no AA flag.**  
A: That is intended: AA is set on NOERROR / NXDOMAIN only. Answer names outside your zones with REFUSED (`rcode = 5`).


# Support the Project

If this library saves you time, consider supporting:

- ⭐ **Star** the repo — helps visibility.
- 🐛 **Issues/PRs** — report bugs, propose features.
- 💖 **Sponsorships** — GitHub Sponsors or your preferred platform.
- 🧪 **Production stories** — share how you use `dnssec-server` (helps guide the roadmap).

> For commercial support or consulting, please open an issue titled **[support]** and we'll coordinate privately.


# License

**Apache License 2.0**

```
Copyright © 2025 colocohen

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```


# References

- RFC 1034 / 1035 — DNS concepts and implementation
- RFC 2308 — Negative caching of DNS queries
- RFC 2181 — Clarifications to the DNS specification (TC, §9)
- RFC 4033 / 4034 / 4035 — DNSSEC
- RFC 4470 — Minimally covering NSEC records and online signing
- RFC 5155 — NSEC3
- RFC 6840 — DNSSEC clarifications
- RFC 6891 — EDNS(0)
- RFC 7344 / 8078 — CDS / CDNSKEY
- RFC 7766 — DNS over TCP
- RFC 7858 — DNS over TLS
- RFC 7830 / 8467 — EDNS(0) Padding and its policy
- RFC 8484 — DNS over HTTPS
- RFC 7871 — EDNS Client Subnet
- RFC 7873 / 9018 — DNS Cookies and the interoperable Server Cookie
- RFC 7828 — The edns-tcp-keepalive EDNS(0) Option
- RFC 8198 — Aggressive use of DNSSEC-validated cache
- RFC 9077 — NSEC and NSEC3 TTLs
- RFC 9250 — DNS over QUIC
- RFC 8906 — A common operational problem in DNS servers: failure to communicate
- RFC 9471 — Glue in DNS referral responses
- RFC 9619 — QDCOUNT is (usually) one
- RFC 9460 / 9461 — SVCB / HTTPS
- RFC 9824 — Compact Denial of Existence in DNSSEC
