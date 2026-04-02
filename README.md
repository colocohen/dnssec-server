<p align="center">
  <img src="https://github.com/colocohen/dnssec-server/raw/main/dnssec-server.svg" width="100%" alt="dnssec-server"/>
</p>

<h1 align="center">dnssec-server</h1>

<p align="center">
  <em>📡 Authoritative DNS server with real-time DNSSEC for Node.js</em>
</p>

<p align="center" style="max-width: 720px; margin: auto;">
  <strong>dnssec-server</strong> brings modern, flexible DNS to the Node.js ecosystem.  
  Instead of managing static zone files or running heavyweight daemons like BIND, you can now compute DNS answers directly in JavaScript.  
  Every response can be signed at runtime with DNSSEC, records can be generated dynamically (Geo-LB, canary, service discovery), and modern RR types are supported out of the box.  
  All with a lightweight API, easy integration, and zero complex configuration.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/dnssec-server">
    <img src="https://img.shields.io/npm/v/dnssec-server?color=blue" alt="npm">
  </a>
  <img src="https://img.shields.io/badge/status-in%20development-yellow" alt="status">
  <img src="https://img.shields.io/github/license/colocohen/dnssec-server?color=brightgreen" alt="license">
</p>


# Table of Contents

- [✨ Why this library?](#why-this-library)
- [📦 Install](#install)
- [🚀 Quick Start](#quick-start)
- [⚙️ API](#api)
  - [`createServer(options, handler)`](#createserveroptions-handler)
  - [Request (`req`) object](#request-req-object)
  - [Response (`res`) object](#response-res-object)
- [🔐 Enabling DNSSEC](#-enabling-dnssec)
  - [1. Generate Keys with ](#1-generate-keys-with-builddnssecmaterial)[`buildDnssecMaterial`](#1-generate-keys-with-builddnssecmaterial)
  - [2. Add DS at your registrar (KSK)](#2-add-ds-at-your-registrar-ksk)
  - [3. Wire DNSSEC into the server](#3-wire-dnssec-into-the-server)
  - [4. Verify](#4-verify)
  - [5. RRSIG Caching](#5-rrsig-caching)
- [📦 Migrating from Zone Files](#-migrating-from-zone-files)
- [🔎 Understanding ECS (EDNS Client Subnet)](#understanding-ecs-edns-client-subnet)
- [🧩 Dynamic DNS Recipes (what you can build)](#dynamic-dns-recipes-what-you-can-build)
  - [Geo Load Balancer by client IP / ECS](#geo-load-balancer-by-client-ip--ecs)
  - [Blue/Green & Canary releases](#bluegreen--canary-releases)
  - [Service discovery with SVCB/HTTPS](#service-discovery-with-svcbhttps)
  - [Regional failover with SOA/NS health](#regional-failover-with-soans-health)
- [📜 Supported Record Types (spec‑aligned)](#-supported-record-types-spec-aligned)
- [Performance Notes](#performance-notes)
- [Troubleshooting FAQ](#troubleshooting-faq)
- [Roadmap](#roadmap)
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

- 🛡️ **DNSSEC at runtime** — responses are signed on the fly (RRSIG, DNSKEY, NSEC/NSEC3). No offline signer, no cron jobs, no external toolchain.  
- ⚡ **Dynamic zones** — answers are computed from logic you write in JavaScript. Use client IP/ECS to return the nearest PoP, shift traffic with weighted canaries, or implement feature-flagged DNS in seconds.  
- 🌍 **Modern record support** — everything from `SVCB/HTTPS` for service discovery, to `TLSA` for DANE, `CAA` for certificate policy, and `URI` for service endpoints. Aligned with the latest RFCs.  
- 🧩 **Simple API surface** — just one request/response handler where you push records and call `res.send()`. No need to learn zone file syntax.  
- 🔧 **Embeddable** — run it standalone as your authoritative DNS, or embed directly in microservices that need fine-grained control.  


This makes **dnssec-server** especially useful when:
- You want DNS decisions tied directly to application logic (load balancing, canaries, failover).  
- You need DNSSEC but don’t want to manage signing infrastructure.  
- You’re building modern protocols (`HTTPS`/`SVCB`, `ECH`, `DoT`) and need a flexible testbed.  
- You want to prototype quickly without carrying the weight of BIND/NSD.  

In short: **dnssec-server** lets you treat DNS as part of your codebase — not as an external, opaque system.


# 📦 Install

```bash
npm i dnssec-server
```

Works with both ESM and CommonJS:

```js
// ESM
import DNSServer from 'dnssec-server';

// CommonJS
const DNSServer = require('dnssec-server');
```


# 🚀 Quick Start

Below is a minimal authoritative server (UDP/TCP by default; enable DNS‑over‑TLS via `options.tls`). It returns an `A` record for `example.com.` and `NXDOMAIN` otherwise.

```js
import fs from 'node:fs';
import tls from 'node:tls';
import DNSServer from 'dnssec-server';

DNSServer.createServer({
  tls: { // enable DNS over TLS (DoT) on port 853 by default
    SNICallback: function (servername, cb) {
      cb(null, tls.createSecureContext({
        key: fs.readFileSync('key.pem'),
        cert: fs.readFileSync('cert.pem')
      }));
    }
  }
}, function (req, res) {
  console.log(`[${req.transport}] from ${req.remoteAddress}:${req.remotePort}  q=${req.name} ${req.type} ${req.class}  DO=${req.flag_do}  ECS=${req.ecsAddress||'-'}/${req.ecsSourcePrefixLength||'-'}`);

  if (req.name === 'example.com.' && req.type === 'A') {
    res.answers.push({
      name: 'example.com.',
      type: 'A',
      class: 'IN',
      ttl: 300,
      data: { address: '200.10.10.1' }
    });
    res.send();
  } else {
    res.header.rcode = 3; // NXDOMAIN
    res.authority.push({
      name: 'example.com.',
      type: 'SOA',
      class: 'IN',
      ttl: 300,
      data: {
        mname: 'ns1.example.com.',
        rname: 'hostmaster.example.com.',
        serial: 2025081001,
        refresh: 3600,
        retry: 600,
        expire: 604800,
        minimum: 300
      }
    });
    res.send();
  }
});
```


# ⚙️ API

## `createServer(options, handler)`

Creates and starts an authoritative DNS server.

**Parameters**

- `options`
  - `udp` 
  *(boolean | { port?: number, address?: string })* — enable/disable UDP transport (default: **enabled**, port 53 unless overridden).
  - `tcp` 
  *(boolean | { port?: number, address?: string })* — enable/disable TCP transport (default: **enabled**, port 53 unless overridden).
  - `tls` 
  *(false | { port?: number, address?: string, SNICallback?: (servername, cb) => void })* — enable DNS‑over‑TLS (default: **disabled**). Supply an `SNICallback` that returns a `SecureContext`.
  - `dnssec` *(optional)*
    - `keyCallback: (name: string, cb: (err, material | null) => void)` — called on every query with `DO=1` to retrieve signing keys. See [DNSSEC](#-enabling-dnssec).
    - `cache` *(optional)* — RRSIG signature cache. See [RRSIG Caching](#-rrsig-caching). Can be:
      - `true` — use built-in in-memory cache.
      - `{ get, set }` — provide your own cache backend (Redis, LRU, etc.).
      - omitted or `false` — no caching, sign every response.
    - `cacheMax` *(number, default 10000)* — max entries for the built-in cache (only when `cache: true`).
  - `onError` *(optional)* — `function(err, transport)` called on socket errors. `transport` is `'udp4'`, `'udp6'`, `'tcp'`, or `'tls'`. Without this, socket errors are silently ignored.
  - Other advanced knobs may exist; consult source for current options.
- `handler(req, res)`
  your request handler. Populate `res.answers` / `res.authority` / `res.additionals` then call `res.send()`.

**Returns** an object with:

- `close(cb)` — gracefully shut down all transports.
- `clearRrsigCache()` — clear the RRSIG signature cache (built-in mode).
- `rrsigCacheSize()` — return number of cached signatures (built-in mode).
- `context` — internal server context (for advanced use).

> **Note**: Defaults above align with common expectations; if you need precise behavior (binding interfaces/ports, concurrency, etc.) refer to the code and examples.


## Request (`req`) object

Properties commonly used in logic:

- `id` *(number)* — message ID.
- `transport` *('udp4'|'udp6'|'tcp'|'tls'|'quic')* — which transport delivered the query.
- `remoteAddress` *(string)*, `remotePort` *(number)* — client socket tuple (for ECS-aware setups prefer `ecsAddress`).
- `client` *({ address, port, family })* — full client info including `'IPv4'` or `'IPv6'`.
- `name` *(FQDN with trailing dot)* — qname, e.g. `example.com.`
- `type` *(string)* — qtype, e.g. `A`, `AAAA`, `TXT`, ...
- `class` *(string)* — typically `IN`.
- `flag_qr` / `flag_aa` / `flag_tc` / `flag_rd` / `flag_ra` / `flag_ad` / `flag_cd` *(booleans)* — header flags.
- `flag_do` *(boolean)* — DO bit (EDNS(0) DNSSEC OK).
- `edns` *(object | undefined)* — full parsed EDNS data (udpSize, options, optionsStructured, etc.).
- `edns_udp_size` *(number | undefined)* — advertised UDP payload size.
- `ednsOptions` *(array | undefined)* — raw EDNS options list if you need to inspect.
- `ecsAddress` *(string | undefined)* — **EDNS Client Subnet** address if sent by resolver.
- `ecsSourcePrefixLength` *(number | undefined)* — ECS source prefix length.
- `ecsScopePrefixLength` *(number | undefined)* — ECS scope prefix length.
- `tls` *(object | undefined)* — TLS info when transport is `'tls'` (includes `authorized`, `alpn`).
- `raw` *(Uint8Array)* — original wire bytes.
- `message` *(object)* — full decoded DNS message (header, questions, answers, etc.).


## Response (`res`) object

- `header` — mutate flags/rcode:
  - `res.header.aa = true` *(default authoritative)*
  - `res.header.rcode = 0` *(0=NOERROR, 3=NXDOMAIN, 2=SERVFAIL, ...)*
- `answers`, `authority`, `additionals` — **arrays of RRs**. Each RR is `{ name, type, class:'IN', ttl, data }` (see [Supported Types](#-supported-record-types-spec-aligned)).
- `send()` — finalize and transmit the response. You can call it once per query.

> When `flag_do` is set and DNSSEC is configured, responses are signed automatically (RRSIG + DNSKEY/NSEC\* as needed).


## 🔧 `encodeMessage` / `decodeMessage`

For advanced use cases, `dnssec-server` also exposes low-level primitives to
**parse** and **serialize** raw DNS messages.  
This is useful if you want to:

- Build your own transport (QUIC/DoH/DoQ) on top of DNS.  
- Implement custom caching layers or middleboxes.  
- Unit-test DNS record encoding/decoding without running a full server.  

```js
import { encodeMessage, decodeMessage } from 'dnssec-server';

// Decode a raw DNS query from a Buffer/Uint8Array
const query = decodeMessage(rawBuffer);

// Manipulate the message object (add answers, change rcode, sign with DNSSEC, etc.)
query.answers.push({
  name: 'example.com.',
  type: 'A',
  class: 'IN',
  ttl: 60,
  data: { address: '203.0.113.10' }
});

// Re-encode into wire format
const wire = encodeMessage(query);
```


# 🔐 Enabling DNSSEC

This section explains how to generate DNSSEC material with the helper function and install it at both your **registrar (e.g., Namecheap)** and in your **DNS zone**.


## 1. Generate Keys with `buildDnssecMaterial`

You can either **provide your own private keys** (Base64 string or `Uint8Array`), or leave them empty and the function will **auto‑generate random secure keys**.

```js
const DNSServer = require('dnssec-server');

// Auto-generate keys
const dnssec_material_obj = DNSServer.buildDnssecMaterial({ signersName: "example.com." });

// Or provide your own private keys
const dnssec_material_obj = DNSServer.buildDnssecMaterial({
  signersName: "example.com.",
  ksk: { privateKey: "BASE64-ENCODED-PRIVATE-KEY" },
  zsk: { privateKey: "BASE64-ENCODED-PRIVATE-KEY" },
  digestType: 2 // optional: 2=SHA-256 (default), 4=SHA-384
});
```

Example output:

```json
{
  "signersName": "example.com.",
  "ksk": {
    "keyTag": 14257,
    "privateKey": "...",
    "publicKey":  "...",
    "algorithm": 13,
    "digestType": 2,
    "digest": "A1B2C3D4E5F6..."
  },
  "zsk": {
    "keyTag": 27179,
    "privateKey": "...",
    "publicKey":  "..."
  }
}
```


## 2. Add DS at your registrar (KSK)

In **Namecheap → Domain List → Manage → Advanced DNS → DNSSEC → Add DS Record**, copy the following values from `material.ksk`:

- **Key Tag** → `ksk.keyTag`
- **Algorithm** → `ksk.algorithm` (usually `13`)
- **Digest Type** → `ksk.digestType` (usually `2`)
- **Digest** → `ksk.digest` (HEX uppercase)

Example:

| Key Tag | Algorithm | Digest Type | Digest          |
| ------- | --------- | ----------- | --------------- |
| 14257   | 13        | 2           | A1B2C3D4E5F6... |

⚠️ Only the **KSK** produces a DS record for the registrar. The **ZSK** is not used here.


## 3. Wire DNSSEC into the server

The library **handles DNSSEC automatically**. Just pass the object returned by `buildDnssecMaterial` into the server via `dnssec.keyCallback`. No manual DNSKEY publishing is needed — `dnssec-server` will expose the DNSKEYs and serve signed responses.

```js
import DNSServer from 'dnssec-server';

// 1) Generate (or load) DNSSEC material
const dnssec_material_obj = DNSServer.buildDnssecMaterial({
  signersName: 'example.com.'
  // optional:
  // ksk: { privateKey: 'BASE64-P256-PRIVATE-KEY' },
  // zsk: { privateKey: 'BASE64-P256-PRIVATE-KEY' },
});

// 2) Create your DNS/TLS server and wire DNSSEC
DNSServer.createServer({
  dnssec: {
    // Return DNSSEC material per signer name. You can support multiple zones.
    keyCallback: function (name, cb) {
      if (name.endsWith('example.com.')) cb(null, dnssec_material_obj);
      else cb(null, null); // no DNSSEC for this name
    }
  }
}, function (req, res) {
  // ... your request handling ...
});
```

**Notes**

- The object structure must match `buildDnssecMaterial` output:
  ```js
  {
    signersName: 'example.com.',
    ksk: { keyTag, privateKey, publicKey, algorithm, digestType, digest },
    zsk: { keyTag, privateKey, publicKey }
  }
  ```
- You can persist `dnssec_material_obj` to disk and load it on startup to keep keys stable across restarts.
- To rotate ZSKs later, generate a new `zsk` and return it alongside the existing KSK; the server will continue serving a valid chain.


## 4. Verify

After propagation, test with:

```bash
dig +dnssec example.com DNSKEY
dig +dnssec example.com A
```

Or use [dnssec-debugger.verisignlabs.com](https://dnssec-debugger.verisignlabs.com) to confirm everything validates.


## 5. RRSIG Caching

ECDSA P-256 signing takes ~1–5ms per RRset. If many clients query the same records, the server re-signs identical responses unnecessarily. RRSIG caching avoids this by reusing previously computed signatures.

**No cache (default)** — every response is signed fresh:

```js
DNSServer.createServer({
  dnssec: { keyCallback: myKeyCallback }
}, handler);
```

**Built-in in-memory cache** — simple and zero-config:

```js
DNSServer.createServer({
  dnssec: {
    keyCallback: myKeyCallback,
    cache: true,
    cacheMax: 5000   // optional, default 10000
  }
}, handler);
```

**Custom cache backend** — full control over storage (Redis, LRU, database, etc.):

```js
DNSServer.createServer({
  dnssec: {
    keyCallback: myKeyCallback,
    cache: {
      get: function (params, cb) {
        // params: { name, type, class, keyTag, hash }
        // Return cached value or null for cache miss
        redis.get(params.hash + ':' + params.keyTag, function (err, raw) {
          cb(err, raw ? JSON.parse(raw) : null);
        });
      },
      set: function (params, value, cb) {
        // value: { rrsig, expiration, inception }
        var key = params.hash + ':' + params.keyTag;
        var ttl = value.expiration - Math.floor(Date.now() / 1000);
        redis.setex(key, ttl, JSON.stringify(value), cb);
      }
    }
  }
}, handler);
```

### Cache `get` callback

Called before signing. If it returns a valid cached entry, signing is skipped.

```js
get(params, cb)
```

`params` contains:

- `name` *(string)* — owner name of the RRset, e.g. `'example.com.'`
- `type` *(string)* — RR type, e.g. `'A'`, `'AAAA'`, `'DNSKEY'`
- `class` *(string)* — RR class, e.g. `'IN'`
- `keyTag` *(number)* — key tag of the signing key
- `hash` *(string)* — SHA-256 hex digest of the canonical RRset bytes (changes when record content changes)

Call `cb(null, cachedValue)` on hit, `cb(null, null)` on miss, or `cb(err)` on error (will sign without caching).


### Cache `set` callback

Called after signing a new RRSIG. Store the value however you like.

```js
set(params, value, cb)
```

`params` is the same object as `get`. `value` contains:

- `rrsig` *(object)* — the full RRSIG record, ready to push to answers
- `expiration` *(number)* — UNIX timestamp when the signature expires
- `inception` *(number)* — UNIX timestamp when the signature becomes valid

Call `cb(null)` when done. Errors don't affect the response (the signature was already computed).


### Server cache control

The object returned by `createServer` provides:

```js
const server = DNSServer.createServer({ ... }, handler);

server.clearRrsigCache();     // flush all cached signatures
server.rrsigCacheSize();      // number of cached entries (built-in mode)
```

These are useful after key rollover or zone updates to force re-signing.


# 📦 Migrating from Zone Files

If you are already operating an external DNS server (such as **BIND**) and maintaining your zones in standard **zone files**, you don’t need to rewrite your data.  
`dnssec-server` provides first-class support for BIND-style zone files: you can load them directly, parse them with `parseZone()`, and use `answerFromZone()` to resolve queries.  

This approach makes migration seamless:
- No manual conversion of records.
- `$ORIGIN` and `$TTL` directives are honored.
- Broad RR support (A, AAAA, NS, CNAME, MX, TXT, SRV, CAA, NAPTR, DNSKEY, DS, RRSIG, NSEC, NSEC3PARAM).
- Full support for **SVCB/HTTPS** including `priority`, `target`, `alpn`, `port`, `ipv4hint`, `ipv6hint`, and glue generation.


**Supported today**
- `$ORIGIN` and `$TTL`
- A, AAAA, NS, CNAME, PTR, MX, TXT, SRV, CAA, NAPTR, DNSKEY, DS, RRSIG, NSEC, NSEC3PARAM
- **SVCB/HTTPS** with normalized `data`:
  - `priority`, `target`, `params` (e.g. `alpn`, `port`, `ipv4hint`, `ipv6hint`, unknown keys preserved)
  - Glue for MX/SRV/NS and SVCB/HTTPS targets (when present in the zone)
  - A/AAAA synthesized from `ipv4hint`/`ipv6hint` for the **TargetName** are added to `additionals`

> ℹ️ If your zone file doesn’t contain `$ORIGIN`, pass `parseZone(text, { origin: 'example.com.' })`.


## Example: load multiple zone files and serve them

```js
import fs from 'node:fs';
import tls from 'node:tls';
import DNSServer from 'dnssec-server';

// 1) Load and parse multiple BIND-style zone files (sync for simplicity)
const zones = {
  'example.com.': DNSServer.parseZone(fs.readFileSync('example.com.zone', 'utf8')),
  'example.net.': DNSServer.parseZone(fs.readFileSync('example.net.zone', 'utf8')),
  // add more apexes as needed...
};

// 2) Choose the zone by longest-suffix match
function pickZone(zs, qname) {
  let bestOrigin = null, bestLen = -1;
  for (const origin of Object.keys(zs)) {
    const match = (qname === origin) || qname.endsWith('.' + origin.replace(/\.$/, '') + '.');
    if (match && origin.length > bestLen) { bestOrigin = origin; bestLen = origin.length; }
  }
  return bestOrigin ? zs[bestOrigin] : null;
}

// 3) Create the server. Map each request to a pure answer object.
DNSServer.createServer({
  tls: {
    SNICallback: (servername, cb) =>
      cb(null, tls.createSecureContext({
        key:  fs.readFileSync('key.pem'),
        cert: fs.readFileSync('cert.pem')
      }))
  }
}, (req, res) => {
  const zone = pickZone(zones, req.name);

  if(zone){
    var { rcode, answers, authority, additionals } = DNSServer.answerFromZone(zone, req.name, req.type, req.class);
  }else{
    var rcode=3; 
    var answers=[]; 
    var authority=[];
    var additionals=[];
  }

  // 👇 You have an opportunity to modify the response here (e.g., adjust TTLs,
  //    inject ECS-based answers, add/remove records, override rcode, etc.)

  res.header.rcode = rcode;          // 0 = NOERROR, 3 = NXDOMAIN
  res.answers.push(...answers);
  res.authority.push(...authority);
  res.additionals.push(...additionals);
  res.send();


}).listen(53, () => {
  console.log('Authoritative DNS (UDP/TCP) on :53 + DoT on :853');
});
```



# 🔎 Understanding ECS (EDNS Client Subnet)

When your DNS server receives a query, the field `req.remoteAddress` does **not** usually show the real end-user’s IP.  
Instead, it shows the **resolver** that made the query on the client’s behalf — typically the ISP’s resolver, or a public one like Google (8.8.8.8) or Cloudflare (1.1.1.1).

To help authoritative servers make smarter decisions (e.g. geo-based routing), some resolvers add the **EDNS Client Subnet (ECS)** option.  
ECS includes only a **prefix** of the user’s real IP address, never the full value, in order to preserve privacy.  

For example:
ECS=200.118.80.0/24

This means the real client was somewhere in the `200.118.80.xxx` range, while the last octet was zeroed out.  
The `/24` indicates how many bits of the address are valid.  

In this library, ECS data is exposed through convenient fields:

- `req.ecsAddress` → the truncated client address (e.g. `200.118.80.0`)  
- `req.ecsSourcePrefixLength` → the prefix length (e.g. `24`)  

Resolvers that do not send ECS will simply yield `ECS=-/-`.

ECS is useful if you want to implement **geo-location logic, load balancing, or analytics** that take into account where users are actually coming from, rather than just the resolver’s IP.


# 🧩 Dynamic DNS Recipes (what you can build)

## Geo Load Balancer by client IP / ECS

Return the nearest POP based on **ECS** if provided (preferred), or fall back to the socket IP.

```js
function pickRegionByIp(ip) {
  // toy example: map IP to region; replace with MaxMind-lite table or your own CIDR map
  if (ip.startsWith('200.10.')) return 'sa-east';
  if (ip.startsWith('192.0.2.')) return 'us-east';
  return 'eu-west';
}

function handler(req, res){
  var clientIp = req.ecsAddress || req.remoteAddress;
  var region = pickRegionByIp(clientIp || '');
  var targets = {
    'sa-east': '200.10.10.1',
    'us-east': '198.51.100.7',
    'eu-west': '203.0.113.42'
  };
  res.answers.push({ 
    name: req.name, 
    type: 'A', 
    class: 'IN', 
    ttl: 30, 
    data: { 
      address: targets[region] 
    }
  });
  res.send();
}
```

**Tips**

- Prefer `ecsAddress` when available; many public resolvers (e.g., 8.8.8.8) include ECS.
- Keep TTL short for agility; adjust by record set.


## Blue/Green & Canary releases

Serve two record sets with weighted selection.

```js
function weightedPick(pct){ return Math.random()*100 < pct; }
function canaryA(req, res){
  var canary = weightedPick(5); // 5% canary
  res.answers.push({ name: req.name, type:'A', class:'IN', ttl:20, data:{ address: canary ? '203.0.113.77' : '203.0.113.10' }});
  res.send();
}
```


## Service discovery with `SVCB`/`HTTPS`

Advertise ALPNs, ports, IPv4/IPv6 hints, and ECH config as per RFC 9460/9461.

```js
res.answers.push({
  name: '_https.example.com.', type: 'HTTPS', class: 'IN', ttl: 300,
  data: {
    priority: 1,
    targetName: 'svc.example.',
    paramsStructured: {
      alpn: ['h3','h2'],
      port: 8443,
      ipv4hint: ['192.0.2.10','192.0.2.11']
      // ech, dohpath, tlsSupportedGroups ...
    }
  }
});
```


## Regional failover with SOA/NS health

Synthesize answers depending on upstream health checks; switch NS/A sets when a region is down. Pair with short TTLs and RRSIG validity windows.


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
{ data: { address: Uint8Array(16) } }
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
      tlsSupportedGroups: [29,23]
    }
  }
}
```


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
- Consider a **small signature validity window** for DNSSEC on highly dynamic zones.
- If you accept high QPS, consider sharding instances per region and delegating via NS.


# 🗺️ Roadmap

The core API is stable, but several enhancements are planned to make **dnssec-server** even more production-ready:

- 🛡️ **DNSSEC optimizations**
  - Response signature caching (avoid re-signing identical RRsets on every query).
  - Key rollover helpers (ZSK/KSK) with automated timing.

- 🌐 **New transports**
  - DNS-over-HTTPS (DoH, RFC 8484).
  - DNS-over-QUIC (DoQ, RFC 9250).

- 📦 **Operational features**
  - Built-in caching layer (configurable TTLs, ECS-aware).
  - Metrics and logging hooks (Prometheus/OpenTelemetry).
  - Basic rate limiting & DNS Cookies (RFC 7873).

- 🔧 **Developer experience**
  - First-class TypeScript definitions.
  - More example recipes (Geo-LB, service discovery with HTTPS/SVCB, TLSA for DANE).

- 🚀 **Future ideas**
  - AXFR/IXFR secondary support with TSIG.
  - Integration with container orchestrators (Kubernetes service discovery).
  - DoH/DoQ benchmarking & performance tuning.


💡 *Want something added? Open a [discussion](https://github.com/colocohen/dnssec-server/discussions) or file an issue with the tag `roadmap`. Contributions and proposals are welcome!*


# Troubleshooting FAQ

**Q: I get ****\`\`**** when enabling DNSSEC.**\
A: Ensure your registrar DS matches your current KSK (`keyTag`, `algorithm`, `digestType`, `digest`). After rotation, DS must be updated.

**Q: Geo routing seems off.**\
A: Many resolvers don’t send ECS. Fall back to `req.remoteAddress` or use anycast + regional NS.

**Q: How do I serve both IPv4 and IPv6?**\
A: Push parallel `A` and `AAAA` answers.


# Support the Project

If this library saves you time, consider supporting:

- ⭐ **Star** the repo — helps visibility.
- 🐛 **Issues/PRs** — report bugs, propose features.
- 💖 **Sponsorships** — GitHub Sponsors or your preferred platform.
- 🧪 **Production stories** — share how you use `dnssec-server` (helps guide roadmap).

> For commercial support or consulting, please open an issue titled **[support]** and we’ll coordinate privately.


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

- RFC 1034/1035 — DNS Concepts & Implementation
- RFC 4033/4034/4035 — DNSSEC
- RFC 5155 — NSEC3
- RFC 6891 — EDNS(0)
- RFC 7871 — EDNS Client Subnet (ECS)
- RFC 9460/9461 — SVCB/HTTPS
- RFC 7858 — DNS over TLS (DoT)

