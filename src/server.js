/*
 * dnssec-server: DNS server for Node.js
 * Copyright 2025 colocohen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * This file is part of the open-source project hosted at:
 *     https://github.com/colocohen/dnssec-server
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 */

import dgram from 'node:dgram';
import net from 'node:net';
import { createQuicServer, createTcpListener } from 'quico';
import lemonTls from 'lemon-tls';
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';

import * as wire from './wire.js';
import { buildEDNSOptions } from './edns.js';
import { createCookieJar } from './cookies.js';
import { fqdn, ensureDot } from './utils.js';
// NOTE: the encrypted transports — DoT and DoQ — both run on quico and
// lemon-tls, so one SNICallback and one kind of certificate context serve
// them both.


// ---------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------
function toHex(u8){
  var s=''; for (var i=0;i<u8.length;i++){ var b=u8[i]; s += (b<16?'0':'') + b.toString(16); }
  return s.toUpperCase();
}

function toB64(u8){
  if (!(u8 instanceof Uint8Array)) u8 = new Uint8Array(u8);
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(u8).toString('base64');
  }
  var bin = '';
  for (var i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin);
}


function toU8(x){
  if (x instanceof Uint8Array) return x;
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(x)) return new Uint8Array(x);
  if (typeof x === 'string') {
    // decode Base64 to byte array
    if (typeof Buffer !== 'undefined') {
      return new Uint8Array(Buffer.from(x, 'base64'));
    } else {
      var bin = atob(x);
      var out = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    }
  }
  throw new Error('Unsupported privateKey format: must be Uint8Array, Buffer, or base64 string');
}

function clamp(n, a, b){ if (n<a) return a; if (n>b) return b; return n; }

function familyOf(address){ return address && address.indexOf(':')!==-1 ? 'IPv6' : 'IPv4'; }

// Convert ECS bytes to text address
function ecsBytesToIP(family, bytes, prefixLen){
  var b = (bytes instanceof Uint8Array) ? Array.from(bytes) : Array.from(bytes || []);
  prefixLen = (prefixLen|0) > 0 ? (prefixLen|0) : (b.length * 8);

  var need = Math.ceil(prefixLen / 8);
  while (b.length < need) b.push(0);

  if (prefixLen % 8 !== 0) {
    var bits = prefixLen % 8;
    var mask = (0xFF << (8 - bits)) & 0xFF;
    b[need - 1] = b[need - 1] & mask;
  }

  if (family === 1) { // IPv4
    while (b.length < 4) b.push(0);
    return b.slice(0,4).join('.');
  }

  if (family === 2) { // IPv6
    while (b.length < 16) b.push(0);
    var parts = [];
    for (var i=0;i<16;i+=2){
      var part = ((b[i] << 8) | b[i+1]) & 0xFFFF;
      parts.push(part.toString(16));
    }
    // basic zero-sequence compression
    var s = parts.join(':').replace(/(^|:)0(:0)+(:|$)/, '::');
    return s;
  }

  return undefined;
}

// ---------------------------------------------------------------
// Build req/res objects
// ---------------------------------------------------------------
function buildReq(transport, peer, buf, msg, tlsInfo){
  var q = (msg && msg.questions && msg.questions[0]) || null;
  var name = q ? fqdn(q.name) : '.';
  var type = q ? q.type : undefined;
  var klass = q ? q.class : undefined;

  var ed  = msg && msg.edns ? sanitizeEdns(msg.edns) : undefined;
  var ecs = ed && (ed.ecs || (ed.optionsStructured && ed.optionsStructured.ecs)) || undefined;
  var ecsIpStr = ecs ? ecsBytesToIP(ecs.family, ecs.addressBytes, ecs.sourcePrefixLength) : undefined;

  var hdr = msg && msg.header ? msg.header : {};

  var req = {
    id: msg && msg.header ? (msg.header.id>>>0) : 0,
    transport: transport, // 'udp4'|'udp6'|'tcp'|'tls'|'quic'
    client: { address: peer.address, port: peer.port>>>0, family: familyOf(peer.address) },
    remoteAddress: peer.address,
    remotePort: peer.port>>>0,
    tls: tlsInfo || undefined,

    // first question
    name: name,
    type: type,
    class: klass,

    // header flags (convenient shortcuts)
    flag_qr: !!hdr.qr,
    flag_aa: !!hdr.aa,
    flag_tc: !!hdr.tc,
    flag_rd: !!hdr.rd,
    flag_ra: !!hdr.ra,
    flag_ad: !!hdr.ad,
    flag_cd: !!hdr.cd,

    // EDNS
    edns: ed,
    flag_do: !!(ed && ed.do),
    edns_udp_size: ed ? ed.udpSize : undefined,
    ednsOptions: ed ? ed.options : undefined,

    // ECS — convenient for geo/load-balancing
    ecs: ecs || undefined,
    ecsAddress: ecsIpStr || undefined,
    ecsSourcePrefixLength: ecs ? ecs.sourcePrefixLength : undefined,
    ecsScopePrefixLength:  ecs ? ecs.scopePrefixLength  : undefined,

    // raw access
    raw: toU8(buf),
    message: msg
  };
  return req;
}

// The largest DNS message sent over UDP, whatever the client advertises.
// A bigger datagram is fragmented at the IP layer, and fragments are dropped
// on many paths — on IPv6 above all — so the answer never arrives and the
// resolver times out instead of retrying over TCP. 1232 is the size every
// path carries whole (IPv6 minimum MTU 1280, less IPv6 and UDP headers): the
// value of DNS Flag Day 2020 and RFC 9715. An answer larger than that goes
// out truncated (TC), and the client asks again over TCP.
var MAX_UDP_PAYLOAD = 1232;

function sanitizeEdns(ed){
  var out = {
    udpSize: clamp(ed.udpSize || MAX_UDP_PAYLOAD, 512, MAX_UDP_PAYLOAD),
    extRcode: ed.extRcode|0,
    version: ed.version|0,
    do: !!ed.do,
    z: ed.z|0,
    options: Array.isArray(ed.options)? ed.options.slice(0) : []
  };

  var os = ed.optionsStructured || {};
  out.optionsStructured = os;

  // promote from structured fields
  if (ed.cookie) out.cookie = ed.cookie;
  if (ed.ecs) out.ecs = ed.ecs;
  if (!out.ecs && os.ecs) out.ecs = os.ecs; // fallback to structured
  if (ed.keyTag) out.keyTag = ed.keyTag.slice(0);
  if (ed.ede) out.ede = ed.ede.slice(0);

  return out;
}

// The RCODE the standards give a query before any handler sees it — 0 when
// it is the handler's (see dispatch).
var RCODE_FORMERR = 1, RCODE_NOTIMP = 4, RCODE_REFUSED = 5, RCODE_BADVERS = 16, RCODE_BADCOOKIE = 23;
// The bytes of the query's COOKIE option, or null. Read raw: what makes one
// malformed is its length (RFC 7873 §5.2.2), which the parsed form hides.
function cookieOption(msg){
  var opts = msg.edns && msg.edns.options;
  if (!opts) return null;
  for (var i = 0; i < opts.length; i++) if (opts[i] && opts[i].code === 10) return toU8(opts[i].data || new Uint8Array(0));
  return null;
}

function standardRcode(msg){
  if (msg.formatError) return RCODE_FORMERR;
  if (msg.edns && (msg.edns.version | 0) !== 0) return RCODE_BADVERS;
  // The opcode first: an unknown one is NOTIMP whatever its sections hold
  // (RFC 8906 §8.1.4 sends opcode 15 with no question); the one-question
  // rule is QUERY's (RFC 9619 §4).
  if ((msg.header.opcode | 0) !== 0) return RCODE_NOTIMP;
  var q = msg.questions && msg.questions[0];
  if ((msg.header.qdcount | 0) !== 1 || !q || !q.name || !q.type) return RCODE_FORMERR;
  return 0;
}

function buildRes(req, serverCtx){
  var hdrIn = req.message && req.message.header || {};
  var res = {
    header: {
      id: req.id|0,
      qr: true,
      opcode: hdrIn.opcode|0,
      // Authoritative Answer: left undecided here so a handler can set it
      // either way; sendResponse fills it in (see decideAA).
      aa: undefined,
      tc: false,//Truncated
      rd: !!hdrIn.rd,//Recursion Desired
      ra: !!serverCtx.options.always_ra,//Recursion Available
      ad: false,
      cd: !!hdrIn.cd,
      rcode: 0
    },
    answers: [],
    authority: [],
    additionals: [],
    // The OPT RR of the answer: present when the query had one, and only then
    // (RFC 6891 §7). Its UDP payload size is OURS — what this server takes
    // (RFC 6891 §6.2.3) — not the client's echoed; what the answer may fill
    // is the client's (udpLimit).
    edns: req.edns ? {
      udpSize: MAX_UDP_PAYLOAD,
      extRcode: 0,
      version: 0,
      do: !!req.edns.do, // echo DO (RFC 6891 ignores it in responses, but echoing aids debugging)
      z: 0,
      options: []
    } : undefined,

    // API
    send: function(){ return serverCtx._sendResponse(req, res); },
    finalize: function(){ return serverCtx._finalizeWire(req, res); }
  };
  return res;
}

// ---------------------------------------------------------------
// Smart truncation + pre-encode injection
// ---------------------------------------------------------------

function encodeNow(res, req){
  var msg = {
    header: res.header,
    questions: req.message && req.message.questions ? req.message.questions.slice(0,1) : (req.name ? [{ name:req.name, type:req.type, class:req.class }] : []),
    answers: res.answers||[],
    authority: res.authority||[],
    additionals: res.additionals||[],
    edns: res.edns
  };
  return wire.encodeMessage(msg);
}

// The address records in the additional section of a referral are its glue:
// a resolver cannot reach the delegated servers without the in-bailiwick
// ones. Leaving them out is a truncation (TC), not an omission (RFC 9471 §3).
function isReferralWithGlue(res){
  if (res.answers && res.answers.length) return false;
  var ns = false;
  for (var i = 0; i < (res.authority ? res.authority.length : 0); i++) if (String(res.authority[i].type).toUpperCase() === 'NS') ns = true;
  if (!ns) return false;
  for (var j = 0; j < (res.additionals ? res.additionals.length : 0); j++){
    var t = String(res.additionals[j].type).toUpperCase();
    if (t === 'A' || t === 'AAAA') return true;
  }
  return false;
}

function truncateSmart(serverCtx, req, res, udpMax){
  // Priority: keep OPT + answers as long as possible.
  // Sections are removed CUMULATIVELY (additionals, then also authority, then also answers) —
  // removals must stack, otherwise a message whose sections are individually too small to
  // matter can never be brought under udpMax.
  //
  // TC says the answer is incomplete — the client must ask again over TCP.
  // Additional records left out are not that (RFC 2181 §9: TC is not set
  // "merely because some extra information could have been included"),
  // except a referral's glue (RFC 9471); anything else left out is. TC was
  // set for every truncation, and a resolver asked again over TCP for an
  // answer it already had whole.
  var tryOrder = ['additionals','authority','answers'];
  var saved = {};
  var glue = isReferralWithGlue(res);

  var wireOut = null;
  for (var i=0;i<tryOrder.length;i++){
    var sec = tryOrder[i];
    if (res[sec] && res[sec].length){
      saved[sec] = res[sec];
      res[sec] = [];
      res.header.tc = sec !== 'additionals' || glue;
      var w = encodeNow(res, req);
      if (w.length <= udpMax){ wireOut = w; break; }
    }
  }

  if (wireOut === null){
    res.header.tc = true;
    // Everything stripped and still too large (huge question / tiny udpMax):
    // send header + question only, without EDNS. NEVER slice raw bytes —
    // a byte-sliced message has header counts that lie about its contents.
    var savedEdns = res.edns;
    res.edns = undefined;
    wireOut = encodeNow(res, req);
    res.edns = savedEdns;
    // (header[12] + question[<=281] always fits any legal 512+ byte UDP limit)
  }

  // restore sections so `res` remains inspectable after send
  for (var k in saved) res[k] = saved[k];
  return wireOut;
}

function isUdp(transport){ return transport === 'udp4' || transport === 'udp6'; }
// Transports whose bytes an observer cannot read: DoT, DoQ, and DoH through
// handleMessage. Padding is for them alone.
function isEncrypted(transport){ return transport === 'tls' || transport === 'quic' || transport === 'https'; }

// EDNS(0) Padding (RFC 7830, RFC 8467 §4.1): over an encrypted transport, an
// answer's length can tell an observer what was asked — so a server pads it,
// to a multiple of 468 octets ("Block-Length Padding", the size RFC 8467
// recommends for responses), when the query was padded: only then (RFC 7830
// §3: "MUST NOT" otherwise), and not over UDP or TCP in the clear. DoQ asks
// for it in RFC 9250 §5.4. The option's 4 octets of code and length count.
var PADDING_BLOCK = 468;
var EDNS_OPT_PADDING = 12;
function wantsPadding(req, res){
  return isEncrypted(req.transport) && !!res.edns && !!req.edns &&
         req.edns.optionsStructured && req.edns.optionsStructured.padding !== undefined;
}
function addPadding(res, encodedLength){
  var opts = res.edns.options || (res.edns.options = []);
  for (var i = 0; i < opts.length; i++) if (opts[i] && opts[i].code === EDNS_OPT_PADDING) return false;   // the handler's own
  var pad = (PADDING_BLOCK - ((encodedLength + 4) % PADDING_BLOCK)) % PADDING_BLOCK;
  opts.push({ code: EDNS_OPT_PADDING, data: new Uint8Array(pad) });
  return true;
}

// EDNS options the server adds to every answer that has an OPT RR, unless
// the handler wrote its own:
//   COOKIE (RFC 7873 §5.2) — the client's cookie and a server cookie for it,
//     whenever the query carried one (not with BADVERS: that answer is for an
//     EDNS version whose options this server does not know);
//   edns-tcp-keepalive (RFC 7828 §3.3.2) — over TCP and DoT, when the query
//     asked: how long this server keeps an idle connection, in units of
//     100 ms, so a client reuses it without racing the server's close.
// Padding (above) comes after them: it is computed last (RFC 8467 §3).
var EDNS_OPT_COOKIE = 10, EDNS_OPT_KEEPALIVE = 11;
function hasOption(opts, code){
  for (var i = 0; i < opts.length; i++) if (opts[i] && opts[i].code === code) return true;
  return false;
}
function addServerOptions(serverCtx, req, res){
  if (!res.edns || (res.header.rcode | 0) === RCODE_BADVERS) return;
  var opts = res.edns.options || (res.edns.options = []);
  var ck = req._cookie;
  if (ck && (ck.status === 'client' || ck.status === 'valid') && serverCtx.cookies && !hasOption(opts, EDNS_OPT_COOKIE)){
    opts.push({ code: EDNS_OPT_COOKIE, data: serverCtx.cookies.responseOption(ck) });
  }
  var idleMs = req._link && req._link.idleMs;
  if (idleMs > 0 && req.edns.optionsStructured && req.edns.optionsStructured.keepalive && !hasOption(opts, EDNS_OPT_KEEPALIVE)){
    var units = Math.min(0xFFFF, Math.round(idleMs / 100));
    opts.push({ code: EDNS_OPT_KEEPALIVE, data: new Uint8Array([units >> 8, units & 0xFF]) });
  }
}

function finalizeWire(serverCtx, req, res){
  addServerOptions(serverCtx, req, res);
  var wire2 = encodeNow(res, req);

  // UDP: no larger than the client takes (its EDNS payload size, at most
  // ours; 512 without EDNS, RFC 1035 §4.2.1).
  if (isUdp(req.transport)){
    var udpMax = req.edns ? req.edns.udpSize : 512;
    if (wire2.length > udpMax){
      wire2 = truncateSmart(serverCtx, req, res, udpMax);
    }
  } else if (wantsPadding(req, res) && addPadding(res, wire2.length)){
    wire2 = encodeNow(res, req);
  }
  return toU8(wire2);
}

function signRRset(signer_name,rrset_bytes,algorithm,key_tag,sig_expiration,sig_inception,private_key,labels,rr_type,ttl){

  var tmp = new Uint8Array(256);
  var off = 0;
  off = wire.encodeName(tmp, off, signer_name, {});
  var signer_name_bytes = tmp.slice(0, off);

  var rr_type_code = wire.type_to_code[rr_type.toUpperCase()] || 0;

  var header_bytes = new Uint8Array(18);
  header_bytes[0] = (rr_type_code >> 8) & 0xff;
  header_bytes[1] = rr_type_code & 0xff;
  header_bytes[2] = algorithm;
  header_bytes[3] = labels;

  header_bytes[4] = (ttl >> 24) & 0xff;
  header_bytes[5] = (ttl >> 16) & 0xff;
  header_bytes[6] = (ttl >> 8) & 0xff;
  header_bytes[7] = ttl & 0xff;

  header_bytes[8] = (sig_expiration >> 24) & 0xff;
  header_bytes[9] = (sig_expiration >> 16) & 0xff;
  header_bytes[10] = (sig_expiration >> 8) & 0xff;
  header_bytes[11] = sig_expiration & 0xff;

  header_bytes[12] = (sig_inception >> 24) & 0xff;
  header_bytes[13] = (sig_inception >> 16) & 0xff;
  header_bytes[14] = (sig_inception >> 8) & 0xff;
  header_bytes[15] = sig_inception & 0xff;

  header_bytes[16] = (key_tag >> 8) & 0xff;
  header_bytes[17] = key_tag & 0xff;

  var hash_payload = new Uint8Array(
    header_bytes.length + signer_name_bytes.length + rrset_bytes.length
  );
  hash_payload.set(header_bytes, 0);
  hash_payload.set(signer_name_bytes, header_bytes.length);
  hash_payload.set(rrset_bytes, header_bytes.length + signer_name_bytes.length);

  if(algorithm === 13) {
    // ECDSAP256SHA256: sign with node:crypto (SHA-256 + P-256)
    var keyObj = createP256SigningKey(toU8(private_key));
    // ieee-p1363 = compact r||s (64 bytes), which is what DNSSEC expects
    var sig_data = new Uint8Array(crypto.sign('sha256', Buffer.from(hash_payload), { key: keyObj, dsaEncoding: 'ieee-p1363' }));

    return sig_data;
  }
  
  return null;
  
}

// RFC 4034 §3.1.3: the Labels field is the number of labels in the owner name,
// NOT counting the root and NOT counting a leftmost '*' (wildcard) label.
function rrsigLabelCount(name){
  var l = String(name || '.').replace(/\.$/, '').split('.').filter(Boolean);
  if (l.length && l[0] === '*') l.shift();
  return l.length;
}

// Group records into RRsets by (name, type, class). RRSIG/OPT are never re-signed.
function groupRRsets(rrs){
  var groups = new Map();
  for (var i=0;i<(rrs?rrs.length:0);i++){
    var rr = rrs[i];
    if (!rr) continue;
    var t = String(rr.type).toUpperCase();
    if (t === 'RRSIG' || t === 'OPT') continue;
    var key = fqdn(rr.name) + '|' + t + '|' + (rr.class || 'IN');
    var arr = groups.get(key);
    if (!arr){ arr = []; groups.set(key, arr); }
    arr.push(rr);
  }
  return Array.from(groups.values());
}

function hasDenial(rrs){
  for (var i = 0; i < (rrs ? rrs.length : 0); i++){
    var t = String(rrs[i] && rrs[i].type).toUpperCase();
    if (t === 'NSEC' || t === 'NSEC3') return true;
  }
  return false;
}

// Minimal async series iterator (the cache API is callback-based).
function eachSeries(items, iter, done){
  var i = 0;
  (function next(err){
    if (err || i >= items.length) return done(err || null);
    iter(items[i++], next);
  })();
}

// Sign one RRset (with cache) and invoke cb(err, rrsigRecord|null).
function signRRsetWithCache(ctx, material, rrset, cb){
  var first = rrset[0];
  var typeUpper = String(first.type).toUpperCase();
  var rrset_bytes;
  try {
    rrset_bytes = wire.buildRRsetBytesFromAnswers(rrset);
  } catch(e){ return cb(e); }

  // The key-set RRsets — DNSKEY, and CDS / CDNSKEY which speak for it to the
  // parent — are signed with the KSK (RFC 7344 §4.1: by a key the current DS
  // points at); everything else with the ZSK.
  var keySet = (typeUpper === 'DNSKEY' || typeUpper === 'CDS' || typeUpper === 'CDNSKEY');
  var key = keySet ? material.ksk : material.zsk;
  if (!key || !key.privateKey) return cb(null, null);

  var now = Math.floor(Date.now() / 1000);
  // Validity window: taken from the key material if provided, otherwise the
  // server's options. The user's material object is never mutated.
  //
  // Short by default. A signature is a proof anyone can replay until it
  // expires: with 346 days, an answer that changed — an old address, a
  // removed record — could be served, validly signed, for most of a year.
  // Signing online makes short windows free; DNSKEY gets a longer one, since
  // it changes only on a key rollover.
  var dnssecOpt = (ctx.options && ctx.options.dnssec) || {};
  var validity = keySet
    ? ((dnssecOpt.dnskeyValidity  | 0) || (30 * 24 * 3600))
    : ((dnssecOpt.signatureValidity | 0) || (7 * 24 * 3600));
  var inception  = (typeof key.inception  === 'number' && key.inception  > 0) ? key.inception  : now - 300;
  var expiration = (typeof key.expiration === 'number' && key.expiration > 0) ? key.expiration : now + validity;

  var cacheParams = {
    name: first.name,
    type: typeUpper,
    class: first.class || 'IN',
    keyTag: Number(key.keyTag),
    hash: toHex(sha256(rrset_bytes))
  };

  function doSign(){
    var labels = rrsigLabelCount(first.name);
    var sig_data = signRRset(material.signersName, rrset_bytes, 13, key.keyTag,
                             expiration, inception, key.privateKey, labels, typeUpper, first.ttl);
    var rrsig_record = {
      name: first.name,
      type: 'RRSIG',
      class: first.class || 'IN',
      ttl: first.ttl,
      data: {
        typeCovered: wire.type_to_code[typeUpper] || 0,
        algorithm: 13,
        labels: labels,
        originalTTL: first.ttl,
        expiration: expiration,
        inception: inception,
        keyTag: Number(key.keyTag),
        signersName: material.signersName,
        signature: sig_data,
      }
    };
    if (ctx._dnssecCache){
      try { ctx._dnssecCache.set(cacheParams, { rrsig: rrsig_record, expiration: expiration, inception: inception }, function(){}); } catch(e){}
    }
    return rrsig_record;
  }

  if (ctx._dnssecCache){
    ctx._dnssecCache.get(cacheParams, function(err, cached){
      // Re-signed once three quarters of its window is spent, not at the last
      // second: a resolver caches the RRSIG with the record, and one served
      // minutes before it expires goes bogus in that cache.
      var fresh = cached && cached.rrsig && cached.inception <= now &&
                  (cached.expiration - now) > (cached.expiration - cached.inception) / 4;
      if (!err && fresh){
        cb(null, cached.rrsig);
      } else {
        try { cb(null, doSign()); } catch(e){ cb(e); }
      }
    });
  } else {
    try { cb(null, doSign()); } catch(e){ cb(e); }
  }
}

// ---------------------------------------------------------------
// Negative answers, ECS — what the standards ask beyond the handler's records
// ---------------------------------------------------------------

// RFC 9824 §2: the NXNAME meta-type, set in the NSEC of a name that does not exist.
var TYPE_NXNAME = 128;
// RFC 9824 §5.1: Compact Answers OK — the EDNS header flag bit after DO.
var EDNS_FLAG_CO = 0x4000;
var EDNS_OPT_ECS = 8;

// Types claimed at a name when the handler did not say which exist (res.types).
// Claiming a type that is absent is harmless — the resolver asks for it and
// gets its own denial; leaving out one that exists is what breaks, since a
// resolver may then answer "no such type" from cache (RFC 8198). So the list
// is broad. Below the apex it never claims NS, SOA, DS, CNAME or DNAME: those
// say "zone cut" or "alias", which would change what the name is.
var DENIAL_FALLBACK_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'CAA', 'SRV', 'HTTPS', 'SVCB', 'TLSA', 'NAPTR'];
var DENIAL_APEX_TYPES = ['SOA', 'NS', 'DNSKEY'];

function typeCode(t){
  if (typeof t === 'number') return t;
  return wire.type_to_code[String(t).toUpperCase()];
}

// A negative answer — nothing of the asked type (NODATA) or no such name
// (NXDOMAIN) — must carry the zone's SOA in authority, with its TTL capped by
// SOA.minimum (RFC 2308 §3, §5). Returns that SOA, or null when this is not a
// negative answer (or is a referral, which carries NS instead).
function prepareNegative(ctx, req, res, onError){
  if (res.answers && res.answers.length) return null;
  var rc = res.header.rcode | 0;
  if (rc !== 0 && rc !== 3) return null;

  var auth = res.authority || [];
  var soaAt = -1, hasNS = false;
  for (var i = 0; i < auth.length; i++){
    var t = String(auth[i] && auth[i].type).toUpperCase();
    if (t === 'SOA' && soaAt < 0) soaAt = i;
    if (t === 'NS') hasNS = true;
  }
  if (soaAt < 0){
    if (!hasNS) onError(new Error('negative answer for "' + req.name + '" ' + req.type +
                                  ' has no SOA in authority (RFC 2308 §3)'), req.transport);
    return null;
  }

  var soa = auth[soaAt];
  var ttl = soa.ttl >>> 0;
  var min = (soa.data && soa.data.minimum != null) ? (soa.data.minimum >>> 0) : ttl;
  if (min < ttl){
    // A copy: the handler's record object is not changed under it.
    soa = { name: soa.name, type: soa.type, class: soa.class, ttl: min, data: soa.data };
    auth[soaAt] = soa;
  }
  return soa;
}

// The NSEC proving a negative answer, signed online — RFC 9824 "compact
// denial": owner is the query name, next is its immediate successor
// (\000.<name>), so it covers nothing but this one name and the zone
// cannot be walked. The TTL is the SOA's negative TTL (RFC 9077).
//
//   NODATA:  the types that DO exist at the name (res.types, or a broad
//            fallback), never the asked one.
//   NXDOMAIN: only NXNAME — the name does not exist.
function buildDenialNSEC(ctx, req, res, soa, material){
  var owner = fqdn(req.name);
  var list;
  if ((res.header.rcode | 0) === 3){
    list = [TYPE_NXNAME];
  } else if (Array.isArray(res.types)){
    list = res.types.slice();
  } else {
    list = DENIAL_FALLBACK_TYPES.slice();
    if (fqdn(soa.name) === owner) list = list.concat(DENIAL_APEX_TYPES);
  }

  // DNSKEY at the apex is answered by this library (autoAnswerIfApplicable),
  // not by the handler, so the handler's list cannot know it is there. Left
  // out, the apex NSEC would deny the zone's own keys — and a resolver that
  // answers from cached NSEC (RFC 8198) would then fail to validate anything.
  // The same goes for CDS / CDNSKEY (autoCds).
  if ((res.header.rcode | 0) !== 3 && material && fqdn(material.signersName) === owner){
    if (ctx.options.dnssec.autoDnskey !== false && list.indexOf('DNSKEY') < 0) list = list.concat(['DNSKEY']);
    if (ctx.options.dnssec.autoCds !== false){
      if (list.indexOf('CDS') < 0) list = list.concat(['CDS']);
      if (list.indexOf('CDNSKEY') < 0) list = list.concat(['CDNSKEY']);
    }
  }

  var asked = typeCode(req.type);
  var codes = [];
  for (var i = 0; i < list.length; i++){
    var c = typeCode(list[i]);
    if (c == null || c === asked) continue;   // unknown names are dropped, the asked type is what's denied
    codes.push(c);
  }
  codes.push(typeCode('RRSIG'), typeCode('NSEC'));

  return {
    name: owner, type: 'NSEC', class: 'IN', ttl: soa.ttl,
    data: { nextDomainName: '\u0000.' + owner, types: codes }
  };
}

// EDNS Client Subnet in the response (RFC 7871 §7.2.1). Only when the query
// carried ECS — never added to a response whose query had none. The scope
// says whom the answer is good for; a resolver caches it for that subnet
// only. Default: the source prefix the resolver sent, so the resolver asks
// again for every other subnet and the zone's handler decides each time.
// res.ecsScope overrides it per answer (0 = the same answer for everyone),
// options.ecsDefaultScope (a number) overrides the default.
function applyEcsScope(ctx, req, res, onError){
  var ecs = req.ecs;
  if (!ecs || !res.edns) return;

  var opts = res.edns.options || (res.edns.options = []);
  for (var i = 0; i < opts.length; i++) if (opts[i] && opts[i].code === EDNS_OPT_ECS) return; // the handler wrote its own

  var src = ecs.sourcePrefixLength | 0;
  var scope;
  if (typeof res.ecsScope === 'number') scope = res.ecsScope;
  else if (typeof ctx.options.ecsDefaultScope === 'number') scope = ctx.options.ecsDefaultScope;
  else scope = src;
  // A client that opted out (source /0) gets scope 0 (RFC 7871 §7.1.2).
  if (src === 0) scope = 0;
  scope = clamp(scope | 0, 0, (ecs.family === 2) ? 128 : 32);

  try {
    var built = buildEDNSOptions({ ecs: {
      family: ecs.family, sourcePrefixLength: src, scopePrefixLength: scope, addressBytes: ecs.addressBytes
    }});
    for (var j = 0; j < built.length; j++) opts.push(built[j]);
  } catch (e){
    onError(e, req.transport);
  }
}

// Encode the answer and hand it to the transport that brought the query
// (see "Transports" in createServer). What a handler's answer gets on top —
// AA, negative answers, ECS, signing — is sendResponse's; an answer the
// server gives on its own (refuse) goes out as it is.
function deliver(ctx, req, res, onError){
  var wire2;
  try {
    wire2 = finalizeWire(ctx, req, res);
  } catch(e){
    onError(e, req.transport);
    return;
  }
  req._link.reply(wire2, res);
}

// A query the 'accept' listener turned away. The answer says no without
// sending anything worth forging an address for:
//   over UDP, from an address not proven —
//     with a client cookie: BADCOOKIE and a fresh server cookie; the client
//       asks again at once, cookie in hand (RFC 7873 §5.2.3);
//     without one: TC, empty; a real client asks again over TCP, which a
//       forged address cannot complete (the "slip" of Response Rate
//       Limiting). REFUSED would cut the forged address's real owner — often
//       a public resolver — off this server's zones;
//   otherwise (TCP, DoT, DoQ, DoH, or UDP with a valid cookie): REFUSED.
function refuse(ctx, req, res){
  res._sent = true;
  res.header.aa = false;
  var ck = req._cookie;
  if (!req.addressVerified && isUdp(req.transport)){
    if (ck && ck.status === 'client' && res.edns) res.header.rcode = RCODE_BADCOOKIE;
    else res.header.tc = true;
  } else {
    res.header.rcode = RCODE_REFUSED;
  }
  deliver(ctx, req, res, ctx.onError);
}

function sendResponse(ctx, req, res){
  var onError = (ctx && ctx.options && typeof ctx.options.onError === 'function') ? ctx.options.onError : function(){};

  // res.send() is one-shot: a second call would emit a duplicate response on the wire.
  if (res._sent){
    onError(new Error('res.send() called more than once for query "' + req.name + '" — response already sent'), req.transport);
    return;
  }
  res._sent = true;

  function actual_send(){ deliver(ctx, req, res, onError); }

  // AA: an authoritative answer is one about the zone's data — NOERROR or
  // NXDOMAIN. A REFUSED or SERVFAIL claims no authority. A handler that set
  // res.header.aa itself is left alone.
  if (res.header.aa === undefined){
    var rc0 = res.header.rcode | 0;
    res.header.aa = (ctx.options.aa !== false) && (rc0 === 0 || rc0 === 3);
  }

  var negativeSOA = prepareNegative(ctx, req, res, onError);
  applyEcsScope(ctx, req, res, onError);

  // If the handler already supplied RRSIGs anywhere, it is managing DNSSEC manually — don't interfere.
  var rrsig_exist = false;
  var sections = [res.answers, res.authority];
  for (var s=0; s<sections.length && !rrsig_exist; s++){
    var sec = sections[s] || [];
    for (var i=0;i<sec.length;i++){
      if (sec[i] && String(sec[i].type).toUpperCase() === 'RRSIG'){ rrsig_exist = true; break; }
    }
  }

  var wantSign = !rrsig_exist &&
                 req.flag_do === true &&
                 ctx && ctx.options && ctx.options.dnssec &&
                 typeof ctx.options.dnssec.keyCallback === 'function' &&
                 ((res.answers && res.answers.length) || (res.authority && res.authority.length));

  if (!wantSign){
    actual_send();
    return;
  }

  ctx.options.dnssec.keyCallback(req.name, function(error, material){
    if (error || !material){
      actual_send();
      return;
    }

    // Negative answer: add the NSEC that proves it (RFC 9824), unless the
    // handler brought its own denial or turned this off (dnssec.autoDenial).
    if (negativeSOA && ctx.options.dnssec.autoDenial !== false && !hasDenial(res.authority)){
      res.authority.push(buildDenialNSEC(ctx, req, res, negativeSOA, material));
      // A name that does not exist is answered NOERROR with NXNAME — what a
      // resolver that does not know compact denial expects. One that set CO
      // can take the NXDOMAIN back, and is told so by CO in the reply
      // (RFC 9824 §5.1).
      if ((res.header.rcode | 0) === 3){
        var co = req.edns && ((req.edns.z | 0) & EDNS_FLAG_CO);
        if (co && res.edns) res.edns.z = (res.edns.z | 0) | EDNS_FLAG_CO;
        else res.header.rcode = 0;
      }
    }

    // Sign every RRset in answers AND authority (e.g. the SOA on negative responses).
    // Each RRset gets its own RRSIG, appended to the same section.
    var work = [];
    groupRRsets(res.answers).forEach(function(g){ work.push({ section: res.answers, rrset: g }); });
    groupRRsets(res.authority).forEach(function(g){ work.push({ section: res.authority, rrset: g }); });

    eachSeries(work, function(item, next){
      signRRsetWithCache(ctx, material, item.rrset, function(err, rrsig){
        if (err) return next(err);
        if (rrsig) item.section.push(rrsig);
        next();
      });
    }, function(err){
      if (err) onError(err, req.transport); // send unsigned rather than dropping the query
      actual_send();
    });
  });
}


// Key-set records the library answers itself, at the zone apex, from the
// material keyCallback returns — they are derived from the keys, so there is
// nothing for a handler to decide:
//
//   DNSKEY   the zone's public keys                       (autoDnskey)
//   CDS      the DS the zone wants its parent to hold     (autoCds)
//   CDNSKEY  the same, as the key itself                  (autoCds)
//
// CDS / CDNSKEY (RFC 7344, RFC 8078) let a parent that scans for them install
// or update the DS without anyone typing it into a registrar's page. They
// always match the KSK this server signs with. A parent that does not scan
// simply never asks.
var KEYSET_TTL = { DNSKEY: 86400, CDS: 3600, CDNSKEY: 3600 };

function hexToU8(hex){
  var out = new Uint8Array(hex.length / 2);
  for (var i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function autoAnswerIfApplicable(req, res, ctx, callback){
  try{
    var dnssecOpt = ctx && ctx.options && ctx.options.dnssec;
    var t = String(req.type || '').toUpperCase();
    var wanted =
      dnssecOpt && typeof dnssecOpt.keyCallback === 'function' &&
      ((t === 'DNSKEY' && dnssecOpt.autoDnskey !== false) ||
       ((t === 'CDS' || t === 'CDNSKEY') && dnssecOpt.autoCds !== false));
    if (!wanted) return callback(false);

    dnssecOpt.keyCallback(req.name, function(error, result){

      // Only at the apex the keys belong to. A query for a subdomain goes to
      // the handler — records owned by a name other than the qname would be
      // a bogus answer.
      if (!result || fqdn(result.signersName) !== fqdn(req.name)) return callback(false);

      var owner = result.signersName;
      var ttl = KEYSET_TTL[t];

      if (t === 'DNSKEY'){
        if (result.ksk) res.answers.push({ name: owner, type: 'DNSKEY', class: 'IN', ttl: ttl,
          data: { flags: 257, algorithm: 13, key: toU8(result.ksk.publicKey) } });
        if (result.zsk) res.answers.push({ name: owner, type: 'DNSKEY', class: 'IN', ttl: ttl,
          data: { flags: 256, algorithm: 13, key: toU8(result.zsk.publicKey) } });
      } else if (t === 'CDNSKEY'){
        if (result.ksk) res.answers.push({ name: owner, type: 'CDNSKEY', class: 'IN', ttl: ttl,
          data: { flags: 257, algorithm: 13, key: toU8(result.ksk.publicKey) } });
      } else if (t === 'CDS'){
        if (result.ksk && result.ksk.digest) res.answers.push({ name: owner, type: 'CDS', class: 'IN', ttl: ttl,
          data: { keyTag: result.ksk.keyTag, algorithm: result.ksk.algorithm || 13,
                  digestType: result.ksk.digestType || 2, digest: hexToU8(result.ksk.digest) } });
      }

      if (!res.answers.length) return callback(false);
      res.send();
      callback(true);
    });

  }catch(e){
    callback(false);
  }
}


// ---------------------------------------------------------------
// DNS over QUIC — RFC 9250
// ---------------------------------------------------------------
//
// One query per client-initiated bidirectional stream, its 2-octet length
// first, the stream finished after it (§4.2); one response on the same
// stream, finished after it. The DNS message itself takes the path every
// transport's does (serverCtx._receive): FORMERR, BADVERS, NOTIMP, the
// handler.
//
// What only DoQ forbids is a protocol error, fatal to the connection: closed
// with DOQ_PROTOCOL_ERROR (§4.3.3: "SHOULD forcibly abort the connection
// using QUIC's CONNECTION_CLOSE mechanism and SHOULD use the DoQ error code
// DOQ_PROTOCOL_ERROR"):
//   a Message ID other than 0 (§4.2.1),
//   the edns-tcp-keepalive option (§5.5.2) — QUIC keeps the connection,
//   a stream finished before the whole message has come,
//   more than one message on a stream, or bytes after it,
//   a unidirectional stream from the client.
// A query is handled as soon as it is whole, without waiting for the
// client's FIN (§4.2: "SHOULD process queries as they arrive").
// A client that gives a query up (§4.3.1): STOP_SENDING cancels it (QUIC
// resets the stream; the answer, if it comes, goes nowhere); RESET_STREAM
// before its FIN cancels it too, and the server resets its side with
// DOQ_REQUEST_CANCELLED — unless the answer and its FIN have already gone.
var DOQ_PROTOCOL_ERROR = 0x2, DOQ_REQUEST_CANCELLED = 0x3, DOQ_EXCESSIVE_LOAD = 0x4;
var DNS_MESSAGE_MAX = 65535;
var DOQ_TICKET_LIFETIME = 6 * 3600;   // seconds

function startQuicServer(serverCtx, quicOpt, onError){
  var quicSrv = createQuicServer({
    alpn:           quicOpt.alpn           || ['doq'],
    key:            quicOpt.key,
    cert:           quicOpt.cert,
    ca:             quicOpt.ca             || undefined,
    SNICallback:    quicOpt.SNICallback    || undefined,
    maxConnections: quicOpt.maxConnections || 10000,
    // Session tickets good for 6 hours, the lifetime RFC 9250 §5.5.3
    // suggests ("e.g., 6 hours"): a resolver that comes back within it
    // resumes instead of a full handshake. lemon-tls's own default is 2.
    sessionTimeout: quicOpt.sessionTimeout != null ? quicOpt.sessionTimeout : DOQ_TICKET_LIFETIME
  });

  quicSrv.on('error', function(err){ onError(err, 'quic'); });

  quicSrv.on('connection', function(quic, peer){
    // Per stream: the query's bytes as they come. Bounded by count (QUIC's
    // stream limit bounds it too; this is the server's own) and by size:
    // a message is at most 65535 octets, its length prefix says how many.
    var streams = new Map();
    var MAX_OPEN_STREAMS = (quicOpt.maxOpenStreams|0) || 100;
    var closed = false;
    var tlsInfo = { alpn: 'doq' };

    function fail(code, why){
      if (closed) return;
      closed = true;
      streams.clear();
      try { quic.close(code, why, true); } catch (e){}
    }

    // Per stream: { parts, total, declared, query, answered, finSeen, cancelled }
    //   query     the message is whole and has gone to dispatch
    //   answered  its answer has gone, with the stream's FIN
    //   finSeen   the client's FIN has come
    //   cancelled the client gave the query up; nothing more is sent
    // A stream is forgotten once both sides are over: answered (or
    // cancelled) and the client's FIN or reset has come.
    function settle(sid, st){
      if ((st.answered || st.cancelled) && st.finSeen) streams.delete(sid);
    }

    // The query, handled as soon as it is whole — §4.2: "Servers SHOULD
    // process queries as they arrive". It used to wait for the client's FIN,
    // and a client that sends the FIN in a frame of its own waited for it.
    function handleQuery(sid, st){
      st.query = true;
      var full = st.parts.length === 1 ? st.parts[0] : Buffer.concat(st.parts, st.total);
      st.parts = null;
      var body = toU8(full).subarray(2, 2 + st.declared);
      // §4.2.1: the Message ID is 0 on DoQ.
      if (body.length >= 2 && (body[0] !== 0 || body[1] !== 0)) return fail(DOQ_PROTOCOL_ERROR, 'DoQ: a Message ID other than 0');

      var reply = function(w){
        if (closed || st.cancelled || st.answered) return;
        var frame = new Uint8Array(2 + w.length);
        frame[0] = (w.length >> 8) & 0xFF;
        frame[1] = w.length & 0xFF;
        frame.set(w, 2);
        st.answered = true;
        settle(sid, st);
        try { quic.sendStream(sid, frame, true); } catch (e){ onError(e, 'quic'); }   // FIN: the one answer
      };
      serverCtx._receive(body, 'quic', peer, { reply: reply, tls: tlsInfo }, function(msg){
        // §5.5.2 / §4.3.3: edns-tcp-keepalive is a protocol error on DoQ.
        var ka = msg.edns && msg.edns.optionsStructured && msg.edns.optionsStructured.keepalive;
        if (ka){ fail(DOQ_PROTOCOL_ERROR, 'DoQ: the edns-tcp-keepalive option'); return false; }
        return true;
      });
    }

    quic.on('stream', function(streamId, chunk, fin){
      if (closed) return;
      var sid = Number(streamId);
      if (sid & 0x2) return fail(DOQ_PROTOCOL_ERROR, 'DoQ: a unidirectional stream');   // §4.3.3
      var st = streams.get(sid);
      if (!st){
        if (streams.size >= MAX_OPEN_STREAMS) return fail(DOQ_EXCESSIVE_LOAD, 'DoQ: too many queries at once');
        st = { parts: [], total: 0, declared: -1, query: false, answered: false, finSeen: false, cancelled: false };
        streams.set(sid, st);
      }
      var n = chunk ? chunk.byteLength : 0;
      if (n > 0 && !st.cancelled){
        // Anything after a whole message is a second one (§4.3.3).
        if (st.query) return fail(DOQ_PROTOCOL_ERROR, 'DoQ: more than one message on a stream');
        st.total += n;
        if (st.total > 2 + DNS_MESSAGE_MAX) return fail(DOQ_PROTOCOL_ERROR, 'DoQ: more than one message on a stream');
        st.parts.push(chunk);
        // As soon as the length is known: no more than it says.
        if (st.declared < 0 && st.total >= 2){
          var head = st.parts.length === 1 ? st.parts[0] : Buffer.concat(st.parts, st.total);
          st.parts = [head];
          st.declared = (head[0] << 8) | head[1];
        }
        if (st.declared >= 0 && st.total > 2 + st.declared) return fail(DOQ_PROTOCOL_ERROR, 'DoQ: bytes after the message on a stream');
      }
      if (fin) st.finSeen = true;
      if (!st.query && !st.cancelled && st.declared >= 0 && st.total === 2 + st.declared){
        handleQuery(sid, st);
        if (closed) return;
      }
      if (fin && !st.query && !st.cancelled) return fail(DOQ_PROTOCOL_ERROR, 'DoQ: the stream finished before its message');
      if (fin) settle(sid, st);
    });

    // The client gave the query up (§4.3.1).
    // STOP_SENDING: QUIC itself answers it with RESET_STREAM (RFC 9000 §3.5).
    // The query is cancelled: its answer, if one comes later, is not sent.
    // RESET_STREAM before the client's FIN: the transaction is abandoned, and
    // the server "MUST issue a RESET_STREAM ... unless ... it has already
    // both sent the response and indicated the STREAM FIN". That holds for a
    // stream the server has seen no byte of, too — a reset can come before
    // any data, or with it lost. (It was answered only for a stream with
    // data already in; a scanner resetting a fresh stream got nothing back.)
    // A reset after the client's FIN is no reset at all: QUIC drops it.
    quic.on('stop_sending', function(sid){
      sid = Number(sid);
      var st = streams.get(sid);
      if (!st) return;
      st.cancelled = true;
      st.parts = null;
      settle(sid, st);
    });
    quic.on('stream_reset', function(sid){
      if (closed) return;
      sid = Number(sid);
      if (sid & 0x2) return;
      var st = streams.get(sid);
      streams.delete(sid);
      if (st && st.answered) return;
      if (st) { st.cancelled = true; st.parts = null; }
      try { quic.resetStream(sid, DOQ_REQUEST_CANCELLED); } catch (e){}
    });

    quic.on('close', function(){
      closed = true;
      streams.clear();
    });
  });

  quicSrv.listen(
    quicOpt.port || 853,
    quicOpt.host || '::',
    function(){ if (quicOpt.onListen) quicOpt.onListen(); }
  );

  serverCtx.quic = quicSrv;
}

// ---------------------------------------------------------------
// Server creation
// ---------------------------------------------------------------
function createServer(options, handler){
  options = options || {};

  // behavioral flags
  //   aa  (default true)  — this is an authoritative server: answers carry AA
  //                         (RFC 1035 §4.1.1). false leaves it off unless a
  //                         handler sets res.header.aa itself.
  //   always_ra (default false)
  // The old `always_aa` could not be turned off — `if (!options.always_aa)`
  // set it back to true whenever it was false.
    if (!options.always_ra) options.always_ra = false;

  var onError = typeof options.onError === 'function' ? options.onError : function(){};

  // default transport options
  var udpOpt = options.udp===false ? null : (options.udp || { udp4:{ host:'0.0.0.0', port:53 }, udp6:{ host:'::', port:53 } });
  if (udpOpt && (!udpOpt.udp4 && !udpOpt.udp6)){
    // { port, host }: a host binds the one socket of its family — '127.0.0.1'
    // must not also open '::' (every IPv6 interface); no host binds both.
    var uport = (udpOpt.port == null) ? 53 : (udpOpt.port|0);
    var ufam = udpOpt.host ? net.isIP(udpOpt.host) : 0;
    if (udpOpt.host && !ufam) throw new TypeError('udp.host must be an IP address: ' + JSON.stringify(udpOpt.host));
    udpOpt = ufam === 4 ? { udp4:{ host:udpOpt.host, port:uport } }
           : ufam === 6 ? { udp6:{ host:udpOpt.host, port:uport } }
           : { udp4:{ host:'0.0.0.0', port:uport }, udp6:{ host:'::', port:uport } };
  }

  var tcpOpt = options.tcp===false ? null : (options.tcp || { host:'::', port:53, idleMs:30000 });
  var tlsOpt = options.tls || null;
  var quicOpt = options.quic || null;

  // server context
  // --- Normalize DNSSEC cache option into { get, set } or null ---
  var dnssecCache = null;
  if (options.dnssec && options.dnssec.cache){
    var cacheOpt = options.dnssec.cache;
    if (typeof cacheOpt === 'object' && typeof cacheOpt.get === 'function' && typeof cacheOpt.set === 'function'){
      // developer-provided cache
      dnssecCache = cacheOpt;
    } else if (cacheOpt === true){
      // built-in in-memory LRU cache: a Map preserves insertion order, so
      // re-inserting on read keeps the most-recently-used entries at the end
      // and lets us evict the single oldest entry instead of wiping everything.
      var _map = new Map();
      var _mapMax = (options.dnssec.cacheMax|0) || 10000;
      dnssecCache = {
        get: function(params, cb){
          var k = params.hash + '|' + params.keyTag;
          var v = _map.get(k);
          if (v !== undefined){ _map.delete(k); _map.set(k, v); } // refresh recency
          cb(null, v || null);
        },
        set: function(params, value, cb){
          var k = params.hash + '|' + params.keyTag;
          if (_map.has(k)) _map.delete(k);
          else if (_map.size >= _mapMax) _map.delete(_map.keys().next().value); // evict LRU
          _map.set(k, value);
          if (cb) cb(null);
        },
        clear: function(){ _map.clear(); },
        size: function(){ return _map.size; }
      };
    }
  }

  // The object createServer returns. Its 'accept' event asks, for every
  // query, whether to answer it at all (see dispatch).
  var server = new EventEmitter();

  var serverCtx = {
    server: server,
    cookies: createCookieJar(options.cookies, crypto.randomBytes),
    onError: onError,
    udp4: null, 
    udp6: null, 
    tcp: null, 
    tls: null, 
    quic: null,
    options: options,
    _sendResponse: function(req, res){ return sendResponse(serverCtx, req, res); },
    _finalizeWire: function(req, res){ return finalizeWire(serverCtx, req, res); },
    dnssec: options.dnssec || null,
    _dnssecCache: dnssecCache
  };

  // One path for every query, whatever carried it. `link` is what the
  // transport brings with it:
  //   reply(wireBytes, res)  how the answer goes back (see "Transports")
  //   tls                    { authorized, alpn } on DoT / DoQ (req.tls)
  //   idleMs                 TCP / DoT: how long an idle connection is kept
  // The transport's name decides the rest (truncation over UDP, padding over
  // an encrypted one).
  //
  // In order:
  //   a message with QR set — a response — is never answered: two servers
  //     could otherwise answer each other's answers forever (RFC 1035 §4.1.1;
  //     RFC 8906 §3.1.4);
  //   its COOKIE is checked (RFC 7873): req.addressVerified says whether the
  //     source address is proven — by a handshake (TCP, DoT, DoQ, DoH) or by
  //     a valid server cookie (UDP);
  //   'accept' — whether to answer at all. Before anything the server would
  //     answer on its own, so the DNSKEY of a zone, the classic reflection
  //     answer, is weighed like any other;
  //   what the standards answer themselves:
  //     FORMERR for a malformed OPT RR (RFC 6891 §6.1.1) or COOKIE (RFC 7873
  //       §5.2.2), and for anything but exactly one question (RFC 9619);
  //     BADVERS for an EDNS version other than 0 (RFC 6891 §6.1.3);
  //     NOTIMP for an opcode other than QUERY (RFC 8906 §3.1.4);
  //   the key sets (autoAnswerIfApplicable); then the handler.
  function dispatch(msg, transport, peer, rawBuf, link){
    if (msg.header.qr) return;
    var req = buildReq(transport, peer, rawBuf, msg, link.tls);
    req._link = link;
    req._cookie = serverCtx.cookies ? serverCtx.cookies.inspect(cookieOption(msg), peer.address) : { status: 'none' };
    req.addressVerified = !isUdp(transport) || req._cookie.status === 'valid';
    var res = buildRes(req, serverCtx);

    if (server.listenerCount('accept') === 0) return answer(req, res);
    var decided = false;
    server.emit('accept', req, function(ok){
      if (decided) return;
      decided = true;
      if (ok) answer(req, res);
      else refuse(serverCtx, req, res);
    });
  }
  function answer(req, res){
    var rcode = standardRcode(req.message) || (req._cookie.status === 'malformed' ? RCODE_FORMERR : 0);
    if (rcode !== 0){
      res.header.rcode = rcode;
      return sendResponse(serverCtx, req, res);
    }
    autoAnswerIfApplicable(req, res, serverCtx, function(is_sent){
      if (is_sent === false) handler(req, res);
    });
  }

  // A message that does not decode: FORMERR from its header alone, when it
  // has one and is a query (RFC 1035 §4.1.1) — or null: nothing to answer.
  function formerrFor(raw){
    if (!raw || raw.length < 12 || (raw[2] & 0x80)) return null;
    try {
      return toU8(wire.encodeMessage({
        header: { id: (raw[0] << 8) | raw[1], qr: true, opcode: (raw[2] >> 3) & 0xF, rd: !!(raw[2] & 1), rcode: 1 },
        questions: [], answers: [], authority: [], additionals: []
      }));
    } catch (e){ return null; }
  }

  // Bytes from a transport: decoded and dispatched — or, undecodable,
  // answered FORMERR.
  // check(msg), optional: a transport's own rules (DoQ's) — false stops
  // the message there.
  function receive(raw, transport, peer, link, check){
    var u8 = toU8(raw), msg;
    try { msg = wire.decodeMessage(u8); }
    catch (e){
      var fe = formerrFor(u8);
      if (fe) link.reply(fe, null);
      return;
    }
    if (check && check(msg) === false) return;
    dispatch(msg, transport, peer, u8, link);
  }
  serverCtx._receive = receive;
  serverCtx._dispatch = dispatch;
  serverCtx._formerrFor = formerrFor;

  // ---- Transports ----
  //
  // Each delivers an answer its own way: a datagram back to the sender over
  // UDP; length-prefixed on the connection over TCP and TLS (RFC 1035
  // §4.2.2, RFC 7858 §3.3); on the query's own stream over QUIC (DoQ below);
  // handed back to the caller for DoH (handleMessage).
  function udpReply(socket, peer){
    return function(w){ socket.send(w, peer.port, peer.address); };
  }
  function streamReply(socket){
    return function(w){
      if (socket.destroyed) return;
      var frame = Buffer.allocUnsafe(2 + w.length);
      frame.writeUInt16BE(w.length, 0);
      frame.set(w, 2);
      socket.write(frame);
    };
  }

  // --- UDP4 ---
  if (udpOpt && udpOpt.udp4){
    var u4 = dgram.createSocket('udp4');
    u4.on('message', function(buf, rinfo){
      var peer = { address: rinfo.address, port: rinfo.port };
      receive(buf, 'udp4', peer, { reply: udpReply(u4, peer) });
    });
    u4.on('error', function(err){ onError(err, 'udp4'); });
    u4.bind((udpOpt.udp4.port|0)||53, udpOpt.udp4.host||'0.0.0.0');
    serverCtx.udp4 = u4;
  }

  // --- UDP6 ---
  if (udpOpt && udpOpt.udp6){
    var u6 = dgram.createSocket({type: 'udp6', ipv6Only: true});
    u6.on('message', function(buf, rinfo){
      var peer = { address: rinfo.address, port: rinfo.port };
      receive(buf, 'udp6', peer, { reply: udpReply(u6, peer) });
    });
    u6.on('error', function(err){ onError(err, 'udp6'); });
    u6.bind((udpOpt.udp6.port|0)||53, udpOpt.udp6.host||'::');
    serverCtx.udp6 = u6;
  }

  // --- Shared DNS-over-stream handler (TCP + TLS) ---
  // Live sockets are tracked so server.close() can destroy them: net's close()
  // only stops accepting — a single idle client would otherwise hold the port
  // forever and starve blue-green reloads with endless EADDRINUSE.
  serverCtx._streamSockets = new Set();

  // A DNS message is at most 65535 bytes + 2-byte length prefix. Any connection
  // buffering more than that without completing a message is malformed or hostile.
  var MAX_CONN_BUFFER = 2 + 65535;

  function handleStreamSocket(socket, transport, idleMs){
    var chunks = [];
    var totalLen = 0;
    var peer = { address: socket.remoteAddress, port: socket.remotePort };

    // The idle timeout (default 30 s) counts from the last whole message,
    // either way — a query in, or an answer out — not from any byte (RFC 7766
    // §6.2.3): a client trickling a message a byte at a time would otherwise
    // hold the connection for ever. It is also what edns-tcp-keepalive tells
    // a client that asks (RFC 7828).
    var effectiveIdle = (idleMs != null && idleMs > 0) ? idleMs : 30000;
    var idleTimer = setTimeout(function(){ socket.destroy(); }, effectiveIdle);
    socket.on('close', function(){ clearTimeout(idleTimer); });

    var write = streamReply(socket);
    var link = {
      reply: function(w, res){ idleTimer.refresh(); write(w, res); },
      tls: (transport === 'tls') ? { authorized: !!socket.authorized, alpn: socket.alpnProtocol } : null,
      idleMs: effectiveIdle
    };

    // Nagle off (TCP_NODELAY). Resolvers pipeline queries over one connection
    // (RFC 7766 §6.2.1.1) and each answer is written as it is ready; with
    // Nagle on, an answer written while the previous one is unacknowledged
    // waits for the ACK — up to a round trip, plus the client's delayed-ACK
    // timer. A TLS socket (DoT) passes it down to its TCP socket; quico's
    // listener already sets it there.
    if (typeof socket.setNoDelay === 'function') socket.setNoDelay(true);

    serverCtx._streamSockets.add(socket);
    socket.on('close', function(){ serverCtx._streamSockets.delete(socket); });

    socket.on('data', function(chunk){
      chunks.push(chunk);
      totalLen += chunk.length;

      if (totalLen > MAX_CONN_BUFFER){ socket.destroy(); return; }

      // assemble only when needed
      var buf = chunks.length === 1 ? chunks[0] : Buffer.concat(chunks, totalLen);

      while (buf.length >= 2){
        var msgLen = buf.readUInt16BE(0);
        if (buf.length < 2 + msgLen) break;
        var body = buf.subarray(2, 2 + msgLen);
        buf = buf.subarray(2 + msgLen);
        // A message that does not decode is answered FORMERR, and the
        // connection goes on: its framing is intact (RFC 7766 §8). It was
        // closed, every query pipelined behind it with it.
        idleTimer.refresh();
        receive(body, transport, peer, link);
        if (socket.destroyed) return;
      }

      // keep only the unparsed remainder — chunks is reset so consumed
      // Buffers become garbage-collectable instead of accumulating
      if (buf.length === 0){
        chunks = [];
        totalLen = 0;
      } else {
        chunks = [buf];
        totalLen = buf.length;
      }
    });

    socket.on('error', function(err){ onError(err, transport); });
  }

  // --- TCP ---
  if (tcpOpt){
    var tcp = net.createServer(function(socket){
      handleStreamSocket(socket, 'tcp', tcpOpt.idleMs || 0);
    });
    // Without this, a bind failure (e.g. EADDRINUSE) is an uncaught exception
    // that kills the process — it must reach onError like UDP errors do,
    // so callers can implement retry/failover logic.
    tcp.on('error', function(err){ onError(err, 'tcp'); });
    if (tcpOpt.maxConnections > 0) tcp.maxConnections = tcpOpt.maxConnections|0; // cap aggregate memory
    tcp.listen((tcpOpt.port|0) || 53, tcpOpt.host || '::');
    serverCtx.tcp = tcp;
  }

  // --- TLS (DoT) ---
  //
  // On quico's TCP listener and lemon-tls, the same stack as DoQ. It ran on
  // node:tls before, which broke it for every client: node:tls cannot use a
  // lemon-tls context (the handshake ended in EOF), and never calls the
  // SNICallback when the client sends no name (internal_error). DNS clients
  // are usually configured by IP, and an IP is never sent as SNI (RFC 6066
  // §3), so that second case is the common one here. lemon-tls resolves every
  // certificate through the callback, SNI or not, and the listener passes the
  // connection's local address as a third argument.
  if (tlsOpt){
    var dot = createTcpListener({
      tls: lemonTls,
      key: tlsOpt.key, cert: tlsOpt.cert, ca: tlsOpt.ca,
      SNICallback: tlsOpt.SNICallback
    });

    // node:net's maxConnections has no equivalent on the listener; the cap is
    // applied as each connection completes its handshake.
    var dotMax = tlsOpt.maxConnections > 0 ? tlsOpt.maxConnections|0 : 0;
    var onDot = function(socket){
      if (dotMax && dot.connections > dotMax){ socket.destroy(); return; }
      handleStreamSocket(socket, 'tls', tlsOpt.idleMs || 0);
    };

    // Registration order is the ALPN preference order.
    var dotAlpns = tlsOpt.ALPNProtocols || ['dot'];
    for (var ai = 0; ai < dotAlpns.length; ai++) dot.register(dotAlpns[ai], onDot);

    dot.on('error', function(err){ onError(err, 'tls'); });   // bind errors must not crash the process
    // A failed handshake is the client's problem. Scanners probing the address
    // arrive continuously and would otherwise flood onError.
    dot.on('clientError', function(){});

    dot.listen((tlsOpt.port|0) || 853, tlsOpt.host || '::');
    serverCtx.tls = dot;
  }

  // --- QUIC (DoQ) ---
  if (quicOpt){ startQuicServer(serverCtx, quicOpt, onError); }

  // One DNS message from a transport the application runs itself — DNS over
  // HTTPS (RFC 8484) behind its own HTTP server. The query takes the same path
  // as one over UDP or TCP: the auto-answered key sets, the handler, and what
  // res.send() completes. The library serves no HTTP; the caller extracts the
  // message (GET ?dns=, base64url / POST body) and returns the reply bytes as
  // application/dns-message.
  //
  //   cb(err, responseBytes, { ttl })
  //     err   the bytes are not a DNS message — answer HTTP 400
  //     ttl   the smallest TTL in the response, for Cache-Control max-age
  //           (RFC 8484 §5.1); undefined when it carries no records
  function handleMessage(bytes, peer, cb){
    peer = peer || {};
    var u8, msg;
    try {
      u8 = toU8(bytes);
      msg = wire.decodeMessage(u8);
    } catch (e){
      return cb(e);
    }
    // A response is never answered (dispatch); the caller still hears back.
    if (msg.header.qr) return cb(new Error('the message is a response (QR set), not a query'));
    var reply = function(responseBytes, res){
      var ttl;
      var secs = res ? [res.answers, res.authority] : [];
      for (var s1 = 0; s1 < secs.length; s1++){
        for (var r1 = 0; r1 < (secs[s1] ? secs[s1].length : 0); r1++){
          var rr = secs[s1][r1];
          if (rr && typeof rr.ttl === 'number' && (ttl === undefined || rr.ttl < ttl)) ttl = rr.ttl;
        }
      }
      cb(null, responseBytes, { ttl: ttl });
    };
    dispatch(msg, peer.transport || 'https',
      { address: peer.address || '', port: peer.port | 0 }, u8, { reply: reply, tls: peer.tls || null });
  }

  // The server: an EventEmitter ('accept'), with these methods.
  return Object.assign(server, {
    handleMessage: handleMessage,
    close: function(cb){
      var pending = 0; var done = function(){ if (--pending===0 && cb) cb(); };
      if (serverCtx.udp4){ pending++; serverCtx.udp4.close(done); }
      if (serverCtx.udp6){ pending++; serverCtx.udp6.close(done); }
      if (serverCtx.tcp){ pending++; serverCtx.tcp.close(done); }
      if (serverCtx.tls){ pending++; serverCtx.tls.close(done); }
      if (serverCtx.quic && serverCtx.quic.close){ pending++; serverCtx.quic.close(done); }

      // Destroy live TCP/TLS connections: without this, net's close() waits for
      // clients to hang up voluntarily — one idle client blocks shutdown forever
      // (and keeps the port held during blue-green reloads).
      if (serverCtx._streamSockets){
        for (var s of serverCtx._streamSockets) s.destroy();
        serverCtx._streamSockets.clear();
      }

      if (pending===0 && cb) cb();
    },
    connectionCount: function(){
      return serverCtx._streamSockets ? serverCtx._streamSockets.size : 0;
    },
    clearRrsigCache: function(){
      if (serverCtx._dnssecCache && typeof serverCtx._dnssecCache.clear === 'function'){
        serverCtx._dnssecCache.clear();
      }
    },
    rrsigCacheSize: function(){
      if (serverCtx._dnssecCache && typeof serverCtx._dnssecCache.size === 'function'){
        return serverCtx._dnssecCache.size();
      }
      return 0;
    },
    context: serverCtx
  });
}


function deriveP256PublicXY(priv){
  var ecdh = crypto.createECDH('prime256v1');
  ecdh.setPrivateKey(Buffer.from(priv));
  var full = ecdh.getPublicKey(); // 65 bytes: 0x04 || X || Y
  var pub = new Uint8Array(full.buffer, full.byteOffset + 1, 64);
  return pub;
}

function generateP256PrivateKey(){
  var ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  return new Uint8Array(ecdh.getPrivateKey());
}

function sha256(data){
  return new Uint8Array(crypto.createHash('sha256').update(Buffer.from(data)).digest());
}

function sha384(data){
  return new Uint8Array(crypto.createHash('sha384').update(Buffer.from(data)).digest());
}

function createP256SigningKey(privBytes){
  var ecdh = crypto.createECDH('prime256v1');
  ecdh.setPrivateKey(Buffer.from(privBytes));
  var pub = ecdh.getPublicKey().slice(1); // 64 bytes X||Y
  var jwk = {
    kty: 'EC', crv: 'P-256',
    d: Buffer.from(privBytes).toString('base64url'),
    x: Buffer.from(pub.slice(0, 32)).toString('base64url'),
    y: Buffer.from(pub.slice(32, 64)).toString('base64url')
  };
  return crypto.createPrivateKey({ key: jwk, format: 'jwk' });
}

function buildDnskeyRdata(flags, protocol, algorithm, publicKeyXY){
  var rdata = new Uint8Array(4 + publicKeyXY.length);
  rdata[0] = (flags >> 8) & 0xFF;
  rdata[1] =  flags       & 0xFF;
  rdata[2] =  protocol    & 0xFF;
  rdata[3] =  algorithm   & 0xFF;
  rdata.set(publicKeyXY, 4);
  return rdata;
}

function computeDnskeyKeyTag(rdata){
  var acc = 0;
  for (var i = 0; i < rdata.length; i++){
    acc += (i & 1) ? rdata[i] : (rdata[i] << 8);
    acc = acc >>> 0; // keep unsigned — `& 0xFFFFFFFF` yields a SIGNED int32 and corrupts large accumulations
  }
  acc += (acc >>> 16) & 0xFFFF;
  return acc & 0xFFFF;
}


function buildDnssecMaterial(params){
  if (!params || !params.signersName) throw new Error('signersName is required');

  // constants per RFC
  var algorithm  = 13;            // ECDSAP256SHA256
  var digestType = 2;             // SHA-256
  var protocol   = 3;             // always 3
  var KSK_FLAGS  = 257;           // SEP
  var ZSK_FLAGS  = 256;           // no SEP

  var signer = fqdn(params.signersName);

  // --- KSK ---
  var kskPrivRaw = (params.ksk && params.ksk.privateKey) ? toU8(params.ksk.privateKey) : generateP256PrivateKey();
  var kskPubRaw  = deriveP256PublicXY(kskPrivRaw);
  var kskRdata   = buildDnskeyRdata(KSK_FLAGS, protocol, algorithm, kskPubRaw);
  var kskTag     = computeDnskeyKeyTag(kskRdata);

  // compute DS (owner_wire + DNSKEY_RDATA of the KSK)
  var tmp = new Uint8Array(256);
  var len = wire.encodeName(tmp, 0, signer.toLowerCase());
  var ownerWire=tmp.slice(0, len);

  var toDigest   = new Uint8Array(ownerWire.length + kskRdata.length);
  toDigest.set(ownerWire, 0);
  toDigest.set(kskRdata, ownerWire.length);

  var dsBytes;
  if (digestType === 2) {
    dsBytes = sha256(toDigest);
  } else if (digestType === 4) {
    dsBytes = sha384(toDigest);
  } else {
    throw new Error('Unsupported digestType (use 2 for SHA-256 or 4 for SHA-384)');
  }
  var dsHex = toHex(dsBytes);

  // --- ZSK ---
  var zskPrivRaw = (params.zsk && params.zsk.privateKey) ? toU8(params.zsk.privateKey) : generateP256PrivateKey();
  var zskPubRaw  = deriveP256PublicXY(zskPrivRaw);
  var zskRdata   = buildDnskeyRdata(ZSK_FLAGS, protocol, algorithm, zskPubRaw);
  var zskTag     = computeDnskeyKeyTag(zskRdata);

  // --- output in simple format for use ---
  return {
    signersName: signer,
    // The DS record for the parent zone, in presentation form — what a
    // registrar's DNSSEC page asks for (key tag, algorithm, digest type, digest).
    ds: signer + ' IN DS ' + kskTag + ' ' + algorithm + ' ' + digestType + ' ' + dsHex,
    ksk: {
      keyTag:     kskTag,
      privateKey: toB64(kskPrivRaw),
      publicKey:  toB64(kskPubRaw),
      algorithm:  algorithm,
      digestType: digestType,
      digest:     dsHex
    },
    zsk: {
      keyTag:     zskTag,
      privateKey: toB64(zskPrivRaw),
      publicKey:  toB64(zskPubRaw),
      algorithm:  algorithm,
    }
  };
}


/////////////////

// Build a lazy name→RR[] index on the zone object (created once, reused on every query).
// Keys are lowercase FQDNs: DNS names are case-insensitive (RFC 1034 §3.1, RFC 4343),
// and real-world resolvers actively randomize query case (dns0x20 anti-spoofing),
// so a case-sensitive index would fail a large share of legitimate queries.
function getZoneIndex(zone){
  if (zone._index) return zone._index;
  var idx = new Map();
  var soaApex = null, soaAny = null;
  var apex = fqdn(zone.origin || '.');
  for (var i = 0; i < zone.records.length; i++){
    var rr = zone.records[i];
    var key = fqdn(rr.name);
    var arr = idx.get(key);
    if (!arr){ arr = []; idx.set(key, arr); }
    arr.push(rr);
    if (rr.type === 'SOA'){
      if (key === apex) soaApex = rr;
      if (!soaAny) soaAny = rr;
    }
  }
  zone._index = idx;
  zone._soa = soaApex || soaAny; // cached — findSOA used to rescan the whole zone on every miss
  return idx;
}

var MAX_CNAME_CHAIN = 8;

function answerFromZone(zone,qname,qtype,qclass){
  qtype = (qtype||'A').toUpperCase();
  qclass = (qclass||'IN').toUpperCase();

  var idx = getZoneIndex(zone);
  var fq = fqdn(qname);

  function existsName(name){ return idx.has(name); }
  function collect(name, type){
    var all = idx.get(name);
    if (!all) return [];
    if (type === 'ANY') return all;
    var out = [];
    for (var i = 0; i < all.length; i++){ if (all[i].type === type) out.push(all[i]); }
    return out;
  }
  function collectAllTypes(name){ return idx.get(name) || []; }
  function negativeSOA(){
    // RFC 2308 §5: the TTL of the SOA in a negative response is capped by SOA.minimum.
    var soa = zone._soa;
    if (!soa) return null;
    var negTtl = Math.min(soa.ttl >>> 0, (soa.data && soa.data.minimum != null) ? (soa.data.minimum >>> 0) : (soa.ttl >>> 0));
    if (negTtl === (soa.ttl >>> 0)) return soa;
    return { name: soa.name, type: soa.type, class: soa.class, ttl: negTtl, data: soa.data };
  }
  function wildcardLookup(name, type){
    if (name === '.') return [];
    var labels = name.slice(0,-1).split('.');
    for (var i=0;i<labels.length-1;i++){
      var suffix = labels.slice(i+1).join('.') + '.';
      var cand = '*.' + suffix;
      var arr = (type==='ANY') ? collectAllTypes(cand) : collect(cand, type);
      if (arr.length){
        var mapped=[];
        for (var j=0;j<arr.length;j++){
          var r=arr[j]; mapped.push({ name:name, type:r.type, class:r.class, ttl:r.ttl, data:r.data });
        }
        return mapped;
      }
    }
    return [];
  }
  // Resolve one step for (name,type): exact match, then CNAME at name, then wildcard.
  // Returns { rrs, via } where via is 'exact' | 'cname' | 'wildcard' | null.
  function resolveStep(name, type){
    var exact = collect(name, type);
    if (exact.length) return { rrs: exact, via: 'exact' };
    if (type !== 'CNAME' && type !== 'ANY'){
      var cn = collect(name, 'CNAME');
      if (cn.length) return { rrs: cn, via: 'cname' };
    }
    if (!existsName(name)){
      var wc = wildcardLookup(name, type);
      if (wc.length) return { rrs: wc, via: 'wildcard' };
      if (type !== 'CNAME' && type !== 'ANY'){
        var wcn = wildcardLookup(name, 'CNAME');
        if (wcn.length) return { rrs: wcn, via: 'cname' };
      }
    }
    return { rrs: [], via: null };
  }

  // Main resolution loop: follows CNAME chains inside the zone (RFC 1034 §3.6.2 —
  // a query for type X on a name that owns a CNAME must return the CNAME and
  // restart resolution at the canonical name).
  var answers = [];
  var reason = null;
  var current = fq;
  var seen = new Set();

  for (var hop = 0; hop <= MAX_CNAME_CHAIN; hop++){
    if (seen.has(current)) break; // CNAME loop — stop, return what we have
    seen.add(current);

    var step = resolveStep(current, qtype);
    if (!step.via){
      if (answers.length){
        // chain ended at a name we don't own — return the partial chain, resolver continues
        break;
      }
      // no match at all for the original qname
      if (existsName(current)){
        var soaN = negativeSOA();
        // The types that do exist here — what the NSEC proving this NODATA
        // lists (copy to res.types).
        var present = [];
        var atName = collectAllTypes(current);
        for (var pt = 0; pt < atName.length; pt++){
          if (present.indexOf(atName[pt].type) < 0) present.push(atName[pt].type);
        }
        return { rcode:0, answers:[], authority: soaN?[soaN]:[], additionals:[], types: present, reason:'NODATA' };
      }
      var soaX = negativeSOA();
      return { rcode:3, answers:[], authority: soaX?[soaX]:[], additionals:[], reason:'NXDOMAIN' };
    }

    Array.prototype.push.apply(answers, step.rrs);
    if (!reason) reason = step.via;

    if (step.via === 'cname' && qtype !== 'CNAME'){
      var target = step.rrs[0] && step.rrs[0].data && step.rrs[0].data.name;
      if (!target) break;
      current = fqdn(target);
      continue; // chase the canonical name
    }
    break; // exact / wildcard / terminal
  }

  var out = { rcode:0, answers:answers, authority:[], additionals:[], reason: reason || 'exact' };
  addGlue(out.answers, out.additionals);
  addSvcbHttpsHints(out.answers, out.additionals);
  return out;

  function addGlue(rrs, out){
    for (var i=0;i<rrs.length;i++){
      var rr=rrs[i];
      var targets=[];
      if (rr.type==='MX' && rr.data && rr.data.exchange) targets.push(rr.data.exchange);
      else if (rr.type==='SRV' && rr.data && rr.data.target) targets.push(rr.data.target);
      else if (rr.type==='NS' && rr.data && rr.data.name) targets.push(rr.data.name);
      else if ((rr.type==='SVCB'||rr.type==='HTTPS') && rr.data && rr.data.targetName) targets.push(rr.data.targetName);
      for (var t=0;t<targets.length;t++){
        var name=fqdn(targets[t]);
        var a4 = collect(name,'A'); if (a4.length) Array.prototype.push.apply(out, a4);
        var a6 = collect(name,'AAAA'); if (a6.length) Array.prototype.push.apply(out, a6);
      }
    }
  }
  function addSvcbHttpsHints(rrs, out){
    for (var i=0;i<rrs.length;i++){
      var rr=rrs[i]; if (rr.type!=='SVCB' && rr.type!=='HTTPS') continue;
      var p = rr.data && rr.data.paramsStructured; var targetName = (rr.data && rr.data.targetName) ? rr.data.targetName : rr.name;
      if (p && Array.isArray(p.ipv4hint)) for (var h=0; h<p.ipv4hint.length; h++) out.push({ name: targetName, type:'A', class:'IN', ttl: rr.ttl, data:{ address: p.ipv4hint[h] }});
      if (p && Array.isArray(p.ipv6hint)) for (var h6=0; h6<p.ipv6hint.length; h6++) out.push({ name: targetName, type:'AAAA', class:'IN', ttl: rr.ttl, data:{ address: p.ipv6hint[h6] }});
    }
  }
}

export {
  createServer,
  buildDnssecMaterial,
  answerFromZone
};