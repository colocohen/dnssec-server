/*
 * dnssec-server: DNS server for Node.js
 * Copyright 2025 colocohen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * https://www.apache.org/licenses/LICENSE-2.0
 */

// --- Binary helpers ---
function readU16(dv, o) { return dv.getUint16(o, false); }
function writeU16(dv, o, v) { dv.setUint16(o, (v >>> 0) & 0xffff, false); return o + 2; }
function readU32(dv, o) { return dv.getUint32(o, false); }
function writeU32(dv, o, v) { dv.setUint32(o, v >>> 0, false); return o + 4; }

function dvFrom(u8) { return new DataView(u8.buffer, u8.byteOffset, u8.byteLength); }

// --- UTF-8 helpers ---
const __te = new TextEncoder();
const __td = new TextDecoder('utf-8', { fatal: false });

function encText(s) { return __te.encode(String(s == null ? '' : s)); }
function decText(bytes, a, b) { return __td.decode(bytes.slice(a, b)); }

// --- IPv6 helpers ---
function ipv6ToBytes(str) {
  if (typeof str !== 'string') throw new Error('AAAA: address must be string or bytes');
  var zone = str.indexOf('%');
  if (zone !== -1) str = str.slice(0, zone).trim();

  var ipv4 = null;
  var lastColon = str.lastIndexOf(':');
  if (str.indexOf('.') !== -1) {
    ipv4 = str.slice(lastColon + 1);
    str = str.slice(0, lastColon);
  }

  var parts = str.split('::');
  if (parts.length > 2) throw new Error('AAAA: invalid IPv6 (multiple ::)');

  var head = parts[0] ? parts[0].split(':').filter(Boolean) : [];
  var tail = parts[1] ? parts[1].split(':').filter(Boolean) : [];

  var hextets = [];
  function pushHextets(arr) {
    for (var i = 0; i < arr.length; i++) {
      var h = arr[i];
      if (!h.length || h.length > 4 || !/^[0-9a-fA-F]{1,4}$/.test(h)) throw new Error('AAAA: invalid hextet "' + h + '"');
      hextets.push(parseInt(h, 16));
    }
  }

  pushHextets(head);
  var need = 8 - hextets.length - (parts.length === 2 ? tail.length : 0) - (ipv4 ? 2 : 0);
  if (parts.length === 2) {
    for (var z = 0; z < need; z++) hextets.push(0);
    pushHextets(tail);
  } else {
    if (ipv4 && hextets.length !== 6) throw new Error('AAAA: invalid IPv6 (IPv4 mapped must leave 6 hextets before)');
    if (!ipv4 && hextets.length !== 8) throw new Error('AAAA: invalid IPv6 (expected 8 hextets)');
  }

  if (ipv4) {
    var oct = ipv4.split('.');
    if (oct.length !== 4) throw new Error('AAAA: invalid IPv4 tail');
    for (var j = 0; j < 4; j++) {
      var n = +oct[j];
      if (!(n >= 0 && n <= 255) || !/^\d{1,3}$/.test(oct[j])) throw new Error('AAAA: bad IPv4 octet');
      if (j % 2 === 0) hextets.push((n << 8) | (+oct[j + 1]));
    }
  }

  if (hextets.length !== 8) throw new Error('AAAA: normalization failed');
  var out = new Uint8Array(16);
  for (var k = 0; k < 8; k++) {
    out[(k << 1)] = (hextets[k] >> 8) & 0xff;
    out[(k << 1) + 1] = hextets[k] & 0xff;
  }
  return out;
}

function bytesToIpv6(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 16) throw new Error('AAAA: need 16 bytes');
  var hextets = new Array(8);
  for (var i = 0; i < 8; i++) {
    hextets[i] = ((bytes[i * 2] << 8) | bytes[i * 2 + 1]).toString(16);
  }
  var bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  for (var h = 0; h < 8; h++) {
    if (hextets[h] === '0') {
      if (curStart === -1) { curStart = h; curLen = 1; } else curLen++;
      if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
    } else {
      curStart = -1; curLen = 0;
    }
  }
  if (bestLen > 1) {
    var rep = hextets.slice(0, bestStart).concat(['']).concat(hextets.slice(bestStart + bestLen));
    var s = rep.join(':');
    if (s.startsWith(':')) s = ':' + s;
    if (s.endsWith(':')) s = s + ':';
    return s.replace(':::', '::');
  }
  return hextets.join(':');
}

// --- DNS name helpers (consolidated — single source of truth) ---
function ensureDot(n) {
  if (!n) return '.';
  return n[n.length - 1] === '.' ? n : n + '.';
}

function ensureNoDot(n) {
  if (!n) return '';
  return n[n.length - 1] === '.' ? n.slice(0, -1) : n;
}

function absName(name, origin) {
  if (name === '@') return ensureDot(origin);
  if (name === '.') return '.';
  if (!name) return null;
  if (name[name.length - 1] === '.') return name;
  if (!origin) return name + '.';
  return name + '.' + ensureNoDot(origin) + '.';
}

function fqdn(name) {
  if (!name) return '.';
  name = String(name).trim();
  if (name.charAt(name.length - 1) !== '.') name += '.';
  return name.toLowerCase();
}

function ensureFqdnLower(s) {
  s = String(s || '').trim();
  return (s.endsWith('.') ? s : s + '.').toLowerCase();
}

export {
  readU16, writeU16, readU32, writeU32,
  dvFrom,
  __te, __td,
  encText, decText,
  ipv6ToBytes, bytesToIpv6,
  ensureDot, ensureNoDot, absName, fqdn, ensureFqdnLower,
};
