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


function invertObject(obj) {
    var out = {};
    for (var key in obj) {
        if (Object.prototype.hasOwnProperty.call(obj, key)) {
            out[obj[key]] = key;
        }
    }
    return out;
}

// Resource Record (RR) TYPEs
var type_to_code = {
  'A': 1,
  'NS': 2,
  'MD': 3, // obsolete (NAME)
  'MF': 4, // obsolete (NAME)
  'CNAME': 5,
  'SOA': 6,
  'MB': 7, // obsolete (NAME)
  'MG': 8, // obsolete (NAME)
  'MR': 9, // obsolete (NAME)
  'NULL': 10,
  'WKS': 11, // obsolete (RFC 1035)
  'PTR': 12,
  'HINFO': 13,
  'MINFO': 14, // obsolete (2*NAME)
  'MX': 15,
  'TXT': 16,
  'RP': 17,
  'AFSDB': 18,
  'X25': 19, // obsolete (character-string)
  'ISDN': 20, // obsolete (character-string[,sa])
  'RT': 21, // obsolete (preference+NAME)
  'NSAP': 22, // obsolete (binary)
  'NSAP_PTR': 23, // obsolete (NAME)
  'SIG': 24, // obsolete (like RRSIG)
  'KEY': 25, // obsolete (similar to DNSKEY)
  'PX': 26, // obsolete (preference, MAP822, MAPX400)
  'GPOS': 27, // obsolete (3 strings)
  'AAAA': 28,
  'LOC': 29,
  'NXT': 30, // obsolete (next name + type bitmap)
  'EID': 31, // obsolete -> RAW
  'NIMLOC': 32, // obsolete -> RAW
  'SRV': 33,
  'ATMA': 34, // obsolete -> RAW
  'NAPTR': 35,
  'KX': 36,
  'CERT': 37,
  'A6': 38, // obsolete
  'DNAME': 39,
  'SINK': 40, // obsolete -> RAW
  'OPT': 41,
  'APL': 42,
  'DS': 43,
  'SSHFP': 44,
  'IPSECKEY': 45,
  'RRSIG': 46,
  'NSEC': 47,
  'DNSKEY': 48,
  'DHCID': 49,
  'NSEC3': 50,
  'NSEC3PARAM': 51,
  'TLSA': 52,
  'SMIMEA': 53,
  'HIP': 55,
  'NINFO': 56, // obsolete -> RAW
  'RKEY': 57, // obsolete -> RAW
  'TALINK': 58, // obsolete -> RAW
  'CDS': 59,
  'CDNSKEY': 60,
  'OPENPGPKEY': 61,
  'CSYNC': 62,
  'ZONEMD': 63,
  'SVCB': 64,
  'HTTPS': 65,
  'NID': 104,
  'L32': 105,
  'L64': 106,
  'LP': 107,
  'EUI48': 108,
  'EUI64': 109,
  'TKEY': 249,
  'TSIG': 250,
  'IXFR': 251,
  'AXFR': 252,
  'MAILB': 253, // obsolete
  'MAILA': 254, // obsolete
  'ANY': 255,
  'URI': 256,
  'CAA': 257,
  'TA': 32768, // obsolete (like DS)
  'DLV': 32769  // obsolete (like DS)
};

var deprecated_types = new Set([
    'MD','MF','MB','MG','MR','WKS','MINFO','X25','ISDN','RT','NSAP','NSAP_PTR',
    'SIG','KEY','PX','GPOS','NXT','EID','NIMLOC','ATMA','A6','SINK','NINFO',
    'RKEY','TALINK','MAILB','MAILA','TA','DLV','SPF'
]);

// RCODEs (כולל EDNS 확)
var rcode_to_code = {
    'NOERROR': 0,
    'FORMERR': 1,
    'SERVFAIL': 2,
    'NXDOMAIN': 3,
    'NOTIMP': 4,
    'REFUSED': 5,
    'YXDOMAIN': 6,
    'YXRRSET': 7,
    'NXRRSET': 8,
    'NOTAUTH': 9,
    'NOTZONE': 10,
    'DSOTYPENI': 11, // DSO specific
    'RCODE_12': 12,
    'RCODE_13': 13,
    'RCODE_14': 14,
    'RCODE_15': 15,
    'BADVERS': 16, // EDNS
    'BADSIG': 16,  // TSIG (אותו ערך)
    'BADKEY': 17,
    'BADTIME': 18,
    'BADMODE': 19,
    'BADNAME': 20,
    'BADALG': 21,
    'BADTRUNC': 22,
    'BADCOOKIE': 23
};

// EDNS Option Codes
var optioncode_to_code = {
    'LLQ': 1,
    'UL': 2,
    'NSID': 3,
    'DAU': 5,
    'DHU': 6,
    'N3U': 7,
    'CLIENT_SUBNET': 8,
    'EXPIRE': 9,
    'COOKIE': 10,
    'TCP_KEEPALIVE': 11,
    'PADDING': 12,
    'CHAIN': 13,
    'KEY_TAG': 14,
    'EDE': 15,
    'DEVICEID': 26946
};

// OPCODEs
var opcode_to_code = {
    'QUERY': 0,
    'IQUERY': 1,
    'STATUS': 2,
    'OPCODE_3': 3,
    'NOTIFY': 4,
    'UPDATE': 5,
    'DSO': 6,
    'OPCODE_7': 7,
    'OPCODE_8': 8,
    'OPCODE_9': 9,
    'OPCODE_10': 10,
    'OPCODE_11': 11,
    'OPCODE_12': 12,
    'OPCODE_13': 13,
    'OPCODE_14': 14,
    'OPCODE_15': 15
};

// Classes
var class_to_code = {
    'IN': 1,
    'CS': 2, // obsolete
    'CH': 3,
    'HS': 4,
    'NONE': 254,
    'ANY': 255
};


// ==== EDNS (OPT) option codes per IANA ====
var EDNS_OPT = {
  LLQ: 1,         // נשאיר RAW
  UL: 2,          // RAW
  NSID: 3,        // RFC 5001
  DAU: 5,         // RFC 6975
  DHU: 6,         // RFC 6975
  N3U: 7,         // RFC 6975
  ECS: 8,         // RFC 7871
  EXPIRE: 9,      // RFC 7314
  COOKIE: 10,     // RFC 7873
  KEEPALIVE: 11,  // RFC 7828
  PADDING: 12,    // RFC 7830
  CHAIN: 13,      // RFC 7901 (נשאיר RAW)
  KEYTAG: 14,     // RFC 8145
  EDE: 15         // RFC 8914
};

var code_to_type = invertObject(type_to_code);
var code_to_rcode = invertObject(rcode_to_code);
var code_to_opcode = invertObject(opcode_to_code);
var code_to_class = invertObject(class_to_code);
var code_to_optioncode = invertObject(optioncode_to_code);

/***************************
 * Type implementations
***************************/

var types={};
for(var type in type_to_code){
    types[type]={
        decode: null,
        encode: null,
    };
}


function readU16(dv, o){ return dv.getUint16(o, false); }
function writeU16(dv, o, v){ dv.setUint16(o, (v>>>0)&0xffff, false); return o+2; }
function readU32(dv, o){ return dv.getUint32(o, false); }
function writeU32(dv, o, v){ dv.setUint32(o, v>>>0, false); return o+4; }

// UTF-8 helpers
const __te = new TextEncoder();
const __td = new TextDecoder('utf-8', { fatal: false });

function encText(s){ return __te.encode(String(s == null ? '' : s)); }
function decText(bytes, a, b){ return __td.decode(bytes.slice(a, b)); }

// DataView helper
function dvFrom(u8){ return new DataView(u8.buffer, u8.byteOffset, u8.byteLength); }

// helpers
function ipv6ToBytes(str) {
  if (typeof str !== 'string') throw new Error('AAAA: address must be string or bytes');
  // התעלמות מאזורים כמו %eth0 אם קיימים
  var zone = str.indexOf('%');
  if (zone !== -1) str = str.slice(0, zone).trim();

  // בדיקת IPv4-ממופה בסוף (::ffff:192.0.2.128)
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

  // המרה להקסות (עד 8 הקסטים בסה"כ; IPv4 ממופה תופס 2 הקסטים)
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
      // שני ההקסות האחרונים מה־IPv4: כל שני בייטים = הקסט אחד
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
    hextets[i] = ((bytes[i*2] << 8) | bytes[i*2+1]).toString(16);
  }
  // דחיסת רצף האפסים הארוך ביותר
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
    var rep = [''];
    rep = hextets.slice(0, bestStart).concat(['']).concat(hextets.slice(bestStart + bestLen));
    // טיפול בקצוות
    var s = rep.join(':');
    if (s.startsWith(':')) s = ':' + s;
    if (s.endsWith(':')) s = s + ':';
    return s.replace(':::', '::');
  }
  return hextets.join(':');
}



// encodeName (non-compressed; מתאים ל-RDATA ול-Question כשלא רוצים דחיסה)
function encodeName(out, off, name/*, _dictIgnored */){
  name = String(name || '.');
  if (name === '.') { out[off++] = 0; return off; }
  if (name[name.length-1] !== '.') name += '.';
  const labels = name.slice(0, -1).split('.');
  for (const lab of labels){
    const b = __te.encode(lab);
    if (b.length === 0 || b.length > 63) throw new Error('label len');
    out[off++] = b.length;
    out.set(b, off); off += b.length;
  }
  out[off++] = 0;
  return off;
}

// decodeName (with compression pointers)
function decodeName(buf, off){
  const max = buf.length;
  let labels = [];
  let jumped = false;
  let retOff = off;
  let hops = 0;

  while (true){
    if (off >= max) throw new Error('decodeName overflow');
    const len = buf[off++];

    if (len === 0) break;

    // pointer?
    if ((len & 0xC0) === 0xC0){
      if (off >= max) throw new Error('decodeName pointer overflow');
      const b2 = buf[off++];
      const ptr = ((len & 0x3F) << 8) | b2;
      if (ptr >= max) throw new Error('decodeName bad ptr');
      if (!jumped){ retOff = off; jumped = true; }
      off = ptr;
      if (++hops > 128) throw new Error('decodeName loop');
      continue;
    }

    if ((len & 0xC0) !== 0) throw new Error('decodeName label type');
    if (off + len > max) throw new Error('decodeName label overflow');

    labels.push(__td.decode(buf.slice(off, off+len)));
    off += len;
  }

  const name = labels.length ? labels.join('.') + '.' : '.';
  return { name, off: jumped ? retOff : off };
}


function makeNameRdataDecoder(){
  return function(buf, off, rdlen){
    var start=off; var n = decodeName(buf, off); off = n.off;
    if (off-start !== rdlen) throw new Error('NAME rdata length mismatch');
    return { value:{ name: n.name }, bytes: rdlen };
  };
}
function makeNameRdataEncoder(field){
  return function(v){
    var s;
    if (typeof v === 'string') {
      s = v;
    } else if (v && typeof v === 'object') {
      s = v[field] || v.name;
    }
    if (!s) s = '.';

    var tmp = new Uint8Array(512), off = 0;
    off = encodeName(tmp, off, s /*, {} */);
    return tmp.slice(0, off);
  };
}


// A
types.A.decode = function(buf, off, rdlen){
  if (rdlen!==4) throw new Error('A: bad rdlen');
  return { value:{ address: buf[off]+'.'+buf[off+1]+'.'+buf[off+2]+'.'+buf[off+3] }, bytes:4 };
};
types.A.encode = function(v){
  var p = String(v.address||'0.0.0.0').split('.');
  var out = new Uint8Array(4);
  out[0]=p[0]|0; out[1]=p[1]|0; out[2]=p[2]|0; out[3]=p[3]|0; return out;
};

// AAAA
types.AAAA.decode = function (buf, off, rdlen) {
  if (rdlen !== 16) throw new Error('AAAA: bad rdlen');
  var slice = buf.subarray ? buf.subarray(off, off + 16) : buf.slice(off, off + 16);
  return { value: { address: bytesToIpv6(slice) }, bytes: 16 };
};

types.AAAA.encode = function (v) {
  var a = v && v.address;
  if (typeof a === 'string') {
    a = ipv6ToBytes(a);
  } else if (a instanceof Uint8Array || (a && a.buffer && typeof a.byteLength === 'number')) {
    a = new Uint8Array(a.buffer, a.byteOffset || 0, a.byteLength || a.length);
  } else {
    throw new Error('AAAA: address must be string or 16-byte array');
  }
  if (a.length !== 16) throw new Error('AAAA: need 16 bytes');
  var out = new Uint8Array(16);
  out.set(a);
  return out;
};

// === NAME-based (obsolete/simple): MD, MF, MB, MG, MR, NSAP_PTR, MAILA, MAILB ===
types.NS.decode = makeNameRdataDecoder(); types.NS.encode = makeNameRdataEncoder('name');
types.CNAME.decode = makeNameRdataDecoder(); types.CNAME.encode = makeNameRdataEncoder('name');
types.PTR.decode = makeNameRdataDecoder(); types.PTR.encode = makeNameRdataEncoder('name');
types.DNAME.decode = makeNameRdataDecoder(); types.DNAME.encode = makeNameRdataEncoder('name');
// obsolete NAME-only: MD, MF, MB, MG, MR, NSAP_PTR, MAILA, MAILB
['MD','MF','MB','MG','MR','NSAP_PTR','MAILA','MAILB'].forEach(function(t){ 
    types[t].decode = types.NS.decode; types[t].encode = types.NS.encode; 
});


// NULL — raw octets
types.NULL.decode = function(buf, off, rdlen){ return { value:{ raw: buf.slice(off, off+rdlen) }, bytes: rdlen }; };
types.NULL.encode = function(v){ var d=v&&v.raw?v.raw:new Uint8Array(0); var out=new Uint8Array(d.length); out.set(d.slice(0)); return out; };

// WKS (RFC 1035): address(IPv4), protocol(u8), bitmap
types.WKS.decode = function(buf, off, rdlen){
  if (rdlen < 5) throw new Error('WKS too short');
  var addr = buf[off]+'.'+buf[off+1]+'.'+buf[off+2]+'.'+buf[off+3];
  var proto = buf[off+4];
  var bitmap = buf.slice(off+5, off+rdlen);
  return { value:{ address:addr, protocol:proto, bitmap:bitmap }, bytes: rdlen };
};
types.WKS.encode = function(v){
  var p = String(v.address||'0.0.0.0').split('.');
  var bm = v.bitmap||new Uint8Array(0);
  var out = new Uint8Array(4+1+bm.length);
  out[0]=p[0]|0; out[1]=p[1]|0; out[2]=p[2]|0; out[3]=p[3]|0; out[4]=v.protocol|0; out.set(bm,5); return out;
};

// HINFO (CPU, OS) — two length-prefixed strings
types.HINFO.decode = function(buf, off, rdlen){
  var end=off+rdlen; if (off>=end) throw new Error('HINFO short');
  var l1=buf[off++]; if (off+l1> end) throw new Error('HINFO overflow');
  var cpu=decText(buf, off, off+l1); off+=l1;
  if (off>=end) throw new Error('HINFO short2');
  var l2=buf[off++]; if (off+l2> end) throw new Error('HINFO overflow2');
  var os=decText(buf, off, off+l2); off+=l2;
  return { value:{ cpu:cpu, os:os }, bytes: rdlen };
};
types.HINFO.encode = function(v){
  var c=encText(v.cpu), o=encText(v.os);
  var out=new Uint8Array(1+c.length+1+o.length), i=0;
  out[i++]=c.length&0xff; out.set(c, i); i+=c.length;
  out[i++]=o.length&0xff; out.set(o, i);
  return out;
};

// MINFO (RFC 1035) — rmailbx(NAME), emailbx(NAME)
types.MINFO.decode = function(buf, off, rdlen){ var s=off; var a=decodeName(buf,off); off=a.off; var b=decodeName(buf,off); off=b.off; if (off-s!==rdlen) throw new Error('MINFO len'); return { value:{ rmailbx:a.name, emailbx:b.name }, bytes: rdlen }; };
types.MINFO.encode = function(v){ var tmp=new Uint8Array(512), off=0; off=encodeName(tmp,off,v.rmailbx||'.'); off=encodeName(tmp,off,v.emailbx||'.'); return tmp.slice(0,off); };

// TXT — sequence of <len><bytes>
types.TXT.decode = function(buf, off, rdlen){ var end=off+rdlen, out=[]; while(off<end){ var l=buf[off++]; if (off+l> end) throw new Error('TXT overflow'); out.push(decText(buf, off, off+l)); off+=l; } return { value:{ texts: out }, bytes: rdlen}; };
types.TXT.encode = function(v){ var arr = Array.isArray(v.texts)? v.texts : (v.texts!=null? [v.texts] : []); var parts=new Array(arr.length), i, total=0; for(i=0;i<arr.length;i++){ var b=encText(arr[i]); parts[i]=b; total+=1+b.length; } var out=new Uint8Array(total), o=0; for(i=0;i<parts.length;i++){ var b2=parts[i]; out[o++]=b2.length&0xff; out.set(b2,o); o+=b2.length; } return out; };

// RP (RFC 1183) — mbox(NAME), txt(NAME)
types.RP.decode = function(buf, off, rdlen){ var s=off; var m=decodeName(buf,off); off=m.off; var t=decodeName(buf,off); off=t.off; if (off-s!==rdlen) throw new Error('RP len'); return { value:{ mbox:m.name, txt:t.name }, bytes: rdlen }; };
types.RP.encode = function(v){ var tmp=new Uint8Array(512), off=0; off=encodeName(tmp,off,v.mbox||'.'); off=encodeName(tmp,off,v.txt||'.'); return tmp.slice(0,off); };

// AFSDB (RFC 1183) — subtype(u16), hostname(NAME)
types.AFSDB.decode = function(buf, off, rdlen){ var s=off, dv=dvFrom(buf); var subtype=readU16(dv,off); off+=2; var n=decodeName(buf,off); off=n.off; if (off-s!==rdlen) throw new Error('AFSDB len'); return { value:{ subtype:subtype, hostname:n.name }, bytes: rdlen }; };
types.AFSDB.encode = function(v){ var tmp=new Uint8Array(512), dv=new DataView(tmp.buffer), off=0; off=writeU16(dv,off,v.subtype|0); off=encodeName(tmp,off,v.hostname||'.'); return tmp.slice(0,off); };

// X25 (RFC 1183) — PSDN address (character-string)
types.X25.decode = function(buf, off, rdlen){ var end=off+rdlen; var l=buf[off++]; if (off+l> end) throw new Error('X25 overflow'); var addr=decText(buf,off,off+l); return { value:{ address:addr }, bytes: rdlen }; };
types.X25.encode = function(v){ var a=encText(v.address); var out=new Uint8Array(1+a.length); out[0]=a.length&0xff; out.set(a,1); return out; };

// ISDN (RFC 1183) — address (char-string), optional sa (char-string)
types.ISDN.decode = function(buf, off, rdlen){ var s=off, end=off+rdlen; var l1=buf[off++]; if (off+l1> end) throw new Error('ISDN'); var addr=decText(buf,off,off+l1); off+=l1; var sa=null; if (off<end){ var l2=buf[off++]; if (off+l2> end) throw new Error('ISDN2'); sa=decText(buf,off,off+l2); off+=l2; } if (off!==end) throw new Error('ISDN trailing'); return { value:{ address:addr, sa:sa }, bytes: rdlen }; };
types.ISDN.encode = function(v){ var a=encText(v.address), sa=v.sa!=null?encText(v.sa):null; var out=new Uint8Array(1+a.length + (sa?1+sa.length:0)); var i=0; out[i++]=a.length&0xff; out.set(a,i); i+=a.length; if (sa){ out[i++]=sa.length&0xff; out.set(sa,i); } return out; };

// RT (RFC 1183) — preference(u16), intermediate-host(NAME)
types.RT.decode = function(buf, off, rdlen){ var s=off, dv=dvFrom(buf); var pref=readU16(dv,off); off+=2; var n=decodeName(buf,off); off=n.off; if (off-s!==rdlen) throw new Error('RT len'); return { value:{ preference:pref, host:n.name }, bytes: rdlen }; };
types.RT.encode = function(v){ var tmp=new Uint8Array(512), dv=new DataView(tmp.buffer), off=0; off=writeU16(dv,off,v.preference|0); off=encodeName(tmp,off,v.host||'.'); return tmp.slice(0,off); };

// NSAP (RFC 1706) — binary address (treat as raw)
types.NSAP.decode = function(buf, off, rdlen){ return { value:{ address: buf.slice(off, off+rdlen) }, bytes: rdlen }; };
types.NSAP.encode = function(v){ var a=v.address||new Uint8Array(0); var out=new Uint8Array(a.length); out.set(a.slice(0)); return out; };

// SIG (obsolete) — same wire as RRSIG
// KEY (obsolete) — nearly same wire as DNSKEY

// PX (RFC 2163) — preference(u16), MAP822(NAME), MAPX400(NAME)
types.PX.decode = function(buf, off, rdlen){ var s=off, dv=dvFrom(buf); var pref=readU16(dv,off); off+=2; var m822=decodeName(buf,off); off=m822.off; var mx400=decodeName(buf,off); off=mx400.off; if (off-s!==rdlen) throw new Error('PX len'); return { value:{ preference:pref, MAP822:m822.name, MAPX400:mx400.name }, bytes: rdlen }; };
types.PX.encode = function(v){ var tmp=new Uint8Array(512), dv=new DataView(tmp.buffer), off=0; off=writeU16(dv,off,v.preference|0); off=encodeName(tmp,off,v.MAP822||'.'); off=encodeName(tmp,off,v.MAPX400||'.'); return tmp.slice(0,off); };

// GPOS (RFC 1712, obsolete) — three strings: latitude, longitude, altitude
types.GPOS.decode = function(buf, off, rdlen){ var end=off+rdlen; function rd(){ var l=buf[off++]; if (off+l> end) throw new Error('GPOS'); var s=decText(buf,off,off+l); off+=l; return s; } var lat=rd(), lon=rd(), alt=rd(); return { value:{ latitude:lat, longitude:lon, altitude:alt }, bytes: rdlen }; };
types.GPOS.encode = function(v){ var a=encText(v.latitude), b=encText(v.longitude), c=encText(v.altitude); var out=new Uint8Array(3 + a.length + b.length + c.length); var i=0; out[i++]=a.length; out.set(a,i); i+=a.length; out[i++]=b.length; out.set(b,i); i+=b.length; out[i++]=c.length; out.set(c,i); return out; };

// MX
types.MX.decode = function(buf, off, rdlen){ var s=off, dv=dvFrom(buf); var pref=readU16(dv,off); off+=2; var n=decodeName(buf,off); off=n.off; if (off-s!==rdlen) throw new Error('MX len'); return { value:{ preference:pref, exchange:n.name }, bytes: rdlen }; };
types.MX.encode = function(v){ var tmp=new Uint8Array(512), dv=new DataView(tmp.buffer), off=0; off=writeU16(dv,off,v.preference|0); off=encodeName(tmp,off,v.exchange||'.'); return tmp.slice(0,off); };

// SOA
types.SOA.decode = function(buf, off, rdlen){ var s=off, dv=dvFrom(buf); var m=decodeName(buf,off); off=m.off; var r=decodeName(buf,off); off=r.off; if (buf.length-off<20) throw new Error('SOA short'); var serial=readU32(dv,off); off+=4; var refresh=readU32(dv,off); off+=4; var retry=readU32(dv,off); off+=4; var expire=readU32(dv,off); off+=4; var minimum=readU32(dv,off); off+=4; if (off-s!==rdlen) throw new Error('SOA len'); return { value:{ mname:m.name, rname:r.name, serial:serial, refresh:refresh, retry:retry, expire:expire, minimum:minimum }, bytes: rdlen}; };
types.SOA.encode = function(v){ var tmp=new Uint8Array(512), dv=new DataView(tmp.buffer), off=0; off=encodeName(tmp,off,v.mname||'.'); off=encodeName(tmp,off,v.rname||'.'); off=writeU32(dv,off,v.serial|0); off=writeU32(dv,off,v.refresh|0); off=writeU32(dv,off,v.retry|0); off=writeU32(dv,off,v.expire|0); off=writeU32(dv,off,v.minimum|0); return tmp.slice(0,off); };

// SRV
types.SRV.decode = function(buf, off, rdlen){ var s=off, dv=dvFrom(buf); var pr=readU16(dv,off); off+=2; var wt=readU16(dv,off); off+=2; var pt=readU16(dv,off); off+=2; var n=decodeName(buf,off); off=n.off; if (off-s!==rdlen) throw new Error('SRV len'); return { value:{ priority:pr, weight:wt, port:pt, target:n.name }, bytes: rdlen}; };
types.SRV.encode = function(v){ var tmp=new Uint8Array(512), dv=new DataView(tmp.buffer), off=0; off=writeU16(dv,off,v.priority|0); off=writeU16(dv,off,v.weight|0); off=writeU16(dv,off,v.port|0); off=encodeName(tmp,off,v.target||'.'); return tmp.slice(0,off); };

// TLSA / SMIMEA (alias)
types.TLSA.decode = function(buf, off, rdlen){ if (rdlen<3) throw new Error('TLSA short'); var usage=buf[off], selector=buf[off+1], mt=buf[off+2]; var data=buf.slice(off+3, off+rdlen); return { value:{ usage:usage, selector:selector, matchingType:mt, certificate:data }, bytes: rdlen}; };
types.TLSA.encode = function(v){ var cert=v.certificate||new Uint8Array(0); var out=new Uint8Array(3+cert.length); out[0]=v.usage|0; out[1]=v.selector|0; out[2]=v.matchingType|0; out.set(cert,3); return out; };

types.SMIMEA = types.TLSA;

// DNSKEY / KEY(obsolete)
types.DNSKEY.decode = function(buf, off, rdlen){ if (rdlen<4) throw new Error('DNSKEY short'); var dv=dvFrom(buf); var flags=readU16(dv,off); off+=2; var proto=buf[off++]; var alg=buf[off++]; var key=buf.slice(off, off+rdlen-4); return { value:{ flags:flags, protocol:proto, algorithm:alg, key:key }, bytes: rdlen}; };
types.DNSKEY.encode = function(v){ var key=v.key||new Uint8Array(0); var out=new Uint8Array(4+key.length); var dv=new DataView(out.buffer); writeU16(dv,0,v.flags|0); out[2]=3; out[3]=v.algorithm|0; out.set(key,4); return out; };

// === CDNSKEY — כמו DNSKEY ===
types.CDNSKEY = types.DNSKEY;





// === KEY (obsolete) — אותו חוט כמו DNSKEY (בגדול) ===
types.KEY = {
  decode: function(buf, off, rdlen){
    if (rdlen < 4) throw new Error('KEY short');
    var dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    var flags = dv.getUint16(off, false); off += 2;
    var proto = buf[off++]; // אמור להיות 3
    var alg   = buf[off++];
    var key   = buf.slice(off, off + (rdlen - 4));
    return { value: { flags: flags, protocol: proto, algorithm: alg, key: key }, bytes: rdlen };
  },
  encode: function(v){
    var key = v.key || new Uint8Array(0);
    var out = new Uint8Array(4 + key.length);
    var dv  = new DataView(out.buffer);
    dv.setUint16(0, (v.flags|0)>>>0, false);
    out[2] = v.protocol != null ? (v.protocol|0) : 3;
    out[3] = v.algorithm|0;
    out.set(key, 4);
    return out;
  }
};


// RRSIG / SIG(obsolete)
types.RRSIG.decode = function(buf, off, rdlen){ var s=off, dv=dvFrom(buf); var tc=readU16(dv,off); off+=2; var alg=buf[off++]; var labels=buf[off++]; var ttl=readU32(dv,off); off+=4; var exp=readU32(dv,off); off+=4; var inc=readU32(dv,off); off+=4; var keyTag=readU16(dv,off); off+=2; var n=decodeName(buf,off); off=n.off; var sig=buf.slice(off, s+rdlen); off=s+rdlen; return { value:{ typeCovered:tc, algorithm:alg, labels:labels, originalTTL:ttl, expiration:exp, inception:inc, keyTag:keyTag, signersName:n.name, signature:sig }, bytes: rdlen}; };
types.RRSIG.encode = function(v){ var nbuf=new Uint8Array(512), noff=0; noff=encodeName(nbuf,noff,v.signersName||'.'); var sig=v.signature||new Uint8Array(0); var out=new Uint8Array(2+1+1+4+4+4+2+noff+sig.length); var dv=new DataView(out.buffer); var o=0; o=writeU16(dv,o,v.typeCovered|0); out[o++]=v.algorithm|0; out[o++]=v.labels|0; o=writeU32(dv,o,v.originalTTL|0); o=writeU32(dv,o,v.expiration|0); o=writeU32(dv,o,v.inception|0); o=writeU16(dv,o,v.keyTag|0); out.set(nbuf.slice(0,noff), o); o+=noff; out.set(sig,o); return out; };
types.SIG = types.RRSIG;

// DS / CDS / DLV / TA (all same wire as DS)
types.DS.decode = function(buf, off, rdlen){ if (rdlen<4) throw new Error('DS short'); var dv=dvFrom(buf); var keyTag=readU16(dv,off); off+=2; var alg=buf[off++]; var dt=buf[off++]; var dig=buf.slice(off, off+rdlen-4); return { value:{ keyTag:keyTag, algorithm:alg, digestType:dt, digest:dig }, bytes: rdlen}; };
types.DS.encode = function(v){ var d=v.digest||new Uint8Array(0); var out=new Uint8Array(4+d.length); var dv=new DataView(out.buffer); writeU16(dv,0,v.keyTag|0); out[2]=v.algorithm|0; out[3]=v.digestType|0; out.set(d,4); return out; };
types.CDS = types.DS;
types.DLV = types.DS; 
types.TA = types.DS;

// SSHFP
types.SSHFP.decode = function(buf, off, rdlen){ if (rdlen<2) throw new Error('SSHFP short'); var alg=buf[off++]; var hash=buf[off++]; var fp=buf.slice(off, off+rdlen-2); return { value:{ algorithm:alg, hash:hash, fingerprint:fp }, bytes: rdlen}; };
types.SSHFP.encode = function(v){ var fp=v.fingerprint||new Uint8Array(0); var out=new Uint8Array(2+fp.length); out[0]=v.algorithm|0; out[1]=v.hash|0; out.set(fp,2); return out; };

// NAPTR
types.NAPTR.decode = function(buf, off, rdlen){ var s=off, dv=dvFrom(buf); var order=readU16(dv,off); off+=2; var pref=readU16(dv,off); off+=2; var fl=buf[off++]; var flags=decText(buf,off,off+fl); off+=fl; var sl=buf[off++]; var services=decText(buf,off,off+sl); off+=sl; var rl=buf[off++]; var regexp=decText(buf,off,off+rl); off+=rl; var n=decodeName(buf,off); off=n.off; if (off-s!==rdlen) throw new Error('NAPTR len'); return { value:{ order:order, preference:pref, flags:flags, services:services, regexp:regexp, replacement:n.name }, bytes: rdlen}; };
types.NAPTR.encode = function(v){ var f=encText(v.flags||''); var s=encText(v.services||''); var r=encText(v.regexp||''); var nbuf=new Uint8Array(512), noff=0; noff=encodeName(nbuf,noff,v.replacement||'.'); var out=new Uint8Array(2+2+1+f.length+1+s.length+1+r.length+noff); var dv=new DataView(out.buffer); var o=0; o=writeU16(dv,o,v.order|0); o=writeU16(dv,o,v.preference|0); out[o++]=f.length&0xff; out.set(f,o); o+=f.length; out[o++]=s.length&0xff; out.set(s,o); o+=s.length; out[o++]=r.length&0xff; out.set(r,o); o+=r.length; out.set(nbuf.slice(0,noff), o); return out; };

// OPT (EDNS) — options array [{code,data}]
types.OPT.decode = function(buf, off, rdlen){ var end=off+rdlen, options=[]; var dv=dvFrom(buf); while(off+4<=end){ var code=readU16(dv,off); off+=2; var len=readU16(dv,off); off+=2; if (off+len> end) throw new Error('OPT overflow'); var val=buf.slice(off, off+len); options.push({ code:code, data: val }); off+=len; } if (off!==end) throw new Error('OPT trailing'); return { value:{ options: options }, bytes: rdlen}; };

types.OPT.encode = function(v){ var opts=(v&&v.options)?v.options:[]; var total=0; for (var i=0;i<opts.length;i++){ var d=opts[i].data||new Uint8Array(0); total += 4 + d.length; } var out=new Uint8Array(total), dv=new DataView(out.buffer), o=0; for (var j=0;j<opts.length;j++){ var op=opts[j], d2=op.data||new Uint8Array(0); o=writeU16(dv,o,op.code|0); o=writeU16(dv,o,d2.length); out.set(d2,o); o+=d2.length; } return out; };




// ===== SVCB/HTTPS — structured params helpers (RFC 9460 etc.) =====
// Sources: RFC 9460 §7.1 (alpn/no-default-alpn), §7.2 (port), §7.3 (ipv4/ipv6 hint), §7.4 (mandatory)
// IANA SvcParamKeys registry (numbers): mandatory=0, alpn=1, no-default-alpn=2, port=3, ipv4hint=4, ech=5, ipv6hint=6, dohpath=7, ohttp=8, tls-supported-groups=9

const SvcParamKeys = {
  mandatory: 0,
  alpn: 1,
  noDefaultAlpn: 2,
  port: 3,
  ipv4hint: 4,
  ech: 5,
  ipv6hint: 6,
  dohpath: 7,
  ohttp: 8,
  tlsSupportedGroups: 9,
};

// ---- value decoders for well-known keys ----
function decode_alpn(u8){
  // SvcParamValue = 1* ( len(1) + alpn-id(len bytes) ), must fill exactly
  let off = 0, out = [];
  while (off < u8.length){
    const l = u8[off++]; if (l===0 || off + l > u8.length) throw new Error('alpn malformed');
    out.push((new TextDecoder('utf-8')).decode(u8.slice(off, off+l)));
    off += l;
  }
  if (off !== u8.length) throw new Error('alpn trailing bytes');
  return out; // e.g., ["h3","h2","http/1.1"]
}
function encode_alpn(ids){
  const enc = new TextEncoder();
  const parts = ids.map(s => {
    const b = enc.encode(String(s));
    if (b.length === 0 || b.length > 255) throw new Error('alpn-id length');
    const out = new Uint8Array(1 + b.length);
    out[0] = b.length; out.set(b, 1); return out;
  });
  let total = parts.reduce((n,p)=>n+p.length, 0);
  const out = new Uint8Array(total); let o=0;
  for (const p of parts){ out.set(p, o); o+=p.length; }
  return out;
}

function decode_port(u8){
  if (u8.length !== 2) throw new Error('port length');
  return dvFrom(u8).getUint16(0, false);
}
function encode_port(n){
  const out = new Uint8Array(2);
  dvFrom(out).setUint16(0, (n>>>0)&0xffff, false);
  return out;
}

function ipv4_to_string(b, o){ return b[o]+'.'+b[o+1]+'.'+b[o+2]+'.'+b[o+3]; }
function decode_ipv4hint(u8){
  if (u8.length % 4 !== 0) throw new Error('ipv4hint len');
  const out = [];
  for (let i=0;i<u8.length;i+=4) out.push(ipv4_to_string(u8, i));
  return out; // array of dotted-quad strings
}
function encode_ipv4hint(arr){
  // accept array of strings "x.x.x.x" or Uint8Array(4)
  const out = new Uint8Array(arr.length * 4);
  let o=0;
  for (const v of arr){
    if (v instanceof Uint8Array){ if (v.length!==4) throw new Error('ipv4hint item'); out.set(v, o); o+=4; }
    else {
      const p = String(v).split('.'); if (p.length!==4) throw new Error('ipv4hint string');
      out[o++] = p[0]|0; out[o++] = p[1]|0; out[o++] = p[2]|0; out[o++] = p[3]|0;
    }
  }
  return out;
}

function decode_ipv6hint(u8){
  if (u8.length % 16 !== 0) throw new Error('ipv6hint len');
  const out = [];
  for (let i=0;i<u8.length;i+=16) out.push(u8.slice(i, i+16)); // keep as 16-byte arrays
  return out;
}
function encode_ipv6hint(items){
  const out = new Uint8Array(items.length * 16); let o=0;
  for (const it of items){
    if (!(it instanceof Uint8Array) || it.length!==16) throw new Error('ipv6hint item must be 16 bytes');
    out.set(it, o); o+=16;
  }
  return out;
}

function decode_mandatory(u8){
  if (u8.length===0 || (u8.length % 2)!==0) throw new Error('mandatory malformed');
  const dv = dvFrom(u8), arr=[];
  for (let i=0;i<u8.length;i+=2) arr.push(dv.getUint16(i, false));
  return arr; // numeric SvcParamKeys that are mandatory
}
function encode_mandatory(keys){
  const out = new Uint8Array(keys.length*2), dv=dvFrom(out);
  for (let i=0;i<keys.length;i++) dv.setUint16(i*2, (keys[i]>>>0)&0xffff, false);
  return out;
}

function decode_dohpath(u8){
  // RFC 9461 DoH path template, UTF-8
  return (new TextDecoder('utf-8')).decode(u8);
}
function encode_dohpath(s){
  return (new TextEncoder()).encode(String(s));
}

function decode_tls_supported_groups(u8){
  if (u8.length===0 || (u8.length % 2)!==0) throw new Error('tls-supported-groups malformed');
  const dv=dvFrom(u8), out=[];
  for (let i=0;i<u8.length;i+=2) out.push(dv.getUint16(i,false));
  return out; // array of IANA TLS Group IDs
}
function encode_tls_supported_groups(ids){
  const out=new Uint8Array(ids.length*2), dv=dvFrom(out);
  for (let i=0;i<ids.length;i++) dv.setUint16(i*2, (ids[i]>>>0)&0xffff, false);
  return out;
}

// ech: opaque bytes (per IANA registry). leave as-is
function decode_ech(u8){ return u8.slice(0); }
function encode_ech(u8){ return (u8 instanceof Uint8Array) ? u8.slice(0) : new Uint8Array(0); }

// ---- master parse/build of SvcParams ----
function parseSvcParams(rawList){
  // rawList: array of { key:number, value:Uint8Array }  (from wire)
  const out = {
    // known structured fields (optional):
    mandatory: undefined,         // number[]
    alpn: undefined,              // string[]
    noDefaultAlpn: false,         // boolean
    port: undefined,              // number
    ipv4hint: undefined,          // string[]
    ech: undefined,               // Uint8Array
    ipv6hint: undefined,          // Uint8Array[] (16b each)
    dohpath: undefined,           // string
    ohttp: undefined,             // reserved/use per RFC 9540 §4 (string URL or bytes)
    tlsSupportedGroups: undefined,// number[]
    // passthrough for unknown keys
    unknown: []                   // array of { key, value(Uint8Array) }
  };

  for (const p of rawList){
    const k = p.key >>> 0;
    const v = p.value || new Uint8Array(0);
    switch(k){
      case SvcParamKeys.mandatory: out.mandatory = decode_mandatory(v); break;
      case SvcParamKeys.alpn: out.alpn = decode_alpn(v); break;
      case SvcParamKeys.noDefaultAlpn:
        if (v.length!==0) throw new Error('no-default-alpn must be empty'); out.noDefaultAlpn = true; break;
      case SvcParamKeys.port: out.port = decode_port(v); break;
      case SvcParamKeys.ipv4hint: out.ipv4hint = decode_ipv4hint(v); break;
      case SvcParamKeys.ech: out.ech = decode_ech(v); break;
      case SvcParamKeys.ipv6hint: out.ipv6hint = decode_ipv6hint(v); break;
      case SvcParamKeys.dohpath: out.dohpath = decode_dohpath(v); break;
      case SvcParamKeys.tlsSupportedGroups: out.tlsSupportedGroups = decode_tls_supported_groups(v); break;
      case SvcParamKeys.ohttp:
        // RFC 9540 defines ohttp param: content is an absolute/relative URI (UTF‑8). Many impls use text.
        out.ohttp = (new TextDecoder()).decode(v); break;
      default:
        out.unknown.push({ key:k, value:v.slice(0) });
    }
  }
  return out;
}

function buildSvcParams(obj){
  // obj: may contain known fields above + unknown[]
  const res = [];
  if (obj.mandatory && obj.mandatory.length) res.push({ key: SvcParamKeys.mandatory, value: encode_mandatory(obj.mandatory) });
  if (obj.alpn && obj.alpn.length)           res.push({ key: SvcParamKeys.alpn,      value: encode_alpn(obj.alpn) });
  if (obj.noDefaultAlpn)                     res.push({ key: SvcParamKeys.noDefaultAlpn, value: new Uint8Array(0) });
  if (obj.port != null)                      res.push({ key: SvcParamKeys.port,      value: encode_port(obj.port) });
  if (obj.ipv4hint && obj.ipv4hint.length)   res.push({ key: SvcParamKeys.ipv4hint,  value: encode_ipv4hint(obj.ipv4hint) });
  if (obj.ech instanceof Uint8Array)         res.push({ key: SvcParamKeys.ech,       value: encode_ech(obj.ech) });
  if (obj.ipv6hint && obj.ipv6hint.length)   res.push({ key: SvcParamKeys.ipv6hint,  value: encode_ipv6hint(obj.ipv6hint) });
  if (obj.dohpath != null)                   res.push({ key: SvcParamKeys.dohpath,   value: encode_dohpath(obj.dohpath) });
  if (obj.tlsSupportedGroups && obj.tlsSupportedGroups.length)
                                              res.push({ key: SvcParamKeys.tlsSupportedGroups, value: encode_tls_supported_groups(obj.tlsSupportedGroups) });
  if (obj.ohttp != null)                     res.push({ key: SvcParamKeys.ohttp,     value: (new TextEncoder()).encode(String(obj.ohttp)) });
  if (obj.unknown && obj.unknown.length){
    for (const u of obj.unknown){
      res.push({ key: u.key>>>0, value: (u.value instanceof Uint8Array)? u.value.slice(0) : new Uint8Array(0) });
    }
  }
  // IMPORTANT: SvcParam list MUST be sorted by key code on the wire (RFC 9460 §2.1)
  res.sort((a,b)=> (a.key|0) - (b.key|0));
  return res;
}

// ---- Replaced SVCB/HTTPS encode/decode with structured params ----
function decode_SVCB_HTTPS(buf, off, rdlen){
  const start = off;
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const priority = dv.getUint16(off, false); off += 2;
  const t = decodeName(buf, off); off = t.off;

  // wire params -> raw list
  const params = [], end = start + rdlen;
  while (off + 4 <= end){
    const key  = dv.getUint16(off, false); off += 2;
    const vlen = dv.getUint16(off, false); off += 2;
    if (off + vlen > end) throw new Error('SVCB param overflow');
    const val = buf.slice(off, off+vlen); off += vlen;
    params.push({ key, value: val });
  }
  if (off !== end) throw new Error('SVCB trailing bytes');

  const parsed = parseSvcParams(params);
  return {
    value: {
      priority: priority,
      targetName: t.name,
      params: params,                 // raw list [{key,value}]
      paramsStructured: parsed        // nice object as described above
    },
    bytes: rdlen
  };
}

function encode_SVCB_HTTPS(v){
  // Accept either raw params (v.params) or structured (v.paramsStructured), or both.
  // If both provided, merge: structured takes precedence on known keys; unknown keys from raw are preserved.
  let raw = Array.isArray(v.params) ? v.params.map(p => ({ key: p.key>>>0, value: (p.value||new Uint8Array(0)).slice(0) })) : [];
  const structured = v.paramsStructured ? buildSvcParams(v.paramsStructured) : [];

  // merge by key: prefer structured for duplicated keys
  const byKey = new Map();
  for (const p of raw){ if (!byKey.has(p.key)) byKey.set(p.key, p); }
  for (const p of structured){ byKey.set(p.key, p); }

  const merged = Array.from(byKey.values()).sort((a,b)=> (a.key|0)-(b.key|0));

  // head (priority) + TargetName + params
  const head = new Uint8Array(2); new DataView(head.buffer).setUint16(0, (v.priority|0)>>>0, false);
  const nameBuf = new Uint8Array(512); let noff = 0; noff = encodeName(nameBuf, noff, v.targetName || '.', {});
  // size params
  let plen = 0;
  for (const p of merged) plen += 4 + (p.value ? p.value.length : 0);
  const pout = new Uint8Array(plen); const pdv = new DataView(pout.buffer); let po=0;
  for (const p of merged){
    const val = p.value || new Uint8Array(0);
    pdv.setUint16(po, (p.key|0)>>>0, false); po+=2;
    pdv.setUint16(po, val.length>>>0, false); po+=2;
    pout.set(val, po); po+=val.length;
  }
  const out = new Uint8Array(head.length + noff + pout.length);
  out.set(head, 0);
  out.set(nameBuf.slice(0,noff), head.length);
  out.set(pout, head.length + noff);
  return out;
}


// === SVCB / HTTPS (minimal, כמו ב‑RFC): priority(u16), targetName(NAME), params list (key,u16; length,u16; value[...]) ===

types.SVCB.decode = decode_SVCB_HTTPS; 
types.SVCB.encode = encode_SVCB_HTTPS;
types.HTTPS.decode = decode_SVCB_HTTPS; 
types.HTTPS.encode = encode_SVCB_HTTPS;

// CERT (RFC 4398)
types.CERT.decode = function(buf, off, rdlen){ var s=off, dv=dvFrom(buf); var ctype=readU16(dv,off); off+=2; var keyTag=readU16(dv,off); off+=2; var alg=buf[off++]; var cert=buf.slice(off, s+rdlen); return { value:{ certType:ctype, keyTag:keyTag, algorithm:alg, certificate:cert }, bytes: rdlen}; };
types.CERT.encode = function(v){ var cert=v.certificate||new Uint8Array(0); var out=new Uint8Array(2+2+1+cert.length), dv=new DataView(out.buffer), o=0; o=writeU16(dv,o,v.certType|0); o=writeU16(dv,o,v.keyTag|0); out[o++]=v.algorithm|0; out.set(cert,o); return out; };

// URI (RFC 7553)
types.URI.decode = function(buf, off, rdlen){ var s=off, dv=dvFrom(buf); var pr=readU16(dv,off); off+=2; var wt=readU16(dv,off); off+=2; var data=buf.slice(off, s+rdlen); var target=decText(data,0,data.length); return { value:{ priority:pr, weight:wt, target:target }, bytes: rdlen}; };
types.URI.encode = function(v){ var t=(typeof v.target==="string")?encText(v.target):(v.target||new Uint8Array(0)); var out=new Uint8Array(4+t.length), dv=new DataView(out.buffer); writeU16(dv,0,v.priority|0); writeU16(dv,2,v.weight|0); out.set(t,4); return out; };

// CAA (RFC 6844/8659)
types.CAA.decode = function(buf, off, rdlen){ var s=off; var flags=buf[off++]; var taglen=buf[off++]; var tag=decText(buf,off,off+taglen); off+=taglen; var val=decText(buf,off,s+rdlen); return { value:{ flags:flags, tag:tag, value:val }, bytes: rdlen}; };
types.CAA.encode = function(v){ var tag=encText(v.tag||""); var val=(typeof v.value==="string")?encText(v.value):(v.value||new Uint8Array(0)); var out=new Uint8Array(1+1+tag.length+val.length), i=0; out[i++]=v.flags|0; out[i++]=tag.length&0xff; out.set(tag,i); i+=tag.length; out.set(val,i); return out; };

// OPENPGPKEY (RFC 7929)
types.OPENPGPKEY.decode = function(buf, off, rdlen){ return { value:{ key: buf.slice(off, off+rdlen) }, bytes: rdlen }; };
types.OPENPGPKEY.encode = function(v){ var k=v.key||new Uint8Array(0); var out=new Uint8Array(k.length); out.set(k); return out; };

// EUI48 / EUI64
types.EUI48.decode = function(buf, off, rdlen){ if (rdlen!==6) throw new Error('EUI48 len'); return { value:{ address: buf.slice(off,off+6) }, bytes: 6 }; };
types.EUI48.encode = function(v){ var a=v.address||new Uint8Array(6); if (a.length!==6) throw new Error('EUI48 need 6'); var out=new Uint8Array(6); out.set(a.slice(0,6)); return out; };
types.EUI64.decode = function(buf, off, rdlen){ if (rdlen!==8) throw new Error('EUI64 len'); return { value:{ address: buf.slice(off,off+8) }, bytes: 8 }; };
types.EUI64.encode = function(v){ var a=v.address||new Uint8Array(8); if (a.length!==8) throw new Error('EUI64 need 8'); var out=new Uint8Array(8); out.set(a.slice(0,8)); return out; };

// DHCID (RFC 4701) — opaque
types.DHCID.decode = function(buf, off, rdlen){ return { value:{ data: buf.slice(off, off+rdlen) }, bytes: rdlen }; };
types.DHCID.encode = function(v){ var d=v.data||new Uint8Array(0); var out=new Uint8Array(d.length); out.set(d); return out; };

// LOC (RFC 1876) — version,u8; size,horz,vert (nibbles); latitude,longitude,altitude (32bit each)
// We expose raw fields; conversion to human format can be implemented externally.
function readLocNibbles(x){ return { mant: (x>>>4)&0x0f, exp: x&0x0f }; }
function writeLocNibbles(mant, exp){ return ((mant&0x0f)<<4) | (exp&0x0f); }
types.LOC.decode = function(buf, off, rdlen){ var dv=dvFrom(buf); if (rdlen!==16) throw new Error('LOC len'); var version=buf[off++]; if (version!==0) {/*still accept*/} var size=buf[off++], horiz=buf[off++], vert=buf[off++]; var lat=readU32(dv,off); off+=4; var lon=readU32(dv,off); off+=4; var alt=readU32(dv,off); off+=4; return { value:{ version:version, size:readLocNibbles(size), horizontal:readLocNibbles(horiz), vertical:readLocNibbles(vert), latitude:lat>>>0, longitude:lon>>>0, altitude:alt>>>0 }, bytes: 16 };
};
types.LOC.encode = function(v){ var out=new Uint8Array(16); var dv=new DataView(out.buffer); var o=0; out[o++]=v.version==null?0:(v.version|0); out[o++]=writeLocNibbles(v.size?.mant||0, v.size?.exp||0); out[o++]=writeLocNibbles(v.horizontal?.mant||0, v.horizontal?.exp||0); out[o++]=writeLocNibbles(v.vertical?.mant||0, v.vertical?.exp||0); o=writeU32(dv,o,(v.latitude>>>0)||0); o=writeU32(dv,o,(v.longitude>>>0)||0); o=writeU32(dv,o,(v.altitude>>>0)||0); return out; };

// NXT (RFC 2535, obsolete) — next(NAME), type bitmap
types.NXT.decode = function(buf, off, rdlen){ var s=off; var n=decodeName(buf,off); off=n.off; var bitmap = buf.slice(off, s+rdlen); return { value:{ next:n.name, bitmap:bitmap }, bytes: rdlen }; };
types.NXT.encode = function(v){ var tmp=new Uint8Array(512), off=0; off=encodeName(tmp,off,v.next||'.'); var bm=v.bitmap||new Uint8Array(0); var out=new Uint8Array(off+bm.length); out.set(tmp.slice(0,off),0); out.set(bm,off); return out; };

// A6 (RFC 2874, obsolete) — prefixLen(u8), address suffix (ceil((128-prefix)/8)), prefix(NAME)
types.A6.decode = function(buf, off, rdlen){ var s=off; var prefix=buf[off++]; var sufBytes = Math.ceil((128-prefix)/8); if (prefix>128) throw new Error('A6 prefix'); var suffix = buf.slice(off, off+sufBytes); off+=sufBytes; var n=decodeName(buf,off); off=n.off; if (off-s!==rdlen) throw new Error('A6 len'); return { value:{ prefixLength:prefix, suffix:suffix, prefixName:n.name }, bytes: rdlen }; };
types.A6.encode = function(v){ var prefix=v.prefixLength|0; var suf=v.suffix||new Uint8Array(0); var tmp=new Uint8Array(512), off=0; tmp[off++]=prefix&0xff; var need=Math.ceil((128-prefix)/8); if (suf.length!==need) throw new Error('A6 suffix len'); tmp.set(suf, off); off+=suf.length; off=encodeName(tmp,off,v.prefixName||'.'); return tmp.slice(0,off); };

// APL (RFC 3123) — list of (family,u16; prefix,u8; neg,afdlen+addr)
types.APL.decode = function(buf, off, rdlen){ var s=off, end=off+rdlen, dv=dvFrom(buf), items=[]; while(off<end){ var fam=readU16(dv,off); off+=2; var prefix=buf[off++]; var blen=buf[off++]; var neg = !!(blen & 0x80); var afdlen = blen & 0x7f; if (off+afdlen> end) throw new Error('APL overflow'); var addr = buf.slice(off, off+afdlen); off += afdlen; items.push({ family:fam, prefix:prefix, neg:neg, address:addr }); } return { value:{ items:items }, bytes: rdlen };
};
types.APL.encode = function(v){ var items=v.items||[]; var parts=[]; var total=0; for (var i=0;i<items.length;i++){ var it=items[i]; var afd=it.address||new Uint8Array(0); var len=2+1+1+afd.length; total+=len; parts.push({it:it, afd:afd, len:len}); } var out=new Uint8Array(total), dv=new DataView(out.buffer), o=0; for (var j=0;j<parts.length;j++){ var p=parts[j], it=p.it; o=writeU16(dv,o,it.family|0); out[o++]=it.prefix|0; out[o++]=((it.neg?0x80:0) | (p.afd.length & 0x7f)) & 0xff; out.set(p.afd,o); o+=p.afd.length; } return out; };

// IPSECKEY (RFC 4025)
// precedence(u8), gatewayType(u8), algorithm(u8), gateway(variant), publicKey
// gatewayType: 0=none,1=IPv4(4b),2=IPv6(16b),3=NAME
types.IPSECKEY.decode = function(buf, off, rdlen){ var s=off; var prec=buf[off++]; var gwt=buf[off++]; var alg=buf[off++]; var gateway=null; if (gwt===0){ gateway=null; } else if (gwt===1){ gateway=buf.slice(off, off+4); off+=4; } else if (gwt===2){ gateway=buf.slice(off, off+16); off+=16; } else if (gwt===3){ var n=decodeName(buf,off); off=n.off; gateway=n.name; } else { throw new Error('IPSECKEY gwt'); } var pub = buf.slice(off, s+rdlen); return { value:{ precedence:prec, gatewayType:gwt, algorithm:alg, gateway:gateway, publicKey:pub }, bytes: rdlen };
};
types.IPSECKEY.encode = function(v){ var head=new Uint8Array(3); head[0]=v.precedence|0; head[1]=v.gatewayType|0; head[2]=v.algorithm|0; var tail; if (v.gatewayType===0){ tail=new Uint8Array(0); } else if (v.gatewayType===1){ if (!(v.gateway instanceof Uint8Array) || v.gateway.length!==4) throw new Error('IPSECKEY IPv4'); tail=v.gateway.slice(0,4); } else if (v.gatewayType===2){ if (!(v.gateway instanceof Uint8Array) || v.gateway.length!==16) throw new Error('IPSECKEY IPv6'); tail=v.gateway.slice(0,16); } else if (v.gatewayType===3){ var t=new Uint8Array(512); var o=encodeName(t,0,v.gateway||'.'); tail=t.slice(0,o); } else { tail=new Uint8Array(0); } var pk=v.publicKey||new Uint8Array(0); var out=new Uint8Array(head.length+tail.length+pk.length); out.set(head,0); out.set(tail,head.length); out.set(pk, head.length+tail.length); return out; };

// NSEC (RFC 4034) — next DOMAIN + Type Bitmaps
function decodeTypeBitmaps(buf, off, end){
  var typesArr = [];
  while (off < end){
    var block = buf[off++], blen = buf[off++];
    if (blen === 0 || off + blen > end) throw new Error('bitmap overflow');
    for (var i=0;i<blen;i++){
      var byte = buf[off+i];
      for (var bit=0; bit<8; bit++){
        if (byte & (0x80>>bit)){
          var t = block*256 + i*8 + bit;
          typesArr.push(t);
        }
      }
    }
    off += blen;
  }
  return { types: typesArr, off: off };
}
function encodeTypeBitmaps(typeCodes){
  typeCodes = Array.from(new Set(typeCodes)).sort(function(a,b){return a-b;});
  if (!typeCodes.length) return new Uint8Array(0);
  var blocks = {};
  for (var i=0;i<typeCodes.length;i++){
    var t=typeCodes[i], blk=(t/256)|0, pos=t%256, idx=(pos/8)|0, bit=pos%8;
    var arr = blocks[blk] || (blocks[blk]=[]);
    arr[idx] = (arr[idx]||0) | (0x80>>bit);
  }
  var parts=[], total=0;
  Object.keys(blocks).sort(function(a,b){return a-b;}).forEach(function(k){
    var blk = +k, arr = blocks[blk], last = arr.length-1;
    while (last>=0 && !arr[last]) last--;
    var len = Math.max(0, last+1);
    var seg = new Uint8Array(2+len);
    seg[0]=blk&0xff; seg[1]=len&0xff;
    for (var j=0;j<len;j++) seg[2+j] = arr[j]||0;
    parts.push(seg); total+=seg.length;
  });
  var out=new Uint8Array(total), o=0; for (var p=0;p<parts.length;p++){ out.set(parts[p],o); o+=parts[p].length; }
  return out;
}

types.NSEC.decode = function(buf, off, rdlen){ var s=off; var n=decodeName(buf,off); off=n.off; var bm = decodeTypeBitmaps(buf, off, s+rdlen); off=bm.off; if (off!==s+rdlen) throw new Error('NSEC trailing'); return { value:{ nextDomainName:n.name, types: bm.types }, bytes: rdlen };
};
types.NSEC.encode = function(v){ var tmp=new Uint8Array(512), off=0; off=encodeName(tmp,off,v.nextDomainName||'.'); var bm=encodeTypeBitmaps(v.types||[]); var out=new Uint8Array(off+bm.length); out.set(tmp.slice(0,off),0); out.set(bm,off); return out; };

// NSEC3 / NSEC3PARAM (RFC 5155)
// NSEC3: hashAlg,u8; flags,u8; iterations,u16; saltLen,u8; salt[..]; hashLen,u8; nextHashedOwnerName[..]; type bitmaps
// We leave hashed fields as raw bytes.
types.NSEC3.decode = function(buf, off, rdlen){ var s=off, dv=dvFrom(buf); var alg=buf[off++]; var flags=buf[off++]; var iter=readU16(dv,off); off+=2; var sl=buf[off++]; var salt=buf.slice(off, off+sl); off+=sl; var hl=buf[off++]; var next=buf.slice(off, off+hl); off+=hl; var bm=decodeTypeBitmaps(buf, off, s+rdlen); off=bm.off; if (off!==s+rdlen) throw new Error('NSEC3 trailing'); return { value:{ hashAlgorithm:alg, flags:flags, iterations:iter, salt:salt, nextHashedOwnerName:next, types:bm.types }, bytes: rdlen };
};
types.NSEC3.encode = function(v){ var salt=v.salt||new Uint8Array(0); var next=v.nextHashedOwnerName||new Uint8Array(0); var bm=encodeTypeBitmaps(v.types||[]); var out=new Uint8Array(1+1+2+1+salt.length+1+next.length+bm.length); var dv=new DataView(out.buffer); var o=0; out[o++]=v.hashAlgorithm|0; out[o++]=v.flags|0; o=writeU16(dv,o,v.iterations|0); out[o++]=salt.length&0xff; out.set(salt,o); o+=salt.length; out[o++]=next.length&0xff; out.set(next,o); o+=next.length; out.set(bm,o); return out; };

types.NSEC3PARAM.decode = function(buf, off, rdlen){ var dv=dvFrom(buf); var alg=buf[off++]; var flags=buf[off++]; var iter=readU16(dv,off); off+=2; var sl=buf[off++]; var salt=buf.slice(off, off+sl); return { value:{ hashAlgorithm:alg, flags:flags, iterations:iter, salt:salt }, bytes: rdlen };
};
types.NSEC3PARAM.encode = function(v){ var salt=v.salt||new Uint8Array(0); var out=new Uint8Array(1+1+2+1+salt.length); var dv=new DataView(out.buffer); var o=0; out[o++]=v.hashAlgorithm|0; out[o++]=v.flags|0; o=writeU16(dv,o,v.iterations|0); out[o++]=salt.length&0xff; out.set(salt,o); return out; };

// HIP (RFC 8005) — hitLength,u8; pkAlg,u8; pkLength,u16; HIT[..]; PublicKey[..]; rendezvousServers: sequence of NAMEs
types.HIP.decode = function(buf, off, rdlen){ var s=off, dv=dvFrom(buf); var hl=buf[off++]; var alg=buf[off++]; var pkl=readU16(dv,off); off+=2; var hit=buf.slice(off, off+hl); off+=hl; var pk=buf.slice(off, off+pkl); off+=pkl; var servers=[]; while(off < s+rdlen){ var n=decodeName(buf,off); off=n.off; servers.push(n.name); } return { value:{ algorithm:alg, hit:hit, publicKey:pk, servers:servers }, bytes: rdlen };
};
types.HIP.encode = function(v){ var hit=v.hit||new Uint8Array(0); var pk=v.publicKey||new Uint8Array(0); var names=v.servers||[]; var size=1+1+2+hit.length+pk.length; var tmp=new Uint8Array(1024), off=0; for (var i=0;i<names.length;i++){ off=encodeName(tmp,off,names[i]||'.'); }
  var tail=tmp.slice(0,off);
  var out=new Uint8Array(size+tail.length); var dv=new DataView(out.buffer); var o=0; out[o++]=hit.length&0xff; out[o++]=v.algorithm|0; o=writeU16(dv,o,pk.length); out.set(hit,o); o+=hit.length; out.set(pk,o); o+=pk.length; out.set(tail,o); return out; };

// TKEY (RFC 2930) — algorithm(NAME), inception(u32), expiration(u32), mode(u16), error(u16), keyLen(u16), key[..], otherLen(u16), other[..]
types.TKEY.decode = function(buf, off, rdlen){ var s=off, dv=dvFrom(buf); var alg=decodeName(buf,off); off=alg.off; var inc=readU32(dv,off); off+=4; var exp=readU32(dv,off); off+=4; var mode=readU16(dv,off); off+=2; var err=readU16(dv,off); off+=2; var klen=readU16(dv,off); off+=2; var key=buf.slice(off, off+klen); off+=klen; var olen=readU16(dv,off); off+=2; var other=buf.slice(off, off+olen); off+=olen; if (off-s!==rdlen) throw new Error('TKEY len'); return { value:{ algorithm:alg.name, inception:inc, expiration:exp, mode:mode, error:err, key:key, other:other }, bytes: rdlen };
};
types.TKEY.encode = function(v){ var t=new Uint8Array(512), o=0; o=encodeName(t,o,v.algorithm||'.'); var key=v.key||new Uint8Array(0); var other=v.other||new Uint8Array(0); var out=new Uint8Array(o + 4+4+2+2 + 2+key.length + 2+other.length); var dv=new DataView(out.buffer); var p=0; out.set(t.slice(0,o), p); p+=o; p=writeU32(dv,p,v.inception|0); p=writeU32(dv,p,v.expiration|0); p=writeU16(dv,p,v.mode|0); p=writeU16(dv,p,v.error|0); p=writeU16(dv,p,key.length); out.set(key,p); p+=key.length; p=writeU16(dv,p,other.length); out.set(other,p); return out; };

// TSIG (RFC 8945) — algorithm(NAME), timeSigned(u48), fudge(u16), MAC size(u16), MAC[..], origId(u16), error(u16), otherLen(u16), otherData[..]
types.TSIG.decode = function(buf, off, rdlen){ var s=off, dv=dvFrom(buf); var alg=decodeName(buf,off); off=alg.off; var tHigh=readU16(dv,off); off+=2; var tLow=readU32(dv,off); off+=4; var fudge=readU16(dv,off); off+=2; var macLen=readU16(dv,off); off+=2; var mac=buf.slice(off, off+macLen); off+=macLen; var origId=readU16(dv,off); off+=2; var err=readU16(dv,off); off+=2; var otherLen=readU16(dv,off); off+=2; var other=buf.slice(off, off+otherLen); off+=otherLen; if (off-s!==rdlen) throw new Error('TSIG len'); return { value:{ algorithm:alg.name, timeSignedHigh:tHigh, timeSignedLow:tLow, fudge:fudge, mac:mac, originalId:origId, error:err, otherData:other }, bytes: rdlen };
};
types.TSIG.encode = function(v){ var t=new Uint8Array(512), o=0; o=encodeName(t,o,v.algorithm||'.'); var mac=v.mac||new Uint8Array(0); var other=v.otherData||new Uint8Array(0); var out=new Uint8Array(o + 2+4+2 + 2+mac.length + 2+2 + 2+other.length); var dv=new DataView(out.buffer); var p=0; out.set(t.slice(0,o), p); p+=o; p=writeU16(dv,p,(v.timeSignedHigh|0)&0xffff); p=writeU32(dv,p,(v.timeSignedLow|0)>>>0); p=writeU16(dv,p,v.fudge|0); p=writeU16(dv,p,mac.length); out.set(mac,p); p+=mac.length; p=writeU16(dv,p,v.originalId|0); p=writeU16(dv,p,v.error|0); p=writeU16(dv,p,other.length); out.set(other,p); return out; };

// NID / L32 / L64 / LP (RFC 6742)
types.NID.decode = function(buf, off, rdlen){ var dv=dvFrom(buf); if (rdlen!==10) throw new Error('NID len'); var pref=readU16(dv,off); off+=2; var nidHigh=readU32(dv,off); off+=4; var nidLow=readU32(dv,off); off+=4; return { value:{ preference:pref, nodeIdHigh:nidHigh, nodeIdLow:nidLow }, bytes: rdlen };
};
types.NID.encode = function(v){ var out=new Uint8Array(10); var dv=new DataView(out.buffer); writeU16(dv,0,v.preference|0); writeU32(dv,2,v.nodeIdHigh>>>0); writeU32(dv,6,v.nodeIdLow>>>0); return out; };



// === RAW pass-through: EID, NIMLOC, ATMA, SINK, NINFO, RKEY, TALINK ===
['EID','NIMLOC','ATMA','SINK','NINFO','RKEY','TALINK'].forEach(function(t){
  types[t] = {
    decode: function(buf, off, rdlen){
      return { value: { raw: buf.slice(off, off+rdlen) }, bytes: rdlen };
    },
    encode: function(v){
      var d = (v && v.raw) ? v.raw : new Uint8Array(0);
      var out = new Uint8Array(d.length); out.set(d); return out;
    }
  };
});

// === KX (RFC 2230): preference(u16) + exchanger(NAME) ===
types.KX = {
  decode: function(buf, off, rdlen){
    var start = off;
    var dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    var pref = dv.getUint16(off, false); off += 2;
    var n = decodeName(buf, off); off = n.off;
    if (off - start !== rdlen) throw new Error('KX length mismatch');
    return { value: { preference: pref, exchanger: n.name }, bytes: rdlen };
  },
  encode: function(v){
    var tmp = new Uint8Array(512), dv = new DataView(tmp.buffer), o = 0;
    dv.setUint16(o, (v.preference|0)>>>0, false); o += 2;
    o = encodeName(tmp, o, v.exchanger || '.', {});
    return tmp.slice(0, o);
  }
};


// === CSYNC (RFC 7477): SOA serial(u32), flags(u16), type bitmaps ===

types.CSYNC = {
  decode: function(buf, off, rdlen){
    var start = off;
    var dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    var serial = dv.getUint32(off, false); off += 4;
    var flags  = dv.getUint16(off, false); off += 2;
    var bm = decodeTypeBitmaps(buf, off, start+rdlen); off = bm.off;
    if (off !== start+rdlen) throw new Error('CSYNC trailing bytes');
    return { value: { serial:serial, flags:flags, types: bm.types }, bytes: rdlen };
  },
  encode: function(v){
    var bm = encodeTypeBitmaps(v.types||[]);
    var out = new Uint8Array(6 + bm.length);
    var dv  = new DataView(out.buffer);
    dv.setUint32(0, (v.serial>>>0), false);
    dv.setUint16(4, (v.flags|0)>>>0, false);
    out.set(bm, 6);
    return out;
  }
};

// === ZONEMD (RFC 8976): scheme(u8), hashAlg(u8), digest[...] ===
types.ZONEMD = {
  decode: function(buf, off, rdlen){
    if (rdlen < 2) throw new Error('ZONEMD short');
    var scheme = buf[off++], alg = buf[off++];
    var dig = buf.slice(off, off + (rdlen-2));
    return { value: { scheme:scheme, hashAlgorithm:alg, digest:dig }, bytes: rdlen };
  },
  encode: function(v){
    var d = v.digest || new Uint8Array(0);
    var out = new Uint8Array(2 + d.length);
    out[0]=v.scheme|0; out[1]=v.hashAlgorithm|0;
    out.set(d, 2);
    return out;
  }
};


// === L32 / L64 / LP (RFC 6742) ===
types.L32 = {
  decode: function(buf, off, rdlen){
    if (rdlen !== 6) throw new Error('L32 len');
    var dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    var pref = dv.getUint16(off, false); off += 2;
    var a = buf[off]+'.'+buf[off+1]+'.'+buf[off+2]+'.'+buf[off+3];
    return { value:{ preference:pref, locator32:a }, bytes: rdlen };
  },
  encode: function(v){
    var out = new Uint8Array(6), dv = new DataView(out.buffer);
    var p = String(v.locator32||'0.0.0.0').split('.');
    dv.setUint16(0, (v.preference|0)>>>0, false);
    out[2]=p[0]|0; out[3]=p[1]|0; out[4]=p[2]|0; out[5]=p[3]|0;
    return out;
  }
};
types.L64 = {
  decode: function(buf, off, rdlen){
    if (rdlen !== 10) throw new Error('L64 len');
    var dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    var pref = dv.getUint16(off, false); off += 2;
    var high = dv.getUint32(off, false); off += 4;
    var low  = dv.getUint32(off, false); off += 4;
    return { value: { preference:pref, locator64High:high, locator64Low:low }, bytes: rdlen };
  },
  encode: function(v){
    var out = new Uint8Array(10), dv = new DataView(out.buffer);
    dv.setUint16(0, (v.preference|0)>>>0, false);
    dv.setUint32(2, (v.locator64High>>>0), false);
    dv.setUint32(6, (v.locator64Low>>>0),  false);
    return out;
  }
};
types.LP = {
  decode: function(buf, off, rdlen){
    var start = off;
    var dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    var pref = dv.getUint16(off, false); off += 2;
    var n = decodeName(buf, off); off = n.off;
    if (off - start !== rdlen) throw new Error('LP len');
    return { value: { preference:pref, fqdn:n.name }, bytes: rdlen };
  },
  encode: function(v){
    var tmp = new Uint8Array(512), dv = new DataView(tmp.buffer), o = 0;
    dv.setUint16(o, (v.preference|0)>>>0, false); o += 2;
    o = encodeName(tmp, o, v.fqdn || '.', {});
    return tmp.slice(0, o);
  }
};

// === IXFR / AXFR / ANY — טיפוסי שאילתה. כרשומות (RR) אין לרוב RDATA. נשמור RAW round-trip. ===
['IXFR','AXFR','ANY'].forEach(function(t){
  types[t] = {
    decode: function(buf, off, rdlen){
      // ברוב המקרים rdlen==0; נשמר בכל זאת את הנתונים אם קיימים
      return { value: { raw: buf.slice(off, off+rdlen) }, bytes: rdlen };
    },
    encode: function(v){
      var d = (v && v.raw) ? v.raw : new Uint8Array(0);
      var out = new Uint8Array(d.length); out.set(d); return out;
    }
  };
});










// === EDNS options decoders/encoders (structured) ===
function parseEDNSOptions(list){
  const out = {
    raw: list.slice(0),           // תמיד נשמור raw
    nsid: undefined,              // Uint8Array
    dau: undefined,               // number[] (alg IDs)
    dhu: undefined,               // number[] (DS hash alg IDs)
    n3u: undefined,               // number[] (NSEC3 hash alg IDs)
    ecs: undefined,               // { family, sourcePrefixLength, scopePrefixLength, addressBytes(Uint8Array) }
    expire: undefined,            // number (u32 seconds)
    cookie: undefined,            // { client(Uint8Array>=8), server?(Uint8Array) }
    keepalive: undefined,         // { timeoutUnits100ms:number }  // units of 100ms (RFC 7828)
    padding: undefined,           // Uint8Array (usually zeros)
    keyTag: undefined,            // number[] (u16 list)
    ede: undefined,               // array of { infoCode:number, extraText?:string, extraData?:Uint8Array }
    unknown: []                   // {code,data}
  };

  const td = new TextDecoder('utf-8');

  for (const op of list){
    const code = op.code>>>0;
    const data = op.data || new Uint8Array(0);
    const dv = dvFrom(data);

    switch(code){
      case EDNS_OPT.NSID:
        out.nsid = data.slice(0);
        break;

      case EDNS_OPT.DAU:
        out.dau = Array.from(data); // RFC 6975: רצף בתים, כל בית=מס' אלגוריתם
        break;

      case EDNS_OPT.DHU:
        out.dhu = Array.from(data); // RFC 6975
        break;

      case EDNS_OPT.N3U:
        out.n3u = Array.from(data); // RFC 6975
        break;

      case EDNS_OPT.ECS: {        // RFC 7871 §6
        if (data.length < 4) { out.unknown.push({code, data:data.slice(0)}); break; }
        const family = dv.getUint16(0,false);
        const src = data[2], scp = data[3];
        const n = Math.ceil(src/8);
        if (data.length < 4+n) { out.unknown.push({code, data:data.slice(0)}); break; }
        const addr = data.slice(4, 4+n);
        out.ecs = { family, sourcePrefixLength:src, scopePrefixLength:scp, addressBytes:addr };
        break;
      }

      case EDNS_OPT.EXPIRE:       // RFC 7314 §3: length 0 in query, 4 in response
        if (data.length === 4) out.expire = dv.getUint32(0,false);
        else if (data.length !== 0) out.unknown.push({code, data:data.slice(0)});
        break;

      case EDNS_OPT.COOKIE: {     // RFC 7873: client cookie = 8 bytes (min), server cookie optional
        if (data.length >= 8){
          out.cookie = { client: data.slice(0,8), server: (data.length>8 ? data.slice(8) : undefined) };
        } else {
          out.unknown.push({code, data:data.slice(0)});
        }
        break;
      }

      case EDNS_OPT.KEEPALIVE:    // RFC 7828 §3.1: length 0 in queries; 2 (timeout in 100ms) in responses
        if (data.length === 0) out.keepalive = { timeoutUnits100ms: undefined };
        else if (data.length === 2) out.keepalive = { timeoutUnits100ms: dv.getUint16(0,false) };
        else out.unknown.push({code, data:data.slice(0)});
        break;

      case EDNS_OPT.PADDING:      // RFC 7830: arbitrary bytes, typically zeroes
        out.padding = data.slice(0);
        break;

      case EDNS_OPT.CHAIN:        // RFC 7901: נשאיר RAW (פורמט מורכב)
        out.unknown.push({code, data:data.slice(0)});
        break;

      case EDNS_OPT.KEYTAG: {     // RFC 8145 §4.1: רצף של u16 Key Tags
        if ((data.length % 2) !== 0) { out.unknown.push({code, data:data.slice(0)}); break; }
        const arr = [];
        for (let i=0;i<data.length;i+=2) arr.push(dv.getUint16(i,false));
        out.keyTag = arr;
        break;
      }

      case EDNS_OPT.EDE: {        // RFC 8914: series; each field is one sub‑option (info‑code u16 + optional text)
        // RDATA may contain multiple EDE fields concatenated
        let i = 0; const items = [];
        while (i + 2 <= data.length){
          const info = dv.getUint16(i,false); i += 2;
          // השאר זה extra‑text אופציונלי (UTF‑8). מותר גם 0 אורך.
          const extra = data.slice(i); // עד סוף ה‑option (אין length פנימי נוסף)
          const text = extra.length ? td.decode(extra) : undefined;
          items.push( text !== undefined ? { infoCode:info, extraText:text } : { infoCode:info } );
          // RFC 8914 מגדיר שכל EDE הוא *option נפרד*, אבל בפועל חלק מהמימושים מחברים כמה בתוך אותו option.
          // אנו מתייחסים לכל יתר ה‑bytes כרשומה אחת; אם יש צורך לתמוך בכמה—פצל מחוץ לקוד זה לפי מדיניותך.
          i = data.length; // אחד בכל option
        }
        out.ede = (out.ede || []).concat(items);
        break;
      }

      default:
        out.unknown.push({ code, data: data.slice(0) });
    }
  }

  return out;
}

function buildEDNSOptions(obj){
  const te = new TextEncoder();
  const out = [];

  if (obj?.nsid instanceof Uint8Array)
    out.push({ code: EDNS_OPT.NSID, data: obj.nsid.slice(0) });

  if (Array.isArray(obj?.dau))
    out.push({ code: EDNS_OPT.DAU, data: new Uint8Array(obj.dau.map(x=>x&0xFF)) });

  if (Array.isArray(obj?.dhu))
    out.push({ code: EDNS_OPT.DHU, data: new Uint8Array(obj.dhu.map(x=>x&0xFF)) });

  if (Array.isArray(obj?.n3u))
    out.push({ code: EDNS_OPT.N3U, data: new Uint8Array(obj.n3u.map(x=>x&0xFF)) });

  if (obj?.ecs){
    const e = obj.ecs;
    const bytes = Math.ceil((e.sourcePrefixLength|0)/8);
    if (!(e.addressBytes instanceof Uint8Array) || e.addressBytes.length !== bytes)
      throw new Error('ECS.addressBytes length mismatch');
    const payload = new Uint8Array(4 + bytes);
    const dv = dvFrom(payload);
    dv.setUint16(0, (e.family|0)>>>0, false);
    payload[2] = (e.sourcePrefixLength|0)&0xFF;
    payload[3] = (e.scopePrefixLength|0)&0xFF;
    payload.set(e.addressBytes, 4);
    out.push({ code: EDNS_OPT.ECS, data: payload });
  }

  if (typeof obj?.expire === 'number'){
    const payload = new Uint8Array(4);
    dvFrom(payload).setUint32(0, (obj.expire>>>0), false);
    out.push({ code: EDNS_OPT.EXPIRE, data: payload });
  } else if (obj && 'expire' in obj && obj.expire == null){
    out.push({ code: EDNS_OPT.EXPIRE, data: new Uint8Array(0) }); // query-side zero length
  }

  if (obj?.cookie){
    const c = obj.cookie;
    if (!(c.client instanceof Uint8Array) || c.client.length < 8) throw new Error('COOKIE.client must be >= 8 bytes');
    const server = (c.server instanceof Uint8Array) ? c.server : new Uint8Array(0);
    const payload = new Uint8Array(c.client.length + server.length);
    payload.set(c.client, 0);
    payload.set(server, c.client.length);
    out.push({ code: EDNS_OPT.COOKIE, data: payload });
  }

  if (obj?.keepalive){
    const t = obj.keepalive.timeoutUnits100ms;
    if (t == null) out.push({ code: EDNS_OPT.KEEPALIVE, data: new Uint8Array(0) });
    else {
      const payload = new Uint8Array(2); dvFrom(payload).setUint16(0, (t|0)&0xFFFF, false);
      out.push({ code: EDNS_OPT.KEEPALIVE, data: payload });
    }
  }

  if (obj?.padding instanceof Uint8Array)
    out.push({ code: EDNS_OPT.PADDING, data: obj.padding.slice(0) });

  // CHAIN – RAW only
  if (obj?.chain instanceof Uint8Array)
    out.push({ code: EDNS_OPT.CHAIN, data: obj.chain.slice(0) });

  if (Array.isArray(obj?.keyTag)){
    const payload = new Uint8Array(obj.keyTag.length*2);
    const dv = dvFrom(payload);
    for (let i=0;i<obj.keyTag.length;i++) dv.setUint16(i*2, (obj.keyTag[i]>>>0)&0xFFFF, false);
    out.push({ code: EDNS_OPT.KEYTAG, data: payload });
  }

  if (Array.isArray(obj?.ede)){
    for (const e of obj.ede){
      const code = (e.infoCode>>>0)&0xFFFF;
      const text = (e.extraText!=null) ? te.encode(String(e.extraText)) :
                   (e.extraData instanceof Uint8Array ? e.extraData : new Uint8Array(0));
      const payload = new Uint8Array(2 + (text?text.length:0));
      const dv = dvFrom(payload);
      dv.setUint16(0, code, false);
      if (text && text.length) payload.set(text, 2);
      out.push({ code: EDNS_OPT.EDE, data: payload });
    }
  }

  // raw passthrough/unknown
  if (Array.isArray(obj?.unknown)){
    for (const u of obj.unknown){
      out.push({ code: u.code>>>0, data: (u.data instanceof Uint8Array)? u.data.slice(0) : new Uint8Array(0) });
    }
  }

  return out;
}




// ===== Header encode/decode =====
function decodeHeader(buf){
  var dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  var id = dv.getUint16(0,false);
  var flags = dv.getUint16(2,false);
  var qd = dv.getUint16(4,false);
  var an = dv.getUint16(6,false);
  var ns = dv.getUint16(8,false);
  var ar = dv.getUint16(10,false);
  return {
    header: {
      id,
      qr: !!(flags & 0x8000),
      opcode: (flags >> 11) & 0xF,
      aa: !!(flags & 0x0400),
      tc: !!(flags & 0x0200),
      rd: !!(flags & 0x0100),
      ra: !!(flags & 0x0080),
      z:  !!(flags & 0x0040),   // must be 0
      ad: !!(flags & 0x0020),
      cd: !!(flags & 0x0010),
      rcode: flags & 0x000F,
      qdcount: qd, ancount: an, nscount: ns, arcount: ar
    },
    bytes: 12
  };
}
function encodeHeader(h){
  var out = new Uint8Array(12), dv = new DataView(out.buffer);
  var f = 0;
  if (h.qr) f |= 0x8000;
  f |= ((h.opcode|0)&0xF) << 11;
  if (h.aa) f |= 0x0400;
  if (h.tc) f |= 0x0200;
  if (h.rd) f |= 0x0100;
  if (h.ra) f |= 0x0080;
  if (h.z)  f |= 0x0040; // SHOULD be 0
  if (h.ad) f |= 0x0020;
  if (h.cd) f |= 0x0010;
  f |= ((h.rcode|0)&0xF);
  dv.setUint16(0, (h.id|0)&0xFFFF, false);
  dv.setUint16(2, f, false);
  dv.setUint16(4, (h.qdcount|0)&0xFFFF, false);
  dv.setUint16(6, (h.ancount|0)&0xFFFF, false);
  dv.setUint16(8, (h.nscount|0)&0xFFFF, false);
  dv.setUint16(10,(h.arcount|0)&0xFFFF, false);
  return out;
}

// ===== Name compression for message-encode =====
function encodeNameCompressed(out, off, name, dict){
  // normalize to absolute FQDN
  name = String(name||'.');
  if (name === '.') { out[off++] = 0; return off; }
  if (name[name.length-1] !== '.') name += '.';
  // labels
  var labels = name.slice(0,-1).split('.');
  for (var i=0;i<labels.length;i++){
    var suffix = labels.slice(i).join('.') + '.';
    var key = suffix.toLowerCase(); // case-insensitive for compression
    if (dict.hasOwnProperty(key)){
      var ptr = dict[key];
      if (ptr >= 0x4000) throw new Error('bad name ptr');
      out[off++] = 0xC0 | ((ptr >> 8) & 0x3F);
      out[off++] = ptr & 0xFF;
      return off;
    }
    // record position of this suffix
    dict[key] = off;
    var lab = labels[i];
    var lb = new TextEncoder().encode(lab);
    if (lb.length === 0 || lb.length > 63) throw new Error('label len');
    out[off++] = lb.length;
    out.set(lb, off); off += lb.length;
  }
  out[off++] = 0; // root
  return off;
}

// ===== Question encode/decode =====
function decodeQuestion(buf, off){
  var n = decodeName(buf, off); off = n.off;
  var dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  var qtype = dv.getUint16(off, false); off+=2;
  var qclass = dv.getUint16(off, false); off+=2;
  return { value: { name: n.name, type: code_to_type[qtype] || qtype, class: code_to_class[qclass] || qclass }, off };

}
function encodeQuestion(out, off, q, dict){
    off = encodeNameCompressed(out, off, q.name, dict);
    var dv = new DataView(out.buffer);
    const tcode = (typeof q.type  === 'string') ? (type_to_code[q.type]  || 0) : (q.type|0);
    const ccode = (typeof q.class === 'string') ? (class_to_code[q.class]|| 1) : (q.class==null ? 1 : (q.class|0));
    dv.setUint16(off, tcode & 0xFFFF, false); off += 2;
    dv.setUint16(off, ccode & 0xFFFF, false); off += 2;
    return off;
}

// ===== RR encode/decode (with EDNS awareness) =====
function unpackOptTTL(ttl){
  return {
    extRcode: (ttl>>>24)&0xFF,
    version:  (ttl>>>16)&0xFF,
    do:       !!(ttl & 0x00008000),
    z:        ttl & 0x00007FFF
  };
}
function packOptTTL(edns){
  var ttl = ((edns.extRcode|0)&0xFF)<<24;
  ttl |= ((edns.version|0)&0xFF)<<16;
  var flags = (edns.do?0x8000:0) | ((edns.z|0)&0x7FFF);
  ttl |= flags;
  return ttl>>>0;
}

function decodeRR(buf, off){
  var start = off;
  var n = decodeName(buf, off); off = n.off;
  var dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  var typeCode = dv.getUint16(off,false); off+=2;
  var klass = dv.getUint16(off,false);    off+=2;
  var ttl   = dv.getUint32(off,false);    off+=4;
  var rdlen = dv.getUint16(off,false);    off+=2;

  var rdata, edns = null;

    if (typeCode === 41){ // OPT (EDNS)
        var udpSize = klass;
        var x = unpackOptTTL(ttl);
        var optVal = types.OPT.decode(buf, off, rdlen).value; // { options: [...] }
        const optsStructured = parseEDNSOptions(optVal.options);

        rdata = { name: n.name, type: 'OPT', class: udpSize, ttlFields: x, data: optVal };
        edns = {
            udpSize,
            extRcode: x.extRcode,
            version: x.version,
            do: x.do,
            z: x.z,
            options: optVal.options,
            optionsStructured: optsStructured
        };
        off += rdlen;
        return {
            value: { name: n.name, type: 'OPT', class: udpSize, ttl: ttl>>>0, data: rdata, _edns: edns },
            off
        };
    }

    // RR רגיל
    var typeName = code_to_type[typeCode] || typeCode;
    var impl = types[typeName];
    if (!impl || !impl.decode) throw new Error('no decoder for type '+typeName);
    var dec = impl.decode(buf, off, rdlen);
    off += rdlen;

    return {
        value: {
        name: n.name,
        type: typeName,
        class: code_to_class[klass] || klass,  // ← מחזיר כמחרוזת (למשל "IN")
        ttl: ttl>>>0,
        data: dec.value
        },
        off
    };
}

function encodeRR(out, off, rr, dict){
  // rr.type יכול להיות מחרוזת או מספר
  var tcode = (typeof rr.type === 'string') ? (type_to_code[rr.type]||0) : (rr.type|0);
  var dv = new DataView(out.buffer);

  // OPT מיוחד (EDNS)
  if (tcode === 41){
    var edns = rr.edns || rr.data || {};
    var opts = edns.options || (edns.optionsStructured ? buildEDNSOptions(edns.optionsStructured) : []);
    var optData = types.OPT.encode({ options: opts });

    off = encodeNameCompressed(out, off, rr.name==null?'.':rr.name, dict);
    dv.setUint16(off, 41, false); off+=2;
    dv.setUint16(off, (edns.udpSize||1232)&0xFFFF, false); off+=2;
    dv.setUint32(off, packOptTTL({
      extRcode: edns.extRcode||0,
      version:  edns.version||0,
      do:       !!edns.do,
      z:        edns.z||0
    }), false); off+=4;

    var optData = types.OPT.encode({ options: edns.options||[] });
    dv.setUint16(off, optData.length&0xFFFF, false); off+=2;
    out.set(optData, off); off+=optData.length;
    return off;
  }

  // RR רגיל
  off = encodeNameCompressed(out, off, rr.name, dict);
  dv.setUint16(off, tcode & 0xFFFF, false); off+=2;

  // class: מחרוזת ("IN") או מספר (1) — שניהם נתמכים, ברירת מחדל IN
  var ccode = (typeof rr.class === 'string') ? (class_to_code[rr.class]||1)
                                             : (rr.class==null ? 1 : (rr.class|0));
  dv.setUint16(off, ccode & 0xFFFF, false); off+=2;

  dv.setUint32(off, (rr.ttl>>>0), false); off+=4;

  var impl = types[(typeof rr.type==='string')? rr.type : code_to_type[tcode]];
  if (!impl || !impl.encode) throw new Error('no encoder for type '+rr.type);
  var rdata = impl.encode(rr.data||rr);
  dv.setUint16(off, rdata.length&0xFFFF, false); off+=2;
  out.set(rdata, off); off+=rdata.length;
  return off;
}


// ===== Message decode/encode =====
function decodeMessage(buf){
  if (!(buf instanceof Uint8Array)) buf = new Uint8Array(buf);
  var { header:h, bytes } = decodeHeader(buf);
  var off = bytes;
  var questions = [];
  for (var i=0;i<h.qdcount;i++){
    var q = decodeQuestion(buf, off); off = q.off;
    questions.push(q.value);
  }
  var answers = [], authority=[], additionals=[], edns=null;

  function readRRs(n, into){
    for (var i=0;i<n;i++){
      var rr = decodeRR(buf, off); off = rr.off;
      if (rr.value._edns){ edns = rr.value._edns; /* אפשר גם לשמור RR גלם אם רוצים */ }
      into.push({ name: rr.value.name, type: rr.value.type, class: rr.value.class, ttl: rr.value.ttl, data: rr.value.data });
    }
  }
  readRRs(h.ancount, answers);
  readRRs(h.nscount, authority);
  readRRs(h.arcount, additionals);

  return { header: h, questions, answers, authority, additionals, edns };
}

function encodeMessage(msg){
  // נחשב מיידית את המונים
  var qd = (msg.questions||[]).length;
  var an = (msg.answers||[]).length;
  var ns = (msg.authority||[]).length;
  var ar = (msg.additionals||[]).length;
  // אם יש edns נוצר OPT אחד נוסף (אם לא כבר נמצא ב-additionals כ-OPT)
  var hasExplicitOPT = (msg.additionals||[]).some(r => (r.type==='OPT' || r.type===41));
  if (msg.edns && !hasExplicitOPT) ar += 1;

  // נבנה header
  var h = Object.assign({
    id: (Math.random()*0x10000)|0,
    qr:false, opcode:0, aa:false, tc:false, rd:true, ra:false, z:false, ad:false, cd:false, rcode:0,
    qdcount: qd, ancount: an, nscount: ns, arcount: ar
  }, msg.header||{});
  h.qdcount = qd; h.ancount = an; h.nscount = ns; h.arcount = ar;

  // נאחסן ל‑buffer גדול (פשוט) ונחתוך בסוף
  var out = new Uint8Array(65535), off = 0;
  out.set(encodeHeader(h), off); off += 12;

  var dict = {}; // לטובת דחיסת שמות

  // Questions
  for (var i=0;i<qd;i++){
    off = encodeQuestion(out, off, msg.questions[i], dict);
  }
  // Helpers to write RR arrays
  function writeRRArray(arr){
    for (var j=0;j<arr.length;j++){
      off = encodeRR(out, off, arr[j], dict);
    }
  }
  writeRRArray(msg.answers||[]);
  writeRRArray(msg.authority||[]);
  // additionals + implicit EDNS
  var add = msg.additionals ? msg.additionals.slice() : [];
  if (msg.edns && !hasExplicitOPT){
    add.push({ name: '.', type:'OPT', edns: msg.edns });
  }
  writeRRArray(add);

  return out.slice(0, off);
}


//* special ------------------- */
function ensureFqdnLower(s){
  s = String(s || '').trim();
  return (s.endsWith('.') ? s : s + '.').toLowerCase();
}
function encodeNameCanonical(out, off, name){
  // משתמש ב-encodeName שלך (ללא דחיסה), רק דואג ל-lowercase+fqdn
  return encodeName(out, off, ensureFqdnLower(name));
}

// הנמכת שמות בתוך RDATA רק לטיפוסים שיש בהם NAME בשדות (דרישת RFC 4034 §6.2)
function canonicalizeRdataNames(rr){
  const t = typeof rr.type==='string' ? rr.type : code_to_type[rr.type];
  const d = rr.data || rr;
  const x = { ...d };
  const F = ensureFqdnLower;

  switch (t){
    case 'NS': case 'CNAME': case 'PTR': case 'DNAME': x.name = F(d.name); break;
    case 'SOA': x.mname = F(d.mname); x.rname = F(d.rname); break;
    case 'MX': x.exchange = F(d.exchange); break;
    case 'KX': x.exchanger = F(d.exchanger); break;
    case 'AFSDB': x.hostname = F(d.hostname); break;
    case 'LP': x.fqdn = F(d.fqdn); break;
    case 'SRV': x.target = F(d.target); break;
    case 'RP': x.mbox = F(d.mbox); x.txt = F(d.txt); break;
    case 'MINFO': x.rmailbx = F(d.rmailbx); x.emailbx = F(d.emailbx); break;
    case 'HIP': if (Array.isArray(d.servers)) x.servers = d.servers.map(F); break;
    case 'NXT': x.next = F(d.next); break;
    case 'NSEC': x.nextDomainName = F(d.nextDomainName); break;
    case 'TSIG': case 'TKEY': x.algorithm = F(d.algorithm); break;
    case 'SVCB': case 'HTTPS': x.targetName = F(d.targetName); break;
    // אחרים: אין שדות NAME בתוך ה-RDATA
  }
  return x;
}

function encodeRDATACanonical(rr){
  const typeStr = typeof rr.type==='string' ? rr.type : code_to_type[rr.type];
  const enc = types[typeStr] && types[typeStr].encode;
  if (typeof enc !== 'function') throw new Error('no encoder for type '+typeStr);
  return enc(canonicalizeRdataNames(rr));
}

function encodeRRCanonical(rr, originalTTL){
  const typeStr = typeof rr.type==='string' ? rr.type : code_to_type[rr.type];
  const tcode   = typeof rr.type==='string' ? (type_to_code[typeStr]||0) : (rr.type|0);
  const ccode   = typeof rr.class==='string' ? (class_to_code[rr.class]||1) : (rr.class==null?1:(rr.class|0));
  const rdata   = encodeRDATACanonical(rr);

  const nameBuf = new Uint8Array(256);
  const noff = encodeNameCanonical(nameBuf, 0, rr.name);

  const out = new Uint8Array(noff + 10 + rdata.length);
  out.set(nameBuf.slice(0, noff), 0);
  const dv = new DataView(out.buffer);
  let o = noff;
  dv.setUint16(o, tcode & 0xFFFF, false); o+=2;
  dv.setUint16(o, ccode & 0xFFFF, false); o+=2;
  dv.setUint32(o, (originalTTL|0)>>>0,  false); o+=4;   // חשוב: TTL אחיד ל-RRset
  dv.setUint16(o, rdata.length & 0xFFFF, false); o+=2;
  out.set(rdata, o);
  return { rdata, full: out };
}

// === הפונקציה שביקשת: answers -> rrsetBytes מוכן לחתימה ===
function buildRRsetBytesFromAnswers(answers){
  if (!Array.isArray(answers) || answers.length === 0) return new Uint8Array(0);

  const owner = ensureFqdnLower(answers[0].name);
  const type0 = typeof answers[0].type==='string' ? answers[0].type.toUpperCase() : answers[0].type;
  const cls0  = answers[0].class || 'IN';
  const ttl0  = answers[0].ttl;

  // קידוד קאנוני לכל RR, ומיון לפי RDATA קאנוני (RFC 4034 §6)
  const items = answers.map(rr => {
    const rrn = { ...rr, name: owner, type: type0, class: cls0 };
    const { rdata, full } = encodeRRCanonical(rrn, ttl0|0);
    return { rdata, full };
  });
  items.sort((a,b)=>{
    const n = Math.min(a.rdata.length, b.rdata.length);
    for (let i=0;i<n;i++){ const d=a.rdata[i]-b.rdata[i]; if (d) return d; }
    return a.rdata.length - b.rdata.length;
  });

  // שרשור לכלל Uint8Array אחד — זה מה שחותמים עליו
  let total=0; for (const it of items) total+=it.full.length;
  const out = new Uint8Array(total);
  let off=0; for (const it of items){ out.set(it.full, off); off+=it.full.length; }
  return out;
}




/*
 * Zone file parser & compiler for dnssec-server (Node.js)
 * ---------------------------------------------------------------
 * DESIGN
 *  - parseZone: PURE compiler → returns compact data only (no methods)
 *    { origin, default_ttl, records }
 *    • records: unique RR array in wire shape { name, type, class, ttl, data }
 *    • No duplicates; no byName map; no helper methods on the zone object
 *  - answerFromZone: Pure resolver over `zone.records`
 *    (exact, ANY, wildcard per RFC 4592, NODATA/NXDOMAIN, glue, SVCB/HTTPS hints)
 */

function parseZone(zoneText, opts){
  opts = opts || {};

  function isDigit(c){ return c >= '0' && c <= '9'; }
  function toU32(x){ var n = parseInt(x, 10); if (isNaN(n) || n < 0) return null; return n >>> 0; }

  function parseTTL(ttlStr){
    if (!ttlStr) return null;
    if (/^\d+$/.test(ttlStr)) return toU32(ttlStr);
    var m = ttlStr.match(/^(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/i);
    if (!m) return null;
    var w = m[1]?parseInt(m[1],10):0;
    var d = m[2]?parseInt(m[2],10):0;
    var h = m[3]?parseInt(m[3],10):0;
    var mi= m[4]?parseInt(m[4],10):0;
    var s = m[5]?parseInt(m[5],10):0;
    var total = (((w*7+d)*24+h)*60+mi)*60+s;
    return total>>>0;
  }

  function b64ToBytes(str){
    try {
      if (typeof Buffer!=='undefined') {
        return new Uint8Array(
          Buffer.from(String(str).replace(/\s+/g,'').replace(/-/g,'+').replace(/_/g,'/'),'base64')
        );
      }
    } catch(e){}
    return new Uint8Array([]);
  }
  function hexToBytes(str){
    var s = String(str).replace(/\s+/g,'');
    if (s.length % 2 !== 0) return new Uint8Array([]);
    var out = new Uint8Array(s.length/2);
    for (var i=0;i<out.length;i++) out[i] = parseInt(s.substr(i*2,2),16)>>>0;
    return out;
  }
  function textTokensToBytes(tokens){
    var joined = tokens.join('');
    if (/^[0-9A-Fa-f]+$/.test(joined) && joined.length%2===0) return hexToBytes(joined);
    return b64ToBytes(joined);
  }

  function ensureDot(n){ if (!n) return '.'; return n[n.length-1]==='.'?n:n+'.'; }
  function ensureNoDot(n){ if (!n) return ''; return n[n.length-1]==='.'?n.slice(0,-1):n; }
  function absName(name, origin){
    if (name==='@') return ensureDot(origin);
    if (name==='.') return '.';
    if (!name) return null;
    if (name[name.length-1]==='.') return name;
    if (!origin) return name+'.';
    return name+'.'+ensureNoDot(origin)+'.';
  }
  function unescapeText(s){
    var out='';
    for (var i=0;i<s.length;i++){
      var c=s[i];
      if (c==='\\'){
        var j=i+1;
        if (j+2<s.length && isDigit(s[j])&&isDigit(s[j+1])&&isDigit(s[j+2])){
          var oct=s.substr(j,3);
          var code=parseInt(oct,8)&0xFF;
          out+=String.fromCharCode(code);i+=3;continue;
        }
        if (j<s.length){out+=s[j];i++;continue;}
      }
      out+=c;
    }
    return out;
  }

  function splitLogicalLines(txt){
    var lines=txt.split(/\r?\n/);
    var out=[];var cur='';var depth=0;
    for (var li=0;li<lines.length;li++){
      var line=lines[li];
      var q=false;var esc=false;var cleaned='';
      for (var k=0;k<line.length;k++){
        var ch=line[k];
        if (!q && ch===';') break;
        if (ch==='"'&&!esc) q=!q;
        if (ch==='('&&!q) depth++;
        if (ch===')'&&!q&&depth>0) depth--;
        cleaned+=ch;
        esc=(ch==='\\'&&!esc);
      }
      cur+=(cleaned+' ');
      if (depth===0){
        var trimmed=cur.replace(/\s+/g,' ').trim();
        if (trimmed.length>0) out.push(trimmed);
        cur='';
      }
    }
    if (cur.trim().length>0) out.push(cur.trim());
    return out;
  }

  function tokenize(s){
    var toks=[];var buf='';var q=false;var esc=false;
    for (var i=0;i<s.length;i++){
      var ch=s[i];
      if (q){
        if (esc){buf+=ch;esc=false;continue;}
        if (ch==='\\'){esc=true;continue;}
        if (ch==='"'){q=false;toks.push(buf);buf='';continue;}
        buf+=ch;continue;
      } else {
        if (ch==='"'){if (buf.length){toks.push(buf);buf='';}q=true;continue;}
        if (/\s/.test(ch)){if (buf.length){toks.push(buf);buf='';}continue;}
        buf+=ch;
      }
    }
    if (buf.length) toks.push(buf);
    return toks;
  }

  function stableStringify(obj){
    if (obj===null || typeof obj!=='object') return String(obj);
    if (Array.isArray(obj)) return '['+obj.map(stableStringify).join(',')+']';
    var keys=Object.keys(obj).sort();
    var parts=[]; for (var i=0;i<keys.length;i++){ var k=keys[i]; parts.push(k+':'+stableStringify(obj[k])); }
    return '{'+parts.join(',')+'}';
  }
  function rrKey(rr){
    return rr.name+'|'+rr.type+'|'+rr.class+'|'+(rr.ttl>>>0)+'|'+stableStringify(rr.data);
  }

  function parseRR(tokens, state){
    var idx=0;var owner=null,ttl=null,rrclass='IN',type=null;
    if (tokens[0]&&tokens[0][0]==='$'){
      var d=tokens[0].toUpperCase();
      if (d==='$ORIGIN'){ if (tokens.length<2) return null; state.origin=ensureDot(tokens[1]); return null; }
      if (d==='$TTL'){ if (tokens.length<2) return null; state.default_ttl=parseTTL(tokens[1]); return null; }
      if (d==='$INCLUDE'){ return null; }
      return null;
    }
    if (idx<tokens.length){
      var t0=tokens[idx];
      var maybeType=t0.toUpperCase();
      var maybeTTL=parseTTL(t0);
      var isClass=class_to_code.hasOwnProperty(maybeType);
      var isType=type_to_code.hasOwnProperty(maybeType);
      if(!isType&&!isClass&&maybeTTL===null){owner=t0;idx++;}
    }
    if (idx<tokens.length){ var ttl1=parseTTL(tokens[idx]); if (ttl1!==null){ttl=ttl1;idx++;} }
    if (idx<tokens.length){ var c=tokens[idx].toUpperCase(); if (class_to_code[c]){rrclass=c;idx++;} }
    if (idx>=tokens.length) return null;
    type=tokens[idx].toUpperCase();idx++;
    if (!type_to_code[type]) return null;
    if (owner===null) owner=state.last_owner||'@';
    var fqdn=absName(owner,state.origin);
    if (ttl===null) ttl=state.default_ttl!=null?state.default_ttl:3600;
    var rdtoks=tokens.slice(idx);

    var rr={ name:fqdn, type:type, class:rrclass, ttl:ttl>>>0, data:null };

    function nameArg(i){ return absName(rdtoks[i], state.origin); }
    function intArg(i){ return toU32(rdtoks[i]); }

    switch(type){
      case 'SOA':{
        var toks=[];for(var si=0;si<rdtoks.length;si++){if(rdtoks[si]==='('||rdtoks[si]===')')continue;toks.push(rdtoks[si]);}
        rr.data={ mname:absName(toks[0],state.origin), rname:absName(toks[1],state.origin), serial:parseInt(toks[2],10)>>>0, refresh:parseTTL(toks[3])||toU32(toks[3]), retry:parseTTL(toks[4])||toU32(toks[4]), expire:parseTTL(toks[5])||toU32(toks[5]), minimum:parseTTL(toks[6])||toU32(toks[6]) };
        break;
      }
      case 'A': rr.data={ address: rdtoks[0] }; break;
      case 'AAAA': rr.data={ address: ipv6ToBytes(rdtoks[0]) }; break;
      case 'NS': rr.data={ name: nameArg(0) }; break;
      case 'CNAME': rr.data={ name: nameArg(0) }; break;
      case 'PTR': rr.data={ name: nameArg(0) }; break;
      case 'DNAME': rr.data={ name: nameArg(0) }; break;
      case 'MX': rr.data={ preference:intArg(0), exchange:nameArg(1) }; break;
      case 'TXT': rr.data={ texts: rdtoks.map(unescapeText) }; break;
      case 'HINFO': rr.data={ cpu: rdtoks[0], os: rdtoks[1] }; break;
      case 'MINFO': rr.data={ rmailbx: nameArg(0), emailbx: nameArg(1) }; break;
      case 'RP': rr.data={ mbox: nameArg(0), txt: nameArg(1) }; break;
      case 'AFSDB': rr.data={ subtype: intArg(0), hostname: nameArg(1) }; break;
      case 'X25': rr.data={ address: rdtoks[0] }; break;
      case 'ISDN': rr.data={ address: rdtoks[0], sa: rdtoks[1]||undefined }; break;
      case 'RT': rr.data={ preference: intArg(0), host: nameArg(1) }; break;
      case 'NSAP': rr.data={ address: hexToBytes(rdtoks[0]) }; break;
      case 'PX': rr.data={ preference: intArg(0), MAP822: nameArg(1), MAPX400: nameArg(2) }; break;
      case 'GPOS': rr.data={ latitude: rdtoks[0], longitude: rdtoks[1], altitude: rdtoks[2] }; break;
      case 'WKS': rr.data={ address: rdtoks[0], protocol: intArg(1), bitmap: textTokensToBytes(rdtoks.slice(2)) }; break;
      case 'NULL': rr.data={ raw: textTokensToBytes(rdtoks) }; break;

      case 'SRV': rr.data={ priority:intArg(0), weight:intArg(1), port:intArg(2), target:nameArg(3) }; break;
      case 'NAPTR': rr.data={ order:intArg(0), preference:intArg(1), flags:rdtoks[2], services:rdtoks[3], regexp:rdtoks[4], replacement:nameArg(5) }; break;
      case 'URI': rr.data={ priority: intArg(0), weight: intArg(1), target: unescapeText(rdtoks.slice(2).join(' ')) }; break;

      case 'DNSKEY':
      case 'CDNSKEY':
        rr.data={ flags:intArg(0), protocol:intArg(1), algorithm:intArg(2), key:b64ToBytes(rdtoks.slice(3).join('')) };
        break;
      case 'KEY':
        rr.data={ flags:intArg(0), protocol:intArg(1), algorithm:intArg(2), key:b64ToBytes(rdtoks.slice(3).join('')) };
        break;
      case 'DS':
      case 'CDS':
      case 'DLV':
      case 'TA':
        rr.data={ keyTag:intArg(0), algorithm:intArg(1), digestType:intArg(2), digest:hexToBytes(rdtoks.slice(3).join('')) };
        break;
      case 'RRSIG':
      case 'SIG':{
        var typeCovered = rdtoks[0];
        var algorithm = intArg(1);
        var labels = intArg(2);
        var originalTTL = intArg(3);
        var expiration = toU32(rdtoks[4]);
        var inception  = toU32(rdtoks[5]);
        var keyTag = intArg(6);
        var signersName = absName(rdtoks[7], state.origin);
        var signature = b64ToBytes(rdtoks.slice(8).join(''));
        rr.data = { typeCovered, algorithm, labels, originalTTL, expiration, inception, keyTag, signersName, signature };
        break;
      }
      case 'NSEC': rr.data={ nextDomainName:nameArg(0), types:rdtoks.slice(1).map(function(x){return String(x).toUpperCase();}) }; break;
      case 'NSEC3':{
        rr.data={ hashAlgorithm:intArg(0), flags:intArg(1), iterations:intArg(2), salt:(rdtoks[3]==='-'? new Uint8Array([]) : hexToBytes(rdtoks[3])), nextHashedOwnerName:b64ToBytes(rdtoks[4]), types:rdtoks.slice(5).map(function(x){return String(x).toUpperCase();}) };
        break;
      }
      case 'NSEC3PARAM': rr.data={ hashAlgorithm:intArg(0), flags:intArg(1), iterations:intArg(2), salt:(rdtoks[3]==='-'? new Uint8Array([]) : hexToBytes(rdtoks[3])) }; break;
      case 'DHCID': rr.data={ data: b64ToBytes(rdtoks.join('')) }; break;
      case 'TLSA':
      case 'SMIMEA': rr.data={ usage:intArg(0), selector:intArg(1), matchingType:intArg(2), certificate: hexToBytes(rdtoks[3]) }; break;
      case 'CERT': rr.data={ certType:intArg(0), keyTag:intArg(1), algorithm:intArg(2), certificate: b64ToBytes(rdtoks.slice(3).join('')) }; break;
      case 'SSHFP': rr.data={ algorithm:intArg(0), hash:intArg(1), fingerprint: hexToBytes(rdtoks[2]) }; break;
      case 'IPSECKEY':{
        rr.data={ precedence:intArg(0), gatewayType:intArg(1), algorithm:intArg(2), gateway:(rdtoks[3]==='.'?'.':nameArg(3)), publicKey: b64ToBytes(rdtoks.slice(4).join('')) };
        break;
      }

      case 'SVCB':
      case 'HTTPS':{
        var priority=intArg(0);var target=nameArg(1);
        var paramsStructured={};
        for (var pi=2;pi<rdtoks.length;pi++){
          var p=String(rdtoks[pi]);var eq=p.indexOf('=');var k=(eq>=0?p.slice(0,eq):p).toLowerCase();var v=(eq>=0?p.slice(eq+1):null);
          if (v&&v[0]==='"'&&v[v.length-1]==='"') v=v.slice(1,-1);
          if (v==null){ if (k==='no-default-alpn') paramsStructured.noDefaultAlpn = true; else paramsStructured[k]=true; continue; }
          if (k==='alpn') paramsStructured.alpn=v.split(',');
          else if (k==='port') paramsStructured.port=parseInt(v,10)>>>0;
          else if (k==='ipv4hint') paramsStructured.ipv4hint=v.split(',');
          else if (k==='ipv6hint') paramsStructured.ipv6hint=v.split(',');
          else if (k==='ech') paramsStructured.ech = b64ToBytes(v);
          else if (k==='dohpath') paramsStructured.dohpath = v;
          else if (k==='tls-supported-groups') paramsStructured.tlsSupportedGroups = v.split(',').map(function(x){return parseInt(x,10)>>>0;});
          else paramsStructured[k]=v;
        }
        rr.data={ priority:priority, targetName:target, paramsStructured:paramsStructured };
        break;
      }

      case 'HIP': rr.data={ algorithm:intArg(0), hit: b64ToBytes(rdtoks[1]), publicKey: b64ToBytes(rdtoks[2]), servers: rdtoks.slice(3).map(function(x){return absName(x, state.origin);}) }; break;
      case 'NID': rr.data={ preference:intArg(0), nodeIdHigh: toU32(rdtoks[1]), nodeIdLow: toU32(rdtoks[2]) }; break;
      case 'L32': rr.data={ preference:intArg(0), locator32: rdtoks[1] }; break;
      case 'L64': rr.data={ preference:intArg(0), locator64High: toU32(rdtoks[1]), locator64Low: toU32(rdtoks[2]) }; break;
      case 'LP': rr.data={ preference:intArg(0), fqdn: nameArg(1) }; break;
      case 'EUI48': rr.data={ address: hexToBytes(rdtoks[0]) }; break;
      case 'EUI64': rr.data={ address: hexToBytes(rdtoks[0]) }; break;
      case 'OPENPGPKEY': rr.data={ key: b64ToBytes(rdtoks.join('')) }; break;
      case 'ZONEMD': rr.data={ scheme:intArg(0), hashAlgorithm:intArg(1), digest: hexToBytes(rdtoks[2]) }; break;
      case 'TKEY': rr.data={ algorithm: nameArg(0), inception: toU32(rdtoks[1]), expiration: toU32(rdtoks[2]), mode: intArg(3), error:intArg(4), key: b64ToBytes(rdtoks[5]||''), other: b64ToBytes(rdtoks[6]||'') }; break;
      case 'TSIG': rr.data={ algorithm: nameArg(0), timeSignedHigh: intArg(1), timeSignedLow: intArg(2), fudge:intArg(3), mac: b64ToBytes(rdtoks[4]), originalId: toU32(rdtoks[5]), error:intArg(6), otherData: b64ToBytes(rdtoks[7]||'') }; break;

      case 'LOC':
      case 'APL':
      case 'EID':
      case 'NIMLOC':
      case 'ATMA':
      case 'SINK':
      case 'NINFO':
      case 'RKEY':
      case 'TALINK':
      case 'IXFR':
      case 'AXFR':
      case 'ANY':
        rr.data={ raw: textTokensToBytes(rdtoks) }; break;

      default:
        rr.data={ raw: textTokensToBytes(rdtoks) }; break;
    }
    state.last_owner = owner || state.last_owner;
    return rr;
  }

  var state={ origin:ensureDot(opts.origin||''), default_ttl:opts.default_ttl||null, last_owner:null };
  var logical=splitLogicalLines(zoneText);
  var zone={ origin:state.origin||'.', default_ttl:state.default_ttl||3600, records:[] };

  var seen = Object.create(null); // key→true for dedup

  for (var i=0;i<logical.length;i++){
    var rr=parseRR(tokenize(logical[i]),state);
    if (!rr) continue;
    var key = rrKey(rr); if (seen[key]) continue; seen[key] = true; // de-dup
    zone.records.push(rr);
  }

  return zone;
}


module.exports = {
  encodeMessage: encodeMessage,
  decodeMessage: decodeMessage,
  encodeName: encodeName,
  decodeName: decodeName,
  
  makeNameRdataEncoder: makeNameRdataEncoder,
  
  buildRRsetBytesFromAnswers: buildRRsetBytesFromAnswers,

  parseZone: parseZone,

  type_to_code,
  rcode_to_code,
  optioncode_to_code,
  opcode_to_code,
  class_to_code,

  code_to_type,
  code_to_rcode,
  code_to_opcode,
  code_to_class,
  code_to_optioncode,
};