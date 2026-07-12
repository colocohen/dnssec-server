/*
 * dnssec-server: DNS server for Node.js
 * Copyright 2025 colocohen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * https://www.apache.org/licenses/LICENSE-2.0
 */

import {
  type_to_code, code_to_type,
  rcode_to_code, code_to_rcode,
  opcode_to_code, code_to_opcode,
  class_to_code, code_to_class,
  EDNS_OPT,
} from './constants.js';

import {
  readU16, writeU16, readU32, writeU32,
  dvFrom, __te, __td,
  encText, decText,
  ipv6ToBytes, bytesToIpv6,
  ensureDot, ensureNoDot, absName, fqdn, ensureFqdnLower,
} from './utils.js';

import {
  types,
  encodeName,
  decodeName,
  makeNameRdataEncoder,
  encodeTypeBitmaps,
  decodeTypeBitmaps,
} from './types.js';

import { parseEDNSOptions, buildEDNSOptions } from './edns.js';

import crypto from 'node:crypto';

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
      out[off++] = 0xC0 | ((ptr >> 8) & 0x3F);
      out[off++] = ptr & 0xFF;
      return off;
    }
    // record position of this suffix — but compression pointers can only address
    // the first 0x4000 bytes of the message (2-bit tag + 14-bit offset), so suffixes
    // that first appear beyond that are simply written uncompressed and never stored.
    if (off < 0x4000) dict[key] = off;
    var lab = labels[i];
    var lb = __te.encode(lab);
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

    // regular RR
    var typeName = code_to_type[typeCode] || typeCode;
    var impl = types[typeName];
    if (!impl || !impl.decode) throw new Error('no decoder for type '+typeName);
    var dec = impl.decode(buf, off, rdlen);
    off += rdlen;

    return {
        value: {
        name: n.name,
        type: typeName,
        class: code_to_class[klass] || klass,  // returns as string (e.g. "IN")
        ttl: ttl>>>0,
        data: dec.value
        },
        off
    };
}

function encodeRR(out, off, rr, dict){
  // rr.type can be string or number
  var tcode = (typeof rr.type === 'string') ? (type_to_code[rr.type]||0) : (rr.type|0);
  var dv = new DataView(out.buffer);

  // OPT special (EDNS)
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
    dv.setUint16(off, optData.length&0xFFFF, false); off+=2;
    out.set(optData, off); off+=optData.length;
    return off;
  }

  // regular RR
  off = encodeNameCompressed(out, off, rr.name, dict);
  dv.setUint16(off, tcode & 0xFFFF, false); off+=2;

  // class: string ("IN") or number (1) — both supported, default IN
  var ccode = (typeof rr.class === 'string') ? (class_to_code[rr.class]||1)
                                             : (rr.class==null ? 1 : (rr.class|0));
  dv.setUint16(off, ccode & 0xFFFF, false); off+=2;

  dv.setUint32(off, (rr.ttl>>>0), false); off+=4;

  var impl = types[(typeof rr.type==='string')? rr.type : code_to_type[tcode]];
  if (!impl || !impl.encode) throw new Error('no encoder for type '+rr.type);
  var encData = rr.data||rr;
  var rdata = impl.encode(encData);
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
      if (rr.value._edns){ edns = rr.value._edns; /* raw RR also available if needed */ }
      into.push({ name: rr.value.name, type: rr.value.type, class: rr.value.class, ttl: rr.value.ttl, data: rr.value.data });
    }
  }
  readRRs(h.ancount, answers);
  readRRs(h.nscount, authority);
  readRRs(h.arcount, additionals);

  return { header: h, questions, answers, authority, additionals, edns };
}

// Shared encode buffer — reused across calls (safe: encodeMessage is synchronous)
var _encodeBuf = new Uint8Array(65535);

function encodeMessage(msg){
  var qd = (msg.questions||[]).length;
  var an = (msg.answers||[]).length;
  var ns = (msg.authority||[]).length;
  var ar = (msg.additionals||[]).length;
  var hasExplicitOPT = (msg.additionals||[]).some(r => (r.type==='OPT' || r.type===41));
  if (msg.edns && !hasExplicitOPT) ar += 1;

  var h = Object.assign({
    id: crypto.randomInt(0, 65536),
    qr:false, opcode:0, aa:false, tc:false, rd:true, ra:false, z:false, ad:false, cd:false, rcode:0,
    qdcount: qd, ancount: an, nscount: ns, arcount: ar
  }, msg.header||{});
  h.qdcount = qd; h.ancount = an; h.nscount = ns; h.arcount = ar;

  var out = _encodeBuf, off = 0;
  out.set(encodeHeader(h), off); off += 12;

  var dict = {}; // for name compression

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
function encodeNameCanonical(out, off, name){
  return encodeName(out, off, ensureFqdnLower(name));
}

// Lowercase names in RDATA for types with NAME fields (RFC 4034 §6.2)
function canonicalizeRdataNames(rr){
  const t = typeof rr.type==='string' ? rr.type : code_to_type[rr.type];
  const d = rr.data != null ? rr.data : rr;
  const F = ensureFqdnLower;

  // Convenience shape: NAME-based types may carry their target as a plain string
  // (e.g. { type:'NS', data:'ns1.example.com' }). The wire encoder accepts this,
  // so canonical (signing) encoding must interpret it identically — spreading a
  // string would silently canonicalize the RDATA to the root name and produce a
  // signature over the wrong bytes.
  if (typeof d === 'string'){
    switch (t){
      case 'NS': case 'CNAME': case 'PTR': case 'DNAME':
      case 'MD': case 'MF': case 'MB': case 'MG': case 'MR':
      case 'NSAP_PTR': case 'MAILA': case 'MAILB':
        return { name: F(d) };
      default:
        return d;
    }
  }

  const x = { ...d };

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
    // others: no NAME fields in RDATA
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
  dv.setUint32(o, (originalTTL|0)>>>0,  false); o+=4;   // important: uniform TTL for RRset
  dv.setUint16(o, rdata.length & 0xFFFF, false); o+=2;
  out.set(rdata, o);
  return { rdata, full: out };
}

// Build canonical RRset bytes from answers for DNSSEC signing
function buildRRsetBytesFromAnswers(answers){
  if (!Array.isArray(answers) || answers.length === 0) return new Uint8Array(0);

  const owner = ensureFqdnLower(answers[0].name);
  const type0 = typeof answers[0].type==='string' ? answers[0].type.toUpperCase() : answers[0].type;
  const cls0  = answers[0].class || 'IN';
  const ttl0  = answers[0].ttl;

  // An RRset is by definition records sharing the same (name, type, class).
  // Silently coercing mixed records would produce a signature over bogus data,
  // so mixed input is a caller error — group records by RRset before signing.
  for (const rr of answers){
    const t = typeof rr.type==='string' ? rr.type.toUpperCase() : rr.type;
    if (ensureFqdnLower(rr.name) !== owner || t !== type0){
      throw new Error('buildRRsetBytesFromAnswers: mixed RRset — expected ' + owner + '/' + type0 +
                      ', got ' + rr.name + '/' + rr.type + '. Group answers by (name,type) first.');
    }
  }

  // canonical encoding for each RR, sorted by canonical RDATA (RFC 4034 §6)
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

  // concatenate into a single Uint8Array — this is what gets signed
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
  // Base32hex (RFC 4648 §7, "Extended Hex" alphabet 0-9 A-V) — the presentation
  // format of NSEC3 nextHashedOwnerName in zone files (RFC 5155 §3.3).
  function base32hexToBytes(str){
    var s = String(str).toUpperCase().replace(/=+$/,'');
    var alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
    var bits = 0, value = 0, out = [];
    for (var i=0;i<s.length;i++){
      var idx = alphabet.indexOf(s[i]);
      if (idx === -1) throw new Error('invalid base32hex character "' + s[i] + '"');
      value = (value << 5) | idx;
      bits += 5;
      if (bits >= 8){ out.push((value >>> (bits - 8)) & 0xFF); bits -= 8; }
    }
    return new Uint8Array(out);
  }
  // RRSIG expiration/inception in zone files: either seconds-since-epoch, or
  // YYYYMMDDHHmmSS in UTC (RFC 4034 §3.2). Wire format is always epoch u32.
  function parseSigTime(tok){
    var s = String(tok);
    if (/^\d{14}$/.test(s)){
      var y = +s.slice(0,4), mo = +s.slice(4,6), d = +s.slice(6,8);
      var h = +s.slice(8,10), mi = +s.slice(10,12), sec = +s.slice(12,14);
      return Math.floor(Date.UTC(y, mo-1, d, h, mi, sec) / 1000) >>> 0;
    }
    return toU32(s);
  }
  function typeToken(tok){
    var t = String(tok).toUpperCase();
    if (type_to_code.hasOwnProperty(t)) return type_to_code[t];
    var m = t.match(/^TYPE(\d+)$/); // RFC 3597 generic type syntax
    if (m) return (+m[1]) & 0xFFFF;
    return 0;
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
        var typeCovered = typeToken(rdtoks[0]);       // numeric code, matches wire decode
        var algorithm = intArg(1);
        var labels = intArg(2);
        var originalTTL = intArg(3);
        var expiration = parseSigTime(rdtoks[4]);     // supports YYYYMMDDHHmmSS and epoch
        var inception  = parseSigTime(rdtoks[5]);
        var keyTag = intArg(6);
        var signersName = absName(rdtoks[7], state.origin);
        var signature = b64ToBytes(rdtoks.slice(8).join(''));
        rr.data = { typeCovered, algorithm, labels, originalTTL, expiration, inception, keyTag, signersName, signature };
        break;
      }
      case 'NSEC': rr.data={ nextDomainName:nameArg(0), types:rdtoks.slice(1).map(typeToken) }; break;
      case 'NSEC3':{
        rr.data={ hashAlgorithm:intArg(0), flags:intArg(1), iterations:intArg(2), salt:(rdtoks[3]==='-'? new Uint8Array([]) : hexToBytes(rdtoks[3])), nextHashedOwnerName:base32hexToBytes(rdtoks[4]), types:rdtoks.slice(5).map(typeToken) };
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

export {
  encodeMessage,
  decodeMessage,
  encodeName,
  decodeName,
  makeNameRdataEncoder,
  buildRRsetBytesFromAnswers,
  parseZone,
  type_to_code,
  rcode_to_code,
  opcode_to_code,
  class_to_code,
  code_to_type,
  code_to_rcode,
  code_to_opcode,
  code_to_class,
};