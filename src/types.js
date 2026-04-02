/*
 * dnssec-server: DNS server for Node.js
 * Copyright 2025 colocohen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * https://www.apache.org/licenses/LICENSE-2.0
 */

import { type_to_code, code_to_type, class_to_code, SvcParamKeys } from './constants.js';
import {
  readU16, writeU16, readU32, writeU32,
  dvFrom, __te, __td,
  encText, decText,
  ipv6ToBytes, bytesToIpv6,
  ensureFqdnLower,
} from './utils.js';

var types={};
for(var type in type_to_code){
    types[type]={
        decode: null,
        encode: null,
    };
}

// Shared buffer for name encoding — reused across calls (safe: all encode functions are synchronous)
var _nameBuf = new Uint8Array(512);
var _nameDv = new DataView(_nameBuf.buffer);


// encodeName (non-compressed; suitable for RDATA and Question without compression)
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
    var off = encodeName(_nameBuf, 0, s);
    return _nameBuf.slice(0, off);
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
types.MINFO.encode = function(v){ var off=0; off=encodeName(_nameBuf,off,v.rmailbx||'.'); off=encodeName(_nameBuf,off,v.emailbx||'.'); return _nameBuf.slice(0,off); };

// TXT — sequence of <len><bytes>
types.TXT.decode = function(buf, off, rdlen){ var end=off+rdlen, out=[]; while(off<end){ var l=buf[off++]; if (off+l> end) throw new Error('TXT overflow'); out.push(decText(buf, off, off+l)); off+=l; } return { value:{ texts: out }, bytes: rdlen}; };
types.TXT.encode = function(v){ var arr = Array.isArray(v.texts)? v.texts : (v.texts!=null? [v.texts] : []); var parts=new Array(arr.length), i, total=0; for(i=0;i<arr.length;i++){ var b=encText(arr[i]); parts[i]=b; total+=1+b.length; } var out=new Uint8Array(total), o=0; for(i=0;i<parts.length;i++){ var b2=parts[i]; out[o++]=b2.length&0xff; out.set(b2,o); o+=b2.length; } return out; };

// RP (RFC 1183) — mbox(NAME), txt(NAME)
types.RP.decode = function(buf, off, rdlen){ var s=off; var m=decodeName(buf,off); off=m.off; var t=decodeName(buf,off); off=t.off; if (off-s!==rdlen) throw new Error('RP len'); return { value:{ mbox:m.name, txt:t.name }, bytes: rdlen }; };
types.RP.encode = function(v){ var off=0; off=encodeName(_nameBuf,off,v.mbox||'.'); off=encodeName(_nameBuf,off,v.txt||'.'); return _nameBuf.slice(0,off); };

// AFSDB (RFC 1183) — subtype(u16), hostname(NAME)
types.AFSDB.decode = function(buf, off, rdlen){ var s=off, dv=dvFrom(buf); var subtype=readU16(dv,off); off+=2; var n=decodeName(buf,off); off=n.off; if (off-s!==rdlen) throw new Error('AFSDB len'); return { value:{ subtype:subtype, hostname:n.name }, bytes: rdlen }; };
types.AFSDB.encode = function(v){ var off=0; off=writeU16(_nameDv,off,v.subtype|0); off=encodeName(_nameBuf,off,v.hostname||'.'); return _nameBuf.slice(0,off); };

// X25 (RFC 1183) — PSDN address (character-string)
types.X25.decode = function(buf, off, rdlen){ var end=off+rdlen; var l=buf[off++]; if (off+l> end) throw new Error('X25 overflow'); var addr=decText(buf,off,off+l); return { value:{ address:addr }, bytes: rdlen }; };
types.X25.encode = function(v){ var a=encText(v.address); var out=new Uint8Array(1+a.length); out[0]=a.length&0xff; out.set(a,1); return out; };

// ISDN (RFC 1183) — address (char-string), optional sa (char-string)
types.ISDN.decode = function(buf, off, rdlen){ var s=off, end=off+rdlen; var l1=buf[off++]; if (off+l1> end) throw new Error('ISDN'); var addr=decText(buf,off,off+l1); off+=l1; var sa=null; if (off<end){ var l2=buf[off++]; if (off+l2> end) throw new Error('ISDN2'); sa=decText(buf,off,off+l2); off+=l2; } if (off!==end) throw new Error('ISDN trailing'); return { value:{ address:addr, sa:sa }, bytes: rdlen }; };
types.ISDN.encode = function(v){ var a=encText(v.address), sa=v.sa!=null?encText(v.sa):null; var out=new Uint8Array(1+a.length + (sa?1+sa.length:0)); var i=0; out[i++]=a.length&0xff; out.set(a,i); i+=a.length; if (sa){ out[i++]=sa.length&0xff; out.set(sa,i); } return out; };

// RT (RFC 1183) — preference(u16), intermediate-host(NAME)
types.RT.decode = function(buf, off, rdlen){ var s=off, dv=dvFrom(buf); var pref=readU16(dv,off); off+=2; var n=decodeName(buf,off); off=n.off; if (off-s!==rdlen) throw new Error('RT len'); return { value:{ preference:pref, host:n.name }, bytes: rdlen }; };
types.RT.encode = function(v){ var off=0; off=writeU16(_nameDv,off,v.preference|0); off=encodeName(_nameBuf,off,v.host||'.'); return _nameBuf.slice(0,off); };

// NSAP (RFC 1706) — binary address (treat as raw)
types.NSAP.decode = function(buf, off, rdlen){ return { value:{ address: buf.slice(off, off+rdlen) }, bytes: rdlen }; };
types.NSAP.encode = function(v){ var a=v.address||new Uint8Array(0); var out=new Uint8Array(a.length); out.set(a.slice(0)); return out; };

// SIG (obsolete) — same wire as RRSIG
// KEY (obsolete) — nearly same wire as DNSKEY

// PX (RFC 2163) — preference(u16), MAP822(NAME), MAPX400(NAME)
types.PX.decode = function(buf, off, rdlen){ var s=off, dv=dvFrom(buf); var pref=readU16(dv,off); off+=2; var m822=decodeName(buf,off); off=m822.off; var mx400=decodeName(buf,off); off=mx400.off; if (off-s!==rdlen) throw new Error('PX len'); return { value:{ preference:pref, MAP822:m822.name, MAPX400:mx400.name }, bytes: rdlen }; };
types.PX.encode = function(v){ var off=0; off=writeU16(_nameDv,off,v.preference|0); off=encodeName(_nameBuf,off,v.MAP822||'.'); off=encodeName(_nameBuf,off,v.MAPX400||'.'); return _nameBuf.slice(0,off); };

// GPOS (RFC 1712, obsolete) — three strings: latitude, longitude, altitude
types.GPOS.decode = function(buf, off, rdlen){ var end=off+rdlen; function rd(){ var l=buf[off++]; if (off+l> end) throw new Error('GPOS'); var s=decText(buf,off,off+l); off+=l; return s; } var lat=rd(), lon=rd(), alt=rd(); return { value:{ latitude:lat, longitude:lon, altitude:alt }, bytes: rdlen }; };
types.GPOS.encode = function(v){ var a=encText(v.latitude), b=encText(v.longitude), c=encText(v.altitude); var out=new Uint8Array(3 + a.length + b.length + c.length); var i=0; out[i++]=a.length; out.set(a,i); i+=a.length; out[i++]=b.length; out.set(b,i); i+=b.length; out[i++]=c.length; out.set(c,i); return out; };

// MX
types.MX.decode = function(buf, off, rdlen){ var s=off, dv=dvFrom(buf); var pref=readU16(dv,off); off+=2; var n=decodeName(buf,off); off=n.off; if (off-s!==rdlen) throw new Error('MX len'); return { value:{ preference:pref, exchange:n.name }, bytes: rdlen }; };
types.MX.encode = function(v){ var off=0; off=writeU16(_nameDv,off,v.preference|0); off=encodeName(_nameBuf,off,v.exchange||'.'); return _nameBuf.slice(0,off); };

// SOA
types.SOA.decode = function(buf, off, rdlen){ var s=off, dv=dvFrom(buf); var m=decodeName(buf,off); off=m.off; var r=decodeName(buf,off); off=r.off; if (buf.length-off<20) throw new Error('SOA short'); var serial=readU32(dv,off); off+=4; var refresh=readU32(dv,off); off+=4; var retry=readU32(dv,off); off+=4; var expire=readU32(dv,off); off+=4; var minimum=readU32(dv,off); off+=4; if (off-s!==rdlen) throw new Error('SOA len'); return { value:{ mname:m.name, rname:r.name, serial:serial, refresh:refresh, retry:retry, expire:expire, minimum:minimum }, bytes: rdlen}; };
types.SOA.encode = function(v){ var off=0; off=encodeName(_nameBuf,off,v.mname||'.'); off=encodeName(_nameBuf,off,v.rname||'.'); off=writeU32(_nameDv,off,v.serial|0); off=writeU32(_nameDv,off,v.refresh|0); off=writeU32(_nameDv,off,v.retry|0); off=writeU32(_nameDv,off,v.expire|0); off=writeU32(_nameDv,off,v.minimum|0); return _nameBuf.slice(0,off); };

// SRV
types.SRV.decode = function(buf, off, rdlen){ var s=off, dv=dvFrom(buf); var pr=readU16(dv,off); off+=2; var wt=readU16(dv,off); off+=2; var pt=readU16(dv,off); off+=2; var n=decodeName(buf,off); off=n.off; if (off-s!==rdlen) throw new Error('SRV len'); return { value:{ priority:pr, weight:wt, port:pt, target:n.name }, bytes: rdlen}; };
types.SRV.encode = function(v){ var off=0; off=writeU16(_nameDv,off,v.priority|0); off=writeU16(_nameDv,off,v.weight|0); off=writeU16(_nameDv,off,v.port|0); off=encodeName(_nameBuf,off,v.target||'.'); return _nameBuf.slice(0,off); };

// TLSA / SMIMEA (alias)
types.TLSA.decode = function(buf, off, rdlen){ if (rdlen<3) throw new Error('TLSA short'); var usage=buf[off], selector=buf[off+1], mt=buf[off+2]; var data=buf.slice(off+3, off+rdlen); return { value:{ usage:usage, selector:selector, matchingType:mt, certificate:data }, bytes: rdlen}; };
types.TLSA.encode = function(v){ var cert=v.certificate||new Uint8Array(0); var out=new Uint8Array(3+cert.length); out[0]=v.usage|0; out[1]=v.selector|0; out[2]=v.matchingType|0; out.set(cert,3); return out; };

types.SMIMEA = types.TLSA;

// DNSKEY / KEY(obsolete)
types.DNSKEY.decode = function(buf, off, rdlen){ if (rdlen<4) throw new Error('DNSKEY short'); var dv=dvFrom(buf); var flags=readU16(dv,off); off+=2; var proto=buf[off++]; var alg=buf[off++]; var key=buf.slice(off, off+rdlen-4); return { value:{ flags:flags, protocol:proto, algorithm:alg, key:key }, bytes: rdlen}; };
types.DNSKEY.encode = function(v){ var key=v.key||new Uint8Array(0); var out=new Uint8Array(4+key.length); var dv=new DataView(out.buffer); writeU16(dv,0,v.flags|0); out[2]=3; out[3]=v.algorithm|0; out.set(key,4); return out; };

// === CDNSKEY — same wire format as DNSKEY ===
types.CDNSKEY = types.DNSKEY;


// === KEY (obsolete) — same wire format as DNSKEY ===
types.KEY = {
  decode: function(buf, off, rdlen){
    if (rdlen < 4) throw new Error('KEY short');
    var dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    var flags = dv.getUint16(off, false); off += 2;
    var proto = buf[off++]; // should be 3
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
types.RRSIG.encode = function(v){ var noff=encodeName(_nameBuf,0,v.signersName||'.'); var sig=v.signature||new Uint8Array(0); var out=new Uint8Array(2+1+1+4+4+4+2+noff+sig.length); var dv=new DataView(out.buffer); var o=0; o=writeU16(dv,o,v.typeCovered|0); out[o++]=v.algorithm|0; out[o++]=v.labels|0; o=writeU32(dv,o,v.originalTTL|0); o=writeU32(dv,o,v.expiration|0); o=writeU32(dv,o,v.inception|0); o=writeU16(dv,o,v.keyTag|0); out.set(_nameBuf.subarray(0,noff), o); o+=noff; out.set(sig,o); return out; };
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
types.NAPTR.encode = function(v){ var f=encText(v.flags||''); var s=encText(v.services||''); var r=encText(v.regexp||''); var noff=encodeName(_nameBuf,0,v.replacement||'.'); var out=new Uint8Array(2+2+1+f.length+1+s.length+1+r.length+noff); var dv=new DataView(out.buffer); var o=0; o=writeU16(dv,o,v.order|0); o=writeU16(dv,o,v.preference|0); out[o++]=f.length&0xff; out.set(f,o); o+=f.length; out[o++]=s.length&0xff; out.set(s,o); o+=s.length; out[o++]=r.length&0xff; out.set(r,o); o+=r.length; out.set(_nameBuf.subarray(0,noff), o); return out; };

// OPT (EDNS) — options array [{code,data}]
types.OPT.decode = function(buf, off, rdlen){ var end=off+rdlen, options=[]; var dv=dvFrom(buf); while(off+4<=end){ var code=readU16(dv,off); off+=2; var len=readU16(dv,off); off+=2; if (off+len> end) throw new Error('OPT overflow'); var val=buf.slice(off, off+len); options.push({ code:code, data: val }); off+=len; } if (off!==end) throw new Error('OPT trailing'); return { value:{ options: options }, bytes: rdlen}; };

types.OPT.encode = function(v){ var opts=(v&&v.options)?v.options:[]; var total=0; for (var i=0;i<opts.length;i++){ var d=opts[i].data||new Uint8Array(0); total += 4 + d.length; } var out=new Uint8Array(total), dv=new DataView(out.buffer), o=0; for (var j=0;j<opts.length;j++){ var op=opts[j], d2=op.data||new Uint8Array(0); o=writeU16(dv,o,op.code|0); o=writeU16(dv,o,d2.length); out.set(d2,o); o+=d2.length; } return out; };


// ===== SVCB/HTTPS — structured params helpers (RFC 9460 etc.) =====

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
  let noff = encodeName(_nameBuf, 0, v.targetName || '.');
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
  out.set(_nameBuf.subarray(0,noff), head.length);
  out.set(pout, head.length + noff);
  return out;
}


// === SVCB / HTTPS (per RFC 9460): priority(u16), targetName(NAME), params list (key,u16; length,u16; value[...]) ===

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
types.NXT.encode = function(v){ var off=encodeName(_nameBuf,0,v.next||'.'); var bm=v.bitmap||new Uint8Array(0); var out=new Uint8Array(off+bm.length); out.set(_nameBuf.subarray(0,off),0); out.set(bm,off); return out; };

// A6 (RFC 2874, obsolete) — prefixLen(u8), address suffix (ceil((128-prefix)/8)), prefix(NAME)
types.A6.decode = function(buf, off, rdlen){ var s=off; var prefix=buf[off++]; var sufBytes = Math.ceil((128-prefix)/8); if (prefix>128) throw new Error('A6 prefix'); var suffix = buf.slice(off, off+sufBytes); off+=sufBytes; var n=decodeName(buf,off); off=n.off; if (off-s!==rdlen) throw new Error('A6 len'); return { value:{ prefixLength:prefix, suffix:suffix, prefixName:n.name }, bytes: rdlen }; };
types.A6.encode = function(v){ var prefix=v.prefixLength|0; var suf=v.suffix||new Uint8Array(0); var off=0; _nameBuf[off++]=prefix&0xff; var need=Math.ceil((128-prefix)/8); if (suf.length!==need) throw new Error('A6 suffix len'); _nameBuf.set(suf, off); off+=suf.length; off=encodeName(_nameBuf,off,v.prefixName||'.'); return _nameBuf.slice(0,off); };

// APL (RFC 3123) — list of (family,u16; prefix,u8; neg,afdlen+addr)
types.APL.decode = function(buf, off, rdlen){ var s=off, end=off+rdlen, dv=dvFrom(buf), items=[]; while(off<end){ var fam=readU16(dv,off); off+=2; var prefix=buf[off++]; var blen=buf[off++]; var neg = !!(blen & 0x80); var afdlen = blen & 0x7f; if (off+afdlen> end) throw new Error('APL overflow'); var addr = buf.slice(off, off+afdlen); off += afdlen; items.push({ family:fam, prefix:prefix, neg:neg, address:addr }); } return { value:{ items:items }, bytes: rdlen };
};
types.APL.encode = function(v){ var items=v.items||[]; var parts=[]; var total=0; for (var i=0;i<items.length;i++){ var it=items[i]; var afd=it.address||new Uint8Array(0); var len=2+1+1+afd.length; total+=len; parts.push({it:it, afd:afd, len:len}); } var out=new Uint8Array(total), dv=new DataView(out.buffer), o=0; for (var j=0;j<parts.length;j++){ var p=parts[j], it=p.it; o=writeU16(dv,o,it.family|0); out[o++]=it.prefix|0; out[o++]=((it.neg?0x80:0) | (p.afd.length & 0x7f)) & 0xff; out.set(p.afd,o); o+=p.afd.length; } return out; };

// IPSECKEY (RFC 4025)
// precedence(u8), gatewayType(u8), algorithm(u8), gateway(variant), publicKey
// gatewayType: 0=none,1=IPv4(4b),2=IPv6(16b),3=NAME
types.IPSECKEY.decode = function(buf, off, rdlen){ var s=off; var prec=buf[off++]; var gwt=buf[off++]; var alg=buf[off++]; var gateway=null; if (gwt===0){ gateway=null; } else if (gwt===1){ gateway=buf.slice(off, off+4); off+=4; } else if (gwt===2){ gateway=buf.slice(off, off+16); off+=16; } else if (gwt===3){ var n=decodeName(buf,off); off=n.off; gateway=n.name; } else { throw new Error('IPSECKEY gwt'); } var pub = buf.slice(off, s+rdlen); return { value:{ precedence:prec, gatewayType:gwt, algorithm:alg, gateway:gateway, publicKey:pub }, bytes: rdlen };
};
types.IPSECKEY.encode = function(v){ var head=new Uint8Array(3); head[0]=v.precedence|0; head[1]=v.gatewayType|0; head[2]=v.algorithm|0; var tail; if (v.gatewayType===0){ tail=new Uint8Array(0); } else if (v.gatewayType===1){ if (!(v.gateway instanceof Uint8Array) || v.gateway.length!==4) throw new Error('IPSECKEY IPv4'); tail=v.gateway.slice(0,4); } else if (v.gatewayType===2){ if (!(v.gateway instanceof Uint8Array) || v.gateway.length!==16) throw new Error('IPSECKEY IPv6'); tail=v.gateway.slice(0,16); } else if (v.gatewayType===3){ var o=encodeName(_nameBuf,0,v.gateway||'.'); tail=_nameBuf.slice(0,o); } else { tail=new Uint8Array(0); } var pk=v.publicKey||new Uint8Array(0); var out=new Uint8Array(head.length+tail.length+pk.length); out.set(head,0); out.set(tail,head.length); out.set(pk, head.length+tail.length); return out; };

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
types.NSEC.encode = function(v){ var off=encodeName(_nameBuf,0,v.nextDomainName||'.'); var bm=encodeTypeBitmaps(v.types||[]); var out=new Uint8Array(off+bm.length); out.set(_nameBuf.subarray(0,off),0); out.set(bm,off); return out; };

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
types.HIP.encode = function(v){ var hit=v.hit||new Uint8Array(0); var pk=v.publicKey||new Uint8Array(0); var names=v.servers||[]; var size=1+1+2+hit.length+pk.length; var off=0; for (var i=0;i<names.length;i++){ off=encodeName(_nameBuf,off,names[i]||'.'); }
  var tail=_nameBuf.slice(0,off);
  var out=new Uint8Array(size+tail.length); var dv=new DataView(out.buffer); var o=0; out[o++]=hit.length&0xff; out[o++]=v.algorithm|0; o=writeU16(dv,o,pk.length); out.set(hit,o); o+=hit.length; out.set(pk,o); o+=pk.length; out.set(tail,o); return out; };

// TKEY (RFC 2930) — algorithm(NAME), inception(u32), expiration(u32), mode(u16), error(u16), keyLen(u16), key[..], otherLen(u16), other[..]
types.TKEY.decode = function(buf, off, rdlen){ var s=off, dv=dvFrom(buf); var alg=decodeName(buf,off); off=alg.off; var inc=readU32(dv,off); off+=4; var exp=readU32(dv,off); off+=4; var mode=readU16(dv,off); off+=2; var err=readU16(dv,off); off+=2; var klen=readU16(dv,off); off+=2; var key=buf.slice(off, off+klen); off+=klen; var olen=readU16(dv,off); off+=2; var other=buf.slice(off, off+olen); off+=olen; if (off-s!==rdlen) throw new Error('TKEY len'); return { value:{ algorithm:alg.name, inception:inc, expiration:exp, mode:mode, error:err, key:key, other:other }, bytes: rdlen };
};
types.TKEY.encode = function(v){ var o=encodeName(_nameBuf,0,v.algorithm||'.'); var key=v.key||new Uint8Array(0); var other=v.other||new Uint8Array(0); var out=new Uint8Array(o + 4+4+2+2 + 2+key.length + 2+other.length); var dv=new DataView(out.buffer); var p=0; out.set(_nameBuf.subarray(0,o), p); p+=o; p=writeU32(dv,p,v.inception|0); p=writeU32(dv,p,v.expiration|0); p=writeU16(dv,p,v.mode|0); p=writeU16(dv,p,v.error|0); p=writeU16(dv,p,key.length); out.set(key,p); p+=key.length; p=writeU16(dv,p,other.length); out.set(other,p); return out; };

// TSIG (RFC 8945) — algorithm(NAME), timeSigned(u48), fudge(u16), MAC size(u16), MAC[..], origId(u16), error(u16), otherLen(u16), otherData[..]
types.TSIG.decode = function(buf, off, rdlen){ var s=off, dv=dvFrom(buf); var alg=decodeName(buf,off); off=alg.off; var tHigh=readU16(dv,off); off+=2; var tLow=readU32(dv,off); off+=4; var fudge=readU16(dv,off); off+=2; var macLen=readU16(dv,off); off+=2; var mac=buf.slice(off, off+macLen); off+=macLen; var origId=readU16(dv,off); off+=2; var err=readU16(dv,off); off+=2; var otherLen=readU16(dv,off); off+=2; var other=buf.slice(off, off+otherLen); off+=otherLen; if (off-s!==rdlen) throw new Error('TSIG len'); return { value:{ algorithm:alg.name, timeSignedHigh:tHigh, timeSignedLow:tLow, fudge:fudge, mac:mac, originalId:origId, error:err, otherData:other }, bytes: rdlen };
};
types.TSIG.encode = function(v){ var o=encodeName(_nameBuf,0,v.algorithm||'.'); var mac=v.mac||new Uint8Array(0); var other=v.otherData||new Uint8Array(0); var out=new Uint8Array(o + 2+4+2 + 2+mac.length + 2+2 + 2+other.length); var dv=new DataView(out.buffer); var p=0; out.set(_nameBuf.subarray(0,o), p); p+=o; p=writeU16(dv,p,(v.timeSignedHigh|0)&0xffff); p=writeU32(dv,p,(v.timeSignedLow|0)>>>0); p=writeU16(dv,p,v.fudge|0); p=writeU16(dv,p,mac.length); out.set(mac,p); p+=mac.length; p=writeU16(dv,p,v.originalId|0); p=writeU16(dv,p,v.error|0); p=writeU16(dv,p,other.length); out.set(other,p); return out; };

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
    var o = 0;
    _nameDv.setUint16(o, (v.preference|0)>>>0, false); o += 2;
    o = encodeName(_nameBuf, o, v.exchanger || '.');
    return _nameBuf.slice(0, o);
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
    var o = 0;
    _nameDv.setUint16(o, (v.preference|0)>>>0, false); o += 2;
    o = encodeName(_nameBuf, o, v.fqdn || '.');
    return _nameBuf.slice(0, o);
  }
};

// === IXFR / AXFR / ANY — query-only types. As RRs they usually have no RDATA. Preserved as RAW for round-trip. ===
['IXFR','AXFR','ANY'].forEach(function(t){
  types[t] = {
    decode: function(buf, off, rdlen){
      // usually rdlen==0; preserve data if present
      return { value: { raw: buf.slice(off, off+rdlen) }, bytes: rdlen };
    },
    encode: function(v){
      var d = (v && v.raw) ? v.raw : new Uint8Array(0);
      var out = new Uint8Array(d.length); out.set(d); return out;
    }
  };
});


export {
  types,
  encodeName,
  decodeName,
  makeNameRdataEncoder,
  encodeTypeBitmaps,
  decodeTypeBitmaps,
};
