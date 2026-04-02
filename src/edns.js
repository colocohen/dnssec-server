/*
 * dnssec-server: DNS server for Node.js
 * Copyright 2025 colocohen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * https://www.apache.org/licenses/LICENSE-2.0
 */

import { EDNS_OPT } from './constants.js';
import { dvFrom } from './utils.js';

// === EDNS options decoders/encoders (structured) ===
function parseEDNSOptions(list){
  const out = {
    raw: list.slice(0),           // always keep raw
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
        out.dau = Array.from(data); // RFC 6975: byte sequence, each byte = algorithm ID
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

      case EDNS_OPT.CHAIN:        // RFC 7901: keep as RAW (complex format)
        out.unknown.push({code, data:data.slice(0)});
        break;

      case EDNS_OPT.KEYTAG: {     // RFC 8145 §4.1: sequence of u16 Key Tags
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
          // remaining bytes are optional extra-text (UTF-8). Zero length is valid.
          const extra = data.slice(i); // until end of option (no inner length field)
          const text = extra.length ? td.decode(extra) : undefined;
          items.push( text !== undefined ? { infoCode:info, extraText:text } : { infoCode:info } );
          // RFC 8914 says each EDE is a *separate option*, but some implementations combine several in one.
          // We treat remaining bytes as a single entry; split externally if needed.
          i = data.length; // one per option
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


export { parseEDNSOptions, buildEDNSOptions };
