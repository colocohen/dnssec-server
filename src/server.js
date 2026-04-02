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
import tls from 'node:tls';
import crypto from 'node:crypto';

import * as wire from './wire.js';
import { fqdn, ensureDot } from './utils.js';


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

function sanitizeEdns(ed){
  var out = {
    udpSize: clamp(ed.udpSize || 1232, 512, 4096),
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

function buildRes(req, serverCtx){
  var hdrIn = req.message && req.message.header || {};
  var res = {
    header: {
      id: req.id|0,
      qr: true,
      opcode: hdrIn.opcode|0,
      aa: !!serverCtx.options.always_aa,//Authoritative Answer
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
    edns: req.edns ? {
      udpSize: req.edns.udpSize,
      extRcode: 0,
      version: 0,
      do: false,
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

function truncateSmart(serverCtx, req, res, udpMax){
  // priority: keep OPT, trim additionals → authority → answers (section-level for simplicity)
  var tryOrder = ['additionals','authority','answers'];
  res.header.tc = true;
  for (var i=0;i<tryOrder.length;i++){
    var sec = tryOrder[i];
    if (res[sec] && res[sec].length){
      var save = res[sec];
      res[sec] = [];
      var w = encodeNow(res, req);
      if (w.length <= udpMax) return w;
      // not enough — restore and continue trimming next section
      res[sec] = save;
    }
  }
  // if still too large — hard truncation as last resort
  var w2 = encodeNow(res, req);
  return toU8(w2).slice(0, udpMax);
}

function finalizeWire(serverCtx, req, res){
  // before encode

  // initial encoding
  var wire2 = encodeNow(res, req);

  // UDP — smart truncation
  if (req.transport === 'udp4' || req.transport === 'udp6'){
    var udpMax = (res.edns && res.edns.udpSize) ? res.edns.udpSize : 512;
    if (wire2.length > udpMax){
      wire2 = truncateSmart(serverCtx, req, res, udpMax);
    }
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

function sendResponse(ctx, req, res){

  function actual_send(){
    var wire2 = finalizeWire(ctx, req, res);

    if (req.transport === 'udp4' || req.transport === 'udp6'){
      if (req._udp) req._udp.send(wire2, req.client.port, req.client.address);
      return;
    }
    if (req.transport === 'tcp' || req.transport === 'tls'){
      if (req._socket){
        var frame = Buffer.allocUnsafe(2 + wire2.length);
        frame.writeUInt16BE(wire2.length, 0);
        frame.set(wire2, 2);
        req._socket.write(frame);
      }
      return;
    }
    if (req.transport === 'quic'){
      if (req._quic && typeof req._quic.send === 'function') req._quic.send(wire2);
      return;
    }
  }

  var rrsig_exist=false;
  for(var i=0;i<res.answers.length;i++){
    if(res.answers[i] && res.answers[i].type==='RRSIG'){
      rrsig_exist=true;
      break;
    }
  }

  if(rrsig_exist===false && res.answers.length>0 && req.flag_do===true && ctx && ctx.options && ctx.options.dnssec && typeof ctx.options.dnssec.keyCallback==='function'){

    ctx.options.dnssec.keyCallback(req.name,function(error,result){

      if(result){
        try{
          var rrset_bytes=wire.buildRRsetBytesFromAnswers(res.answers);

          var labels=String(res.answers[0].name).replace(/\.$/, '').split('.').length;

          var the_key=null;
          if(res.answers[0].type==='DNSKEY'){
            the_key=result.ksk;
          }else{
            the_key=result.zsk;
          }

          var timestamp_now = Math.floor(Date.now() / 1000);

          if(!('inception' in the_key) || the_key.inception<=0 || typeof the_key.inception!=='number'){
            the_key.inception=timestamp_now - 300;
          }

          if(!('expiration' in the_key) || the_key.expiration<=0 || typeof the_key.expiration!=='number'){
            the_key.expiration=timestamp_now + (346 * 24 * 3600);
          }

          // --- params object shared by cache.get and cache.set ---
          var cacheParams = {
            name: res.answers[0].name,
            type: res.answers[0].type,
            class: res.answers[0].class || 'IN',
            keyTag: Number(the_key.keyTag),
            hash: toHex(sha256(rrset_bytes))
          };

          function doSign(){
            var sig_data = signRRset(result.signersName, rrset_bytes, 13, the_key.keyTag, the_key.expiration, the_key.inception, the_key.privateKey, labels, res.answers[0].type, res.answers[0].ttl);

            var rrsig_record = {
              name: res.answers[0].name,
              type: 'RRSIG',
              class: res.answers[0].class,
              ttl: res.answers[0].ttl,
              data: {
                typeCovered: wire.type_to_code[res.answers[0].type.toUpperCase()] || 0,
                algorithm: 13,
                labels: labels,
                originalTTL: res.answers[0].ttl,
                expiration: the_key.expiration,
                inception: the_key.inception,
                keyTag: Number(the_key.keyTag),
                signersName: result.signersName,
                signature: sig_data,
              }
            };

            // store in cache if available
            if (ctx._dnssecCache){
              var cacheValue = { rrsig: rrsig_record, expiration: the_key.expiration, inception: the_key.inception };
              try { ctx._dnssecCache.set(cacheParams, cacheValue, function(){}); } catch(e){}
            }

            return rrsig_record;
          }

          function appendAndSend(rrsig_record){
            res.answers.push(rrsig_record);
            res.additionals.push({
              type: 'OPT',
              name: '.',
              edns: { udpSize: 4096, extRcode: 0, version: 0, do: true, options: [] }
            });
            actual_send();
          }

          // --- cache lookup or sign ---
          if (ctx._dnssecCache){
            ctx._dnssecCache.get(cacheParams, function(err, cached){
              if (!err && cached && cached.rrsig && cached.expiration > timestamp_now && cached.inception <= timestamp_now){
                appendAndSend(cached.rrsig);
              } else {
                appendAndSend(doSign());
              }
            });
          } else {
            appendAndSend(doSign());
          }

        }catch(e2){
          console.log(e2);
          actual_send();
        }
      }else{
        actual_send();
      }

    });

  }else{
    actual_send();
  }
  
}


function autoAnswerIfApplicable(req, res, ctx, callback){
  try{

    if(req.type === 'DNSKEY' && ctx && ctx.options && ctx.options.dnssec && typeof ctx.options.dnssec.keyCallback==='function'){

      ctx.options.dnssec.keyCallback(req.name,function(error,result){

        if(result){
          if(result.ksk){
            res.answers.push({
              name: result.signersName,
              type: 'DNSKEY',
              class: 'IN',
              ttl: 86400,
              data: {
                flags: 257,
                algorithm: 13,
                key: toU8(result.ksk.publicKey)
              }
            });
          }
          if(result.zsk){
            res.answers.push({
              name: result.signersName,
              type: 'DNSKEY',
              class: 'IN',
              ttl: 86400,
              data: {
                flags: 256,
                algorithm: 13,
                key: toU8(result.zsk.publicKey)
              }
            });
          }
          
          res.send();

          callback(true);
        }else{
          callback(false);
        }

      });

    }else{
      callback(false);
    }

  }catch(e){
    callback(false);
  }
}


// ---------------------------------------------------------------
// DNS over QUIC stub (not implemented yet)
// ---------------------------------------------------------------
function startQuicServer(serverCtx, quicOpt, handler){
  serverCtx.quic = { options: quicOpt, close: function(cb){ cb&&cb(); } };
}

// ---------------------------------------------------------------
// Server creation
// ---------------------------------------------------------------
function createServer(options, handler){
  options = options || {};

  // behavioral flags
    if (!options.always_aa) options.always_aa = true;
    if (!options.always_ra) options.always_ra = false;

  var onError = typeof options.onError === 'function' ? options.onError : function(){};

  // default transport options
  var udpOpt = options.udp===false ? null : (options.udp || { udp4:{ host:'0.0.0.0', port:53 }, udp6:{ host:'::', port:53 } });
  if (udpOpt && (!udpOpt.udp4 && !udpOpt.udp6)){
    var uhost = udpOpt.host||'0.0.0.0';
    var uport = (udpOpt.port == null) ? 53 : (udpOpt.port|0);
    udpOpt = { udp4:{ host:uhost, port:uport }, udp6:{ host:'::', port:uport } };
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
      // built-in in-memory cache
      var _map = new Map();
      var _mapMax = (options.dnssec.cacheMax|0) || 10000;
      dnssecCache = {
        get: function(params, cb){
          var k = params.hash + '|' + params.keyTag;
          cb(null, _map.get(k) || null);
        },
        set: function(params, value, cb){
          var k = params.hash + '|' + params.keyTag;
          if (_map.size >= _mapMax) _map.clear();
          _map.set(k, value);
          if (cb) cb(null);
        },
        clear: function(){ _map.clear(); },
        size: function(){ return _map.size; }
      };
    }
  }

  var serverCtx = {
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

  function earlyGuardsAndMaybeHandle(msg, transport, peer, rawBuf, socket, tlsInfo){
    // basic validity checks before passing to handler
    var qd = msg && msg.header ? (msg.header.qdcount|0) : 0;
    var opcode = msg && msg.header ? (msg.header.opcode|0) : 0;

    // EDNS BADVERS
    if (msg && msg.edns && (msg.edns.version|0) !== 0){
      var req = buildReq(transport, peer, rawBuf, msg, tlsInfo);
      var res = buildRes(req, serverCtx);
      res.header.rcode = 0; // MUST be 0, error goes in extRcode
      res.edns = res.edns || { udpSize: clamp( (req.edns&&req.edns.udpSize)||1232, 512, 4096 ), extRcode:16, version:0, do:false, z:0, options:[] };
      res.edns.extRcode = 16; // BADVERS
      // send immediately
      req._udp = (transport==='udp4'||transport==='udp6') ? socket : undefined;
      req._socket = (transport==='tcp'||transport==='tls') ? socket : undefined;
      return sendResponse(serverCtx, req, res);
    }

    if (qd < 1){
      var req0 = buildReq(transport, peer, rawBuf, msg, tlsInfo);
      var res0 = buildRes(req0, serverCtx);
      res0.header.rcode = 1; // FORMERR
      req0._udp = (transport==='udp4'||transport==='udp6') ? socket : undefined;
      req0._socket = (transport==='tcp'||transport==='tls') ? socket : undefined;
      return sendResponse(serverCtx, req0, res0);
    }

    if (!msg.questions || !msg.questions[0] || !msg.questions[0].name || !msg.questions[0].type) {
      var reqQ = buildReq(transport, peer, rawBuf, msg, tlsInfo);
      var resQ = buildRes(reqQ, serverCtx);
      resQ.header.rcode = 1; // FORMERR
      reqQ._udp = (transport==='udp4'||transport==='udp6') ? socket : undefined;
      reqQ._socket = (transport==='tcp'||transport==='tls') ? socket : undefined;
      return sendResponse(serverCtx, reqQ, resQ);
    }

    if (opcode !== 0){
      var req1 = buildReq(transport, peer, rawBuf, msg, tlsInfo);
      var res1 = buildRes(req1, serverCtx);
      res1.header.rcode = 4; // NOTIMP
      req1._udp = (transport==='udp4'||transport==='udp6') ? socket : undefined;
      req1._socket = (transport==='tcp'||transport==='tls') ? socket : undefined;
      return sendResponse(serverCtx, req1, res1);
    }

    // valid — pass to handler
    var req = buildReq(transport, peer, rawBuf, msg, tlsInfo);
    if (transport==='udp4' || transport==='udp6'){
      req._udp = socket;
    }else{
      req._socket = socket;
    }
    var res = buildRes(req, serverCtx);


    autoAnswerIfApplicable(req, res, serverCtx,function(is_sent){
      if(is_sent===false){
        return handler(req, res);
      }
    });
    
  }

  // --- UDP4 ---
  if (udpOpt && udpOpt.udp4){
    var u4 = dgram.createSocket('udp4');
    u4.on('message', function(buf, rinfo){
      try {
        var u8 = toU8(buf);
        var msg = wire.decodeMessage(u8);
        earlyGuardsAndMaybeHandle(msg, 'udp4', { address:rinfo.address, port:rinfo.port }, u8, u4, null);
      } catch (e){
        try {
          var dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
          var id = dv.getUint16(0, false);
          var errWire = wire.encodeMessage({ header:{ id:id, qr:true, rcode:1, qdcount:0, ancount:0, nscount:0, arcount:0 }, questions:[], answers:[], authority:[], additionals:[] });
          u4.send(toU8(errWire), rinfo.port, rinfo.address);
        } catch(_e){}
      }
    });
    u4.on('error', function(err){ onError(err, 'udp4'); });
    u4.bind((udpOpt.udp4.port|0)||53, udpOpt.udp4.host||'0.0.0.0');
    serverCtx.udp4 = u4;
  }

  // --- UDP6 ---
  if (udpOpt && udpOpt.udp6){
    var u6 = dgram.createSocket({type: 'udp6', ipv6Only: true});
    u6.on('message', function(buf, rinfo){
      try {
        var u8 = toU8(buf);
        var msg = wire.decodeMessage(u8);
        earlyGuardsAndMaybeHandle(msg, 'udp6', { address:rinfo.address, port:rinfo.port }, u8, u6, null);
      } catch (e){
        try {
          var dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
          var id = dv.getUint16(0, false);
          var errWire = wire.encodeMessage({ header:{ id:id, qr:true, rcode:1, qdcount:0, ancount:0, nscount:0, arcount:0 }, questions:[], answers:[], authority:[], additionals:[] });
          u6.send(toU8(errWire), rinfo.port, rinfo.address);
        } catch(_e){}
      }
    });
    u6.on('error', function(err){ onError(err, 'udp6'); });
    u6.bind((udpOpt.udp6.port|0)||53, udpOpt.udp6.host||'::');
    serverCtx.udp6 = u6;
  }

  // --- Shared DNS-over-stream handler (TCP + TLS) ---
  function handleStreamSocket(socket, transport, idleMs){
    var chunks = [];
    var totalLen = 0;

    socket.on('data', function(chunk){
      chunks.push(chunk);
      totalLen += chunk.length;

      // assemble only when needed
      var buf = chunks.length === 1 ? chunks[0] : Buffer.concat(chunks, totalLen);

      while (buf.length >= 2){
        var msgLen = buf.readUInt16BE(0);
        if (buf.length < 2 + msgLen) break;
        var body = buf.subarray(2, 2 + msgLen);
        buf = buf.subarray(2 + msgLen);
        try {
          var u8 = toU8(body);
          var msg = wire.decodeMessage(u8);
          var tlsInfo = (transport === 'tls') ? { authorized: !!socket.authorized, alpn: socket.alpnProtocol } : null;
          earlyGuardsAndMaybeHandle(msg, transport, { address: socket.remoteAddress, port: socket.remotePort }, u8, socket, tlsInfo);
        } catch(e){ socket.destroy(); return; }
      }

      // keep only the unparsed remainder
      if (buf.length === 0){
        chunks = [];
        totalLen = 0;
      } else {
        chunks = [buf];
        totalLen = buf.length;
      }
    });

    if (idleMs > 0) socket.setTimeout(idleMs, function(){ socket.destroy(); });
    socket.on('error', function(err){ onError(err, transport); });
  }

  // --- TCP ---
  if (tcpOpt){
    var tcp = net.createServer(function(socket){
      handleStreamSocket(socket, 'tcp', tcpOpt.idleMs || 0);
    });
    tcp.listen((tcpOpt.port|0) || 53, tcpOpt.host || '::');
    serverCtx.tcp = tcp;
  }

  // --- TLS (DoT) ---
  if (tlsOpt){
    if (!('ALPNProtocols' in tlsOpt)) tlsOpt.ALPNProtocols = ['dot'];
    var tlsSrv = tls.createServer(tlsOpt, function(socket){
      handleStreamSocket(socket, 'tls', tlsOpt.idleMs || 0);
    });
    tlsSrv.listen((tlsOpt.port|0) || 853, tlsOpt.host || '::');
    serverCtx.tls = tlsSrv;
  }

  // --- QUIC (stub) ---
  if (quicOpt){ startQuicServer(serverCtx, quicOpt, handler); }

  // return minimal control object (e.g. for shutdown)
  return {
    close: function(cb){
      var pending = 0; var done = function(){ if (--pending===0 && cb) cb(); };
      if (serverCtx.udp4){ pending++; serverCtx.udp4.close(done); }
      if (serverCtx.udp6){ pending++; serverCtx.udp6.close(done); }
      if (serverCtx.tcp){ pending++; serverCtx.tcp.close(done); }
      if (serverCtx.tls){ pending++; serverCtx.tls.close(done); }
      if (serverCtx.quic && serverCtx.quic.close){ pending++; serverCtx.quic.close(done); }
      if (pending===0 && cb) cb();
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
  };
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
    acc &= 0xFFFFFFFF;
  }
  acc += (acc >> 16) & 0xFFFF;
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

// Build a lazy name→RR[] index on the zone object (created once, reused on every query)
function getZoneIndex(zone){
  if (zone._index) return zone._index;
  var idx = new Map();
  for (var i = 0; i < zone.records.length; i++){
    var rr = zone.records[i];
    var arr = idx.get(rr.name);
    if (!arr){ arr = []; idx.set(rr.name, arr); }
    arr.push(rr);
  }
  zone._index = idx;
  return idx;
}

function answerFromZone(zone,qname,qtype,qclass){
  qtype = (qtype||'A').toUpperCase();
  qclass = (qclass||'IN').toUpperCase();

  var idx = getZoneIndex(zone);
  var fq = ensureDot(qname);

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
  function findSOA(){
    var apex = zone.origin || '.';
    var best=null;
    for (var i=0;i<zone.records.length;i++){
      var rr=zone.records[i];
      if (rr.type==='SOA' && rr.name===apex) return rr;
      if (!best && rr.type==='SOA') best = rr;
    }
    return best;
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

  // exact
  var answers = collect(fq, qtype);
  if (answers.length){
    var out = { rcode:0, answers:answers, authority:[], additionals:[], reason:'exact' };
    addGlue(out.answers, out.additionals);
    addSvcbHttpsHints(out.answers, out.additionals);
    return out;
  }
  if (existsName(fq)){
    var soa = findSOA();
    return { rcode:0, answers:[], authority: soa?[soa]:[], additionals:[], reason:'NODATA' };
  }
  // wildcard
  var wc = wildcardLookup(fq, qtype);
  if (wc.length){
    var out2 = { rcode:0, answers:wc, authority:[], additionals:[], reason:'wildcard' };
    addGlue(out2.answers, out2.additionals);
    addSvcbHttpsHints(out2.answers, out2.additionals);
    return out2;
  }
  var soa2 = findSOA();
  return { rcode:3, answers:[], authority: soa2?[soa2]:[], additionals:[], reason:'NXDOMAIN' };

  function addGlue(rrs, out){
    for (var i=0;i<rrs.length;i++){
      var rr=rrs[i];
      var targets=[];
      if (rr.type==='MX' && rr.data && rr.data.exchange) targets.push(rr.data.exchange);
      else if (rr.type==='SRV' && rr.data && rr.data.target) targets.push(rr.data.target);
      else if (rr.type==='NS' && rr.data && rr.data.name) targets.push(rr.data.name);
      else if ((rr.type==='SVCB'||rr.type==='HTTPS') && rr.data && rr.data.targetName) targets.push(rr.data.targetName);
      for (var t=0;t<targets.length;t++){
        var name=targets[t];
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