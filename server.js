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

var dgram = require('node:dgram');
var net   = require('node:net');
var tls   = require('node:tls');

var wire   = require('./wire');

var nobleHashes={
    hmac: require("@noble/hashes/hmac.js")['hmac'],
    hkdf: require("@noble/hashes/hkdf.js")['hkdf'],
    sha256: require("@noble/hashes/sha2.js")['sha256'],
};
var nobleCurves={
    p256: require("@noble/curves/nist")['p256'],
    secp256k1: require("@noble/curves/secp256k1")['secp256k1']
};





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
    // לפענח Base64 למערך בתים
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

function fqdn(name){
  if (!name) return '.';
  name = String(name).trim();
  if (name.charAt(name.length-1) !== '.') name += '.';
  return name.toLowerCase();
}

function familyOf(address){ return address && address.indexOf(':')!==-1 ? 'IPv6' : 'IPv4'; }

// המרה של ECS bytes לכתובת טקסטואלית
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
    // קיצור בסיסי של רצפי אפסים
    var s = parts.join(':').replace(/(^|:)0(:0)+(:|$)/, '::');
    return s;
  }

  return undefined;
}

// ---------------------------------------------------------------
// יצירת req/res (פונקציות)
// ---------------------------------------------------------------
function buildReq(transport, peer, buf, msg, tlsInfo){
  var q = (msg && msg.questions && msg.questions[0]) || null;
  var name = q ? fqdn(q.name) : '.';
  var type = q ? q.type : undefined;
  var klass = q ? q.class : undefined;

  var ed  = msg && msg.edns ? sanitizeEdns(msg.edns) : undefined;
  var ecs = ed && (ed.ecs || (ed.optionsStructured && ed.optionsStructured.ecs)) || undefined;
  var ecsIpStr = ecs ? ecsBytesToIP(ecs.family, ecs.addressBytes, ecs.sourcePrefixLength) : undefined;

  var req = {
    id: msg && msg.header ? (msg.header.id>>>0) : 0,
    transport: transport, // 'udp4'|'udp6'|'tcp'|'tls'|'quic'
    client: { address: peer.address, port: peer.port>>>0, family: familyOf(peer.address) },
    // אליאסים נוחים
    remoteAddress: peer.address,
    remotePort: peer.port>>>0,
    tls: tlsInfo || undefined,

    // השאלה הראשונה בלבד
    name: name,
    type: type,
    class: klass,

    // EDNS
    edns: ed,
    // דגל DO נגיש ישירות
    flag_do: !!(ed && ed.do),

    // ECS (אם קיים) – נגיש בקלות לטובת ניתוב/איזון עומסים
    ecs: ecs || undefined,
    ecsAddress: ecsIpStr || undefined,
    ecsSourcePrefixLength: ecs ? ecs.sourcePrefixLength : undefined,
    ecsScopePrefixLength:  ecs ? ecs.scopePrefixLength  : undefined,

    // גישה גולמית
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

  // הרמות משדות מפורקים
  if (ed.cookie) out.cookie = ed.cookie;
  if (ed.ecs) out.ecs = ed.ecs;
  if (!out.ecs && os.ecs) out.ecs = os.ecs; // <-- חשוב
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
// Truncation "חכם" + הזרקות לפני encode
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
  // סדר עדיפויות: השאר תמיד OPT, קצץ additionals → authority → answers (RRset‑wise, כאן נשמור פשטות: מחיקה שלמה של המקטע)
  var tryOrder = ['additionals','authority','answers'];
  res.header.tc = true;
  for (var i=0;i<tryOrder.length;i++){
    var sec = tryOrder[i];
    if (res[sec] && res[sec].length){
      var save = res[sec];
      res[sec] = [];
      var w = encodeNow(res, req);
      if (w.length <= udpMax) return w;
      // לא הספיק — החזר ונמשיך לקצר את הבא
      res[sec] = save;
    }
  }
  // אם גם אחרי כל זה גדול — חיתוך גס כמשענת אחרונה
  var w2 = encodeNow(res, req);
  return toU8(w2).slice(0, udpMax);
}

function finalizeWire(serverCtx, req, res){
  // לפני encode

  // קידוד ראשוני
  var wire2 = encodeNow(res, req);

  // UDP — טרנקציה חכמה
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
    var hash_sig = nobleHashes.sha256(hash_payload);
    var sig_data=nobleCurves.p256.sign(hash_sig, toU8(private_key)).toCompactRawBytes();

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
    if (req.transport === 'tcp'){
      var head = Buffer.alloc(2); head.writeUInt16BE(wire2.length, 0);
      req._socket && req._socket.write(Buffer.concat([head, Buffer.from(wire2)]));
      return;
    }
    if (req.transport === 'tls'){
      var head2 = Buffer.alloc(2); head2.writeUInt16BE(wire2.length, 0);
      req._socket && req._socket.write(Buffer.concat([head2, Buffer.from(wire2)]));
      return;
    }
    if (req.transport === 'quic'){
      if (req._quic && typeof req._quic.send === 'function') req._quic.send(wire2);
      return;
    }
  }

  var rrsig_exist=false;
  for(var i in res.answers){
    if(res.answers[i] && 'type' in res.answers[i] && res.answers[i].type=='RRSIG'){
      rrsig_exist=true;
      break;
    }
  }

  //console.log(ctx.options);

  if(rrsig_exist==false && res.answers.length>0 && req.flag_do && req.flag_do==true && ctx && ctx.options && ctx.options.dnssec && typeof ctx.options.dnssec.keyCallback=='function'){

    ctx.options.dnssec.keyCallback(req.name,function(error,result){

      if(result){
        try{
          var rrset_bytes=wire.buildRRsetBytesFromAnswers(res.answers);

          var labels=String(res.answers[0].name).replace(/\.$/, '').split('.').length;

          var the_key=null;
          if(res.answers[0].type=='DNSKEY'){
            the_key=result.ksk;
          }else{
            the_key=result.zsk;
          }

          var timestamp_now = Math.floor(Date.now() / 1000);

          if('inception' in the_key==false || the_key.inception<=0 || typeof the_key.inception!=='number'){
            the_key.inception=timestamp_now - 300;
          }

          if('expiration' in the_key==false || the_key.expiration<=0 || typeof the_key.expiration!=='number'){
            the_key.expiration=timestamp_now + (346 * 24 * 3600);
          }

          var sig_data=signRRset(result.signersName,rrset_bytes,13,the_key.keyTag,the_key.expiration,the_key.inception,the_key.privateKey,labels,res.answers[0].type,res.answers[0].ttl);

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

          res.answers.push(rrsig_record);

          res.additionals.push({
            type: 'OPT',
            name: '.',
            edns: {
              udpSize: 4096,
              extRcode: 0,
              version: 0,
              do: true,
              options: []
            }
          });

          actual_send();

        }catch(e2){
          console.log(e2);
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

    if(req.type === 'TLSA'){

      var for_domain=null;
			var regex = /^(?:_(\d+)\._(tcp|udp)\.)?([a-z0-9.-]+)\.?\s*$/i;
			var match = req.name.match(regex);
			if (match && match.length >= 4) {
				var port = match[1] ? parseInt(match[1], 10) : null;
				var protocol = match[2] ? match[2].toLowerCase() : null;
				for_domain = match[3].toLowerCase();
			}



    }else if(req.type === 'DNSKEY'){

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

    }else if(req.type === 'DS'){

      res.answers.push({
        name: '',
        type: 'DS',
        class: 'IN',
        ttl: 86400,
        data: {
          keyTag: 0,
          algorithm: 13,
          digestType: 0,
          digest: 0
        }
      });

      callback(false);

    }else{
      callback(false);
    }

    if (ctx && ctx.options && ctx.options.tls && typeof ctx.tls.SNICallback=='function') {
      
    }

    if (ctx && ctx.options && typeof ctx.dnssec.keyCallback=='function') {

    }


  }catch(e){
    callback(false);
  }
}


// ---------------------------------------------------------------
// הכנה ל‑DNS over QUIC (רק שלד, בלי מימוש כרגע)
// ---------------------------------------------------------------
function startQuicServer(serverCtx, quicOpt, handler){
  serverCtx.quic = { options: quicOpt, close: function(cb){ cb&&cb(); } };
}

// ---------------------------------------------------------------
// יצירת שרת (ללא classes)
// ---------------------------------------------------------------
function createServer(options, handler){
  options = options || {};

  // דגלים התנהגותיים
    if (!options.always_aa) options.always_aa = true;  // ברירת מחדל שביקשת
    if (!options.always_ra) options.always_ra = false; // אלא אם אתה רזולבר

  // הגדרות ברירת מחדל
  var udpOpt = options.udp===false ? null : (options.udp || { udp4:{ host:'0.0.0.0', port:53 }, udp6:{ host:'::', port:53 } });
  if (udpOpt && (!udpOpt.udp4 && !udpOpt.udp6)){
    var uhost = udpOpt.host||'0.0.0.0';
    var uport = udpOpt.port==null?53:(udpOpt.port|0);
    udpOpt = { udp4:{ host:uhost, port:uport }, udp6:{ host:'::', port:uport } };
  }

  var tcpOpt = options.tcp===false ? null : (options.tcp || { host:'::', port:53, idleMs:30000 });
  var tlsOpt = options.tls || null;
  var quicOpt = options.quic || null;

  // הקשר שרת
  var serverCtx = {
    udp4: null, 
    udp6: null, 
    tcp: null, 
    tls: null, 
    quic: null,
    options: options,
    _sendResponse: function(req, res){ return sendResponse(serverCtx, req, res); },
    _finalizeWire: function(req, res){ return finalizeWire(serverCtx, req, res); },
    dnssec: options.dnssec || null
  };

  function earlyGuardsAndMaybeHandle(msg, transport, peer, rawBuf, socket, tlsInfo){
    // בדיקות תקינות בסיסיות לפני handler
    var qd = msg && msg.header ? (msg.header.qdcount|0) : 0;
    var opcode = msg && msg.header ? (msg.header.opcode|0) : 0;

    // EDNS BADVERS
    if (msg && msg.edns && (msg.edns.version|0) !== 0){
      var req = buildReq(transport, peer, rawBuf, msg, tlsInfo);
      var res = buildRes(req, serverCtx);
      res.header.rcode = 0; // MUST be 0, השגיאה ב-extRcode
      res.edns = res.edns || { udpSize: clamp( (req.edns&&req.edns.udpSize)||1232, 512, 4096 ), extRcode:16, version:0, do:false, z:0, options:[] };
      res.edns.extRcode = 16; // BADVERS
      // שליחה מידית
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

    // תקין — מעבירים ל‑handler
    var req = buildReq(transport, peer, rawBuf, msg, tlsInfo);
    if (transport==='udp4' || transport==='udp6'){
      req._udp = socket;
    }else{
      req._socket = socket;
    }
    var res = buildRes(req, serverCtx);


    autoAnswerIfApplicable(req, res, serverCtx,function(is_sent){
      if(is_sent==false){
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
    u4.on('error', function(err){});
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
    u6.on('error', function(err){});
    u6.bind((udpOpt.udp6.port|0)||53, udpOpt.udp6.host||'::');
    serverCtx.udp6 = u6;
  }

  // --- TCP ---
  if (tcpOpt){
    var tcp = net.createServer(function(socket){
      var buf = Buffer.alloc(0);
      socket.on('data', function(chunk){
        buf = Buffer.concat([buf, chunk]);
        while (buf.length >= 2){
          var len = buf.readUInt16BE(0);
          if (buf.length < 2 + len) break;
          var body = buf.subarray(2, 2+len);
          buf = buf.subarray(2+len);
          try {
            var u8 = toU8(body);
            var msg = wire.decodeMessage(u8);
            earlyGuardsAndMaybeHandle(msg, 'tcp', { address:socket.remoteAddress, port:socket.remotePort }, u8, socket, null);
          } catch(e){ socket.destroy(); break; }
        }
      });
      if (tcpOpt.idleMs>0){ socket.setTimeout(tcpOpt.idleMs, function(){ socket.destroy(); }); }
      socket.on('error', function(err){});
    });
    tcp.listen((tcpOpt.port|0)||53, tcpOpt.host||'::');
    serverCtx.tcp = tcp;
  }

  // --- TLS (DoT) ---
  if (tlsOpt){

    if (!('ALPNProtocols' in tlsOpt)) {
        tlsOpt.ALPNProtocols = ['dot'];
    }

    var tlsSrv = tls.createServer(tlsOpt, function(socket){
      var buf = Buffer.alloc(0);
      socket.on('data', function(chunk){
        buf = Buffer.concat([buf, chunk]);
        while (buf.length >= 2){
          var len = buf.readUInt16BE(0);
          if (buf.length < 2 + len) break;
          var body = buf.subarray(2, 2+len);
          buf = buf.subarray(2+len);
          try {
            var u8 = toU8(body);
            var msg = wire.decodeMessage(u8);
            var tlsInfo = { authorized: !!socket.authorized, alpn: socket.alpnProtocol };
            earlyGuardsAndMaybeHandle(msg, 'tls', { address:socket.remoteAddress, port:socket.remotePort }, u8, socket, tlsInfo);
          } catch(e){ socket.destroy(); break; }
        }
      });
      if (tlsOpt.idleMs>0){ socket.setTimeout(tlsOpt.idleMs, function(){ socket.destroy(); }); }
      socket.on('error', function(err){});
    });
    tlsSrv.listen((tlsOpt.port|0) || 853, tlsOpt.host||'::');
    serverCtx.tls = tlsSrv;
  }

  // --- QUIC (שלד) ---
  if (quicOpt){ startQuicServer(serverCtx, quicOpt, handler); }

  // מחזירים אובייקט שליטה מינימלי (למשל לסגירה)
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
    context: serverCtx // אם תרצה גישה פנימית (למשל ל‑sockets)
  };
}




function deriveP256PublicXY(priv){
  var full = nobleCurves.p256.getPublicKey(priv, false); // 65 bytes: 0x04 || X || Y
  var pub = full.slice(1);
  if (pub.length !== 64) throw new Error('P-256 public key must be 64 bytes (X||Y).');
  return pub;
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

  // קבועים לפי RFC
  var algorithm  = 13;            // ECDSAP256SHA256
  var digestType = 2;             // SHA-256
  var protocol   = 3;             // תמיד 3
  var KSK_FLAGS  = 257;           // SEP
  var ZSK_FLAGS  = 256;           // ללא SEP

  var signer = fqdn(params.signersName);

  // --- KSK ---
  var kskPrivRaw = (params.ksk && params.ksk.privateKey) ? toU8(params.ksk.privateKey) : nobleCurves.p256.utils.randomPrivateKey();
  var kskPubRaw  = deriveP256PublicXY(kskPrivRaw);
  var kskRdata   = buildDnskeyRdata(KSK_FLAGS, protocol, algorithm, kskPubRaw);
  var kskTag     = computeDnskeyKeyTag(kskRdata);

  // לחשב DS (owner_wire + DNSKEY_RDATA של ה־KSK)
  var tmp = new Uint8Array(256);
  var len = wire.encodeName(tmp, 0, signer.toLowerCase()); // ללא קומפרסיה
  var ownerWire=tmp.slice(0, len);

  

  var toDigest   = new Uint8Array(ownerWire.length + kskRdata.length);
  toDigest.set(ownerWire, 0);
  toDigest.set(kskRdata, ownerWire.length);

  var dsBytes;
  if (digestType === 2) {
    dsBytes = nobleHashes.sha256(toDigest);
  } else if (digestType === 4) {
    dsBytes = nobleHashes.sha384(toDigest);
  } else {
    throw new Error('Unsupported digestType (use 2 for SHA-256 or 4 for SHA-384)');
  }
  var dsHex = toHex(dsBytes);

  // --- ZSK ---
  var zskPrivRaw = (params.zsk && params.zsk.privateKey) ? toU8(params.zsk.privateKey) : nobleCurves.p256.utils.randomPrivateKey();
  var zskPubRaw  = deriveP256PublicXY(zskPrivRaw);
  var zskRdata   = buildDnskeyRdata(ZSK_FLAGS, protocol, algorithm, zskPubRaw);
  var zskTag     = computeDnskeyKeyTag(zskRdata);

  // --- פלט בפורמט הפשוט לשימוש ---
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

function answerFromZone(zone,qname,qtype,qclass){
  // Work only with zone.records (compact array) — no byName map.
  qtype = (qtype||'A').toUpperCase();
  qclass = (qclass||'IN').toUpperCase();

  function ensureDot(n){ if (!n) return '.'; return n[n.length-1]==='.'?n:n+'.'; }
  function absName(n){ return (n && n[n.length-1]==='.') ? n : ensureDot(n||''); }

  var fq = absName(qname);

  function existsName(name){
    for (var i=0;i<zone.records.length;i++){ if (zone.records[i].name === name) return true; }
    return false;
  }
  function collect(name, type){
    var out=[];
    for (var i=0;i<zone.records.length;i++){
      var rr=zone.records[i];
      if (rr.name===name && (type==='ANY' || rr.type===type)) out.push(rr);
    }
    return out;
  }
  function collectAllTypes(name){
    var out=[]; for (var i=0;i<zone.records.length;i++){ var rr=zone.records[i]; if (rr.name===name) out.push(rr); } return out;
  }
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
      if (p && Array.isArray(p.ipv6hint)) for (var h6=0; h<p.ipv6hint.length; h6++) out.push({ name: targetName, type:'AAAA', class:'IN', ttl: rr.ttl, data:{ address: p.ipv6hint[h6] }});
    }
  }
}


module.exports = {
  createServer: createServer,
  buildDnssecMaterial: buildDnssecMaterial,
  answerFromZone: answerFromZone
};