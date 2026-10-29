// DNS Cookies (RFC 7873), with the interoperable Server Cookie of RFC 9018.
//
// A query over UDP can come from a forged address. A server cookie proves it
// did not: the server hands one to each client — a keyed hash of the
// client's own cookie and its address — and only a client at that address
// can send it back. With it, the server knows the address is real; without
// it, a response may go to a victim (reflection).
//
// Server Cookie, version 1 (RFC 9018 §4):
//   Version (1) = 1 | Reserved (3) | Timestamp (4, seconds) | Hash (8)
//   Hash = SipHash-2-4( Client Cookie | Version | Reserved | Timestamp | Client-IP, Secret )
// Every server that holds the same secret makes and accepts the same cookies,
// so an anycast set shares one.

var COOKIE_CLIENT_LEN = 8;
var COOKIE_V1_LEN = 24;            // a version 1 option: client (8) + server (16), exactly (RFC 9018 §4.4)
var VALID_PAST = 3600;             // a cookie made up to an hour ago is accepted…
var VALID_FUTURE = 300;            // …or up to 5 minutes ahead, for clock skew in an anycast set (§4.3)
var RENEW_AFTER = 1800;            // older than half an hour: a new one goes back (§4.3)

// ---------------------------------------------------------------
// SipHash-2-4 (Aumasson & Bernstein), 64-bit words held as 32-bit halves.
// ---------------------------------------------------------------
function sipHash24(key, msg){
  var k0l = le32(key, 0), k0h = le32(key, 4), k1l = le32(key, 8), k1h = le32(key, 12);
  var v0l = (k0l ^ 0x70736575) >>> 0, v0h = (k0h ^ 0x736f6d65) >>> 0;
  var v1l = (k1l ^ 0x6e646f6d) >>> 0, v1h = (k1h ^ 0x646f7261) >>> 0;
  var v2l = (k0l ^ 0x6e657261) >>> 0, v2h = (k0h ^ 0x6c796765) >>> 0;
  var v3l = (k1l ^ 0x79746573) >>> 0, v3h = (k1h ^ 0x74656462) >>> 0;
  var t, lo, hi;

  // Every value kept unsigned (>>> 0): the carry test (lo < a) needs it.
  function round(){
    // v0 += v1; v1 <<<= 13; v1 ^= v0; v0 <<<= 32
    lo = (v0l + v1l) >>> 0; v0h = (v0h + v1h + (lo < v0l ? 1 : 0)) >>> 0; v0l = lo;
    t = v1h; v1h = ((v1h << 13 | v1l >>> 19) ^ v0h) >>> 0; v1l = ((v1l << 13 | t >>> 19) ^ v0l) >>> 0;
    t = v0l; v0l = v0h; v0h = t;
    // v2 += v3; v3 <<<= 16; v3 ^= v2
    lo = (v2l + v3l) >>> 0; v2h = (v2h + v3h + (lo < v2l ? 1 : 0)) >>> 0; v2l = lo;
    t = v3h; v3h = ((v3h << 16 | v3l >>> 16) ^ v2h) >>> 0; v3l = ((v3l << 16 | t >>> 16) ^ v2l) >>> 0;
    // v0 += v3; v3 <<<= 21; v3 ^= v0
    lo = (v0l + v3l) >>> 0; v0h = (v0h + v3h + (lo < v0l ? 1 : 0)) >>> 0; v0l = lo;
    t = v3h; v3h = ((v3h << 21 | v3l >>> 11) ^ v0h) >>> 0; v3l = ((v3l << 21 | t >>> 11) ^ v0l) >>> 0;
    // v2 += v1; v1 <<<= 17; v1 ^= v2; v2 <<<= 32
    lo = (v2l + v1l) >>> 0; v2h = (v2h + v1h + (lo < v2l ? 1 : 0)) >>> 0; v2l = lo;
    t = v1h; v1h = ((v1h << 17 | v1l >>> 15) ^ v2h) >>> 0; v1l = ((v1l << 17 | t >>> 15) ^ v2l) >>> 0;
    t = v2l; v2l = v2h; v2h = t;
  }
  function compress(ml, mh){
    v3l = (v3l ^ ml) >>> 0; v3h = (v3h ^ mh) >>> 0;
    round(); round();
    v0l = (v0l ^ ml) >>> 0; v0h = (v0h ^ mh) >>> 0;
  }

  var len = msg.length, end = len - (len % 8), i;
  for (i = 0; i < end; i += 8) compress(le32(msg, i), le32(msg, i + 4));
  // The last word: the remaining bytes, and the length in the top byte.
  var last = new Uint8Array(8);
  for (var j = 0; i + j < len; j++) last[j] = msg[i + j];
  last[7] = len & 0xFF;
  compress(le32(last, 0), le32(last, 4));

  v2l = (v2l ^ 0xFF) >>> 0;
  round(); round(); round(); round();

  var out = new Uint8Array(8);
  wle32(out, 0, (v0l ^ v1l ^ v2l ^ v3l) >>> 0);
  wle32(out, 4, (v0h ^ v1h ^ v2h ^ v3h) >>> 0);
  return out;
}
function le32(b, o){ return (b[o] | b[o + 1] << 8 | b[o + 2] << 16 | b[o + 3] << 24) >>> 0; }
function wle32(b, o, v){ b[o] = v & 0xFF; b[o + 1] = (v >>> 8) & 0xFF; b[o + 2] = (v >>> 16) & 0xFF; b[o + 3] = (v >>> 24) & 0xFF; }

// ---------------------------------------------------------------
// Addresses: the 4 or 16 bytes the hash takes. An IPv4 client reached
// through a dual-stack socket ('::ffff:a.b.c.d') is the IPv4 client.
// ---------------------------------------------------------------
function addressBytes(addr){
  addr = String(addr || '');
  var m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(addr);
  if (m) addr = m[1];
  if (/^\d+\.\d+\.\d+\.\d+$/.test(addr)){
    var p = addr.split('.');
    return new Uint8Array([p[0] & 0xFF, p[1] & 0xFF, p[2] & 0xFF, p[3] & 0xFF]);
  }
  var zone = addr.indexOf('%'); if (zone >= 0) addr = addr.slice(0, zone);
  if (addr.indexOf(':') < 0) return null;
  var halves = addr.split('::');
  if (halves.length > 2) return null;
  var head = halves[0] ? halves[0].split(':') : [];
  var tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  // An IPv4 tail ('…:1.2.3.4') is two groups.
  var lastG = tail.length ? tail : head;
  if (lastG.length && lastG[lastG.length - 1].indexOf('.') >= 0){
    var v4 = lastG.pop().split('.');
    lastG.push(((v4[0] << 8) | v4[1]).toString(16), ((v4[2] << 8) | v4[3]).toString(16));
  }
  var fill = 8 - head.length - tail.length;
  if (fill < 0 || (halves.length === 1 && fill !== 0)) return null;
  var groups = head.concat(new Array(fill).fill('0'), tail);
  var out = new Uint8Array(16);
  for (var i = 0; i < 8; i++){
    var g = parseInt(groups[i], 16);
    if (!(g >= 0 && g <= 0xFFFF)) return null;
    out[i * 2] = g >> 8; out[i * 2 + 1] = g & 0xFF;
  }
  return out;
}

function toSecret(s){
  if (s == null) return null;
  var b = typeof s === 'string' ? Buffer.from(s, 'hex') : s;
  if (!(b instanceof Uint8Array) || b.length !== 16) throw new TypeError('cookies: a secret is 16 bytes (a Uint8Array, or 32 hex characters)');
  return new Uint8Array(b);
}

// ---------------------------------------------------------------
// The jar: one per server.
//
//   options.cookies   undefined / true → on, with a random secret (enough for
//                     one server; restarting changes it, and clients simply
//                     learn a new cookie)
//                     { secret, previousSecret } → on, with these: 16 bytes
//                     each. Every server of an anycast set gets the same
//                     secret. On rollover the old one goes in previousSecret
//                     and is still accepted (RFC 9018 §5).
//                     false → off: a COOKIE option is ignored (RFC 7873 §5.2)
// ---------------------------------------------------------------
export function createCookieJar(opt, randomBytes, now){
  if (opt === false) return null;
  opt = (opt && typeof opt === 'object') ? opt : {};
  var secret = toSecret(opt.secret) || new Uint8Array(randomBytes(16));
  var previous = toSecret(opt.previousSecret);
  now = now || function(){ return Math.floor(Date.now() / 1000); };

  function hashFor(secretKey, client, prefix, ip){
    var input = new Uint8Array(COOKIE_CLIENT_LEN + 8 + ip.length);
    input.set(client, 0);
    input.set(prefix, COOKIE_CLIENT_LEN);       // version, reserved, timestamp — as received
    input.set(ip, COOKIE_CLIENT_LEN + 8);
    return sipHash24(secretKey, input);
  }
  function same(a, b, off){
    var d = 0;
    for (var i = 0; i < 8; i++) d |= a[i] ^ b[off + i];
    return d === 0;
  }

  // What the query carries, given its COOKIE option's bytes (or none) and
  // the client's address:
  //   { status: 'none' }                      no COOKIE option
  //   { status: 'malformed' }                 a length RFC 7873 §5.2.2 forbids → FORMERR
  //   { status: 'client', client }            only a client cookie, or a server
  //                                           cookie that is not (or no longer) ours
  //   { status: 'valid', client, server, age }
  function inspect(optionData, address){
    if (!optionData) return { status: 'none' };
    var n = optionData.length;
    if (n < COOKIE_CLIENT_LEN || (n > COOKIE_CLIENT_LEN && n < 16) || n > 40) return { status: 'malformed' };
    var client = optionData.slice(0, COOKIE_CLIENT_LEN);
    var ip = addressBytes(address);
    if (n !== COOKIE_V1_LEN || optionData[8] !== 1 || !ip) return { status: 'client', client: client, ip: ip };

    var ts = ((optionData[12] << 24) | (optionData[13] << 16) | (optionData[14] << 8) | optionData[15]) >>> 0;
    // Serial number arithmetic (RFC 1982): the signed difference.
    var age = (now() - ts) | 0;
    if (age > VALID_PAST || age < -VALID_FUTURE) return { status: 'client', client: client, ip: ip };

    var prefix = optionData.subarray(8, 16);
    if (same(hashFor(secret, client, prefix, ip), optionData, 16) ||
        (previous && same(hashFor(previous, client, prefix, ip), optionData, 16))){
      return { status: 'valid', client: client, ip: ip, server: optionData.slice(8, 24), age: age };
    }
    return { status: 'client', client: client, ip: ip };
  }

  // The COOKIE option for the response: the client's cookie and a server
  // cookie — the one it sent back, while that is under half an hour old and
  // made with the current secret; otherwise a new one.
  function responseOption(state){
    var server;
    if (state.status === 'valid' && state.age >= 0 && state.age < RENEW_AFTER){
      var prefix = state.server.subarray(0, 8);
      if (same(hashFor(secret, state.client, prefix, state.ip), state.server, 8)) server = state.server;
    }
    if (!server){
      var t = now() >>> 0;
      var fresh = new Uint8Array([1, 0, 0, 0, (t >>> 24) & 0xFF, (t >>> 16) & 0xFF, (t >>> 8) & 0xFF, t & 0xFF]);
      server = new Uint8Array(16);
      server.set(fresh, 0);
      server.set(hashFor(secret, state.client, fresh, state.ip), 8);
    }
    var data = new Uint8Array(COOKIE_V1_LEN);
    data.set(state.client, 0);
    data.set(server, COOKIE_CLIENT_LEN);
    return data;
  }

  return { inspect: inspect, responseOption: responseOption };
}

export { sipHash24, addressBytes };
