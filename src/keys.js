/*
 * dnssec-server: DNSSEC keys - local, or behind an external signer
 * Copyright 2025 colocohen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 */

import * as SPKI from 'cryptographic-formats/spki';
import * as PKCS8 from 'cryptographic-formats/pkcs8';
import * as PEM from 'cryptographic-formats/pem';
import * as SIG from 'cryptographic-formats/signature';
import * as JWK from 'cryptographic-formats/jwk';
import { p256 } from 'cryptographic-primitives/nist.js';
import * as ED25519 from 'cryptographic-primitives/ed25519.js';
import { sha256_sync } from 'cryptographic-primitives/sha2.js';

// The keys' encodings (SPKI, PKCS#8, PEM, JWK) are cryptographic-formats';
// the keys themselves - generating, deriving the public key, signing,
// verifying - cryptographic-primitives'. The curve's name, as
// cryptographic-formats spells P-256.
var P256 = 'secp256r1';

// The DNSSEC algorithms this server signs with:
//   13  ECDSAP256SHA256 (RFC 6605)  - P-256, signature r||s (64 bytes)
//   15  ED25519         (RFC 8080)  - Ed25519, signature 64 bytes
// The algorithm follows from the key: a P-256 key is 13, an Ed25519 key 15.
var ALGORITHMS = { 13: 'P-256', 15: 'Ed25519' };

function keyError(code, message){
  var e = new Error(message);
  e.code = code;
  return e;
}

function toU8(x){
  if (x instanceof Uint8Array) return new Uint8Array(x.buffer, x.byteOffset, x.byteLength);
  if (typeof x === 'string') return new Uint8Array(Buffer.from(x, 'base64'));
  if (x && x.buffer instanceof ArrayBuffer) return new Uint8Array(x.buffer, x.byteOffset || 0, x.byteLength);
  throw keyError('KEY_INVALID', 'a key must be bytes or base64');
}

function b64(u8){ return Buffer.from(u8).toString('base64'); }

// A node:crypto KeyObject, told by its shape (it is read through its own
// export(), so this module needs no node:crypto)
function isKeyObject(x){
  return !!x && typeof x === 'object' && typeof x.export === 'function' && typeof x.asymmetricKeyType === 'string' &&
         (x.type === 'public' || x.type === 'private');
}

// --- public keys ---

// A public key as the API takes it - SPKI PEM or DER, a KeyObject (public or
// private), or a JWK - read by cryptographic-formats: { algorithm, curve, point }.
function toPublicKeyObject(input){
  try {
    if (isKeyObject(input)){
      if (input.type === 'public') return SPKI.from_der(new Uint8Array(input.export({ type: 'spki', format: 'der' })));
      return publicOfPrivate(PKCS8.from_der(new Uint8Array(input.export({ type: 'pkcs8', format: 'der' }))));
    }
    if (typeof input === 'string'){
      var block = PEM.decode(input).filter(function(b){ return b.label === 'PUBLIC KEY'; })[0];
      if (!block) throw new Error('no PUBLIC KEY block');
      return SPKI.from_der(block.der);
    }
    if (input instanceof Uint8Array || Buffer.isBuffer(input)) return SPKI.from_der(toU8(input));
    if (input && typeof input === 'object' && input.kty) return JWK.to_key(input);
  } catch (e){
    throw keyError('KEY_INVALID', 'publicKey cannot be read: ' + e.message);
  }
  throw keyError('KEY_INVALID', 'publicKey: SPKI PEM or DER, a KeyObject, or a JWK');
}

// The public key of a private one (cryptographic-formats' PKCS#8 shape)
function publicOfPrivate(p){
  if (p.algorithm === 'Ed25519') return { algorithm: 'Ed25519', point: ED25519.get_public_key_sync(p.scalar) };
  if (p.algorithm === 'ecPublicKey' && p.curve === P256) return { algorithm: 'ecPublicKey', curve: P256, point: p.point || p256.get_public_key_sync(p.scalar, false) };
  return { algorithm: p.algorithm, curve: p.curve };
}

// → { algorithm, dnskey }: the DNSSEC algorithm, and the key as the DNSKEY
// record carries it - P-256: x||y (64 bytes, the uncompressed point without
// its 0x04); Ed25519: the 32-byte key.
function dnskeyFromPublic(spki){
  if (spki.algorithm === 'Ed25519') return { algorithm: 15, dnskey: new Uint8Array(spki.point) };
  if (spki.algorithm === 'ecPublicKey'){
    if (spki.curve !== P256) throw keyError('KEY_INVALID', 'an EC key for DNSSEC must be P-256 (algorithm 13), not ' + spki.curve);
    var point = spki.point;
    if (point[0] !== 0x04) point = uncompressed(point);   // a compressed point: the same key
    return { algorithm: 13, dnskey: new Uint8Array(point.subarray(1)) };
  }
  throw keyError('KEY_INVALID', 'DNSSEC keys are P-256 (algorithm 13) or Ed25519 (algorithm 15), not ' +
                 ({ rsaEncryption: 'rsa', Ed448: 'ed448' }[spki.algorithm] || spki.algorithm));
}

// A compressed P-256 point, uncompressed (04 || x || y)
function uncompressed(point){
  var xy = p256.decode_point_sync(point);
  var hex = function(n){ return n.toString(16).padStart(64, '0'); };
  return new Uint8Array(Buffer.from('04' + hex(xy.x) + hex(xy.y), 'hex'));
}

// --- local private keys: the raw 32 bytes the material keeps ---

function publicFromRaw(algorithm, raw){
  if (raw.length !== 32) throw keyError('KEY_INVALID', 'a raw DNSSEC private key is 32 bytes (got ' + raw.length + ')');
  return algorithm === 15 ? ED25519.get_public_key_sync(raw) : p256.get_public_key_sync(raw, false).subarray(1);
}

function generateRaw(algorithm){
  return new Uint8Array(algorithm === 15 ? ED25519.keygen_sync().sk : p256.keygen_sync().sk);
}

// A private key given as PEM (PKCS#8 or SEC 1) or a KeyObject → { algorithm, raw }
function rawFromPrivate(input){
  var p;
  try {
    if (isKeyObject(input)) p = PKCS8.from_der(new Uint8Array(input.export({ type: 'pkcs8', format: 'der' })));
    else {
      var blocks = PEM.decode(String(input));
      for (var i = 0; i < blocks.length && !p; i++){
        if (blocks[i].encrypted || blocks[i].label === 'ENCRYPTED PRIVATE KEY') throw new Error('the key is encrypted');
        if (blocks[i].label === 'PRIVATE KEY') p = PKCS8.from_der(blocks[i].der);
        else if (blocks[i].label === 'EC PRIVATE KEY') p = PKCS8.sec1_from_der(blocks[i].der);
      }
      if (!p) throw new Error('no private key in the PEM');
    }
  } catch (e){ throw keyError('KEY_INVALID', 'privateKey cannot be read: ' + e.message); }
  var alg = dnskeyFromPublic(publicOfPrivate(p)).algorithm;
  return { algorithm: alg, raw: new Uint8Array(p.scalar) };
}

// --- one key, as buildDnssecMaterial is given it ---
//
//   undefined / {}                    generated (algorithm: params.algorithm, default 13)
//   { privateKey: raw 32 bytes|b64 }  as before; algorithm: spec.algorithm, params.algorithm, or 13
//   { privateKey: PEM | KeyObject }   the algorithm from the key's type
//   { publicKey, sign(bytes, cb) }    an external signer (HSM, KMS, threshold signing)
//
// → { algorithm, publicKey (DNSKEY bytes), privateRaw | null, signer | null }

function isSigner(spec){ return !!spec && typeof spec.sign === 'function'; }

function readKey(spec, defaultAlgorithm, role){
  try {
    if (isSigner(spec)){
      if (spec.publicKey == null) throw keyError('KEY_INVALID', 'a signer needs publicKey');
      var pub = dnskeyFromPublic(toPublicKeyObject(spec.publicKey));
      if (spec.algorithm != null && Number(spec.algorithm) !== pub.algorithm){
        throw keyError('KEY_INVALID', 'algorithm ' + spec.algorithm + ' does not match the key (' + ALGORITHMS[pub.algorithm] + ' is ' + pub.algorithm + ')');
      }
      return { algorithm: pub.algorithm, publicKey: pub.dnskey, privateRaw: null, signer: spec };
    }
    var alg, raw;
    if (spec && spec.privateKey != null){
      var pk = spec.privateKey;
      var pemOrObject = isKeyObject(pk) || (typeof pk === 'string' && pk.indexOf('-----BEGIN') >= 0);
      if (pemOrObject){
        var r = rawFromPrivate(pk);
        alg = r.algorithm; raw = r.raw;
        if (spec.algorithm != null && Number(spec.algorithm) !== alg){
          throw keyError('KEY_INVALID', 'algorithm ' + spec.algorithm + ' does not match the key (' + ALGORITHMS[alg] + ' is ' + alg + ')');
        }
      } else {
        alg = Number(spec.algorithm || defaultAlgorithm || 13);
        raw = toU8(pk);
      }
    } else {
      alg = Number((spec && spec.algorithm) || defaultAlgorithm || 13);
      raw = generateRaw(alg);
    }
    if (!ALGORITHMS[alg]) throw keyError('KEY_INVALID', 'DNSSEC algorithm ' + alg + ' is not supported (13: P-256, 15: Ed25519)');
    var pubKey = new Uint8Array(publicFromRaw(alg, raw));
    return { algorithm: alg, publicKey: pubKey, privateRaw: raw, signer: null };
  } catch (e){
    if (!e.code) e.code = 'KEY_INVALID';
    e.message = role + ': ' + e.message;
    throw e;
  }
}


// --- signing ---

// Local keys: the library's signer, made once per key
var signers = new Map();
function localSigner(algorithm, privateKey){
  var id = algorithm + '|' + (typeof privateKey === 'string' ? privateKey : b64(privateKey));
  var sg = signers.get(id);
  if (!sg){
    var raw = toU8(privateKey);
    if (raw.length !== 32) throw keyError('KEY_INVALID', 'a raw DNSSEC private key is 32 bytes (got ' + raw.length + ')');
    sg = algorithm === 15 ? ED25519.signer_create(raw) : p256.signer_create(raw);
    if (signers.size >= 1000){ var old = signers.keys().next().value; signers.get(old).wipe(); signers.delete(old); }
    signers.set(id, sg);
  }
  return sg;
}

// Public keys: the library's verifier, made once per key
var verifiers = new Map();
function verifierOf(key){
  var id = key.algorithm + '|' + key.publicKey;
  var v = verifiers.get(id);
  if (!v){
    var pk = toU8(key.publicKey);
    v = Number(key.algorithm) === 15 ? ED25519.verifier_create(pk, undefined, undefined, 'strict')
                                     : p256.verifier_create(concat([0x04], pk));
    if (verifiers.size >= 1000) verifiers.delete(verifiers.keys().next().value);
    verifiers.set(id, v);
  }
  return v;
}

function concat(a, b){
  var out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function big(bytes){
  var n = 0n;
  for (var i = 0; i < bytes.length; i++) n = (n << 8n) | BigInt(bytes[i]);
  return n;
}
function be32(n){
  return new Uint8Array(Buffer.from(n.toString(16).padStart(64, '0'), 'hex'));
}

// A P-256 ECDSA signature in DER (SEQUENCE { INTEGER r, INTEGER s }) → r||s,
// 64 bytes; null when it is not one
function derToRaw(der){
  try { return new Uint8Array(SIG.der_to_raw({ der: der, curve: P256 })); }
  catch (e){ return null; }
}

// A signature (r||s for P-256) over payload by key's public key
function verify(key, payload, sig){
  try {
    if (Number(key.algorithm) === 15) return verifierOf(key).verify_sync(payload, sig) === true;
    if (sig.length !== 64) return false;
    return verifierOf(key).verify_message_sync(sha256_sync, payload, { r: big(sig.subarray(0, 32)), s: big(sig.subarray(32)) }) === true;
  } catch (e){ return false; }
}

// One local signature: Ed25519's 64 bytes, or P-256's r||s
function signLocal(algorithm, privateKey, payload){
  var sg = localSigner(algorithm, privateKey);
  if (algorithm === 15) return sg.sign_sync(payload);
  var rs = sg.sign_message_sync(sha256_sync, payload);
  return concat(be32(rs.r), be32(rs.s));
}

// Sign the RRSIG payload with a key from the material:
//   { algorithm, publicKey, privateKey }  locally
//   { algorithm, publicKey, signer }      through signer.sign(bytes, cb) - with a
//                                         timeout, retries for retryable errors,
//                                         and the signature verified before use
// cb(err, signature) - err.code: SIGN_TIMEOUT | SIGN_REJECTED | SIGN_INVALID | KEY_INVALID
function signPayload(key, payload, opts, cb){
  var algorithm = Number(key.algorithm) || 13;
  if (!ALGORITHMS[algorithm]) return setImmediate(cb, keyError('KEY_INVALID', 'DNSSEC algorithm ' + algorithm + ' is not supported'));

  if (!key.signer){
    var sig;
    try {
      sig = signLocal(algorithm, key.privateKey, toU8(payload));
    } catch (e){
      if (!e.code) e.code = 'KEY_INVALID';
      return setImmediate(cb, e);
    }
    return setImmediate(cb, null, sig);
  }

  var timeout = opts && opts.signTimeout > 0 ? opts.signTimeout : 1500;
  var retries = opts && opts.signRetries >= 0 ? opts.signRetries : 0;
  var attempt = 0;

  (function tryOnce(){
    var done = false;
    // Not unref'd: a signature in progress keeps the process alive
    var timer = setTimeout(function(){
      if (done) return;
      done = true;
      if (attempt < retries){ attempt++; return tryOnce(); }
      cb(keyError('SIGN_TIMEOUT', 'the signer did not answer within ' + timeout + 'ms'));
    }, timeout);

    function answer(err, signature){
      if (done) return;            // late, or called twice
      done = true;
      clearTimeout(timer);
      if (err){
        if (err.retryable && attempt < retries){ attempt++; return tryOnce(); }
        var e = keyError('SIGN_REJECTED', 'the signer refused: ' + (err.message || err));
        e.cause = err;
        return cb(e);
      }
      var s;
      try { s = toU8(signature); } catch (x){ return cb(keyError('SIGN_INVALID', 'the signer returned no signature')); }
      // P-256: r||s, or DER - accepted, and made r||s
      if (algorithm === 13 && s.length !== 64){
        var raw = derToRaw(s);
        if (!raw) return cb(keyError('SIGN_INVALID', 'a P-256 signature is 64 bytes (r||s) or DER, got ' + s.length + ' bytes'));
        s = raw;
      }
      if (algorithm === 15 && s.length !== 64) return cb(keyError('SIGN_INVALID', 'an Ed25519 signature is 64 bytes, got ' + s.length));
      if (!verify(key, payload, s)) return cb(keyError('SIGN_INVALID', 'the signature does not verify under the key\'s public key - the signer used another key'));
      cb(null, s);
    }

    try { key.signer.sign(new Uint8Array(payload), answer); }
    catch (e){ answer(e); }
  })();
}

export { ALGORITHMS, readKey, signPayload, isSigner, keyError, toPublicKeyObject, dnskeyFromPublic, b64 };
