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

import crypto from 'node:crypto';
import * as SPKI from 'cryptographic-formats/spki';
import * as PKCS8 from 'cryptographic-formats/pkcs8';
import * as SIG from 'cryptographic-formats/signature';
import * as JWK from 'cryptographic-formats/jwk';

// node:crypto takes and gives a raw key only inside SPKI or PKCS#8 (or a
// JWK); cryptographic-formats writes and reads that wrapping. The curve's name, as
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


// --- public keys ---

// A public key as Node takes it: SPKI PEM or DER, a KeyObject (public or
// private), or a JWK.
function toPublicKeyObject(input){
  if (input instanceof crypto.KeyObject) return input.type === 'private' ? crypto.createPublicKey(input) : input;
  try {
    if (typeof input === 'string') return crypto.createPublicKey(input);
    if (input instanceof Uint8Array || Buffer.isBuffer(input)) return crypto.createPublicKey({ key: Buffer.from(input), format: 'der', type: 'spki' });
    if (input && typeof input === 'object' && input.kty) return crypto.createPublicKey({ key: Buffer.from(SPKI.to_der(JWK.to_key(input))), format: 'der', type: 'spki' });
  } catch (e){
    throw keyError('KEY_INVALID', 'publicKey cannot be read: ' + e.message);
  }
  throw keyError('KEY_INVALID', 'publicKey: SPKI PEM or DER, a KeyObject, or a JWK');
}

// → { algorithm, dnskey }: the DNSSEC algorithm, and the key as the DNSKEY
// record carries it - P-256: x||y (64 bytes, the uncompressed point without
// its 0x04); Ed25519: the 32-byte key.
function dnskeyFromPublic(ko){
  var spki = SPKI.from_der(ko.export({ type: 'spki', format: 'der' }));
  if (spki.algorithm === 'Ed25519') return { algorithm: 15, dnskey: new Uint8Array(spki.point) };
  if (ko.asymmetricKeyType === 'ec'){
    if (spki.curve !== P256) throw keyError('KEY_INVALID', 'an EC key for DNSSEC must be P-256 (algorithm 13), not ' + spki.curve);
    return { algorithm: 13, dnskey: new Uint8Array(spki.point.subarray(1)) };
  }
  throw keyError('KEY_INVALID', 'DNSSEC keys are P-256 (algorithm 13) or Ed25519 (algorithm 15), not ' + ko.asymmetricKeyType);
}

// The public key back from what a DNSKEY carries
function publicFromDnskey(algorithm, dnskey){
  var der = algorithm === 15
    ? SPKI.to_der({ algorithm: 'Ed25519', point: dnskey })
    : SPKI.to_der({ algorithm: 'ecPublicKey', curve: P256, point: concat([0x04], dnskey) });
  return crypto.createPublicKey({ key: Buffer.from(der), format: 'der', type: 'spki' });
}
function concat(a, b){
  var out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}


// --- local private keys: the raw 32 bytes the material keeps ---

// A P-256 key needs no public point in its PKCS#8: node:crypto derives it.
function privateFromRaw(algorithm, raw){
  if (raw.length !== 32) throw keyError('KEY_INVALID', 'a raw DNSSEC private key is 32 bytes (got ' + raw.length + ')');
  var der = algorithm === 15
    ? PKCS8.to_der({ algorithm: 'Ed25519', scalar: raw })
    : PKCS8.to_der({ algorithm: 'ecPublicKey', curve: P256, scalar: raw });
  return crypto.createPrivateKey({ key: Buffer.from(der), format: 'der', type: 'pkcs8' });
}

// A private key's raw scalar, read out of its PKCS#8
function rawOf(ko){
  return new Uint8Array(PKCS8.from_der(ko.export({ type: 'pkcs8', format: 'der' })).scalar);
}

function generateRaw(algorithm){
  return rawOf(algorithm === 15 ? crypto.generateKeyPairSync('ed25519').privateKey
                                : crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey);
}

// A private key given as PEM or a KeyObject → { algorithm, raw }
function rawFromPrivate(input){
  var ko;
  try { ko = input instanceof crypto.KeyObject ? input : crypto.createPrivateKey(input); }
  catch (e){ throw keyError('KEY_INVALID', 'privateKey cannot be read: ' + e.message); }
  var alg = dnskeyFromPublic(crypto.createPublicKey(ko)).algorithm;
  return { algorithm: alg, raw: rawOf(ko) };
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
      var pemOrObject = pk instanceof crypto.KeyObject || (typeof pk === 'string' && pk.indexOf('-----BEGIN') >= 0);
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
    var pubKey = dnskeyFromPublic(crypto.createPublicKey(privateFromRaw(alg, raw))).dnskey;
    return { algorithm: alg, publicKey: pubKey, privateRaw: raw, signer: null };
  } catch (e){
    if (!e.code) e.code = 'KEY_INVALID';
    e.message = role + ': ' + e.message;
    throw e;
  }
}


// --- signing ---

// Local keys, made into KeyObjects once
var keyObjects = new Map();
function localKey(algorithm, privateKey){
  var id = algorithm + '|' + (typeof privateKey === 'string' ? privateKey : b64(privateKey));
  var ko = keyObjects.get(id);
  if (!ko){
    ko = privateFromRaw(algorithm, toU8(privateKey));
    if (keyObjects.size >= 1000) keyObjects.delete(keyObjects.keys().next().value);
    keyObjects.set(id, ko);
  }
  return ko;
}

var publicObjects = new Map();
function publicKeyOf(key){
  var id = key.algorithm + '|' + key.publicKey;
  var ko = publicObjects.get(id);
  if (!ko){
    ko = publicFromDnskey(Number(key.algorithm), toU8(key.publicKey));
    if (publicObjects.size >= 1000) publicObjects.delete(publicObjects.keys().next().value);
    publicObjects.set(id, ko);
  }
  return ko;
}

// A P-256 ECDSA signature in DER (SEQUENCE { INTEGER r, INTEGER s }) → r||s,
// 64 bytes; null when it is not one
function derToRaw(der){
  try { return new Uint8Array(SIG.der_to_raw({ der: der, curve: P256 })); }
  catch (e){ return null; }
}

function verify(key, payload, sig){
  try {
    var pub = publicKeyOf(key);
    if (Number(key.algorithm) === 15) return crypto.verify(null, Buffer.from(payload), pub, Buffer.from(sig));
    return crypto.verify('sha256', Buffer.from(payload), { key: pub, dsaEncoding: 'ieee-p1363' }, Buffer.from(sig));
  } catch (e){ return false; }
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
      var ko = localKey(algorithm, key.privateKey);
      sig = algorithm === 15
        ? crypto.sign(null, Buffer.from(payload), ko)
        : crypto.sign('sha256', Buffer.from(payload), { key: ko, dsaEncoding: 'ieee-p1363' });
    } catch (e){
      if (!e.code) e.code = 'KEY_INVALID';
      return setImmediate(cb, e);
    }
    return setImmediate(cb, null, new Uint8Array(sig));
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
