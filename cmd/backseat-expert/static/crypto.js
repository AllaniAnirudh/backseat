// BackseatCrypto: pure WebCrypto helpers for end-to-end payload encryption.
//
// Wire envelope for an encrypted payload:
//   {"v":1,"alg":"AES-256-GCM","nonce":b64,"ct":b64}
// where ct = ciphertext || 16-byte tag, matching Go's gcm.Seal output.
//
// Key derivation bit-matches Go's pairing.DeriveKeys:
//   HKDF-SHA256(salt=challenge, ikm=secret, info="backseat-v1-pairing") -> 64 bytes
//   first 32 bytes = HostToExpert, last 32 = ExpertToHost.
//
// No DOM access here, so this file also runs under node for interop tests:
// node loads it and uses globalThis.BackseatCrypto.
(function () {
  'use strict';

  var INFO = 'backseat-v1-pairing';

  function b64ToBytes(s) {
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function bytesToB64(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }

  // base64url (no padding) as used in the invite fragment.
  function b64urlToBytes(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    return b64ToBytes(s);
  }

  // HMAC-SHA256(secret, challenge): the phase-2 enrollment response.
  async function hmacResponse(secretBytes, challengeBytes) {
    var key = await crypto.subtle.importKey(
      'raw', secretBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    var sig = await crypto.subtle.sign('HMAC', key, challengeBytes);
    return new Uint8Array(sig);
  }

  // Derive the two AES-GCM directional keys from the invite secret and the
  // host's fresh challenge.
  async function deriveKeys(secretBytes, challengeBytes) {
    var ikm = await crypto.subtle.importKey('raw', secretBytes, 'HKDF', false, ['deriveBits']);
    var bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: challengeBytes,
        info: new TextEncoder().encode(INFO) },
      ikm, 512);
    var okm = new Uint8Array(bits);
    var hostToExpert = await crypto.subtle.importKey(
      'raw', okm.slice(0, 32), 'AES-GCM', false, ['encrypt', 'decrypt']);
    var expertToHost = await crypto.subtle.importKey(
      'raw', okm.slice(32, 64), 'AES-GCM', false, ['encrypt', 'decrypt']);
    return { hostToExpert: hostToExpert, expertToHost: expertToHost };
  }

  // Seal plaintext under key; resolves to the JSON envelope string.
  async function seal(key, plaintext) {
    var nonce = crypto.getRandomValues(new Uint8Array(12));
    var ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, plaintext);
    return JSON.stringify({
      v: 1, alg: 'AES-256-GCM',
      nonce: bytesToB64(nonce),
      ct: bytesToB64(new Uint8Array(ct))
    });
  }

  // Open an envelope JSON string; rejects on bad version/alg or AEAD failure.
  async function open(key, envelopeText) {
    var env = JSON.parse(envelopeText);
    if (!env || env.v !== 1 || env.alg !== 'AES-256-GCM') throw new Error('bad envelope');
    var nonce = b64ToBytes(env.nonce);
    var ct = b64ToBytes(env.ct);
    var pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, ct);
    return new Uint8Array(pt);
  }

  globalThis.BackseatCrypto = {
    b64ToBytes: b64ToBytes,
    bytesToB64: bytesToB64,
    b64urlToBytes: b64urlToBytes,
    hmacResponse: hmacResponse,
    deriveKeys: deriveKeys,
    seal: seal,
    open: open
  };
})();
