// Interop check: runs the real browser crypto (static/crypto.js) under node
// and asserts it bit-matches the Go test vectors in
// internal/pairing/crypto_test.go. Run: node crypto-interop.mjs
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import assert from 'node:assert/strict';

const dir = dirname(fileURLToPath(import.meta.url));
const src = readFileSync(join(dir, 'static', 'crypto.js'), 'utf8');
// The script assigns globalThis.BackseatCrypto; indirect eval keeps it global.
(0, eval)(src);
const C = globalThis.BackseatCrypto;
assert(C, 'BackseatCrypto did not load');

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const secret = Uint8Array.from({ length: 32 }, (_, i) => i);
const challenge = Uint8Array.from({ length: 32 }, (_, i) => 0xa0 + i);

// 1. HKDF parameters must match Go's DeriveKeys exactly. deriveKeys() imports
// the AES keys non-extractable (correct for production), so the byte check
// runs deriveBits directly with identical parameters.
const ikm = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits']);
const bits = await crypto.subtle.deriveBits(
  { name: 'HKDF', hash: 'SHA-256', salt: challenge,
    info: new TextEncoder().encode('backseat-v1-pairing') },
  ikm, 512);
assert.equal(hex(new Uint8Array(bits)),
  '6892f29095fa58434f9b45c4eebb486b6f5d099bf41c94a09b10fa0e4b1a7b76' +
  '6873e2ec1ce8727d77a2fd8bfcfb8ff1c06bd075c3d48ad1c8eb46687ed99867',
  'HKDF-SHA256 output mismatch vs Go');
console.log('hkdf vector: match');

// The CryptoKeys from deriveKeys() are exercised below via seal/open;
// their bytes are the HKDF output verified above (same parameters).
const keys = await C.deriveKeys(secret, challenge);

// 2. HMAC enrollment response must match Go's EnrollmentResponse.
const resp = await C.hmacResponse(secret, challenge);
assert.equal(hex(resp),
  '0c95bd8bdd96004ec3f84f7bcc9526ee33491925dae778d32b6b81a42c38fe93',
  'HMAC response mismatch vs Go');
console.log('hmac vector: match');

// 3. Seal/open round trip through the real envelope.
const pt = new TextEncoder().encode('hello from the browser side');
const envText = await C.seal(keys.hostToExpert, pt);
const env = JSON.parse(envText);
assert.equal(env.v, 1);
assert.equal(env.alg, 'AES-256-GCM');
assert.equal(Object.keys(env).sort().join(','), 'alg,ct,nonce,v');
const back = await C.open(keys.hostToExpert, envText);
assert.equal(Buffer.from(back).toString(), 'hello from the browser side');
console.log('seal/open round trip: ok');

// 4. Tampered ciphertext is rejected.
const tampered = { ...env };
const ctBytes = C.b64ToBytes(tampered.ct);
ctBytes[0] ^= 1;
tampered.ct = C.bytesToB64(ctBytes);
await assert.rejects(C.open(keys.hostToExpert, JSON.stringify(tampered)));
console.log('tamper rejection: ok');

// 5. base64url secret parsing (invite fragment form).
const frag = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
const parsed = C.b64urlToBytes(frag);
assert.equal(hex(parsed), hex(secret));
console.log('b64url secret parse: ok');

// 6. Optional cross-language check: decrypt one Go-sealed envelope given
// as argv[2], or print a JS-sealed envelope for Go to verify.
if (process.argv[2]) {
  const pt = await C.open(keys.hostToExpert, process.argv[2]);
  console.log('GO_ENVELOPE_PLAINTEXT=' + Buffer.from(pt).toString());
} else {
  console.log('JS_ENVELOPE=' + envText);
}

console.log('ALL INTEROP CHECKS PASSED');
