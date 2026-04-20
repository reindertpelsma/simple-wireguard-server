import { x25519 } from '@noble/curves/ed25519.js';

// Utility to convert Uint8Array to Base64
function toBase64(u8) {
  return btoa(String.fromCharCode.apply(null, u8));
}

function fromBase64(str) {
  return new Uint8Array(atob(str).split("").map(c => c.charCodeAt(0)));
}

async function sha256(message) {
  const msgUint8 = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(str) {
  return new Uint8Array(str.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

async function deriveClientKey(nonceHex) {
  const material = new TextEncoder().encode(`uwgsocks-ui:${nonceHex}`);
  const digest = await crypto.subtle.digest('SHA-256', material);
  return new Uint8Array(digest);
}

export async function generateKeyPair() {
  const { secretKey, publicKey } = x25519.keygen();
  return {
    privateKey: toBase64(secretKey),
    publicKey: toBase64(publicKey)
  };
}

export async function getPublicKey(privateKeyBase64) {
  const privKeyU8 = fromBase64(privateKeyBase64);
  return toBase64(x25519.getPublicKey(privKeyU8));
}

export async function encryptPrivateKey(privateKeyBase64, nonceHex, aesKeyHex) {
  const privKeyU8 = fromBase64(privateKeyBase64);
  const nonceU8 = fromHex(nonceHex);
  const aesKeyU8 = aesKeyHex ? fromHex(aesKeyHex) : await deriveClientKey(nonceHex);

  const key = await crypto.subtle.importKey(
    'raw',
    aesKeyU8,
    'AES-GCM',
    false,
    ['encrypt']
  );

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonceU8 },
    key,
    privKeyU8
  );

  const encoded = toBase64(new Uint8Array(encrypted));
  return aesKeyHex ? encoded : `v2:${encoded}`;
}

export async function decryptPrivateKey(encryptedBase64, nonceHex, aesKeyHex) {
  const isClientDerived = encryptedBase64.startsWith('v2:');
  const payload = isClientDerived ? encryptedBase64.slice(3) : encryptedBase64;
  const encryptedU8 = fromBase64(payload);
  const nonceU8 = fromHex(nonceHex);
  const aesKeyU8 = isClientDerived
    ? await deriveClientKey(nonceHex)
    : aesKeyHex
      ? fromHex(aesKeyHex)
      : null;

  if (!aesKeyU8) {
    throw new Error('Legacy encrypted key requires a server-derived nonce helper.');
  }

  const key = await crypto.subtle.importKey(
    'raw',
    aesKeyU8,
    'AES-GCM',
    false,
    ['decrypt']
  );

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonceU8 },
    key,
    encryptedU8
  );

  return toBase64(new Uint8Array(decrypted));
}

export function generateNonce() {
  const b = new Uint8Array(12);
  crypto.getRandomValues(b);
  return Array.from(b).map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function hashNonce(nonceHex) {
  return await sha256(nonceHex);
}
