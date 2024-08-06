// Helper functions
function base64UrlEncode(str) {
  return btoa(str)
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function arrayBufferToString(buffer) {
  return String.fromCharCode.apply(null, new Uint8Array(buffer));
}

// Key generation functions
export async function generateRsaKeyPair() {
  return window.crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"]
  );
}

export async function generateRsaKeyPairAsString() {
  const keyPair = await generateRsaKeyPair();
  const publicJwk = await exportPublicKeyAsJwk(keyPair.publicKey);
  const privateJwk = await window.crypto.subtle.exportKey("jwk", keyPair.privateKey);

  return {
    publicKey: JSON.stringify(publicJwk),
    privateKey: JSON.stringify(privateJwk)
  };
}

export async function generateRsaKeyPairAsPem() {
  const keyPair = await generateRsaKeyPair();
  const publicKeySpki = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
  const privateKeyPkcs8 = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

  return {
    publicKey: spkiToPem(publicKeySpki),
    privateKey: pkcs8ToPem(privateKeyPkcs8)
  };
}

// Key export functions
export async function exportPublicKeyAsJwk(publicKey) {
  const jwk = await window.crypto.subtle.exportKey("jwk", publicKey);
  return {
    kty: jwk.kty,
    n: jwk.n,
    e: jwk.e,
  };
}

function spkiToPem(spkiBuffer) {
  const base64 = btoa(arrayBufferToString(spkiBuffer));
  return `-----BEGIN PUBLIC KEY-----\n${base64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
}

function pkcs8ToPem(pkcs8Buffer) {
  const base64 = btoa(arrayBufferToString(pkcs8Buffer));
  return `-----BEGIN PRIVATE KEY-----\n${base64.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`;
}

// Key import functions
export async function importKeyFromJwkString(jwkString, isPublic = true) {
  const jwk = JSON.parse(jwkString);
  const keyUsages = isPublic ? ['verify'] : ['sign'];
  return window.crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    true,
    keyUsages
  );
}

export async function importKeyFromPem(pemString, isPublic = true) {
  const pemHeader = isPublic ? "-----BEGIN PUBLIC KEY-----" : "-----BEGIN PRIVATE KEY-----";
  const pemFooter = isPublic ? "-----END PUBLIC KEY-----" : "-----END PRIVATE KEY-----";
  const pemContents = pemString.substring(
    pemString.indexOf(pemHeader) + pemHeader.length,
    pemString.indexOf(pemFooter)
  ).replace(/\s/g, '');

  const binaryDer = atob(pemContents);
  const arrayBuffer = Uint8Array.from(binaryDer, c => c.charCodeAt(0));

  return window.crypto.subtle.importKey(
    isPublic ? "spki" : "pkcs8",
    arrayBuffer,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    true,
    isPublic ? ["verify"] : ["sign"]
  );
}

// Signing and JWS functions
export async function signPayload(privateKey, payload) {
  const encoder = new TextEncoder();
  const data = encoder.encode(payload);
  const signature = await window.crypto.subtle.sign(
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: { name: "SHA-256" },
    },
    privateKey,
    data
  );
  return base64UrlEncode(arrayBufferToString(signature));
}

export function createJws(header, payload, signature) {
  return {
    protected: base64UrlEncode(JSON.stringify(header)),
    payload: base64UrlEncode(JSON.stringify(payload)),
    signature: signature
  };
}

export function createSigningInput(header, payload) {
  return `${base64UrlEncode(JSON.stringify(header))}.${base64UrlEncode(JSON.stringify(payload))}`;
}