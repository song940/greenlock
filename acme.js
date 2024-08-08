import {
  sign,
  sha256,
  exportKeyPairToPem,
  exportPublicKeyToJwk,
  importKeyPairFromPem,
} from 'https://lsong.org/scripts/crypto.js?a';
import { base64UrlEncode } from 'https://lsong.org/scripts/crypto/base64.js?v22';

const algorithm = {
  name: "RSASSA-PKCS1-v1_5",
  hash: "SHA-256",
};

// Key generation functions
export async function generateRsaKeyPair() {
  return window.crypto.subtle.generateKey(
    {
      ...algorithm,
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
    },
    true,
    ["sign", "verify"]
  );
}

export async function generateRsaKeyPairAsPem() {
  const keyPair = await generateRsaKeyPair();
  return exportKeyPairToPem(keyPair, algorithm);
};

// Signing and JWS functions
export async function signPayload(privateKey, payload) {
  const encoder = new TextEncoder();
  const data = encoder.encode(payload);
  const signature = await sign(privateKey, data, algorithm);
  console.log('signature:', signature);
  return base64UrlEncode(signature);
}

export function createJws(header, payload, signature) {
  return {
    protected: base64UrlEncode(JSON.stringify(header)),
    payload: base64UrlEncode(JSON.stringify(payload)),
    signature: signature,
  };
}

export class AcmeClient {
  constructor() {
    this.directoryUrl = null;
    this.directory = null;
    this.nonce = null;
    this.accountUrl = null;
    this.keyPair = null;
    this.publicJwk = null;
  }

  // Public methods

  setDirectoryUrl(directoryUrl) {
    this.directoryUrl = directoryUrl;
  }

  async getDirectory() {
    if (!this.directoryUrl)
      throw new Error('Provider not set. Call setProvider() first.');
    const response = await fetch(this.directoryUrl);
    this.directory = await response.json();
    return this.directory;
  }

  async importKeyPair(publicKeyPem, privateKeyPem) {
    this.keyPair = await importKeyPairFromPem({
      publicKey: publicKeyPem,
      privateKey: privateKeyPem,
    }, algorithm);
    console.log(this.keyPair);
    this.publicJwk = await exportPublicKeyToJwk(this.keyPair.publicKey);
  }


  async _getNonce() {
    if (this.nonce) return this.nonce;
    const response = await fetch(this.directory.newNonce, { method: 'HEAD' });
    this.nonce = response.headers.get('Replay-Nonce');
    return this.nonce;
  }

  _createRequestHeader(url) {
    return {
      alg: 'RS256',
      nonce: this.nonce,
      url: url,
      kid: this.accountUrl || undefined,
      jwk: this.accountUrl ? undefined : this.publicJwk,
    };
  }

  async _createJws(header, payload) {
    const encodedHeader = base64UrlEncode(JSON.stringify(header));
    const encodedPayload = payload ? base64UrlEncode(JSON.stringify(payload)) : '';
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const signature = await signPayload(this.keyPair.privateKey, signingInput);
    return createJws(header, payload, signature);
  }

  async _sendRequest(url, jws, method) {
    const response = await fetch(url, {
      method: method,
      headers: { 'Content-Type': 'application/jose+json' },
      body: method !== 'GET' ? JSON.stringify(jws) : undefined,
    });
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(`ACME request failed: ${errorData.detail}`);
    }
    this.nonce = response.headers.get('Replay-Nonce');
    return response;
  }

  async _signedRequest(url, payload, method = 'POST') {
    await this._getNonce();
    const header = this._createRequestHeader(url);
    const jws = await this._createJws(header, payload);
    return this._sendRequest(url, jws, method);
  }


  async registerAccount(accountUrl) {
    this.accountUrl = accountUrl;
  }

  async createAccount(payload) {
    const response = await this._signedRequest(this.directory.newAccount, payload);
    const data = await response.json();
    data.url = response.headers.get('Location');
    return data;
  }

  async createOrder(payload) {
    const response = await this._signedRequest(this.directory.newOrder, payload);
    const order = await response.json();
    order.url = response.headers.get('Location');
    return order;
  }

  async getAuthorization(authUrl) {
    const response = await fetch(authUrl);
    const authorization = await response.json();
    authorization.url = authUrl;
    return authorization;
  }

  async finalizeOrder(finalizeUrl, csr) {
    const payload = { csr };
    const response = await this._signedRequest(finalizeUrl, payload);
    return response.json();
  }
  async getThumbprint() {
    if (!this.publicJwk)
      throw new Error('Public key not set. Import key pair first.');
    // Create a canonical JWK by including only the required fields in lexicographic order
    const canonicalJwk = {
      e: this.publicJwk.e,
      kty: this.publicJwk.kty,
      n: this.publicJwk.n
    };
    // Stringify the canonical JWK without whitespace
    const jwkString = JSON.stringify(canonicalJwk);
    // Calculate SHA-256 hash
    const hashBuffer = await sha256(jwkString);
    this.thumbprint = base64UrlEncode(hashBuffer);
    return this.thumbprint;
  }

  async verifyChallenge(challengeUrl) {
    if (!this.accountUrl) {
      throw new Error('Account not registered. Call createAccount() first.');
    }

    // The payload for challenge verification is an empty JSON object
    const payload = {};
    const response = await this._signedRequest(challengeUrl, payload, 'POST');
    const challenge = await response.json();

    // The server will usually respond with the updated challenge object
    console.log('Challenge verification initiated:', challenge);

    // Start polling for challenge status
    return this.pollChallengeStatus(challengeUrl);
  }
  async getChallenge(challengeUrl) {
    const response = await this._signedRequest(challengeUrl, null, 'GET');
    return response.json();
  }

  async pollChallengeStatus(challengeUrl, maxAttempts = 10, interval = 5000) {
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const challenge = await this.getChallenge(challengeUrl);
      console.log(`Challenge status (attempt ${attempt + 1}):`, challenge.status);
      if (challenge.status === 'valid') {
        return challenge;
      } else if (challenge.status === 'invalid') {
        throw new Error('Challenge validation failed: ' + JSON.stringify(challenge.error));
      }
      // Wait before the next attempt
      await new Promise(resolve => setTimeout(resolve, interval));
    }
    throw new Error('Challenge validation timed out');
  }
}