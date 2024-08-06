import { exportPublicKeyAsJwk, signPayload, createJws, importKeyFromPem } from './jwk.js';

function base64UrlEncode(str) {
  return btoa(str).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
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
    const publicKey = await importKeyFromPem(publicKeyPem, true);
    const privateKey = await importKeyFromPem(privateKeyPem, false);
    this.keyPair = { publicKey, privateKey };
    this.publicJwk = await exportPublicKeyAsJwk(this.keyPair.publicKey);
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
    const encoder = new TextEncoder();
    const data = encoder.encode(jwkString);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);

    // Convert hash to base64url encoding
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    this.thumbprint = base64UrlEncode(hashHex);

    return this.thumbprint;
  }
  
  async verifyChallenge(challengeUrl) {
    if (!this.accountUrl) {
      throw new Error('Account not registered. Call createAccount() first.');
    }

    // The payload for challenge verification is an empty JSON object
    const payload = {};

    try {
      const response = await this._signedRequest(challengeUrl, payload, 'POST');
      const challenge = await response.json();

      // The server will usually respond with the updated challenge object
      console.log('Challenge verification initiated:', challenge);

      // Start polling for challenge status
      return this.pollChallengeStatus(challengeUrl);
    } catch (error) {
      console.error('Error verifying challenge:', error);
      throw error;
    }
  }
  async getChallenge(challengeUrl){
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