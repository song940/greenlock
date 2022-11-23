import {
  sign,
  sha256,
  exportPublicKeyToJwk,
} from 'https://lsong.org/scripts/crypto/index.js';
import { base64UrlEncode } from 'https://lsong.org/scripts/crypto/base64.js';

export class AcmeClient {
  constructor() {
    this.directoryUrl = null;
    this.directory = null;
    this.nonce = null;
    this.accountUrl = null;
    this.keyPair = null;
    this.publicJwk = null;
    this.thumbprint = null;
  }

  // Public methods

  setDirectoryUrl(directoryUrl) {
    this.directoryUrl = directoryUrl;
  }

  async getDirectory() {
    if (!this.directoryUrl)
      throw new Error('Provider not set. Call setProvider() first.');
    const response = await fetch(this.directoryUrl);
    return this.directory = await response.json();
  }

  async importKeyPair(keyPair) {
    this.keyPair = keyPair;
    this.publicJwk = await exportPublicKeyToJwk(this.keyPair.publicKey);
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

  async getNonce({ force = false } = {}) {
    if (!force && this.nonce) return this.nonce;
    const response = await fetch(this.directory.newNonce, { method: 'HEAD' });
    return this.nonce = response.headers.get('Replay-Nonce');
  }

  async _createRequestHeader(url) {
    return {
      url,
      alg: 'RS256',
      nonce: await this.getNonce(),
      kid: this.accountUrl || undefined,
      jwk: this.accountUrl ? undefined : this.publicJwk,
    };
  }

  async _createJws(header, payload) {
    const encodedHeader = base64UrlEncode(JSON.stringify(header));
    const encodedPayload = payload ? base64UrlEncode(JSON.stringify(payload)) : '';
    const encoder = new TextEncoder();
    const data = encoder.encode(`${encodedHeader}.${encodedPayload}`);
    const signature = await sign(this.keyPair.privateKey, data);
    return {
      protected: encodedHeader,
      payload: encodedPayload,
      signature: base64UrlEncode(signature),
    };
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
    const header = await this._createRequestHeader(url);
    const jws = await this._createJws(header, payload);
    return this._sendRequest(url, jws, method);
  }

  async getResourceUrl(name) {
    if (!this.directory)
      this.directory = await this.getDirectory();
    return this.directory[name];
  }

  async registerAccount(accountUrl) {
    this.accountUrl = accountUrl;
  }

  async createAccount(payload) {
    const url = await this.getResourceUrl('newAccount');
    const response = await this._signedRequest(url, payload);
    const data = await response.json();
    data.url = response.headers.get('Location');
    return data;
  }


  async updateAccount(payload) {
    const response = await this._signedRequest(this.accountUrl, payload);
    return response.json();
  }

  async deactivateAccount() {
    const payload = { status: 'deactivated' };
    const response = await this._signedRequest(this.accountUrl, payload);
    return response.json();
  }

  async changeAccountKey(newPublicKey) {
    const payload = {
      account: this.accountUrl,
      oldKey: this.publicJwk,
      newKey: newPublicKey,
    };
    const url = await this.getResourceUrl('keyChange');
    const response = await this._signedRequest(url, payload);
    return response.json();
  }

  async createOrder(payload) {
    const url = await this.getResourceUrl('newOrder');
    const response = await this._signedRequest(url, payload);
    const order = await response.json();
    order.url = response.headers.get('Location');
    return order;
  }

  async getOrder(orderUrl) {
    const response = await fetch(orderUrl);
    return response.json();
  }

  async getAuthorization(authUrl) {
    const response = await fetch(authUrl);
    return response.json();
  }

  async getChallenge(challengeUrl) {
    const response = await fetch(challengeUrl);
    return response.json();
  }

  async verifyChallenge(challengeUrl) {
    const payload = {};
    const response = await this._signedRequest(challengeUrl, payload);
    return response.json();
  }

  async finalizeOrder(finalizeUrl, csr) {
    const payload = { csr };
    const response = await this._signedRequest(finalizeUrl, payload);
    return response.json();
  }

  async getCertificate(certUrl){
    const response = await fetch(certUrl);
    return response.text();
  }

  async revokeCertificate(certificate, reason) {
    const payload = { certificate, reason };
    const url = await this.getResourceUrl('revokeCert');
    const response = await this._signedRequest(url, payload);
    return response.json();
  }
}