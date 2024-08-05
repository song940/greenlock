import { generateRsaKeyPair, exportPublicKeyAsJwk, signPayload, createJws, importKeyFromPem } from './jwk.js';

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
    console.log("Importing key pair...");
    const publicKey = await importKeyFromPem(publicKeyPem, true);
    const privateKey = await importKeyFromPem(privateKeyPem, false);
    this.keyPair = { publicKey, privateKey };
    this.publicJwk = await exportPublicKeyAsJwk(this.keyPair.publicKey);
    console.log("Key pair imported and JWK exported successfully.");
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

  async createOrder(identifiers) {
    const payload = {
      identifiers: identifiers.map(identifier => ({ type: "dns", value: identifier }))
    };
    const response = await this._signedRequest(this.directory.newOrder, payload);
    const order = await response.json();
    order.url = response.headers.get('Location');
    return order;
  }

  async finalizeOrder(finalizeUrl, csr) {
    const payload = { csr };
    console.log("Finalizing order with payload:", JSON.stringify(payload, null, 2));
    const response = await this._signedRequest(finalizeUrl, payload);
    return response.json();
  }

  async getAuthorization(authUrl) {
    return this._signedRequest(authUrl, null, 'GET').then(res => res.json());
  }

  async checkAuthorizationStatus(authUrl) {
    return this._signedRequest(authUrl, null, 'POST').then(res => res.json());
  }

  async generateCsr(domains) {
    // This is a simplified CSR generation. In a real-world scenario,
    // you'd use a proper library to generate a CSR.
    const { privateKey } = await generateRsaKeyPair();
    const csr = btoa(`CSR for domains: ${domains.join(', ')}`);
    return { csr, privateKey };
  }

  // Private methods

  async _getNonce() {
    if (this.nonce) return this.nonce;
    const response = await fetch(this.directory.newNonce, { method: 'HEAD' });
    this.nonce = response.headers.get('Replay-Nonce');
    return this.nonce;
  }

  async _signedRequest(url, payload, method = 'POST') {
    await this._getNonce();
    const header = this._createRequestHeader(url);
    const jws = await this._createJws(header, payload);
    console.log("Sending JWS:", JSON.stringify(jws, null, 2));
    return this._sendRequest(url, jws, method);
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
    const encodedHeader = this._base64UrlEncode(JSON.stringify(header));
    const encodedPayload = payload ? this._base64UrlEncode(JSON.stringify(payload)) : '';
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

  _base64UrlEncode(str) {
    return btoa(str).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  }

  _handleError(message, error) {
    console.error(message, error);
    throw new Error(`${message}: ${error.message}`);
  }
}