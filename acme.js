import { generateRsaKeyPair, exportPublicKeyAsJwk, signPayload, createJws, importKeyFromPem, createSigningInput } from './jwk.js';

export class AcmeClient {
    constructor() {
        this.directoryUrl = null;
        this.directory = null;
        this.nonce = null;
        this.accountUrl = null;
        this.keyPair = null;
        this.publicJwk = null;
    }

    async importKeyPair(publicKeyPem, privateKeyPem) {
        try {
            console.log("Importing public key...");
            const publicKey = await importKeyFromPem(publicKeyPem, true);
            console.log("Public key imported successfully.");

            console.log("Importing private key...");
            const privateKey = await importKeyFromPem(privateKeyPem, false);
            console.log("Private key imported successfully.");

            this.keyPair = { publicKey, privateKey };
            this.publicJwk = await exportPublicKeyAsJwk(this.keyPair.publicKey);
            console.log("Key pair imported and JWK exported successfully.");
        } catch (error) {
            console.error("Error importing key pair:", error);
            throw new Error(`Failed to import key pair: ${error.message}`);
        }
    }

    // ... (other methods remain the same)

    async createAccount(contact, termsOfServiceAgreed) {
        if (!this.directory) {
            throw new Error('Directory not fetched. Call getDirectory() first.');
        }

        const payload = {
            contact,
            termsOfServiceAgreed
        };

        const response = await this.signedRequest(this.directory.newAccount, payload);
        this.accountUrl = response.headers.get('Location');
        return await response.json();
    }

    setProvider(directoryUrl) {
        this.directoryUrl = directoryUrl;
    }

    async getDirectory() {
        if (!this.directoryUrl) {
            throw new Error('Provider not set. Call setProvider() first.');
        }
        const response = await fetch(this.directoryUrl);
        this.directory = await response.json();
        return this.directory;
    }

    async getNonce() {
        if (!this.directory) {
            throw new Error('Directory not fetched. Call getDirectory() first.');
        }
        const response = await fetch(this.directory.newNonce, { method: 'HEAD' });
        this.nonce = response.headers.get('Replay-Nonce');
        return this.nonce;
    }

    async signedRequest(url, payload) {
        if (!this.keyPair) {
          throw new Error('KeyPair not initialized. Call importKeyPair() first.');
        }
        await this.getNonce();
        const header = {
          alg: 'RS256',
          nonce: this.nonce,
          url: url,
          jwk: this.publicJwk,
        };
    
        const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
        const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
        const signingInput = `${encodedHeader}.${encodedPayload}`;
        const signature = await signPayload(this.keyPair.privateKey, signingInput);
        const jws = createJws(header, payload, signature);
    
        console.log("Sending JWS:", JSON.stringify(jws, null, 2));
    
        const response = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/jose+json',
          },
          body: JSON.stringify(jws),
        });
    
        if (!response.ok) {
          const errorData = await response.json();
          console.error('ACME request failed:', errorData);
          throw new Error(`ACME request failed: ${errorData.detail}`);
        }
    
        return response;
      }


    async createAccount(contact, termsOfServiceAgreed) {
        if (!this.directory) {
            throw new Error('Directory not fetched. Call getDirectory() first.');
        }

        const payload = {
            termsOfServiceAgreed: termsOfServiceAgreed,
            contact: contact.map(c => c.startsWith('mailto:') ? c : `mailto:${c}`)
        };

        console.log("Creating account with payload:", JSON.stringify(payload, null, 2));

        const response = await this.signedRequest(this.directory.newAccount, payload);
        this.accountUrl = response.headers.get('Location');
        return await response.json();
    }

    // Additional methods as needed...
}