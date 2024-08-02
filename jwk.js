// Function to generate a new RSA key pair
export async function generateRsaKeyPair() {
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: "RSASSA-PKCS1-v1_5",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true,
        ["sign", "verify"]
    );
    return keyPair;
}

// Function to export public key as JWK
export async function exportPublicKeyAsJwk(publicKey) {
    const jwk = await window.crypto.subtle.exportKey("jwk", publicKey);
    return {
        kty: jwk.kty,
        n: jwk.n,
        e: jwk.e,
    };
}

// Function to generate a new RSA key pair and return as strings
export async function generateRsaKeyPairAsString() {
    const keyPair = await generateRsaKeyPair();
    const publicJwk = await exportPublicKeyAsJwk(keyPair.publicKey);
    const privateJwk = await window.crypto.subtle.exportKey("jwk", keyPair.privateKey);

    return {
        publicKey: JSON.stringify(publicJwk),
        privateKey: JSON.stringify(privateJwk)
    };
}

// Function to import key from JWK string
export async function importKeyFromJwkString(jwkString, isPublic = true) {
    const jwk = JSON.parse(jwkString);
    const keyUsages = isPublic ? ['verify'] : ['sign'];
    return await window.crypto.subtle.importKey(
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

export function createJws(header, payload, signature) {
    return {
        protected: btoa(JSON.stringify(header)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_'),
        payload: btoa(JSON.stringify(payload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_'),
        signature: signature
    };
}

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
    return btoa(String.fromCharCode.apply(null, new Uint8Array(signature)))
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
}

// New function to create the input for signing
export function createSigningInput(data, payload) {
    return `${btoa(JSON.stringify(data))}.${btoa(JSON.stringify(payload))}`;
}


// Function to generate a new RSA key pair in PEM format
export async function generateRsaKeyPairAsPem() {
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: "RSASSA-PKCS1-v1_5",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true,
        ["sign", "verify"]
    );

    const publicKeySpki = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
    const privateKeyPkcs8 = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

    const publicKeyPem = await spkiToPem(publicKeySpki);
    const privateKeyPem = await pkcs8ToPem(privateKeyPkcs8);

    return { publicKey: publicKeyPem, privateKey: privateKeyPem };
}

async function spkiToPem(spkiBuffer) {
    const base64 = btoa(String.fromCharCode(...new Uint8Array(spkiBuffer)));
    const pem = `-----BEGIN PUBLIC KEY-----\n${base64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
    return pem;
}

async function pkcs8ToPem(pkcs8Buffer) {
    const base64 = btoa(String.fromCharCode(...new Uint8Array(pkcs8Buffer)));
    const pem = `-----BEGIN PRIVATE KEY-----\n${base64.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`;
    return pem;
}

// ... (other functions remain the same)

// Function to import key from PEM format
export async function importKeyFromPem(pemString, isPublic = true) {
    const pemHeader = isPublic ? "-----BEGIN PUBLIC KEY-----" : "-----BEGIN PRIVATE KEY-----";
    const pemFooter = isPublic ? "-----END PUBLIC KEY-----" : "-----END PRIVATE KEY-----";
    const pemContents = pemString.substring(
        pemString.indexOf(pemHeader) + pemHeader.length,
        pemString.indexOf(pemFooter)
    ).replace(/\s/g, '');

    const binaryDer = window.atob(pemContents);
    const arrayBuffer = new Uint8Array(binaryDer.length);
    for (let i = 0; i < binaryDer.length; i++) {
        arrayBuffer[i] = binaryDer.charCodeAt(i);
    }

    const algorithm = {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256",
    };

    return await window.crypto.subtle.importKey(
        isPublic ? "spki" : "pkcs8",
        arrayBuffer,
        algorithm,
        true,
        isPublic ? ["verify"] : ["sign"]
    );
}

// ... (other functions remain the same)