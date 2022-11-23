import { ready } from 'https://lsong.org/scripts/dom.js';
import { base64UrlEncode } from 'https://lsong.org/scripts/crypto/base64.js';
import { sha256, generateCSR, parsePem, generateRsaKeyPairAsPem, importKeyPairFromPem } from 'https://lsong.org/scripts/crypto/index.js?v1.2';
import { initFormPersistence, saveElementValue, serialize } from 'https://lsong.org/scripts/form.js';

import { AcmeClient } from './acme.js';

// Create an instance of AcmeClient
const acme = new AcmeClient();

// Helper function to refresh order status
async function refreshOrderStatus(orderUrl) {
  await renderOrder(orderUrl);
  console.log('Order status refreshed');
}

// Select Service Provider
document.getElementById('step1').addEventListener('submit', async (event) => {
  event.preventDefault();
  const select = event.target.querySelector('select');
  await acme.setDirectoryUrl(select.value);
  acme.directory = await acme.getDirectory();
  console.log('acme.directory:', acme.directory);
  document.getElementById('tos').href = acme.directory.meta.termsOfService;
});

// Generate new keys
function setupKeyGeneration(buttonId, pubkeyId, privkeyId) {
  document.getElementById(buttonId).addEventListener('click', async (event) => {
    event.preventDefault();
    const { publicKey, privateKey } = await generateRsaKeyPairAsPem();
    document.getElementById(pubkeyId).value = publicKey;
    document.getElementById(privkeyId).value = privateKey;
    saveElementValue(`#${pubkeyId}`);
    saveElementValue(`#${privkeyId}`);
  });
}

setupKeyGeneration('generateKeys', 'pubkey', 'privkey');
setupKeyGeneration('generateKeys2', 'pubkey2', 'privkey2');

document.getElementById('importKeys').addEventListener('click', async (event) => {
  event.preventDefault();
  console.log("Importing key pair...");
  const algorithm = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  const privateKey = document.getElementById('privkey').value;
  const publicKey = document.getElementById('pubkey').value;
  const keyPair = await importKeyPairFromPem({ privateKey, publicKey }, algorithm);
  await acme.importKeyPair(keyPair);
  await acme.getThumbprint();
  console.log("Key pair imported and JWK exported successfully.");
});

// Step 2: Create Account
document.getElementById('signup').addEventListener('submit', async (event) => {
  event.preventDefault();
  const email = event.target.querySelector('input[type="email"]').value;
  const agreed = event.target.querySelector('#agree').checked;
  const account = await acme.createAccount({
    contact: [`mailto:${email}`],
    termsOfServiceAgreed: agreed,
  });
  document.getElementById('accountUrl').value = account.url;
  saveElementValue('#accountUrl');
});

document.getElementById('login').addEventListener('submit', async (event) => {
  event.preventDefault();
  const accountUrl = event.target.querySelector('input[type="url"]').value;
  await acme.registerAccount(accountUrl);
  console.log('Acme account registered:', acme.accountUrl);
});

// Create New Order
document.getElementById('createOrder').addEventListener('click', async (event) => {
  event.preventDefault();
  const domains = document.getElementById('domains').value.trim().split(/\s+/);
  const order = await acme.createOrder({
    identifiers: domains.map(domain => ({ type: 'dns', value: domain })),
  });
  await renderOrder(order.url);
  console.log('Acme order created:', order.url);
  document.getElementById('orderUrl').value = order.url;
});

// Step 3: Create CSR
document.getElementById('step3').addEventListener('submit', async (event) => {
  event.preventDefault();
  const { publicKey, privateKey, ...inputs } = serialize(event.target);
  const algorithm = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  const keyPair = await importKeyPairFromPem({ privateKey, publicKey }, algorithm);
  const csr = await generateCSR(keyPair, inputs);
  document.getElementById('csr').value = csr;
});

async function renderOrder(orderUrl) {
  const order = await acme.getOrder(orderUrl);
  document.getElementById('finalizeUrl').value = order.finalize;
  document.getElementById('download').href = order.certificate;
  const authorizations = document.getElementById('authorizations');
  authorizations.innerHTML = '';
  
  for (const authUrl of order.authorizations) {
    const auth = await acme.getAuthorization(authUrl);
    const li = createAuthorizationListItem(auth, authUrl);
    authorizations.appendChild(li);
  }
  
  if ('certificate' in order) {
    document.getElementById('download').href = order.certificate;
    const cert = await acme.getCertificate(order.certificate);
    document.getElementById('certificate').value = cert;
  }
}

function createAuthorizationListItem(auth, authUrl) {
  const li = document.createElement('li');
  li.className = 'flex flex-jc-between';
  li.dataset.authUrl = authUrl;
  li.innerHTML = `
    <span>${auth.identifier.value}</span>
    <span>${auth.status}</span>
  `;
  li.onclick = () => {
    li.setAttribute('selected', '');
    renderAuthorization(authUrl);
  };
  return li;
}

async function renderAuthorization(authUrl) {
  const challenges = document.getElementById('challenges');
  challenges.innerHTML = '';
  const auth = await acme.getAuthorization(authUrl);
  
  for (const challenge of auth.challenges) {
    const li = createChallengeListItem(challenge, auth);
    challenges.appendChild(li);
  }
}

function createChallengeListItem(challenge, auth) {
  const li = document.createElement('li');
  li.className = 'flex flex-jc-between';
  li.innerHTML = `
    <span>${challenge.type}</span>
    <span>${challenge.status}</span>
  `;
  li.onclick = async () => {
    li.setAttribute('selected', '');
    const instructions = await renderInstructions(challenge, auth);
    document.getElementById('instructions').innerHTML = instructions;
    document.getElementById('challengeUrl').value = challenge.url;
  };
  return li;
}

async function renderInstructions(challenge, auth) {
  const instructions = {
    'http-01': async () => `
      <li>Create a file at <code>http://${auth.identifier.value}/.well-known/acme-challenge/${challenge.token}</code>
      <li>File content should be: <code>${challenge.token}.${acme.thumbprint}</code>
      <li>Ensure the file is accessible via HTTP
    `,
    'dns-01': async () => {
      const hashBuffer = await sha256(`${challenge.token}.${acme.thumbprint}`);
      const txt = base64UrlEncode(hashBuffer);
      return `
        <li>Create a TXT record for <code>_acme-challenge.${auth.identifier.value}</code>
        <li>Record content should be: <code>${txt}</code>
        <li>Wait for DNS propagation (this may take a few minutes to hours)
      `;
    },
    'tls-alpn-01': async () => `
      <li>Configure your TLS server for ${auth.identifier.value} to use ALPN
      <li>Set up a self-signed certificate with a acmeIdentifier extension
      <li>Extension content should be: <code>${auth.identifier.value}: ${challenge.token}</code>
      <li>Ensure the TLS server is accessible
    `
  };

  return instructions[challenge.type] ? await instructions[challenge.type]() : 'Unsupported challenge type';
}

document.getElementById('order').addEventListener('submit', async (event) => {
  event.preventDefault();
  const { orderUrl } = serialize(event.target);
  await renderOrder(orderUrl);
});

document.getElementById('verifyChallenge').addEventListener('submit', async (event) => {
  event.preventDefault();
  const { challengeUrl } = serialize(event.target);
  await acme.verifyChallenge(challengeUrl);
  const orderUrl = document.getElementById('orderUrl').value;
  await refreshOrderStatus(orderUrl);
});

document.getElementById('finalize').addEventListener('submit', async (event) => {
  event.preventDefault();
  const { finalizeUrl, csr } = serialize(event.target);
  const { type, data } = parsePem(csr);
  console.log(type, data);
  const res = await acme.finalizeOrder(finalizeUrl, base64UrlEncode(data));
  console.log(res);
  const orderUrl = document.getElementById('orderUrl').value;
  await refreshOrderStatus(orderUrl);
});

document.getElementById('revoke').addEventListener('submit', async e => {
  e.preventDefault();
  const { certificate, reason } = serialize(e.target);
  await acme.revokeCertificate(certificate, reason);
  console.log('Certificate revoked');
});

ready(() => {
  initFormPersistence();
});