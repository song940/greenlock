import { AcmeClient } from './acme.js';
import { generateRsaKeyPairAsPem } from './jwk.js';
import { initFormPersistence, saveElementValue } from './persist.js';

// Create an instance of AcmeClient
const acme = new AcmeClient();

// Helper function to show/hide sections
function showSection(id) {
}

// Step 1: Select Service Provider
document.getElementById('step1').addEventListener('submit', async (event) => {
  event.preventDefault();
  const select = event.target.querySelector('select');
  await acme.setDirectoryUrl(select.value);
  acme.directory = await acme.getDirectory();
  console.log('acme.directory:', acme.directory);
});

// Generate new keys
document.getElementById('generateKeys').addEventListener('click', async (event) => {
  event.preventDefault();
  console.log(event.target);
  const { publicKey, privateKey } = await generateRsaKeyPairAsPem();
  document.getElementById('pubkey').value = publicKey;
  document.getElementById('privkey').value = privateKey;
  saveElementValue('#pubkey');
  saveElementValue('#privkey');
});

document.getElementById('importKeys').addEventListener('click', async (event) => {
  event.preventDefault();
  const privateKey = document.getElementById('privkey').value;
  const publicKey = document.getElementById('pubkey').value;
  await acme.importKeyPair(publicKey, privateKey);
});

// Step 2: Create Account
document.getElementById('signup').addEventListener('submit', async (event) => {
  event.preventDefault();
  const email = event.target.querySelector('input[type="email"]').value;
  const agreed = event.target.querySelector('#agree').checked;
  const account = await acme.createAccount({
    contact: [`mailto:${email}`],
    termsOfServiceAgreed: agreed
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

// Step 3: Create New Order
document.getElementById('step3').addEventListener('submit', async (event) => {
  event.preventDefault();
  const domains = event.target.querySelector('textarea').value.split('\n');
  const order = await acme.createOrder(domains);
  console.log(order);
});

// Initialize the page
document.addEventListener('DOMContentLoaded', () => {
  showSection('step1');
  initFormPersistence();
});