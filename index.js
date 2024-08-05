import { h, render, useState, useLocalStorageState } from 'https://lsong.org/scripts/react/index.js';

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
  document.getElementById('tos').href = acme.directory.meta.termsOfService;
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
  console.log("Importing key pair...");
  const privateKey = document.getElementById('privkey').value;
  const publicKey = document.getElementById('pubkey').value;
  await acme.importKeyPair(publicKey, privateKey);
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

// Step 3: Create New Order
document.getElementById('step3').addEventListener('submit', async (event) => {
  event.preventDefault();
  const domains = event.target.querySelector('textarea').value.split('\n');
  const order = await acme.createOrder({
    identifiers: domains.map(domain => ({ type: 'dns', value: domain })),
  });
  console.log(order);
  const orders = JSON.parse(localStorage.getItem('orders')) || [];
  orders.push(order);
  localStorage.setItem('orders', JSON.stringify(orders));
  console.log('Orders:', orders);
  renderApp();
});

// Initialize the page
document.addEventListener('DOMContentLoaded', () => {
  showSection('step1');
  initFormPersistence();
  renderApp();
});

const App = () => {
  const [orders, setOrders] = useLocalStorageState('orders', []);
  const [authorizations, setAuthorizations] = useState([]);
  console.log(orders);
  const handleOrderClick = async order => {
    const auths = [];
    for (const url of order.authorizations) {
      const authorization = await acme.getAuthorization(url);
      auths.push(authorization);
    }
    setAuthorizations(auths);
  };
  return h('div', { id: 'orders' }, [
    h('h3', null, 'Orders'),
    h('ul', {}, orders.map(order =>
      h('li', { className: 'flex flex-jc-between', onClick: handleOrderClick.bind(null, order) }, [
        h('a', { href: order.url }, '#' + order.url.split('/').pop()),
        h('span', {}, order.identifiers.map(x => x.value).join(', ')),
        h('span', {}, order.status),
        h('span', {}, order.expires),
        h('button', {}, 'finalize'),
      ]))
    ),
    h('h3', null, "Order Details"),
    h('p', null, 'Tips: '),
    h('h4', null, 'Authorizations'),
    h('ol', {}, authorizations.map(auth =>
      h('li', null, [
        h('h4', { className: 'flex flex-jc-between' }, [
          "Authorization ",
          h('a', { href: auth.url }, '#' + auth.url.split('/').pop()),
          h('span', {}, auth.status),
        ]),
        h('ul', {}, auth.challenges.map(challenge =>
          h('li', { className: 'flex flex-jc-between' }, [
            h('span', {}, challenge.type),
            h('span', {}, challenge.status),
          ]))
        )
      ])
    ))
  ]);
};

const renderApp = () => {
  const app = document.getElementById('app');
  render(h(App), app);
}