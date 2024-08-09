import { ready } from 'https://lsong.org/scripts/dom.js';
import { sha256 } from 'https://lsong.org/scripts/crypto.js';
import { generateCSRPem } from 'https://lsong.org/scripts/crypto/csr.js';
import { base64UrlEncode } from 'https://lsong.org/scripts/crypto/base64.js';
import { initFormPersistence, saveElementValue, serialize } from 'https://lsong.org/scripts/form.js';
import { h, render, useState, useLocalStorageState, useCallback, useEffect } from 'https://lsong.org/scripts/react/index.js';

import { AcmeClient, generateRsaKeyPairAsPem } from './acme.js';

// Create an instance of AcmeClient
const acme = new AcmeClient();

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
document.getElementById('generateKeys').addEventListener('click', async (event) => {
  event.preventDefault();
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
  console.log(order);
  const orders = JSON.parse(localStorage.getItem('orders')) || [];
  orders.push(order);
  localStorage.setItem('orders', JSON.stringify(orders));
  console.log('Orders:', orders);
  renderApp();
});

// Step 3: Create CSR
document.getElementById('step3').addEventListener('submit', async (event) => {
  event.preventDefault();
  const inputs = serialize(event.target);
  console.log(inputs);
  const csr = await generateCSRPem(acme.keyPair, inputs);
  document.getElementById('csr').value = csr;
});

document.getElementById('finalize').addEventListener('submit', async (event) => {
  event.preventDefault();
  const csr = event.target.querySelector('textarea').value;
  console.log('finalize', csr);
});

const hex = uint8array =>
  uint8array.reduce((a, b) => a + b.toString(16).padStart(2, '0'), '');

const DNS01ChallengeInstructions = ({ authorization, challenge, thumbprint }) => {
  const [token, setToken] = useState('');
  const computeDnsTxtRecord = async (token, thumbprint) => {
    const hashBuffer = await sha256(`${token}.${thumbprint}`);
    console.log('sha256', hex(hashBuffer), `${token}.${thumbprint}`);
    return base64UrlEncode(hashBuffer);
  };
  useEffect(() => {
    computeDnsTxtRecord(challenge.token, thumbprint).then(setToken);
  }, []);
  return h('div', {}, [
    h('h5', {}, 'DNS-01 Challenge Instructions:'),
    h('ol', {}, [
      h('li', {}, `Create a TXT record for _acme-challenge.${authorization.identifier.value}`),
      h('li', {}, `Record content should be: `,
        h('code', null, token)
      ),
      h('li', {}, 'Wait for DNS propagation (this may take a few minutes to hours)'),
    ])
  ])
}

const App = () => {
  const [orders] = useLocalStorageState('orders', []);
  const [selectedOrder, setOrder] = useState(null);
  const [selectedAuth, setSelectedAuth] = useState(null);
  const [selectedChallenge, setSelectedChallenge] = useState(null);

  const handleOrderClick = useCallback(async (order) => {
    setSelectedAuth(null);
    setSelectedChallenge(null);
    const authPromises = order.authorizations.map(url => acme.getAuthorization(url));
    order.auths = await Promise.all(authPromises);
    setOrder(order);
    console.log(order);
  }, []);

  const handleAuthClick = (auth) => {
    setSelectedAuth(auth);
    setSelectedChallenge(null);
  };

  const handleChallengeClick = (challenge) => {
    setSelectedChallenge(challenge);
  };

  const handleVerifyChallenge = async () => {
    if (!selectedChallenge || !selectedAuth) return;
    const result = await acme.verifyChallenge(selectedChallenge.url);
    console.log(result);
  };

  return h('div', { id: 'orders' }, [
    h('h3', null, 'Orders'),
    h('ul', { className: 'padding-0' }, orders.map(order =>
      h('li', {
        className: 'flex flex-jc-between',
        onClick: () => handleOrderClick(order),
        style: { cursor: 'pointer', padding: '5px', backgroundColor: selectedOrder === order ? '#e0e0e0' : 'transparent' }
      }, [
        h('a', { href: order.url }, '#' + order.url.split('/').pop()),
        h('span', {}, order.identifiers.map(x => x.value).join(', ')),
        h('span', {}, order.status),
        h('span', {}, order.expires),
      ]))
    ),
    h('h4', null, "Order Details"),
    h('h5', null, 'Authorizations'),
    selectedOrder && [
      h('ul', { className: 'padding-0' }, selectedOrder.auths.map(auth =>
        h('li', {
          className: 'flex flex-jc-between',
          onClick: () => handleAuthClick(auth),
          style: { cursor: 'pointer', padding: '5px', backgroundColor: selectedAuth === auth ? '#e0e0e0' : 'transparent' }
        }, [
          h('span', {}, `Domain: ${auth.identifier.value}`),
          h('span', {}, `Status: ${auth.status}`),
        ])
      )),
    ],
    selectedAuth && [
      h('h5', null, `Challenges for ${selectedAuth.identifier.value}`),
      h('ul', { className: 'padding-0' }, selectedAuth.challenges.map(challenge =>
        h('li', {
          className: 'flex flex-jc-between',
          onClick: () => handleChallengeClick(challenge),
          style: { cursor: 'pointer', padding: '5px', backgroundColor: selectedChallenge === challenge ? '#e0e0e0' : 'transparent' }
        }, [
          h('span', {}, `Type: ${challenge.type}`),
          h('span', {}, `Status: ${challenge.status}`),
        ])
      )),
    ],
    selectedChallenge && selectedAuth && [
      h('h5', null, 'Selected Challenge'),
      selectedChallenge.type == 'http-01' && h('div', {}, [
        h('h6', {}, 'HTTP-01 Challenge Instructions:'),
        h('ol', {}, [
          h('li', {}, `Create a file at `, [
            h('a', {
              target: '_blank',
              href: `http://${selectedAuth.identifier.value}/.well-known/acme-challenge/${selectedChallenge.token}`
            }, `http://${selectedAuth.identifier.value}/.well-known/acme-challenge/${selectedChallenge.token}`)
          ]),
          h('li', {}, `File content should be: `,
            h('code', {}, `${selectedChallenge.token}.${acme.thumbprint}`)
          ),
          h('li', {}, 'Ensure the file is accessible via HTTP'),
        ])
      ]),
      selectedChallenge.type == 'dns-01' && h(DNS01ChallengeInstructions, {
        authorization: selectedAuth,
        challenge: selectedChallenge,
        thumbprint: acme.thumbprint,
      }),
      selectedChallenge.type == 'tls-alpn-01' && h('div', {}, [
        h('h5', {}, 'TLS-ALPN-01 Challenge Instructions:'),
        h('ol', {}, [
          h('li', {}, `Configure your TLS server for ${selectedAuth.identifier.value} to use ALPN`),
          h('li', {}, 'Set up a self-signed certificate with a acmeIdentifier extension'),
          h('li', {}, `Extension content should be: `,
            h('code', null, `${selectedChallenge.token}.${acme.thumbprint}`)
          ),
          h('li', {}, 'Ensure the TLS server is accessible'),
        ])
      ]),
      h('p', {}, 'Verify the challenge by clicking the button below'),
      h('button', { onClick: handleVerifyChallenge }, 'Verify Challenge')
    ],
    selectedAuth && selectedAuth.status == '' && h('button', null, "Finalize")
  ]);
};
const renderApp = () => {
  const app = document.getElementById('app');
  render(h(App), app);
}

ready(() => {
  initFormPersistence();
  renderApp();
});
