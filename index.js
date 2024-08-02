import { ready } from 'https://lsong.org/scripts/dom.js';
import { h, render, useState, useEffect } from 'https://lsong.org/scripts/react/index.js';
import { AcmeClient } from './acme.js';
import { generateRsaKeyPairAsPem } from './jwk.js';

const PROVIDERS = [
  { name: "Let's Encrypt Production", url: "https://acme-v02.api.letsencrypt.org/directory" },
  { name: "Let's Encrypt Staging", url: "https://acme-staging-v02.api.letsencrypt.org/directory" },
  { name: "ZeroSSL", url: "https://acme.zerossl.com/v2/DV90" },
  { name: "Buypass", url: "https://api.buypass.com/acme/directory" },
];

const Step1 = ({ acme, onSubmit }) => {
  const [selectedProvider, setSelectedProvider] = useState("");

  const handleSubmit = async e => {
    e.preventDefault();
    if (!selectedProvider) {
      alert("Please select a service provider");
      return;
    }
    try {
      acme.setProvider(selectedProvider);
      onSubmit && onSubmit({ provider: selectedProvider });
    } catch (error) {
      console.error("Error setting provider:", error);
      alert("Failed to set provider. Please try again.");
    }
  }

  return (
    h('form', { className: 'step1', onSubmit: handleSubmit },
      h("h2", null, "Select Service Provider"),
      h("select",
        {
          value: selectedProvider,
          onChange: (e) => setSelectedProvider(e.target.value),
          required: true
        },
        h("option", { value: "" }, "Choose a provider"),
        PROVIDERS.map(provider =>
          h("option", { key: provider.url, value: provider.url }, provider.name)
        )
      ),
      h("button", { type: "submit" }, "Confirm"),
      h("p", null, [
        "API Compatibility: ",
        h("a", { href: "https://letsencrypt.org/docs/client-options" }, "Let's Encrypt v2"),
        "/",
        h("a", { href: "https://www.rfc-editor.org/rfc/rfc8555.html" }, "ACME RFC8555"),
      ])
    )
  );
}
const Step2 = ({ acme, onSubmit }) => {
  const [email, setEmail] = useState("");
  const [directory, setDirectory] = useState(null);
  const [agreed, setAgreed] = useState(false);
  const [publicKey, setPublicKey] = useState("");
  const [privateKey, setPrivateKey] = useState("");

  useEffect(() => {
    const fetchDirectory = async () => {
      try {
        const dir = await acme.getDirectory();
        setDirectory(dir);
      } catch (error) {
        console.error("Error fetching directory:", error);
        alert("Failed to fetch directory. Please try again.");
      }
    };
    fetchDirectory();
  }, []);

  const handleGenerateKeys = async () => {
    try {
      const { publicKey: pubKey, privateKey: privKey } = await generateRsaKeyPairAsPem();
      setPublicKey(pubKey);
      setPrivateKey(privKey);
      console.log("Generated public key:", pubKey);
      console.log("Generated private key:", privKey);
    } catch (error) {
      console.error("Error generating keys:", error);
      alert("Failed to generate keys. Please try again.");
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!agreed) {
      alert("Please agree to the Terms of Service");
      return;
    }
    if (!publicKey || !privateKey) {
      alert("Please provide both public and private keys");
      return;
    }
    try {
      console.log("Importing key pair...");
      console.log("Public key:", publicKey);
      console.log("Private key:", privateKey);
      await acme.importKeyPair(publicKey, privateKey);
      console.log("Key pair imported successfully.");

      console.log("Creating account...");
      console.log("Email:", email);
      console.log("Agreed:", agreed);
      const account = await acme.createAccount([email], agreed);
      console.log("Account created successfully:", account);

      onSubmit && onSubmit({ email, account, publicKey, privateKey });
    } catch (error) {
      console.error("Error in account creation process:", error);
      alert(`Failed to create account: ${error.message}`);
    }
  };

  if (!directory) {
    return h("div", null, "Loading directory...");
  }

  return (
    h('form', { onSubmit: handleSubmit },
      h("h2", null, "Create New Account"),
      h("div", null, [
        h("input", { type: "email", value: email, onChange: (e) => setEmail(e.target.value), placeholder: "hi@lsong.org", required: true }),
      ]),
      h("div", null, [
        h("textarea", {
          value: publicKey,
          onChange: (e) => setPublicKey(e.target.value),
          placeholder: "Public Key (PEM format)",
          required: true
        }),
      ]),
      h("div", null, [
        h("textarea", {
          value: privateKey,
          onChange: (e) => setPrivateKey(e.target.value),
          placeholder: "Private Key (PEM format)",
          required: true
        }),
      ]),
      h("button", { type: "button", onClick: handleGenerateKeys }, "Generate New Keys"),
      h("label", null, [
        h("input", { type: "checkbox", checked: agreed, onChange: (e) => setAgreed(e.target.checked) }),
        "Agree to ",
        h("a", { href: directory.meta.website }, "Let's Encrypt"),
        " ",
        h("a", { href: directory.meta.termsOfService }, "Terms of Service"),
      ]),
      h("div", null, [
        h("button", { type: "submit" }, "Create Account"),
      ])
    )
  );
};

const Step3 = ({ acme, onSubmit }) => {
  const [domain, setDomain] = useState("");

  const handleSubmit = (e) => {
    e.preventDefault();
    onSubmit && onSubmit({ domain });
  };

  return (
    h('form', { onSubmit: handleSubmit },
      h("h2", null, "New Order"),
      h("div", { className: "domain-input" }, [
        h('span', null, "Secure "),
        h('span', null, "https://"),
        h("input", { value: domain, placeholder: "Your domain name", required: true, onChange: e => setDomain(e.target.value) }),
      ]),
      h("p", null, "Domain, subdomain, or wildcard domain"),
      h("button", { type: "submit" }, "Create Order")
    )
  );
};

const App = () => {
  const [step, setStep] = useState(1);
  const [data, setData] = useState({});
  const [acme] = useState(() => new AcmeClient());

  useEffect(() => {
    console.log('App is ready');
  }, []);

  const handleStep1 = (stepData) => {
    setData({ ...data, ...stepData });
    setStep(2);
  }

  const handleStep2 = (stepData) => {
    setData({ ...data, ...stepData });
    setStep(3);
  };

  const handleStep3 = (stepData) => {
    setData({ ...data, ...stepData });
    console.log("Final data:", { ...data, ...stepData });
    // Here you would typically send the data to your backend or perform the next action
  };

  return [
    h("h1", null, "Protect your website"),
    step === 1 && h(Step1, { acme, onSubmit: handleStep1 }),
    step === 2 && h(Step2, { acme, onSubmit: handleStep2 }),
    step === 3 && h(Step3, { acme, onSubmit: handleStep3 }),
  ]
}

ready(() => {
  const app = document.getElementById('app');
  render(h(App), app);
});