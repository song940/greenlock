import { ready } from 'https://lsong.org/scripts/dom.js';
import { h, render, useState, useEffect } from 'https://lsong.org/scripts/components/index.js';

const Step1 = ({ onSubmit }) => {
  const [domain, setDomain] = useState();
  const [api, setAPI] = useState();
  const handleSubmit = async e => {
    e.preventDefault();
    const res = await fetch(api);
    const data = await res.json();
    onSubmit && onSubmit({ domain, directory: data });
  }
  return (
    h('form', { className: 'step1', onSubmit: handleSubmit },
      h("div", { class: "domain-input" }, [
        h('span', null, "Secure "),
        h('span', null, "https://"),
        h("input", { value: domain, placeholder: "Your domain name", required: true, onChange: e => setDomain(e.target.value) }),
      ]),
      h("p", null, "Domain, subdomain, or wildcard domain"),
      h("button", { type: "submit" }, "Let's Encrypt"),
      h("p"),
      h("div", null,
        h("div", null, [
          h("input", { type: "text", value: api, required: true }),
        ]),
        h("label", null, [
          h("input", { name: "api", type: "radio", onClick: () => setAPI("https://acme-v02.api.letsencrypt.org/directory") }),
          "Production"
        ]),
        h("label", null, [
          h("input", { name: "api", type: "radio", onClick: () => setAPI("https://acme-staging-v02.api.letsencrypt.org/directory") }),
          "Testing"
        ]),

        h("p", null, [
          "API Compatibility: ",
          h("a", { href: "https://letsencrypt.org/docs/client-options" }, "Let's Encrypt v2"),
          "/",
          h("a", { href: "https://www.rfc-editor.org/rfc/rfc8555.html" }, "ACME RFC8555"),
        ]),
      ),
    )
  );
}

const Step2 = ({ directory, onSubmit }) => {
  const handleSubmit = () => {
    onSubmit && onSubmit();
  };
  return (
    h('div', null, [
      h("h2", null, "What's your email?"),
      h("div", null, [
        h("input", { type: "email", name: "email", placeholder: "hi@lsong.org" }),
      ]),
      h("label", null, [
        h("input", { type: "checkbox" }),
        "Agree to ",
        h("a", { href: directory.meta.website }, "Let's Encrypt"),
        h("a", { href: directory.meta.termsOfService }, "Terms of Service"),
      ]),
      h("div", null, [
        h("button", { onClick: handleSubmit }, "Next"),
      ])
    ])
  );
};

const App = () => {
  const [step, setStep] = useState(1);
  const [step1Data, setStep1Data] = useState();
  useEffect(() => {
    console.log('App is ready');
  }, []);
  const handleStep1 = (e) => {
    setStep1Data(e);
    setStep(2);
  }
  const handleStep2 = (e) => {
    console.log(e);
    setStep(3);
  };
  return [
    h("h1", null, "Protect your website"),
    step == 1 && h(Step1, { onSubmit: handleStep1 }),
    step == 2 && h(Step2, { ...step1Data, onSubmit: handleStep2 }),
  ]
}

ready(() => {
  const app = document.getElementById('app');
  render(h(App), app);
});