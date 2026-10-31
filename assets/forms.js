/* Same-origin contact/request forms; no secrets in the browser. */
(() => {
  const forms = [...document.querySelectorAll('form[data-site-form]')];
  if (!forms.length) return;
  const widgets = new Map();
  const status = form => form.querySelector('[role="status"]');
  for (const form of forms) {
    form.addEventListener('submit', async event => {
      event.preventDefault();
      if (!form.reportValidity()) return;
      const output = status(form);
      const button = form.querySelector('button[type="submit"]');
      const widget = widgets.get(form);
      const token = window.turnstile && widget !== undefined ? window.turnstile.getResponse(widget) : '';
      if (!token) { output.textContent = 'Complete verification before submitting. If unavailable, use the direct email link.'; return; }
      button.disabled = true;
      output.textContent = 'Sending…';
      const values = Object.fromEntries(new FormData(form));
      values.consent = form.querySelector('[name="consent"]').checked;
      values.token = token;
      try {
        const response = await fetch(`/api/${form.dataset.siteForm}`, {method:'POST',
          headers:{'Content-Type':'application/json'}, body:JSON.stringify(values), signal:AbortSignal.timeout(25000)});
        const body = await response.json();
        output.textContent = response.ok && body.accepted ? body.message : (body.message || 'Unable to send. Please use the direct email link.');
        if (response.ok && body.accepted) form.reset();
      } catch { output.textContent = 'Unable to confirm submission. Please use the direct email link; do not assume your request was received.'; }
      finally { window.turnstile.reset(widget); button.disabled = false; }
    });
  }
  async function setup() {
    let config;
    try { const response = await fetch('/api/forms/config'); if (!response.ok) throw new Error(); config = await response.json(); }
    catch { config = {enabled:false}; }
    if (!config.enabled) {
      for (const form of forms) {
        status(form).textContent = 'Online forms are not connected yet. Please use the direct email link below.';
        form.querySelector('button[type="submit"]').disabled = true;
      }
      return;
    }
    window.shadow313FormsReady = () => {
      for (const form of forms) {
        const id = window.turnstile.render(form.querySelector('.form-verification'), {
          sitekey:config.siteKey, action:form.dataset.siteForm,
          callback:() => { form.querySelector('button[type="submit"]').disabled = false; },
          'expired-callback':() => { form.querySelector('button[type="submit"]').disabled = true; },
          'error-callback':() => { status(form).textContent = 'Verification unavailable. Use the direct email link.'; },
        });
        widgets.set(form, id);
        status(form).textContent = 'Complete verification, then submit your request.';
      }
    };
    const script = document.createElement('script');
    script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?onload=shadow313FormsReady&render=explicit';
    script.async = true; script.defer = true;
    script.onerror = () => { for (const form of forms) status(form).textContent = 'Verification unavailable. Use the direct email link.'; };
    document.head.appendChild(script);
  }
  setup();
})();
