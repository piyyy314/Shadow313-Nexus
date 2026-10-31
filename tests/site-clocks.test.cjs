const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const pages = [
  '313-bind-verification-portal', 'adversarial-pivot-dashboard',
  'federated-mesh', 'launch-checklist', 'shadow313-ai-stack-map', 'vsat-tactical-suite',
];
for (const name of pages) {
  test(`${name}: clock initialization survives the shared header`, () => {
    const html = fs.readFileSync(path.join(__dirname, '../docs', `${name}.html`), 'utf8');
    const footer = {};
    const clock = {};
    const source = html.match(/function updateClock\(\)\s*\{[\s\S]*?\}/)[0];
    const sandbox = {
      document: {getElementById: id => id === 'footer-clock' ? footer : null},
    };
    vm.runInNewContext(`${source}; updateClock();`, sandbox);
    if (name === 'vsat-tactical-suite') assert.match(footer.textContent, / UTC$/);
    sandbox.document.getElementById = id => id === 'clock' ? clock : footer;
    vm.runInNewContext(`${source}; updateClock();`, sandbox);
    assert.match(clock.textContent, / UTC$/);
  });
}
