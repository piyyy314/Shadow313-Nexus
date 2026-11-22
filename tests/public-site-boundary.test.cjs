'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { build } = require('../scripts/build-public-site.cjs');

const root = path.resolve(__dirname, '..');
const output = path.join(root, 'public-site');

function walk(directory, prefix = '') {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const relative = path.posix.join(prefix, entry.name);
    if (entry.isDirectory()) return walk(path.join(directory, entry.name), relative);
    return [relative];
  });
}

test('public site contains exactly the explicit static allowlist plus .nojekyll', () => {
  build();
  const allowlist = JSON.parse(fs.readFileSync(path.join(root, 'site/public-files.json'), 'utf8'));
  const expected = [...allowlist, '.nojekyll'].sort();
  const actual = walk(output).sort();
  assert.deepEqual(actual, expected);
});

test('Vercel serverless API and repository source stay outside static output', () => {
  assert.ok(fs.statSync(path.join(root, 'api/index.js')).isFile());
  for (const excluded of ['api', '.github', 'scripts', 'tests', 'shadow313', 'local_bundle', 'logs', '.git']) {
    assert.equal(fs.existsSync(path.join(output, excluded)), false, `unexpected published path: ${excluded}`);
  }
});
