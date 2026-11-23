'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { build } = require('../scripts/build-public-site.cjs');

const root = path.resolve(__dirname, '..');
const output = path.join(root, 'public-site');

test('public build contains only allowlisted files plus required deployment metadata', () => {
  build();
  const allowlist = JSON.parse(fs.readFileSync(path.join(root, 'site/public-files.json'), 'utf8'));
  for (const relative of allowlist) {
    assert.ok(fs.statSync(path.join(output, relative)).isFile(), `missing public file: ${relative}`);
  }
  assert.ok(fs.statSync(path.join(output, 'vercel.json')).isFile());
  assert.ok(fs.statSync(path.join(output, 'api/index.js')).isFile());
  assert.ok(fs.existsSync(path.join(output, '.nojekyll')));
  for (const privatePath of ['.github', 'scripts', 'tests', 'shadow313', 'local_bundle', 'logs']) {
    assert.equal(fs.existsSync(path.join(output, privatePath)), false, `unexpected published path: ${privatePath}`);
  }
});

test('every Vercel rewrite destination exists in the allowlisted output', () => {
  build();
  const config = JSON.parse(fs.readFileSync(path.join(output, 'vercel.json'), 'utf8'));
  for (const rewrite of config.rewrites || []) {
    const destination = rewrite.destination.replace(/^\//, '');
    assert.ok(fs.existsSync(path.join(output, destination)), `missing rewrite destination: ${rewrite.destination}`);
  }
});
