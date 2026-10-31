#!/usr/bin/env node
// Reviewable public-output boundary. Never copy repository archives or source trees.
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const output = path.join(root, 'public-site');
const allowed = JSON.parse(fs.readFileSync(path.join(root, 'site/public-files.json'), 'utf8'));
function build() {
  fs.rmSync(output, {recursive:true, force:true});
  for (const relative of allowed) {
    if (path.isAbsolute(relative) || relative.split('/').includes('..') ||
        !/\.(html|js|css|json|xml|txt)$/.test(relative)) throw new Error(`Invalid public file ${relative}`);
    const file = path.join(root, relative);
    if (!fs.statSync(file).isFile() || fs.lstatSync(file).isSymbolicLink()) throw new Error(`Not a regular file: ${relative}`);
    const dest = path.join(output, relative);
    fs.mkdirSync(path.dirname(dest), {recursive:true});
    if (relative.startsWith('docs/') && relative.endsWith('.html')) {
      const notice = '<aside role="note" style="padding:12px 24px;background:#100c24;color:#ded6ff;font:14px/1.6 system-ui">Reference / demo content. Static metrics and service labels are not live health, scan results, certifications, or signed receipts. Run and verify the local tools separately.</aside>';
      const html = fs.readFileSync(file, 'utf8').replace(/(<nav id="site-nav"[\s\S]*?<\/nav>)/, '$1' + notice);
      fs.writeFileSync(dest, html);
    } else {
      fs.copyFileSync(file, dest);
    }
  }
  fs.writeFileSync(path.join(output, '.nojekyll'), '');
  console.log(`Published ${allowed.length} allowlisted static files; repository source not served.`);
}
if (require.main === module) build();
module.exports = {build};
