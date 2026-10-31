#!/usr/bin/env node
// Copy only explicitly reviewed public files. Never recursively publish the repo.
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const output = path.join(root, 'site-dist');
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'site/public-files.json'), 'utf8'));
const files = new Set(manifest.files);
const config = JSON.parse(fs.readFileSync(path.join(root, 'vercel.json'), 'utf8'));
const excluded = new Set(['docs/shadow313-file-portal.html', 'docs/shadow313-download-portal.html',
  'docs/CyberShield-Suite.html', 'docs/launch-checklist.html', 'docs/performance-report.html',
  'docs/project-roadmap.html', 'docs/shadow313-analysis.html']);
const demos = new Set(manifest.files.filter(f => f.startsWith('docs/') && f.endsWith('.html') &&
  !['index','install','quickstart','api','modules','pqc','attck','contact','privacy','terms',
    'security-policy','changelog','careers','partners','case-studies','compliance'].includes(path.basename(f, '.html'))));
const notice = '<aside class="publication-notice" role="note" style="padding:12px 24px;border-bottom:1px solid #615192;background:#100c24;color:#ded6ff;font:14px/1.6 system-ui">Reference / demonstration page. Any sample metrics, security findings, certifications, signatures, or receipts shown here are not evidence of live monitoring or independently verified compliance. No Python scanner runs on this website.</aside>';

function build() {
  for (const relative of files) {
    if (path.isAbsolute(relative) || relative.split('/').some(p => p === '..') ||
        !/\.(html|css|js|json|txt|xml)$/.test(relative) || relative.startsWith('api/')) {
      throw new Error(`Invalid public path: ${relative}`);
    }
    const src = path.join(root, relative);
    if (!fs.statSync(src).isFile() || fs.lstatSync(src).isSymbolicLink()) throw new Error(`Not a file: ${relative}`);
  }
  for (const rule of config.rewrites) {
    if (rule.destination.startsWith('/api/')) continue;
    if (!files.has(rule.destination.slice(1))) throw new Error(`Unpublished rewrite: ${rule.source}`);
  }
  fs.rmSync(output, {recursive: true, force: true});
  for (const relative of files) {
    let data = fs.readFileSync(path.join(root, relative));
    if (relative.endsWith('.html')) {
      let text = data.toString();
      // Keep archive/source files intact, but never link visitors to unpublished artifacts.
      text = text.replace(/<a\b[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/g, (tag, href, label) => {
        let target;
        try { target = new URL(href, `https://site.invalid/${relative}`).pathname.slice(1); }
        catch { return tag; }
        if (excluded.has(target)) return `<span title="Repository-only historical document">${label}</span>`;
        const rewrite = config.rewrites.find(r => r.source === '/' + target);
        if (!rewrite && ['roadmap','performance','analysis'].includes(target)) return `<span>${label}</span>`;
        return tag;
      });
      if (demos.has(relative)) text = text.replace(/(<nav id="site-nav"[\s\S]*?<\/nav>)/, '$1' + notice);
      data = Buffer.from(text);
    }
    const dest = path.join(output, relative);
    fs.mkdirSync(path.dirname(dest), {recursive:true});
    fs.writeFileSync(dest, data);
  }
  fs.writeFileSync(path.join(output, '.nojekyll'), '');
  console.log(`Built ${files.size} public files into site-dist; no repository fallback.`);
}
if (require.main === module) build();
module.exports = {build, files, output};
