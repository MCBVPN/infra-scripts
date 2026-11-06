// run-nuclei-targeted.js
// One-off, scoped nuclei run for a known authorized pentest engagement
// (e.g. confirming a specific CVE/template match) instead of the full
// default template set the regular Advanced Scan runs. Doesn't compete
// with ZAP for the job's time budget -- this is its own workflow, so a
// slow target doesn't get cut off by someone else's timeout.
// Writes /tmp/nuclei-targeted-result.json or /tmp/nuclei-targeted-error.txt.

const { execFile } = require('child_process');
const fs = require('fs');

const TARGET_URL = process.env.TARGET_URL;
const TAGS = process.env.TEMPLATE_TAGS || '';
const TEMPLATE_IDS = process.env.TEMPLATE_IDS || '';
const MAX_DURATION_SECONDS = parseInt(process.env.NUCLEI_MAX_DURATION_SECONDS, 10) || 300;

const args = ['-u', TARGET_URL, '-severity', 'critical,high,medium,low,info', '-silent', '-timeout', '15', '-retries', '2', '-jsonl'];
if (TAGS) args.push('-tags', TAGS);
if (TEMPLATE_IDS) args.push('-id', TEMPLATE_IDS);

console.log('nuclei args:', args.join(' '));

execFile('nuclei', args, { timeout: MAX_DURATION_SECONDS * 1000, maxBuffer: 20 * 1024 * 1024 }, (err, stdout, stderr) => {
  const out = stdout || '';
  const rows = out.split('\n').map((l) => l.trim()).filter(Boolean).map((line) => {
    try {
      const o = JSON.parse(line);
      return {
        template: o['template-id'] || o.templateID || 'finding',
        severity: (o.info && o.info.severity) || 'unknown',
        name: (o.info && o.info.name) || '',
        matched: o.matched || o.host || TARGET_URL,
        extracted: o['extracted-results'] || o.extractedResults || undefined,
        curl: o['curl-command'] || undefined,
      };
    } catch (e) { return null; }
  }).filter(Boolean);

  if (err && !err.killed && rows.length === 0) {
    console.error('nuclei scan failed:', err.message, stderr || '');
    fs.writeFileSync('/tmp/nuclei-targeted-error.txt', `${err.message}\n${stderr || ''}`);
    process.exit(0);
  }
  if (err && err.killed) {
    console.error(`nuclei hit its own ${MAX_DURATION_SECONDS}s timeout -- reporting ${rows.length} partial result(s)`);
  }
  fs.writeFileSync('/tmp/nuclei-targeted-result.json', JSON.stringify(rows, null, 2));
  console.log(`nuclei targeted scan done: ${rows.length} finding(s)`);
});
