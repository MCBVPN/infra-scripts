// run-nuclei-scan.js
// Runs nuclei (ProjectDiscovery's community CVE/misconfig template engine)
// against the target on the GitHub Actions runner, alongside ZAP + subfinder.
// nuclei's runtime against a live host is too variable to run inline in the
// synchronous free scan (60s-150s+, throttled by CDN/WAF), so it lives here
// where a multi-minute run is fine. Writes /tmp/nuclei-result.json (array of
// {template, severity, target}) or /tmp/nuclei-error.txt.

const { execFile } = require('child_process');
const fs = require('fs');

const TARGET_URL = process.env.TARGET_URL;
const MAX_DURATION_SECONDS = parseInt(process.env.NUCLEI_MAX_DURATION_SECONDS, 10) || 600;

(async () => {
  try {
    const findings = await new Promise((resolve, reject) => {
      execFile(
        'nuclei',
        ['-u', TARGET_URL, '-severity', 'critical,high,medium', '-silent', '-timeout', '10', '-retries', '1', '-jsonl'],
        { timeout: MAX_DURATION_SECONDS * 1000, maxBuffer: 20 * 1024 * 1024 },
        (err, stdout) => {
          const out = stdout || '';
          const rows = out.split('\n').map((l) => l.trim()).filter(Boolean).map((line) => {
            try {
              const o = JSON.parse(line);
              return {
                template: o['template-id'] || o.templateID || 'finding',
                severity: (o.info && o.info.severity) || 'unknown',
                name: (o.info && o.info.name) || '',
                target: o.matched || o.host || TARGET_URL,
              };
            } catch (e) { return null; }
          }).filter(Boolean);
          // A timeout-kill still leaves partial JSONL worth reporting.
          if (err && !err.killed && rows.length === 0) { reject(err); return; }
          resolve(rows.slice(0, 100));
        }
      );
    });
    fs.writeFileSync('/tmp/nuclei-result.json', JSON.stringify(findings));
    console.log(`nuclei scan done: ${findings.length} finding(s)`);
  } catch (err) {
    console.error('nuclei scan failed:', err.message);
    fs.writeFileSync('/tmp/nuclei-error.txt', err.message);
  }
})();
