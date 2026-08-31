// run-subdomain-recon.js
// Passive subdomain enumeration for Advanced Scan, run on the GitHub Actions
// runner alongside ZAP. Replaces the earlier amass runner: OWASP Amass v5
// reliably hung past any reasonable timeout with zero output (confirmed on
// both solvbeat-prod and GitHub runners), so this uses ProjectDiscovery's
// subfinder instead -- single Go binary, passive sources only, one FQDN per
// line to stdout, exits cleanly. Writes /tmp/subdomain-result.json (array of
// subdomain strings) or /tmp/subdomain-error.txt, same partial-results shape
// as the ZAP/SpiderFoot scripts in this repo.

const { execFile } = require('child_process');
const fs = require('fs');

const TARGET_URL = process.env.TARGET_URL;
const MAX_DURATION_SECONDS = parseInt(process.env.SUBFINDER_MAX_DURATION_SECONDS, 10) || 180;

function hostnameFromUrl(targetUrl) {
  try { return new URL(targetUrl).hostname; } catch (e) { return targetUrl; }
}

(async () => {
  const hostname = hostnameFromUrl(TARGET_URL);
  try {
    const subdomains = await new Promise((resolve, reject) => {
      // -silent: only FQDNs on stdout (no banner/log). -all: every passive
      // source. -timeout bounds slow individual sources; the outer execFile
      // timeout is the hard ceiling. A timeout-kill still leaves partial
      // stdout worth keeping rather than failing the whole step.
      execFile(
        'subfinder',
        ['-d', hostname, '-silent', '-all', '-timeout', '30'],
        { timeout: MAX_DURATION_SECONDS * 1000, maxBuffer: 10 * 1024 * 1024 },
        (err, stdout) => {
          const lines = (stdout || '').split('\n').map((l) => l.trim().toLowerCase()).filter((l) => l && l.includes('.'));
          if (err && !err.killed && lines.length === 0) { reject(err); return; }
          resolve([...new Set(lines)]);
        }
      );
    });
    fs.writeFileSync('/tmp/subdomain-result.json', JSON.stringify(subdomains));
    console.log(`Subdomain recon done: ${subdomains.length} subdomain(s) for ${hostname}`);
  } catch (err) {
    console.error('Subdomain recon failed:', err.message);
    fs.writeFileSync('/tmp/subdomain-error.txt', err.message);
  }
})();
