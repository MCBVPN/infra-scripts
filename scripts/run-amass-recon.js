// run-amass-recon.js
// Passive subdomain enumeration for Advanced Scan, run on this same GitHub
// Actions runner alongside ZAP -- amass (OWASP Amass v5) proved too slow
// and unreliable on solvbeat-prod itself (a 2-vCPU box; a passive amass
// enum against a real domain regularly ran past 4 minutes with zero
// output), so it lives here instead where a runner has real headroom and
// slowness just costs GitHub Actions minutes, not shared production
// capacity. Writes /tmp/amass-result.json (array of subdomain strings) or
// /tmp/amass-error.txt, same partial-results-on-timeout shape as the ZAP
// and SpiderFoot scripts in this repo.

const { execFile } = require('child_process');
const fs = require('fs');

const TARGET_URL = process.env.TARGET_URL;
const MAX_DURATION_SECONDS = parseInt(process.env.AMASS_MAX_DURATION_SECONDS, 10) || 180;

function hostnameFromUrl(targetUrl) {
  try {
    return new URL(targetUrl).hostname;
  } catch (e) {
    return targetUrl;
  }
}

(async () => {
  const hostname = hostnameFromUrl(TARGET_URL);
  try {
    const subdomains = await new Promise((resolve, reject) => {
      // -passive: certificate-transparency/DNS-record sources only, never
      // touches the target directly (matches "detect and report, never
      // exploit" -- also the only mode fast enough to bound with a
      // timeout at all). -timeout is amass's own "minutes without
      // progress" budget; the outer execFile timeout is the hard ceiling
      // that actually guarantees this step ends.
      execFile(
        'amass',
        ['enum', '-passive', '-silent', '-d', hostname, '-timeout', String(Math.max(1, Math.round(MAX_DURATION_SECONDS / 60)))],
        { timeout: MAX_DURATION_SECONDS * 1000, maxBuffer: 5 * 1024 * 1024 },
        (err, stdout) => {
          // amass -silent still prints one FQDN per line to stdout on
          // completion; a timeout-kill (err.killed) still leaves partial
          // stdout worth keeping rather than treating as a hard failure.
          const lines = (stdout || '').split('\n').map((l) => l.trim()).filter((l) => l && l.includes('.'));
          if (err && !err.killed && lines.length === 0) {
            reject(err);
            return;
          }
          resolve([...new Set(lines)]);
        }
      );
    });
    fs.writeFileSync('/tmp/amass-result.json', JSON.stringify(subdomains));
    console.log(`Amass recon done: ${subdomains.length} subdomain(s) for ${hostname}`);
  } catch (err) {
    console.error('Amass recon failed:', err.message);
    fs.writeFileSync('/tmp/amass-error.txt', err.message);
  }
})();
