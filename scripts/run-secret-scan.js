// run-secret-scan.js
// Renders the target in a real headless browser (same technique as
// run-js-render-recon.js -- sees SPA-injected bundles a static fetch
// misses), downloads every script it actually loads (external + inline),
// then runs TruffleHog's filesystem scan against them looking for hardcoded
// API keys, cloud credentials, and tokens shipped in client-side JS. This
// is a genuinely common real-world finding class (client-side JS is public
// by definition -- anything hardcoded in it is exposed to every visitor)
// that nothing else on this page checks for.

const fs = require('fs');
const path = require('path');
const os = require('os');
const https = require('https');
const http = require('http');
const { execFile } = require('child_process');
const puppeteer = require('puppeteer');

const TARGET_URL = process.env.TARGET_URL;
const SCAN_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';

function fetchText(url, timeoutMs = 8000) {
  return new Promise((resolve) => {
    try {
      const mod = url.startsWith('https:') ? https : http;
      const req = mod.get(url, { timeout: timeoutMs, headers: { 'User-Agent': SCAN_USER_AGENT } }, (res) => {
        if (res.statusCode !== 200) { resolve(null); res.resume(); return; }
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (c) => { body += c; if (body.length > 5_000_000) { req.destroy(); } });
        res.on('end', () => resolve(body));
      });
      req.on('error', () => resolve(null));
      req.on('timeout', () => { req.destroy(); resolve(null); });
    } catch (err) {
      resolve(null);
    }
  });
}

async function collectRenderedScripts(targetUrl) {
  const browser = await puppeteer.launch({ headless: 'new', args: ['--no-sandbox', '--disable-setuid-sandbox'] });
  const scriptUrls = new Set();
  let inlineScripts = [];
  try {
    const page = await browser.newPage();
    await page.setUserAgent(SCAN_USER_AGENT);
    page.on('response', (res) => {
      try {
        const req = res.request();
        const ct = res.headers()['content-type'] || '';
        if (req.resourceType() === 'script' || /javascript/i.test(ct)) scriptUrls.add(res.url().split('#')[0]);
      } catch (e) {}
    });
    await page.goto(targetUrl, { waitUntil: 'networkidle2', timeout: 45000 });
    await new Promise((resolve) => setTimeout(resolve, 3000));
    inlineScripts = await page.$$eval('script:not([src])', (els) => els.map((e) => e.textContent || ''));
  } finally {
    await browser.close();
  }
  return { scriptUrls: Array.from(scriptUrls).slice(0, 60), inlineScripts: inlineScripts.filter((t) => t.trim().length > 50).slice(0, 15) };
}

function runTrufflehog(dir) {
  return new Promise((resolve) => {
    execFile('trufflehog', ['filesystem', dir, '--json', '--no-update'], { timeout: 60000, maxBuffer: 20 * 1024 * 1024 }, (err, stdout) => {
      // TruffleHog exits non-zero when it finds results (that's success for
      // us, not a tool failure) -- only ENOENT (binary missing) is a real
      // "the tool itself didn't run" condition.
      if (err && err.code === 'ENOENT') {
        resolve({ lines: [], toolError: 'trufflehog is not installed on this runner.' });
        return;
      }
      const lines = (stdout || '').split('\n').map((l) => l.trim()).filter(Boolean);
      resolve({ lines, toolError: null });
    });
  });
}

function maskSecret(raw) {
  if (!raw || raw.length <= 8) return '••••••••';
  return raw.slice(0, 4) + '…' + raw.slice(-4);
}

(async () => {
  try {
    const { scriptUrls, inlineScripts } = await collectRenderedScripts(TARGET_URL);
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'solvbeat-secrets-'));
    const urlByFile = {};
    try {
      let i = 0;
      for (const url of scriptUrls) {
        const body = await fetchText(url);
        if (!body) continue;
        const filename = `script_${i}.js`;
        fs.writeFileSync(path.join(tmpDir, filename), body);
        urlByFile[filename] = url;
        i++;
      }
      inlineScripts.forEach((content, idx) => {
        const filename = `inline_${idx}.js`;
        fs.writeFileSync(path.join(tmpDir, filename), content);
        urlByFile[filename] = `${TARGET_URL} (inline <script> #${idx + 1})`;
      });

      const { lines, toolError } = await runTrufflehog(tmpDir);
      const findings = [];
      const seen = new Set();
      for (const line of lines) {
        let rec;
        try { rec = JSON.parse(line); } catch (e) { continue; }
        const raw = rec.Raw || '';
        const dedupeKey = (rec.DetectorName || '') + '|' + raw;
        if (seen.has(dedupeKey)) continue;
        seen.add(dedupeKey);
        const filePath = (rec.SourceMetadata && rec.SourceMetadata.Data && rec.SourceMetadata.Data.Filesystem && rec.SourceMetadata.Data.Filesystem.file) || '';
        const filename = path.basename(filePath);
        const sourceUrl = urlByFile[filename] || filename || TARGET_URL;
        const verified = !!rec.Verified;
        findings.push({
          type: 'leaked_secret',
          severity: verified ? 'critical' : 'medium',
          title: `${rec.DetectorName || 'Secret'} ${verified ? '(confirmed live)' : '(pattern match, unconfirmed)'} found in client-side JS`,
          detail: `${verified ? 'TruffleHog confirmed this credential is live by testing it against the real service — not a pattern guess.' : 'Matches the known format for this credential type, but was not (or could not be) verified live -- confirm before reporting as definite.'} Masked value: ${rec.Redacted || maskSecret(raw)}. Found in: ${sourceUrl}`,
          scriptUrl: sourceUrl,
        });
      }
      const notes = [];
      if (toolError) notes.push(toolError);
      fs.writeFileSync('/tmp/secret-scan-result.json', JSON.stringify({ findings, notes, scriptCount: scriptUrls.length + inlineScripts.length }));
      console.log(`Secret scan done: ${findings.length} finding(s) across ${scriptUrls.length + inlineScripts.length} script(s).`);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  } catch (err) {
    console.error('Secret scan failed:', err.message);
    fs.writeFileSync('/tmp/secret-scan-error.txt', String((err && err.message) || err));
  }
})();
