// run-js-render-recon.js
// Rendered-browser version of SolveBeat's Black-box Recon (supplyChainRecon.js
// on solvbeat-prod): that tool only regex-parses <script src> out of the raw
// HTML a plain HTTP fetch returns, so a JS-framework/SPA site (client's own
// bundle injected into the DOM by its own runtime, not present as a static
// <script> tag) is mostly invisible to it -- confirmed live against a real
// client site (Reevue-based ordering SPA): the static fetch saw 2 scripts,
// nowhere near everything the site's own JS actually loads once it runs.
// This runs an actual headless Chrome via Puppeteer, lets the page's own
// scripts execute, and records every script response Chrome itself made --
// then runs the exact same two checks the static version does (exposed
// source maps, retire.js signature matching for known-vulnerable library
// versions) against that real, complete set.
//
// Runs on an isolated GitHub Actions runner (not solvbeat-prod) for the same
// reason ZAP/SpiderFoot/Nuclei do -- a headless Chrome process is memory-
// heavy enough to risk starving the live API process sharing that box's RAM.

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

function headOk(url, timeoutMs = 6000) {
  return new Promise((resolve) => {
    try {
      const mod = url.startsWith('https:') ? https : http;
      const req = mod.request(url, { method: 'GET', timeout: timeoutMs, headers: { 'User-Agent': SCAN_USER_AGENT, Range: 'bytes=0-2048' } }, (res) => {
        resolve(res.statusCode === 200 || res.statusCode === 206);
        res.resume();
      });
      req.on('error', () => resolve(false));
      req.on('timeout', () => { req.destroy(); resolve(false); });
      req.end();
    } catch (err) {
      resolve(false);
    }
  });
}

// Lets the target's own JS run in a real browser, then records every script
// response Chrome itself actually made -- this is the entire point: it sees
// bundles a framework injects after load, not just what's declared in the
// static initial HTML.
async function collectRenderedScripts(targetUrl) {
  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });
  const scriptUrls = new Set();
  try {
    const page = await browser.newPage();
    await page.setUserAgent(SCAN_USER_AGENT);
    page.on('response', (res) => {
      try {
        const req = res.request();
        const ct = res.headers()['content-type'] || '';
        if (req.resourceType() === 'script' || /javascript/i.test(ct)) {
          scriptUrls.add(res.url().split('#')[0]);
        }
      } catch (e) { /* ignore malformed responses */ }
    });
    await page.goto(targetUrl, { waitUntil: 'networkidle2', timeout: 45000 });
    // A short settle window for SPAs that lazy-load a second wave of
    // bundles just after the initial idle point (route-based code
    // splitting, deferred analytics, etc).
    await new Promise((resolve) => setTimeout(resolve, 3000));
  } finally {
    await browser.close();
  }
  return Array.from(scriptUrls).slice(0, 60); // bounded, same spirit as the static version's cap
}

async function checkExposedSourceMaps(scriptUrls) {
  const findings = [];
  for (const url of scriptUrls) {
    if (url.endsWith('.map')) continue;
    let mapUrl;
    try {
      const u = new URL(url);
      if (!u.pathname.endsWith('.js')) continue;
      u.pathname = u.pathname + '.map';
      u.search = '';
      mapUrl = u.toString();
    } catch (err) { continue; }
    const exposed = await headOk(mapUrl);
    if (exposed) {
      findings.push({
        type: 'source_map_exposed',
        severity: 'medium',
        title: 'Source map exposed for a served script',
        detail: `${mapUrl} is publicly reachable — it can reveal unminified source code, internal file paths, and sometimes comments or config left in during development. Found via rendered-browser recon (not visible to a static HTML fetch).`,
        scriptUrl: url,
      });
    }
  }
  return findings;
}

function runRetire(dir) {
  return new Promise((resolve) => {
    execFile('retire', ['--path', dir, '--outputformat', 'json', '--exitwith', '0'], { timeout: 60000, maxBuffer: 10 * 1024 * 1024 }, (err, stdout) => {
      if (err) {
        const reason = err.code === 'ENOENT' ? 'retire.js is not installed on this runner.' : `retire.js failed to run: ${err.message}`;
        resolve({ data: [], toolError: reason });
        return;
      }
      if (!stdout) { resolve({ data: [] }); return; }
      try {
        resolve(JSON.parse(stdout));
      } catch (parseErr) {
        resolve({ data: [], toolError: 'retire.js produced output that could not be parsed as JSON.' });
      }
    });
  });
}

async function scanScriptsWithRetire(scriptUrls) {
  if (!scriptUrls.length) return { findings: [], toolError: null };
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'solvbeat-retire-'));
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
    if (i === 0) return { findings: [], toolError: null };

    const result = await runRetire(tmpDir);
    const findings = [];
    for (const fileResult of (result.data || [])) {
      const filename = path.basename(fileResult.file || '');
      const sourceUrl = urlByFile[filename] || filename;
      for (const component of (fileResult.results || [])) {
        for (const vuln of (component.vulnerabilities || [])) {
          const cveList = (vuln.identifiers && vuln.identifiers.CVE) || [];
          findings.push({
            type: 'vulnerable_library',
            severity: vuln.severity || 'medium',
            title: `${component.component} ${component.version} — ${(vuln.identifiers && vuln.identifiers.summary) || 'known vulnerability'}`,
            detail: `Detected via retire.js signature matching against a script the rendered page actually loaded (not visible to a static HTML fetch).${cveList.length ? ' ' + cveList.join(', ') : ''}`,
            scriptUrl: sourceUrl,
            component: component.component,
            version: component.version,
            cveIds: cveList,
          });
        }
      }
    }
    return { findings, toolError: result.toolError || null };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

(async () => {
  try {
    const scriptUrls = await collectRenderedScripts(TARGET_URL);
    const [sourceMapFindings, retireResult] = await Promise.all([
      checkExposedSourceMaps(scriptUrls),
      scanScriptsWithRetire(scriptUrls),
    ]);
    const notes = [`Rendered-browser scan saw ${scriptUrls.length} script(s) actually loaded by the page -- including any injected by its own JavaScript after load, not just what's declared in the static HTML.`];
    if (retireResult.toolError) notes.push(retireResult.toolError);
    const findings = [...sourceMapFindings, ...retireResult.findings];
    fs.writeFileSync('/tmp/js-recon-result.json', JSON.stringify({ findings, notes, scriptCount: scriptUrls.length }));
    console.log(`JS-render recon done: ${findings.length} finding(s) across ${scriptUrls.length} rendered script(s).`);
  } catch (err) {
    console.error('JS-render recon failed:', err.message);
    fs.writeFileSync('/tmp/js-recon-error.txt', String((err && err.message) || err));
  }
})();
