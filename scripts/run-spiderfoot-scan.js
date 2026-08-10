// run-spiderfoot-scan.js
// Runs inside the GitHub Actions runner against the SpiderFoot daemon
// started earlier in this same job (127.0.0.1). Ported from the
// orchestration logic that used to live in SolveBeat's backend
// (zapSpiderfoot.js) -- same startscan/scanstatus/scaneventresults calls,
// same AUTOMATED_EXPOSURE_MODULES list, same max-duration-with-partial-
// results behaviour.
//
// One deliberate simplification vs. the old backend code: production's
// SpiderFoot talked to solvbeat-prod over curl+digest-auth because that
// instance is a permanent, always-on daemon on a shared multi-tenant box
// (defense in depth) -- and because the npm 'digest-fetch' library
// mis-computes the digest against it. Here, SpiderFoot is a fresh
// daemon started by THIS SAME job, bound to loopback, with no other
// tenant on the runner that could ever reach it -- so there is nothing
// for auth to defend against, and it's started with no passwd file (no
// auth configured), letting this script use plain fetch() instead of a
// curl subprocess. The scan logic/parsing itself is unchanged.

const fs = require('fs');

const SPIDERFOOT_URL = process.env.SPIDERFOOT_URL;
const TARGET_URL = process.env.TARGET_URL;
const MAX_DURATION_MS = (parseInt(process.env.MAX_DURATION_SECONDS, 10) || 720) * 1000;

const AUTOMATED_EXPOSURE_MODULES = [
  'sfp_dnsresolve',
  'sfp_spider',
  'sfp_ssl',
  'sfp_pgp',
  'sfp_mnemonic',
  'sfp_dnsbrute',
  'sfp_email',
  'sfp_crt',
  'sfp_accounts',
  'sfp_leakix',
  'sfp_s3bucket',
  'sfp_portscan_tcp',
  'sfp_tool_dnstwist',
  'sfp_blocklistde',
  'sfp_abuseipdb',
  'sfp_openphish',
  'sfp_phishtank',
  'sfp_phishstats',
  'sfp_pastebin',
  'sfp_spamcop',
  'sfp_spamhaus',
  'sfp_digitaloceanspace',
  'sfp_honeypot',
];

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function hostnameFromUrl(targetUrl) {
  try {
    return new URL(targetUrl).hostname;
  } catch (e) {
    return targetUrl;
  }
}

async function startSpiderfootScan(targetDomain, scanName, modules) {
  const params = new URLSearchParams({
    scanname: scanName,
    scantarget: targetDomain,
    modulelist: modules.join(','),
    typelist: '',
    usecase: modules.length ? '' : 'all',
  });

  const res = await fetch(`${SPIDERFOOT_URL}/startscan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
    redirect: 'manual',
  });

  // SpiderFoot responds 303 (redirect) to /scaninfo?id=XXXX when the scan
  // was created OK.
  if (res.status !== 303 && res.status !== 200) {
    throw new Error(`SpiderFoot startscan failed: ${res.status}`);
  }

  const location = res.headers.get('location') || '';
  const match = location.match(/id=([a-zA-Z0-9]+)/);
  if (match) return match[1];

  const body = await res.text();
  const bodyMatch = body.match(/Scan \[([A-Z0-9]+)\]/);
  if (bodyMatch) {
    throw new Error(`SpiderFoot scan created but failed to start: ${bodyMatch[1]}`);
  }
  throw new Error('SpiderFoot startscan: no scan ID found in response');
}

async function getSpiderfootScanStatus(scanId) {
  const res = await fetch(`${SPIDERFOOT_URL}/scanstatus?id=${scanId}`);
  if (res.status !== 200) {
    throw new Error(`SpiderFoot scanstatus failed: ${res.status}`);
  }
  return res.json();
  // Result is usually an array; index 5 is the state:
  // 'RUNNING', 'FINISHED', 'ERROR-FAILED', etc.
}

async function getSpiderfootResults(scanId) {
  const res = await fetch(`${SPIDERFOOT_URL}/scaneventresults?id=${scanId}&eventType=ALL`);
  if (res.status !== 200) {
    throw new Error(`SpiderFoot scaneventresults failed: ${res.status}`);
  }
  return res.json();
}

(async () => {
  const deadline = Date.now() + MAX_DURATION_MS;
  const hostname = hostnameFromUrl(TARGET_URL);
  try {
    const scanId = await startSpiderfootScan(hostname, `SolveBeat - ${hostname}`, AUTOMATED_EXPOSURE_MODULES);
    let results = null;
    while (Date.now() < deadline) {
      const status = await getSpiderfootScanStatus(scanId);
      const state = Array.isArray(status) ? status[5] : null;
      if (state === 'FINISHED') {
        results = await getSpiderfootResults(scanId);
        break;
      }
      if (state && state.indexOf('ERROR') !== -1) {
        throw new Error('SpiderFoot scan failed (' + state + ')');
      }
      await sleep(6000);
    }
    if (results === null) {
      // Hard timeout: take whatever's been found so far instead of
      // requiring FINISHED, same as the old maxDurationMs-with-partial
      // behaviour -- the client never gets left with no response.
      results = await getSpiderfootResults(scanId);
    }
    fs.writeFileSync('/tmp/spiderfoot-result.json', JSON.stringify(results));
    console.log(`SpiderFoot scan done: ${results.length} event(s) for ${hostname}`);
  } catch (err) {
    console.error('SpiderFoot scan failed:', err.message);
    fs.writeFileSync('/tmp/spiderfoot-error.txt', err.message);
  }
})();
