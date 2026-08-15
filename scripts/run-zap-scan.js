// run-zap-scan.js
// Runs inside the GitHub Actions runner against the ZAP daemon started
// earlier in this same job (127.0.0.1). Ported verbatim from the
// orchestration logic that used to live in SolveBeat's backend
// (zapSpiderfoot.js) -- only the environment changed (isolated ephemeral
// runner instead of a permanent process sharing solvbeat-prod's RAM with
// the live API), the scan sequence itself is unchanged: spider -> AJAX
// spider (best-effort) -> active scan -> alerts filtered to the target
// host. Writes the final alerts (or a partial result if MAX_DURATION is
// hit) to /tmp/zap-result.json for the workflow's "Report results" step.

const fs = require('fs');

const ZAP_API_URL = process.env.ZAP_API_URL;
const ZAP_API_KEY = process.env.ZAP_API_KEY;
const TARGET_URL = process.env.TARGET_URL;
const MAX_DURATION_MS = (parseInt(process.env.MAX_DURATION_SECONDS, 10) || 600) * 1000;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForZapSpider(spiderScanId, maxWaitMs = 120000) {
  const start = Date.now();
  while (Date.now() - start < maxWaitMs) {
    const res = await fetch(`${ZAP_API_URL}/JSON/spider/view/status/?apikey=${ZAP_API_KEY}&scanId=${spiderScanId}`);
    const data = await res.json();
    if (parseInt(data.status) >= 100) return;
    await sleep(3000);
  }
}

async function waitForAjaxSpider(maxWaitMs = 90000) {
  const start = Date.now();
  while (Date.now() - start < maxWaitMs) {
    const res = await fetch(`${ZAP_API_URL}/JSON/ajaxSpider/view/status/?apikey=${ZAP_API_KEY}`);
    const data = await res.json();
    if (data.status === 'stopped') return;
    await sleep(3000);
  }
  await fetch(`${ZAP_API_URL}/JSON/ajaxSpider/action/stop/?apikey=${ZAP_API_KEY}`);
}

async function startZapScan(targetUrl) {
  const spiderRes = await fetch(`${ZAP_API_URL}/JSON/spider/action/scan/?apikey=${ZAP_API_KEY}&url=${encodeURIComponent(targetUrl)}`);
  const spiderData = await spiderRes.json();
  const spiderScanId = spiderData.scan;
  await waitForZapSpider(spiderScanId);

  try {
    await fetch(`${ZAP_API_URL}/JSON/ajaxSpider/action/scan/?apikey=${ZAP_API_KEY}&url=${encodeURIComponent(targetUrl)}`);
    await waitForAjaxSpider();
  } catch (err) {
    console.warn('AJAX Spider failed or unavailable (non-blocking):', err.message);
  }

  const activeRes = await fetch(`${ZAP_API_URL}/JSON/ascan/action/scan/?apikey=${ZAP_API_KEY}&url=${encodeURIComponent(targetUrl)}`);
  const activeData = await activeRes.json();
  return activeData.scan;
}

async function getZapScanStatus(scanId) {
  const res = await fetch(`${ZAP_API_URL}/JSON/ascan/view/status/?apikey=${ZAP_API_KEY}&scanId=${scanId}`);
  const data = await res.json();
  return parseInt(data.status);
}

// ZAP's alerts API returns one row PER MATCHED URL -- a passive check like
// "Missing Anti-clickjacking Header" fires once for every single page the
// spider crawled, so a real site with a few thousand pages produces a few
// thousand near-identical rows for the SAME underlying issue. Confirmed
// live against www.computacenter.com: 30,000-36,000+ raw alerts, a JSON
// payload so large it blew through nginx/Express body limits raised as
// high as 150MB/140MB (twice). The fix belongs here, not in ever-larger
// size limits: group same issue+risk into one finding with an instance
// count and a capped sample of affected URLs -- what the backend already
// stores per finding (severity/title/description/solution) doesn't lose
// anything, since it never used the per-instance url field anyway.
const MAX_SAMPLE_URLS = 15;

function dedupeAlerts(alerts) {
  const groups = new Map();
  for (const a of alerts) {
    const key = `${a.alert || a.name || ''}|${a.risk || ''}`;
    if (!groups.has(key)) {
      groups.set(key, { representative: a, urls: new Set(), count: 0 });
    }
    const g = groups.get(key);
    g.count += 1;
    if (a.url) g.urls.add(a.url);
  }
  return Array.from(groups.values()).map((g) => {
    const sample = Array.from(g.urls).slice(0, MAX_SAMPLE_URLS);
    const urlNote = g.count > 1
      ? `\n\nDetected on ${g.count} page(s). Sample (${sample.length} of ${g.urls.size} unique URLs): ${sample.join(', ')}`
      : '';
    return {
      ...g.representative,
      instanceCount: g.count,
      affectedUrlCount: g.urls.size,
      description: (g.representative.description || '') + urlNote,
    };
  });
}

async function getZapAlerts(targetUrl) {
  const res = await fetch(`${ZAP_API_URL}/JSON/core/view/alerts/?apikey=${ZAP_API_KEY}`);
  const data = await res.json();
  const targetHost = new URL(targetUrl).hostname.toLowerCase();
  const allAlerts = data.alerts || [];
  const hostAlerts = allAlerts.filter((a) => {
    try {
      return new URL(a.url).hostname.toLowerCase() === targetHost;
    } catch (e) {
      return false;
    }
  });
  return dedupeAlerts(hostAlerts);
}

(async () => {
  const deadline = Date.now() + MAX_DURATION_MS;
  try {
    const scanId = await startZapScan(TARGET_URL);
    let alerts = null;
    while (Date.now() < deadline) {
      const progress = await getZapScanStatus(scanId);
      if (progress >= 100) {
        alerts = await getZapAlerts(TARGET_URL);
        break;
      }
      await sleep(6000);
    }
    if (alerts === null) {
      // Hard timeout hit -- report whatever ZAP has found so far, same as
      // the old maxDurationMs-with-partial-results behaviour, so the
      // client never gets left with no response at all.
      alerts = await getZapAlerts(TARGET_URL);
    }
    fs.writeFileSync('/tmp/zap-result.json', JSON.stringify(alerts));
    const totalInstances = alerts.reduce((sum, a) => sum + (a.instanceCount || 1), 0);
    console.log(`ZAP scan done: ${alerts.length} distinct finding(s) (${totalInstances} raw instance(s)) for ${TARGET_URL}`);
  } catch (err) {
    console.error('ZAP scan failed:', err.message);
    fs.writeFileSync('/tmp/zap-error.txt', err.message);
  }
})();
