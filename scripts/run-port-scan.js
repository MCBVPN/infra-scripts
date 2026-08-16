// run-port-scan.js
// Combines naabu's raw port-open results with httpx's HTTP fingerprinting
// of whatever responds on each open port, then assigns a severity per port
// based on what's typically exposed there -- a public database or remote-
// admin port is a very different finding from an expected 80/443. Every
// other tool on this page assumes the target is "a website on 443"; this
// is the one that actually checks what else is reachable, the same first
// step any real network pentest starts with.

const fs = require('fs');

const NAABU_FILE = '/tmp/naabu-results.jsonl';
const HTTPX_FILE = '/tmp/httpx-results.jsonl';

// Severity by port -- databases and remote-admin protocols reachable from
// the public internet are a materially bigger deal than an unusual-but-
// harmless open port. 80/443 are expected for a "website" target and are
// filtered out entirely below, not just downgraded.
const PORT_INFO = {
  21: { name: 'FTP', severity: 'critical' },
  23: { name: 'Telnet', severity: 'critical' },
  3306: { name: 'MySQL', severity: 'critical' },
  5432: { name: 'PostgreSQL', severity: 'critical' },
  27017: { name: 'MongoDB', severity: 'critical' },
  6379: { name: 'Redis', severity: 'critical' },
  9200: { name: 'Elasticsearch', severity: 'critical' },
  1433: { name: 'MSSQL', severity: 'critical' },
  3389: { name: 'RDP', severity: 'critical' },
  5900: { name: 'VNC', severity: 'critical' },
  22: { name: 'SSH', severity: 'medium' },
  8080: { name: 'HTTP-alt (8080)', severity: 'medium' },
  8443: { name: 'HTTPS-alt (8443)', severity: 'medium' },
  8000: { name: 'HTTP-alt (8000)', severity: 'medium' },
  9000: { name: 'App server (9000)', severity: 'medium' },
  9090: { name: 'App server (9090)', severity: 'medium' },
  5000: { name: 'App server (5000)', severity: 'medium' },
};
const SKIP_PORTS = new Set([80, 443]); // expected on any website, not a finding

function readJsonl(file) {
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, 'utf8').split('\n').map((l) => l.trim()).filter(Boolean).map((l) => {
    try { return JSON.parse(l); } catch (e) { return null; }
  }).filter(Boolean);
}

const naabuRows = readJsonl(NAABU_FILE);
const httpxRows = readJsonl(HTTPX_FILE);
const httpxByPort = {};
httpxRows.forEach((r) => {
  const port = r.port || (r.url && new URL(r.url).port);
  if (port) httpxByPort[String(port)] = r;
});

const findings = [];
const seenPorts = new Set();
for (const row of naabuRows) {
  const port = row.port;
  if (!port || seenPorts.has(port) || SKIP_PORTS.has(port)) continue;
  seenPorts.add(port);
  const info = PORT_INFO[port] || { name: `Port ${port}`, severity: 'info' };
  const httpInfo = httpxByPort[String(port)];
  const httpDetail = httpInfo
    ? ` HTTP probe: ${httpInfo['status-code'] || httpInfo.status_code || '?'} ${httpInfo.title ? '"' + httpInfo.title + '"' : ''} ${httpInfo.webserver ? 'via ' + httpInfo.webserver : ''}${(httpInfo.tech || []).length ? ' -- tech: ' + httpInfo.tech.join(', ') : ''}`.trim()
    : '';
  findings.push({
    type: 'open_port',
    severity: info.severity,
    title: `Open port ${port} (${info.name})`,
    detail: `Reachable from the public internet on ${row.host || row.ip}:${port}.${httpDetail ? ' ' + httpDetail : ' No HTTP response on this port (raw TCP service).'}`,
    matchedAt: `${row.host || row.ip}:${port}`,
  });
}

fs.writeFileSync('/tmp/port-scan-result.json', JSON.stringify({ findings, portsScanned: 100 }));
console.log(`Port scan done: ${findings.length} notable open port(s) out of ${naabuRows.length} total open.`);
