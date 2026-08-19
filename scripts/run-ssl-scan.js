// run-ssl-scan.js
// testssl.sh's --jsonfile output is a flat array of {id, severity, finding,
// cve, cwe} rows covering everything it checked -- protocol support,
// cipher strength, certificate validity/chain, and known vulnerabilities
// (Heartbleed, ROBOT, etc.) in one pass. Most rows are informational or
// "OK" (the check passed); this keeps only the ones that represent an
// actual weakness and maps testssl's severity scale onto ours.

const fs = require('fs');

const TESTSSL_FILE = '/tmp/testssl-results.json';

// testssl severities: DEBUG, INFO, OK, WARN, LOW, MEDIUM, HIGH, CRITICAL, FATAL
const SEVERITY_MAP = {
  FATAL: 'critical',
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  WARN: 'medium',
  LOW: 'low',
};

// A handful of ids are worth surfacing even at testssl's own "OK"/"INFO"
// level because they're informational context an operator will want
// alongside real findings (e.g. cert expiry date), not because they're a
// weakness by themselves.
const ALWAYS_INCLUDE_IDS = new Set(['cert_expirationStatus', 'cert_expDays']);

function readResults(file) {
  if (!fs.existsSync(file)) return [];
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    return Array.isArray(parsed) ? parsed : (parsed.scanResult || []);
  } catch (e) {
    return [];
  }
}

const rows = readResults(TESTSSL_FILE);
const findings = [];

for (const row of rows) {
  const sev = (row.severity || '').toUpperCase();
  const mapped = SEVERITY_MAP[sev];
  const include = mapped || ALWAYS_INCLUDE_IDS.has(row.id);
  if (!include || !row.finding) continue;

  findings.push({
    type: 'tls_weakness',
    severity: mapped || 'info',
    title: `${row.id}: ${row.finding}`.slice(0, 200),
    detail: `${row.finding}${row.cve ? ` (${row.cve})` : ''}${row.cwe ? ` [${row.cwe}]` : ''}`,
    matchedAt: row.ip && row.port ? `${row.ip}:${row.port}` : undefined,
  });
}

const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
findings.sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));

fs.writeFileSync('/tmp/ssl-scan-result.json', JSON.stringify({ findings }));
console.log(`TLS/SSL scan done: ${findings.length} finding(s) from ${rows.length} check(s).`);
