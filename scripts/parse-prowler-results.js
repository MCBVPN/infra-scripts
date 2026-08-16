// parse-prowler-results.js
// Prowler (ProjectDiscovery-adjacent, but actually Prowler's own
// open-source project) is the industry-standard free CSPM tool -- it
// checks an AWS account against hundreds of security best-practice rules
// (public S3 buckets, overly-permissive IAM, open security groups, unused
// access keys, missing MFA, etc) and reports PASS/FAIL per check. We only
// ever turn FAIL rows into findings -- a PASS is the tool confirming
// something is already configured correctly, not evidence of a problem.

const fs = require('fs');

const PROWLER_OUTPUT_FILE = process.env.PROWLER_OUTPUT_FILE || '/tmp/prowler-output/prowler-output.ocsf.json';

const SEVERITY_MAP = {
  critical: 'critical',
  high: 'critical',
  medium: 'medium',
  low: 'medium',
  informational: 'info',
  info: 'info',
};

function readProwlerRows() {
  if (!fs.existsSync(PROWLER_OUTPUT_FILE)) return [];
  const raw = fs.readFileSync(PROWLER_OUTPUT_FILE, 'utf8').trim();
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch (e) {
    // OCSF output can also be JSONL (one object per line) depending on
    // Prowler version -- fall back to that if a single JSON.parse fails.
    return raw.split('\n').map((l) => l.trim()).filter(Boolean).map((l) => {
      try { return JSON.parse(l); } catch (e2) { return null; }
    }).filter(Boolean);
  }
}

// Prowler's OCSF-ish JSON has shifted field names across versions -- this
// reads defensively across the shapes seen in practice rather than
// assuming one exact schema.
function normalizeRow(row) {
  const status = (row.status || row.Status || (row.status_code) || '').toString().toUpperCase();
  const severity = (row.severity || row.Severity || (row.finding_info && row.finding_info.severity) || 'medium').toString().toLowerCase();
  const title = row.check_title || row.CheckTitle || row.title || (row.finding_info && row.finding_info.title) || row.check_id || 'Prowler finding';
  const detail = row.status_extended || row.StatusExtended || row.description || (row.finding_info && row.finding_info.desc) || '';
  const resource = row.resource_uid || row.ResourceId || (row.resources && row.resources[0] && row.resources[0].uid) || '';
  const service = row.service_name || row.ServiceName || (row.resources && row.resources[0] && row.resources[0].type) || '';
  const region = row.region || row.Region || '';
  return { status, severity, title, detail, resource, service, region };
}

const rows = readProwlerRows().map(normalizeRow);
const failed = rows.filter((r) => r.status === 'FAIL');

const findings = failed.map((r) => ({
  severity: SEVERITY_MAP[r.severity] || 'medium',
  title: `${r.title}${r.service ? ` (${r.service})` : ''}`,
  detail: `${r.detail || 'Failed a CSPM best-practice check.'}${r.resource ? ` Resource: ${r.resource}.` : ''}${r.region ? ` Region: ${r.region}.` : ''}`,
}));

fs.writeFileSync('/tmp/cloud-scan-result.json', JSON.stringify({
  findings,
  checksTotal: rows.length,
  checksFailed: failed.length,
}));
console.log(`Cloud scan done: ${findings.length} failed check(s) out of ${rows.length} total.`);
