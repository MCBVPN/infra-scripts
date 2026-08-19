// zap-findings.js
// Shared parser for OWASP ZAP's --J JSON report -- used by both the DAST
// scan (zap-full-scan.py against a live URL) and the API scan
// (zap-api-scan.py against an OpenAPI/Swagger schema), since both produce
// the exact same alert-report shape. ZAP's own riskcode (0-3) is a
// pattern-based signal, same caveat as Semgrep: it flags a class of
// issue, it doesn't prove exploitability the way SQLi/SSRF Verify do --
// so High maps to our "high", not "critical".

const fs = require('fs');

const RISK_SEVERITY = { '3': 'high', '2': 'medium', '1': 'low', '0': 'info' };

// A handful of CWE IDs are common/important enough to give a more
// specific finding `type` than the generic 'zap_alert' -- this lets the
// compliance-mapping module (which matches on type substrings) place
// these under the right NIST control instead of always falling back to
// the generic RA-5 vulnerability-scanning bucket.
const CWE_TYPE_OVERRIDE = {
  89: 'sqli_finding',       // SQL Injection
  79: 'xss_finding',        // Cross-Site Scripting
  352: 'csrf_finding',      // CSRF
  611: 'ssrf_finding',      // XXE/SSRF-adjacent
  918: 'ssrf_finding',      // SSRF
  200: 'exposed_path',      // Information exposure
  522: 'credential_confirmed', // Insufficiently protected credentials
};

function readZapReport(file) {
  if (!fs.existsSync(file)) return null;
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    return null;
  }
}

// maxFindings caps the TOTAL findings emitted (a full active scan can
// produce a very long tail of low-value low/info alerts) -- worst-first
// so nothing important gets truncated away.
function parseZapFindings(reportFile, maxFindings = 80) {
  const report = readZapReport(reportFile);
  if (!report) return { ok: false, error: 'ZAP produced no parseable report -- the scan may have failed to start or the target may be unreachable.', findings: [] };

  const findings = [];
  const sites = report.site || [];
  for (const site of sites) {
    for (const alert of (site.alerts || [])) {
      const severity = RISK_SEVERITY[String(alert.riskcode)] || 'info';
      const cweId = parseInt(alert.cweid, 10);
      const type = CWE_TYPE_OVERRIDE[cweId] || 'zap_alert';
      const instances = (alert.instances || []).slice(0, 3);
      const desc = (alert.desc || '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 400);
      const solution = (alert.solution || '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 250);
      if (instances.length === 0) {
        findings.push({
          type, severity,
          title: `${alert.name || alert.alert || 'ZAP alert'}`.slice(0, 200),
          detail: `${desc}${solution ? ` Solution: ${solution}` : ''}${cweId ? ` [CWE-${cweId}]` : ''}`,
        });
        continue;
      }
      for (const inst of instances) {
        findings.push({
          type, severity,
          title: `${alert.name || alert.alert || 'ZAP alert'}: ${inst.method || 'GET'} ${(inst.uri || '').replace(/^https?:\/\/[^/]+/, '')}`.slice(0, 200),
          detail: `${desc}${inst.param ? ` Parameter: ${inst.param}.` : ''}${inst.evidence ? ` Evidence: ${inst.evidence.slice(0, 200)}.` : ''}${solution ? ` Solution: ${solution}` : ''}${cweId ? ` [CWE-${cweId}]` : ''}`,
          matchedAt: inst.uri,
        });
      }
    }
  }

  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));

  const truncated = findings.length > maxFindings;
  const kept = findings.slice(0, maxFindings);
  const notes = [];
  if (truncated) notes.push(`${findings.length - maxFindings} additional lower-priority alert(s) truncated -- worst findings kept.`);

  return { ok: true, findings: kept, notes };
}

module.exports = { parseZapFindings };
