// run-wp-scan.js
// WPScan's JSON output bundles several distinct things under one object:
// the detected WP core version (with vulnerabilities[] if it matched a
// known CVE), interesting_findings (readme/xmlrpc/wp-json/debug-log style
// info leaks), per-plugin and per-theme version + vulnerabilities, and
// enumerated usernames. Each of those becomes its own finding with its
// own severity -- a known-vulnerable plugin is a very different risk than
// "xmlrpc.php is reachable".

const fs = require('fs');

const WPSCAN_FILE = '/tmp/wpscan-results.json';

function readResults(file) {
  if (!fs.existsSync(file)) return null;
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    return null;
  }
}

const data = readResults(WPSCAN_FILE);
const findings = [];

if (data) {
  // Not WordPress at all -- WPScan itself reports this rather than
  // erroring, so surface it as a note rather than a false "no findings".
  if (data.not_fully_configured || (!data.version && !data.plugins && (data.interesting_findings || []).length === 0)) {
    // still fall through -- other sections may have data
  }

  const vulnsToFindings = (vulns, subject) => {
    for (const v of (vulns || [])) {
      findings.push({
        type: 'wp_known_vulnerability',
        severity: 'critical',
        title: `${subject}: ${v.title}`.slice(0, 200),
        detail: `Known vulnerability affecting the detected version.${v.fixed_in ? ` Fixed in ${v.fixed_in}.` : ' No fixed version listed by the vulnerability database.'} References: ${(v.references && (v.references.url || []).join(', ')) || 'none listed'}`,
      });
    }
  };

  if (data.version) {
    const v = data.version;
    vulnsToFindings(v.vulnerabilities, `WordPress core ${v.number || ''}`.trim());
    if (v.status === 'insecure') {
      findings.push({
        type: 'wp_outdated_core',
        severity: 'high',
        title: `WordPress core is outdated (${v.number})`,
        detail: 'The detected core version is marked insecure by WPScan\'s version database -- update to the latest WordPress release.',
      });
    }
  }

  if (data.main_theme) {
    const t = data.main_theme;
    vulnsToFindings(t.vulnerabilities, `Theme "${t.slug}"${t.version ? ' ' + t.version.number : ''}`);
  }

  for (const [slug, plugin] of Object.entries(data.plugins || {})) {
    vulnsToFindings(plugin.vulnerabilities, `Plugin "${slug}"${plugin.version ? ' ' + plugin.version.number : ''}`);
    if (plugin.outdated) {
      findings.push({
        type: 'wp_outdated_plugin',
        severity: 'medium',
        title: `Plugin "${slug}" is outdated${plugin.version ? ` (${plugin.version.number})` : ''}`,
        detail: `Latest known version is ${plugin.latest_version || 'unknown'}. Outdated plugins are the most common WordPress compromise vector even without a specific known CVE.`,
      });
    }
  }

  for (const finding of (data.interesting_findings || [])) {
    const t = (finding.type || '').toLowerCase();
    let severity = 'info';
    if (t.includes('xmlrpc')) severity = 'medium';
    else if (t.includes('debug') || t.includes('backup') || t.includes('config')) severity = 'high';
    else if (t.includes('readme') || t.includes('full_path_disclosure')) severity = 'low';
    findings.push({
      type: 'wp_interesting_finding',
      severity,
      title: (finding.to_s || finding.type || 'Interesting finding').slice(0, 200),
      detail: `${finding.to_s || ''} (${finding.url || 'no URL'})`,
      matchedAt: finding.url,
    });
  }

  const users = Object.keys(data.users || {});
  if (users.length) {
    findings.push({
      type: 'wp_user_enumeration',
      severity: 'medium',
      title: `${users.length} WordPress username(s) enumerable`,
      detail: `Usernames found: ${users.slice(0, 20).join(', ')}${users.length > 20 ? `, and ${users.length - 20} more` : ''}. These are valid login usernames for brute-force/credential-stuffing attempts -- consider disabling user enumeration (REST API + author archives) and enforcing strong passwords or 2FA.`,
    });
  }
}

const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
findings.sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));

fs.writeFileSync('/tmp/wp-scan-result.json', JSON.stringify({
  findings,
  notes: data ? [] : ['WPScan produced no parseable output -- the target most likely is not running WordPress, or blocked the scan.'],
}));
console.log(`WordPress scan done: ${findings.length} finding(s).`);
