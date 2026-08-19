// run-dir-scan.js
// ffuf reports every path that returned a "kept" status code (see -mc in
// the workflow). Most of those are just normal pages -- the finding is in
// WHICH paths came back, not that paths exist at all. A short list of
// path patterns (source control internals, env files, backups, admin
// panels, raw DB dumps) gets flagged by severity; everything else is
// reported as info so the operator can still see the full surface area.

const fs = require('fs');

const FFUF_FILE = '/tmp/ffuf-results.json';

// Ordered most-specific-first; first match wins.
const PATH_RULES = [
  { re: /\.git\//i, severity: 'critical', label: 'Exposed .git directory' },
  { re: /\.env(\.|$)/i, severity: 'critical', label: 'Exposed .env file' },
  { re: /\.(sql|dump)$/i, severity: 'critical', label: 'Exposed database dump' },
  { re: /wp-config\.php/i, severity: 'critical', label: 'Exposed wp-config.php' },
  { re: /credentials|id_rsa|\.pem$|private\.key|server\.key/i, severity: 'critical', label: 'Exposed credential/key material' },
  { re: /(^|\/)(backup|old|db_backup)s?(\.|\/|$)|\.(bak|old)$/i, severity: 'high', label: 'Exposed backup file' },
  { re: /(^|\/)(\.aws|\.azure|\.gcloud)(\/|$)/i, severity: 'high', label: 'Exposed cloud credentials directory' },
  { re: /composer\.json|package\.json|Gemfile|requirements\.txt/i, severity: 'low', label: 'Dependency manifest exposed' },
  { re: /phpinfo\.php|info\.php/i, severity: 'high', label: 'phpinfo() disclosure' },
  { re: /(^|\/)(admin|administrator|wp-admin|cpanel|phpmyadmin|pma|adminer\.php)(\/|$)/i, severity: 'medium', label: 'Admin/control panel reachable' },
  { re: /actuator/i, severity: 'high', label: 'Spring Boot Actuator endpoint reachable' },
  { re: /\.well-known\/openid-configuration|oauth\/token/i, severity: 'info', label: 'OAuth/OIDC endpoint (expected if SSO is in use)' },
  { re: /xmlrpc\.php/i, severity: 'medium', label: 'WordPress XML-RPC reachable (brute-force/amplification vector)' },
  { re: /wp-json\/wp\/v2\/users/i, severity: 'medium', label: 'WordPress REST API user enumeration reachable' },
  { re: /\.git$|\.svn|\.hg\//i, severity: 'critical', label: 'Exposed version-control directory' },
  { re: /server-status|server-info/i, severity: 'medium', label: 'Web server status page reachable' },
  { re: /swagger|openapi|graphiql|graphql/i, severity: 'low', label: 'API schema/introspection endpoint reachable' },
  { re: /docker-compose|Dockerfile|Vagrantfile|terraform\.tfstate|terraform\.tfvars/i, severity: 'high', label: 'Infrastructure-as-code file exposed' },
  { re: /login|signin/i, severity: 'info', label: 'Login page reachable' },
];

function classify(path) {
  for (const rule of PATH_RULES) {
    if (rule.re.test(path)) return rule;
  }
  return { severity: 'info', label: 'Path reachable' };
}

function readJsonlOrArray(file) {
  if (!fs.existsSync(file)) return [];
  const raw = fs.readFileSync(file, 'utf8').trim();
  if (!raw) return [];
  // ffuf -json -o writes one JSON object per line when streaming; some
  // versions write a single top-level object with a "results" array.
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed;
    if (parsed.results) return parsed.results;
  } catch (e) { /* fall through to line-delimited parsing */ }
  return raw.split('\n').map((l) => l.trim()).filter(Boolean).map((l) => {
    try { return JSON.parse(l); } catch (e) { return null; }
  }).filter(Boolean);
}

const rows = readJsonlOrArray(FFUF_FILE);
const findings = [];
const seen = new Set();

for (const row of rows) {
  const url = row.url || row.input?.FUZZ;
  const status = row.status;
  if (!url || seen.has(url)) continue;
  seen.add(url);
  const { severity, label } = classify(url);
  findings.push({
    type: 'exposed_path',
    severity,
    title: `${label}: ${url.replace(/^https?:\/\/[^/]+/, '')}`,
    detail: `HTTP ${status} at ${url}${row.length ? ` (${row.length} bytes)` : ''}. ${severity === 'info' ? 'Reachable and worth a quick manual look, but not inherently a security issue on its own.' : 'This path type is commonly sensitive -- verify manually and restrict access if it should not be public.'}`,
    matchedAt: url,
  });
}

// Sort worst-first so the operator sees the important stuff without
// scrolling past a long tail of info-level "path reachable" noise.
const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
findings.sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));

fs.writeFileSync('/tmp/dir-scan-result.json', JSON.stringify({ findings, pathsChecked: rows.length ? undefined : 0 }));
console.log(`Directory scan done: ${findings.length} reachable path(s) found.`);
