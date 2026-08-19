// run-dast-scan.js
const fs = require('fs');
const { parseZapFindings } = require('./zap-findings');

const result = parseZapFindings('/tmp/zap-wrk/report.json');
if (!result.ok) {
  console.error('DAST scan: ' + result.error);
} else {
  fs.writeFileSync('/tmp/dast-scan-result.json', JSON.stringify({ findings: result.findings, notes: result.notes }));
  console.log(`DAST scan done: ${result.findings.length} finding(s).`);
}
