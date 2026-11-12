'use strict';
// Encryption-less extortion scenario: nothing is encrypted, so the only
// signal is the data leaving. A client enumerates a document store and pulls
// everything as fast as it can.
//
// All records are generated in memory and are fake.
const http = require('http');
const { sleep, cleanAddr, httpReq, listen, close } = require('../lib/harness');

const CANARY = 'backup_passwords.csv';
const FILE_COUNT = 200;
const MASS_READ_FILES = 20;
const VOLUME_LIMIT = 1024 * 1024;

function fakeFile(i) {
  const rows = ['id,name,email,iban'];
  for (let r = 0; r < 300; r++) rows.push(`${i}-${r},Fake Person ${r},fake${r}@example.invalid,ES00FAKE${String(i * 1000 + r).padStart(12, '0')}`);
  return Buffer.from(rows.join('\n'));
}

async function start(bus, { bind, ports }) {
  const files = new Map([[CANARY, Buffer.from('user,password\ncanary,not-a-real-password\n')]]);
  for (let i = 0; i < FILE_COUNT; i++) files.set(`customers_${String(i).padStart(3, '0')}.csv`, fakeFile(i));

  const server = http.createServer((req, res) => {
    const src = cleanAddr(req.socket.remoteAddress);
    if (req.url === '/files') {
      bus.emit('docstore', 'file.list', { src });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify([...files.keys()]));
      return;
    }
    const name = decodeURIComponent(req.url.replace(/^\/files\//, ''));
    const data = files.get(name);
    if (!data) { res.writeHead(404); res.end(); return; }
    bus.emit('docstore', 'file.read', { src, name, bytes: data.length });
    res.writeHead(200, { 'Content-Type': 'text/csv' });
    res.end(data);
  });

  return {
    ports: { http: await listen(server, ports.http, bind) },
    stop: () => close(server),
  };
}

// Normal use: a user lists the store and opens a few documents.
async function baseline({ host, ports, src }) {
  const base = { host, port: ports.http, localAddress: src };
  await httpReq({ ...base, path: '/files' });
  for (const n of ['customers_004.csv', 'customers_017.csv', 'customers_101.csv']) {
    await httpReq({ ...base, path: `/files/${n}` });
    await sleep(80);
  }
}

async function attack(bus, { host, ports, src }) {
  const base = { host, port: ports.http, localAddress: src };

  bus.step('enumerate', 'T1083', 'List every document in the store');
  const listing = await httpReq({ ...base, path: '/files' });
  let names = [];
  try { names = JSON.parse(listing.body.toString()); } catch { /* target unreachable */ }

  bus.step('bulk-download', 'T1041', `Download all ${names.length} documents in one pass`);
  let bytes = 0;
  for (const n of names) bytes += (await httpReq({ ...base, path: `/files/${encodeURIComponent(n)}` })).body.length;
  return { files: names.length, bytes };
}

const mb = (n) => `${(n / 1024 / 1024).toFixed(2)} MB`;

// Every rule tracks how much had already left when it fired, which is the
// number that matters for "did we catch it in time".
const track = () => ({ bySrc: {} });
function account(e, s) {
  const t = (s.bySrc[e.src] = s.bySrc[e.src] || { files: new Set(), bytes: 0 });
  t.files.add(e.name);
  t.bytes += e.bytes;
  return t;
}

const rules = [
  {
    id: 'EXF-01', title: 'Document listing requested from an untrusted address', severity: 'low', technique: 'T1083',
    detects: ['enumerate'], init: ({ trusted }) => ({ trusted: trusted && trusted.length ? trusted : null }),
    match: (e, s) => e.type === 'file.list' && s.trusted && !s.trusted.includes(e.src) && `src=${e.src}`,
  },
  {
    id: 'EXF-02', title: 'Canary document opened', severity: 'critical', technique: 'T1005',
    detects: ['bulk-download'], init: track,
    match: (e, s) => {
      if (e.type !== 'file.read') return false;
      const t = account(e, s);
      return e.name === CANARY && `${t.files.size - 1} real files (${mb(t.bytes - e.bytes)}) gone before alert`;
    },
  },
  {
    id: 'EXF-03', title: `More than ${MASS_READ_FILES} distinct documents read by one client`, severity: 'high', technique: 'T1005',
    detects: ['bulk-download'], init: track,
    match: (e, s) => {
      if (e.type !== 'file.read') return false;
      const t = account(e, s);
      return t.files.size > MASS_READ_FILES && `${t.files.size} files (${mb(t.bytes)}) gone before alert`;
    },
  },
  {
    id: 'EXF-04', title: `More than ${mb(VOLUME_LIMIT)} served to one client`, severity: 'high', technique: 'T1041',
    detects: ['bulk-download'], init: track,
    match: (e, s) => {
      if (e.type !== 'file.read') return false;
      const t = account(e, s);
      return t.bytes > VOLUME_LIMIT && `${t.files.size} files (${mb(t.bytes)}) gone before alert`;
    },
  },
];

module.exports = {
  id: 'exfil',
  title: 'Bulk data theft without encryption',
  inspiredBy: 'Encryption-less extortion campaigns, Oct-Nov 2026',
  portNames: ['http'],
  start, baseline, attack, rules,
};
