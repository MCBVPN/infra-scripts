'use strict';
// Web post-exploitation scenario, modelled on what follows the PeopleSoft and
// PHP2Shell intrusions: a script dropped in the web root, then commands run
// by the web server process.
//
// No real vulnerability is exploited. The decoy has an upload endpoint that
// keeps whatever it is sent, and a stand-in "web shell" that only runs when
// the uploaded file carries the lab marker and only executes four fixed,
// read-only commands.
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const { execFile } = require('child_process');
const { sleep, cleanAddr, httpReq, listen, close } = require('../lib/harness');

const MARKER = 'SOLVBEAT-EMULATION-WEBSHELL';
const SCRIPT_EXT = /\.(php\d?|phtml|jsp|jspx|aspx?|cgi|sh|py)$/i;
const SENSITIVE = /^\/(\.env|\.git\/config|admin|phpmyadmin|backup\.zip|wp-login\.php|server-status)/;

async function start(bus, { bind, ports }) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'emulation-webroot-'));
  const uploads = path.join(root, 'uploads');
  fs.mkdirSync(uploads);
  const commands = { id: ['id', []], whoami: ['whoami', []], uname: ['uname', ['-a']], ls: ['ls', ['-la', uploads]] };

  const server = http.createServer((req, res) => {
    const src = cleanAddr(req.socket.remoteAddress);
    const url = new URL(req.url, 'http://decoy');
    const done = (status, body = '') => {
      bus.emit('web', 'http.access', { src, method: req.method, path: url.pathname, query: url.search, status });
      res.writeHead(status, { 'Content-Type': 'text/plain' });
      res.end(body);
    };

    if (req.method === 'POST' && url.pathname === '/upload') {
      const name = path.basename(url.searchParams.get('name') || 'file.bin');
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        fs.writeFileSync(path.join(uploads, name), Buffer.concat(chunks));
        bus.emit('web', 'file.create', { src, path: `/uploads/${name}`, name });
        done(201, 'stored');
      });
      return;
    }

    if (url.pathname.startsWith('/uploads/')) {
      const file = path.join(uploads, path.basename(url.pathname));
      if (!fs.existsSync(file)) return done(404);
      const cmd = commands[url.searchParams.get('c')];
      if (cmd && fs.readFileSync(file, 'utf8').includes(MARKER)) {
        bus.emit('web', 'process.spawn', { parent: 'webserver', image: cmd[0], args: cmd[1].join(' '), src });
        execFile(cmd[0], cmd[1], { timeout: 3000 }, (err, stdout) => done(200, err ? '' : stdout));
        return;
      }
      return done(200, 'ok');
    }

    done(url.pathname === '/' ? 200 : 404, url.pathname === '/' ? 'decoy app' : '');
  });

  return {
    ports: { http: await listen(server, ports.http, bind) },
    stop: async () => {
      await close(server);
      fs.rmSync(root, { recursive: true, force: true });
    },
  };
}

// Normal use: page views and one ordinary image upload that is then fetched.
async function baseline({ host, ports, src }) {
  const base = { host, port: ports.http, localAddress: src };
  for (let i = 0; i < 3; i++) await httpReq({ ...base, path: '/' });
  await httpReq({ ...base, method: 'POST', path: '/upload?name=logo.png', body: Buffer.from('not really a png') });
  await httpReq({ ...base, path: '/uploads/logo.png' });
  await httpReq({ ...base, path: '/favicon.ico' });
}

async function attack(bus, { host, ports, src }) {
  const base = { host, port: ports.http, localAddress: src };

  bus.step('path-recon', 'T1595.003', 'Probe for sensitive paths');
  for (const p of ['/.env', '/.git/config', '/admin', '/phpmyadmin', '/backup.zip', '/server-status']) {
    await httpReq({ ...base, path: p });
  }

  bus.step('webshell-upload', 'T1505.003', 'Drop a script file into the web root');
  await httpReq({ ...base, method: 'POST', path: '/upload?name=health.php', body: `<?php /* ${MARKER} (inert lab marker) */ ?>` });

  bus.step('command-exec', 'T1059.004', 'Run a first command through the dropped file');
  await httpReq({ ...base, path: '/uploads/health.php?c=id' });

  bus.step('host-discovery', 'T1082', 'Enumerate user, kernel and directory contents');
  for (const c of ['whoami', 'uname', 'ls']) await httpReq({ ...base, path: `/uploads/health.php?c=${c}` });
  await sleep(50);
}

const rules = [
  {
    id: 'WEB-01', title: 'Burst of requests for sensitive paths', severity: 'low', technique: 'T1595.003',
    detects: ['path-recon'], init: () => ({ bySrc: {} }),
    match: (e, s) => {
      if (e.type !== 'http.access' || e.status !== 404 || !SENSITIVE.test(e.path)) return false;
      const hits = (s.bySrc[e.src] = (s.bySrc[e.src] || []).filter((t) => e.ts - t < 10000).concat(e.ts));
      return hits.length >= 3 && `${hits.length} probes from ${e.src}`;
    },
  },
  {
    id: 'WEB-02', title: 'Script file created in an upload directory', severity: 'high', technique: 'T1505.003',
    detects: ['webshell-upload'],
    match: (e) => e.type === 'file.create' && SCRIPT_EXT.test(e.name) && e.path,
  },
  {
    id: 'WEB-03', title: 'Uploaded file requested with a query string shortly after upload', severity: 'high', technique: 'T1505.003',
    detects: ['command-exec'], init: () => ({ created: {} }),
    match: (e, s) => {
      if (e.type === 'file.create') s.created[e.path] = e.ts;
      return e.type === 'http.access' && e.query && s.created[e.path] !== undefined
        && e.ts - s.created[e.path] < 60000 && `${e.path}${e.query}`;
    },
  },
  {
    id: 'WEB-04', title: 'Web server process spawned a system command', severity: 'critical', technique: 'T1059.004',
    detects: ['command-exec', 'host-discovery'],
    match: (e) => e.type === 'process.spawn' && e.parent === 'webserver' && `${e.image} ${e.args}`.trim(),
  },
  {
    id: 'WEB-05', title: 'Several distinct discovery commands from the web server', severity: 'critical', technique: 'T1082',
    detects: ['host-discovery'], init: () => ({ seen: new Set() }),
    match: (e, s) => {
      if (e.type !== 'process.spawn' || e.parent !== 'webserver') return false;
      s.seen.add(e.image);
      return s.seen.size >= 3 && [...s.seen].join(', ');
    },
  },
];

module.exports = {
  id: 'web-postex',
  title: 'Web shell and command execution after a web intrusion',
  inspiredBy: 'Post-exploitation seen after the PeopleSoft and PHP2Shell intrusions, Oct-Nov 2026',
  portNames: ['http'],
  start, baseline, attack, rules,
};
