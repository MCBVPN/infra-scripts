'use strict';
// Shared plumbing for the attack-emulation lab: the telemetry bus that
// detection rules subscribe to, the target guard, and small network helpers.
const fs = require('fs');
const path = require('path');
const http = require('http');
const { performance } = require('perf_hooks');

const now = () => performance.timeOrigin + performance.now();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const cleanAddr = (a) => String(a || '').replace(/^::ffff:/, '');

function isLoopback(host) {
  return host === 'localhost' || /^127\./.test(host);
}

function isPrivate(host) {
  if (isLoopback(host)) return true;
  const m = /^(\d+)\.(\d+)\.\d+\.\d+$/.exec(host);
  if (!m) return false;
  const a = Number(m[1]);
  const b = Number(m[2]);
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

// The decoys are weak on purpose (factory credentials, unauthenticated
// upload), so they must never listen on a public address, and the attacker
// side only ever talks to loopback or to a private address that someone
// deliberately wrote into emulation/targets.allow.
function assertBindAllowed(bind) {
  if (!isPrivate(bind)) {
    throw new Error(`Refusing to bind decoy to ${bind}: only loopback or RFC1918 addresses are allowed.`);
  }
}

function assertTargetAllowed(target) {
  if (isLoopback(target)) return;
  if (!isPrivate(target)) {
    throw new Error(`Refusing target ${target}: only loopback or RFC1918 addresses can be attacked.`);
  }
  const file = path.join(__dirname, '..', 'targets.allow');
  const allowed = fs.existsSync(file)
    ? fs.readFileSync(file, 'utf8').split('\n').map((l) => l.replace(/#.*/, '').trim()).filter(Boolean)
    : [];
  if (!allowed.includes(target)) {
    throw new Error(`Refusing target ${target}: add it to emulation/targets.allow first (own hosts only).`);
  }
}

class Bus {
  constructor({ disabled = [], live = false } = {}) {
    this.entries = [];
    this.alerts = [];
    this.steps = [];
    this.eventCount = 0;
    this.phase = 'baseline';
    this.disabled = new Set(disabled);
    this.live = live;
  }

  addRules(rules, opts) {
    for (const rule of rules) {
      if (this.disabled.has(rule.id)) continue;
      this.entries.push({ rule, state: rule.init ? rule.init(opts) : {}, seen: {} });
    }
  }

  // Telemetry event from a decoy. Rules run synchronously, so an alert's
  // timestamp is the moment the rule had enough evidence to fire.
  emit(source, type, data = {}) {
    const e = { ts: now(), source, type, ...data };
    this.eventCount++;
    for (const entry of this.entries) {
      const hit = entry.rule.match(e, entry.state);
      if (!hit) continue;
      const prev = entry.seen[this.phase];
      if (prev) { prev.count++; continue; }
      const alert = {
        ts: now(),
        phase: this.phase,
        rule: entry.rule.id,
        title: entry.rule.title,
        severity: entry.rule.severity,
        technique: entry.rule.technique,
        detects: entry.rule.detects,
        detail: hit === true ? '' : String(hit),
        count: 1,
      };
      entry.seen[this.phase] = alert;
      this.alerts.push(alert);
      if (this.live) {
        console.log(`${new Date(alert.ts).toISOString()} ALERT [${alert.severity}] ${alert.rule} ${alert.title}${alert.detail ? ' -- ' + alert.detail : ''}`);
      }
    }
  }

  step(id, technique, desc) {
    const s = { id, technique, desc, ts: now() };
    this.steps.push(s);
    if (this.live) console.log(`${new Date(s.ts).toISOString()} STEP  ${id} (${technique}) ${desc}`);
  }

  scorecard() {
    const attackAlerts = this.alerts.filter((a) => a.phase === 'attack');
    const steps = this.steps.map((s) => {
      const hits = attackAlerts
        .filter((a) => a.detects.includes(s.id) && a.ts >= s.ts)
        .map((a) => ({ rule: a.rule, title: a.title, latencyMs: Math.round((a.ts - s.ts) * 10) / 10, detail: a.detail }))
        .sort((x, y) => x.latencyMs - y.latencyMs);
      return { id: s.id, technique: s.technique, desc: s.desc, detected: hits.length > 0, detections: hits };
    });
    const detected = steps.filter((s) => s.detected).length;
    return {
      steps,
      coveragePct: steps.length ? Math.round((detected / steps.length) * 100) : 0,
      falsePositives: this.alerts.filter((a) => a.phase === 'baseline').map((a) => ({ rule: a.rule, title: a.title, detail: a.detail })),
      telemetryEvents: this.eventCount,
    };
  }
}

function httpReq({ host, port, method = 'GET', path: p = '/', headers = {}, body, localAddress }) {
  return new Promise((resolve) => {
    const req = http.request({ host, port, method, path: p, headers, localAddress, agent: false, timeout: 5000 }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on('error', (err) => resolve({ status: 0, error: err.message, body: Buffer.alloc(0) }));
    req.on('timeout', () => req.destroy(new Error('timeout')));
    if (body) req.write(body);
    req.end();
  });
}

function listen(server, port, bind) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, bind, () => resolve(server.address().port));
  });
}

function close(server) {
  return new Promise((resolve) => {
    if (server.closeAllConnections) server.closeAllConnections();
    server.close(() => resolve());
  });
}

module.exports = { Bus, now, sleep, cleanAddr, isLoopback, assertBindAllowed, assertTargetAllowed, httpReq, listen, close };
