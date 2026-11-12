#!/usr/bin/env node
'use strict';
// Attack-emulation lab runner.
//
//   node emulation/run.js [all|<scenario>] [--disable RULE,RULE] [--json out.json]
//       Start the decoy, replay normal traffic, replay the attack, and print
//       which steps the detection rules caught. Everything stays on loopback.
//
//   node emulation/run.js serve <scenario> --bind <private-ip> [--port-base N] [--trusted ip,ip]
//       Run only the decoy (with rules printing alerts live) on one of our
//       own hosts, so real network sensors and the SIEM see real traffic.
//
//   node emulation/run.js attack <scenario> --target <private-ip> [--port-base N]
//       Run only the attack steps against a decoy started with "serve".
//       The target must be listed in emulation/targets.allow.
const fs = require('fs');
const { Bus, sleep, assertBindAllowed, assertTargetAllowed } = require('./lib/harness');

const scenarios = [require('./scenarios/cold-chain'), require('./scenarios/web-postex'), require('./scenarios/exfil')];

function parseArgs(argv) {
  const pos = [];
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) flags[argv[i].slice(2)] = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : 'true';
    else pos.push(argv[i]);
  }
  return { pos, flags };
}

const list = (v) => (v ? v.split(',').map((s) => s.trim()).filter(Boolean) : []);

function pick(name) {
  const s = scenarios.find((x) => x.id === name);
  if (!s) throw new Error(`Unknown scenario "${name}". Available: ${scenarios.map((x) => x.id).join(', ')}`);
  return s;
}

function fixedPorts(scenario, base) {
  const offset = scenarios.indexOf(scenario) * 10;
  return Object.fromEntries(scenario.portNames.map((n, i) => [n, base + offset + i]));
}

async function runLocal(scenario, disabled) {
  const bus = new Bus({ disabled });
  // On Linux all of 127.0.0.0/8 is loopback, so the attacker can come from a
  // different source address than the legitimate client and the
  // address-based rules can be exercised too.
  const split = process.platform === 'linux';
  const trusted = split ? ['127.0.0.1'] : null;
  bus.addRules(scenario.rules, { trusted });

  const decoy = await scenario.start(bus, { bind: '127.0.0.1', ports: Object.fromEntries(scenario.portNames.map((n) => [n, 0])) });
  try {
    const ctx = { host: '127.0.0.1', ports: decoy.ports };
    bus.phase = 'baseline';
    await scenario.baseline({ ...ctx, src: split ? '127.0.0.1' : undefined });
    await sleep(150);
    bus.phase = 'attack';
    const outcome = await scenario.attack(bus, { ...ctx, src: split ? '127.0.0.2' : undefined });
    return { scenario: scenario.id, title: scenario.title, inspiredBy: scenario.inspiredBy, addressRulesActive: split, outcome: outcome || (decoy.state ? decoy.state() : null), ...bus.scorecard() };
  } finally {
    await decoy.stop();
  }
}

function print(card) {
  console.log(`\n=== ${card.title} [${card.scenario}] ===`);
  console.log(`Modelled on: ${card.inspiredBy}`);
  for (const s of card.steps) {
    console.log(`  ${s.detected ? 'DETECTED' : 'MISSED  '}  ${s.id} (${s.technique}) - ${s.desc}`);
    for (const d of s.detections) console.log(`              ${d.rule} +${d.latencyMs} ms  ${d.title}${d.detail ? ' -- ' + d.detail : ''}`);
  }
  console.log(`  Coverage: ${card.coveragePct}% of steps, false positives on normal traffic: ${card.falsePositives.length}`);
  for (const f of card.falsePositives) console.log(`    FALSE POSITIVE ${f.rule} ${f.title} ${f.detail}`);
  if (card.outcome) console.log(`  End state: ${JSON.stringify(card.outcome)}`);
}

async function main() {
  const { pos, flags } = parseArgs(process.argv.slice(2));
  const mode = pos[0] === 'serve' || pos[0] === 'attack' ? pos[0] : 'local';
  const portBase = Number(flags['port-base'] || 18000);

  if (mode === 'serve') {
    const scenario = pick(pos[1]);
    const bind = flags.bind || '127.0.0.1';
    assertBindAllowed(bind);
    const bus = new Bus({ disabled: list(flags.disable), live: true });
    bus.phase = 'attack';
    bus.addRules(scenario.rules, { trusted: list(flags.trusted) });
    const decoy = await scenario.start(bus, { bind, ports: fixedPorts(scenario, portBase) });
    console.log(`Decoy "${scenario.id}" listening on ${bind} ${JSON.stringify(decoy.ports)}. Ctrl+C to stop.`);
    process.on('SIGINT', async () => { await decoy.stop(); process.exit(0); });
    return;
  }

  if (mode === 'attack') {
    const scenario = pick(pos[1]);
    const target = flags.target || '127.0.0.1';
    assertTargetAllowed(target);
    const bus = new Bus({ live: true });
    await scenario.attack(bus, { host: target, ports: fixedPorts(scenario, portBase) });
    return;
  }

  const chosen = !pos[0] || pos[0] === 'all' ? scenarios : [pick(pos[0])];
  const cards = [];
  for (const s of chosen) {
    const card = await runLocal(s, list(flags.disable));
    cards.push(card);
    print(card);
  }
  if (flags.json) fs.writeFileSync(flags.json, JSON.stringify({ generatedAt: new Date().toISOString(), scenarios: cards }, null, 2));
  const missed = cards.reduce((n, c) => n + c.steps.filter((s) => !s.detected).length, 0);
  const fps = cards.reduce((n, c) => n + c.falsePositives.length, 0);
  console.log(`\nTotal: ${missed} undetected step(s), ${fps} false positive(s).`);
  if (flags.strict && (missed || fps)) process.exitCode = 1;
}

main().catch((err) => { console.error(err.message); process.exit(1); });
