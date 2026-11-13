// Long random histories, C (WebAssembly) and JavaScript in lockstep, about one call in seven hostile.
// After every call: the same result and the same journal head. After every step: each companion's
// expressed values lie in her bands, no two companions come closer than their distance, and every
// current view of a companion lies in her band. Every 250 calls the store is saved, reloaded into a
// second pair, and both pairs then run the same 60 calls: a reloaded store must behave exactly as
// the one that was never saved (save/load transparency). The final heads of three seeds are frozen.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { Pair, define, text, bytes32, secret, hex, rng, giveOf, root } from './lib.mjs';
import { NONE } from '../oracle/anchor.mjs';

const SEEDS = Number(process.env.DIFF_SEEDS || 12);
const CALLS = Number(process.env.DIFF_CALLS || 4000);
const VECTORS = new URL('tests/vectors.json', root);

// Six of Simoa 10.15.0's topics with the three companions' own stances (Simoa, Mika, Neris).
const TOPICS = [['storms', ['storms', 'thunderstorms'], [-1, -2, 2]], ['rain', ['rain'], [1, 1, 2]],
  ['tea', ['tea', 'green tea'], [0, 1, 2]], ['coffee', ['coffee', 'black coffee'], [2, 0, 0]],
  ['archive', ['the archive'], [2, 0, 1]], ['dancing', ['dancing'], [-1, 2, 1]]];
const LINES = [['I love storms', -1, 0], ['I hate rain!', -1, 0], ['i like tea', -1, 0], ["I don't like coffee.", -1, 0],
  ['I am undecided about the archive', -1, 0], ['I love dancing', -1, 0], ['Mika thinks I love tea', 2, 2],
  ['I agree', 0, -1], ['I really love rain', 1, 2], ['thunderstorms are great', 0, 1], ['I hate thunderstorms!!', -1, 0],
  ['I love green tea', -1, 0], ['tea?', -1, 0], ['I don’t like black coffee', -1, 0]];

async function history(seed) {
  const r = rng(seed);
  let p = await Pair.create();
  assert.equal(define(p, { persons: 4, traits: TOPICS.length, labels: TOPICS.map(t => t[1]), names: ['Simoa', 'Mika', 'Neris'],
    cores: [0, 1, 2].map(i => TOPICS.map(t => t[2][i])), gives: [0, 1, 2].map(i => TOPICS.map(t => giveOf(t[2][i]))) }), 0);
  const w = { seq: [], secret: [], revoked: [], persona: [] };
  let made = 0, nextInstance = 10;
  const incept = (ch, inst, rt, persona) => {
    const s = secret(seed * 100000 + made++);
    const i = exec('incept', ch, inst, rt, persona, bytes32('key' + seed, made++), s.commit);
    if (i >= 0) { w.seq[i] = 0; w.secret[i] = s.secret; w.revoked[i] = 0; w.persona[i] = persona; }
    return i;
  };
  let fork = null, forkLeft = 0;
  const stats = { calls: 0, hostile: 0, forks: 0, forkCalls: 0, accepted: {}, refused: {} };
  function exec(name, ...args) {
    const a = p.call(name, ...args);
    stats.calls++;
    if (fork) {
      const b = fork.call(name, ...args);
      assert.deepEqual(JSON.stringify(b, (k, v) => (v instanceof Uint8Array ? hex(v) : v)),
        JSON.stringify(a, (k, v) => (v instanceof Uint8Array ? hex(v) : v)), 'a reloaded store behaved differently: ' + name);
      assert.equal(hex(fork.c.headBytes().bytes), hex(p.c.headBytes().bytes), 'reloaded journal head');
      stats.forkCalls++;
    }
    const res = typeof a === 'number' ? a : Array.isArray(a) ? 0 : a.result;
    const bucket = res >= 0 ? stats.accepted : stats.refused;
    bucket[name] = (bucket[name] || 0) + 1;
    return a;
  }
  const users = () => w.persona.map((x, i) => i).filter(i => w.persona[i] === 0 && !w.revoked[i]);
  const voices = q => w.persona.map((x, i) => i).filter(i => w.persona[i] === q && !w.revoked[i]);
  const live = q => { const v = voices(q); return v.length ? r.pick(v) : 0; };
  const mask = (...exclude) => { let m = 0; for (let h = 1; h < 4; h++) if (!exclude.includes(h) && r.int(3)) m |= 1 << h; return m || [2, 4, 8].find(b => !exclude.includes(Math.log2(b))) || 2; };
  const readings = [];

  incept(2, 0, 0, 0); incept(1, 1, 1, 1); incept(1, 2, 1, 2); incept(1, 3, 1, 3); incept(4, 0, 2, 255); incept(1, 4, 3, 2);

  for (let step = 0; step < CALLS; step++) {
    if (fork && --forkLeft === 0) fork = null;
    if (!fork && step > 0 && step % 250 === 0) {
      const bytes = p.save();
      fork = await Pair.create();
      assert.equal(fork.call('load', bytes), 0);
      assert.equal(hex(fork.save()), hex(bytes));
      forkLeft = 60;
      stats.forks++;
    }
    const dice = r.int(1000);
    if (dice < 220) { // a companion speaks
      const q = 1 + r.int(3), k = r.int(TOPICS.length), wr = r.int(12) ? live(q) : r.int(w.seq.length);
      const value = r.int(7) ? p.j.expressed(q, k) : r.int(5) - 2;
      exec('say', wr, r.int(15) ? w.seq[wr] ?? 0 : (w.seq[wr] ?? 0) + 1, q, k, value, r.int(15) ? mask(q) : r.int(40) - 8);
    } else if (dice < 400) { // the user speaks
      const [line, hint, hv] = r.pick(LINES), u = users();
      const wr = u.length ? r.pick(u) : 0;
      const res = exec('userLine', wr, w.seq[wr] ?? 0, text(line), hint, hv, mask());
      if (res === 2) readings.push([line, hint, hv]);
    } else if (dice < 540) { // a retelling
      const q = 1 + r.int(3);
      let a = r.int(4);
      if (a === q) a = 0;
      const wr = live(q);
      exec('tell', wr, w.seq[wr] ?? 0, q, a, r.int(TOPICS.length), mask(q, a));
    } else if (dice < 620) {
      exec('episode');
    } else if (dice < 680) { // the user's yes to a reading
      const [line, hint, hv] = readings.length ? r.pick(readings) : LINES[6];
      const id = p.j.constructor === undefined ? null : p.c.lineId(text(line));
      const t = exec('issueConfirm', r.int(8) ? hint : r.int(TOPICS.length), r.int(8) ? hv : r.int(5) - 2, id);
      const u = users(), wr = u.length ? r.pick(u) : 0;
      exec('confirm', wr, w.seq[wr] ?? 0, hint, hv, id, r.int(10) ? t.token : bytes32('bogus', step).slice(0, 16));
    } else if (dice < 720) { // rotate a writer's key
      const wr = r.int(w.seq.length);
      const s = secret(seed * 100000 + made++);
      const res = exec('rotate', wr, r.int(10) ? w.secret[wr] : bytes32('wrong', step), bytes32('key' + seed, made++), s.commit);
      if (res === 0) { w.seq[wr]++; w.secret[wr] = s.secret; }
    } else if (dice < 740) { // recover a writer whose secret was lost, with the user's consent
      const wr = r.int(w.seq.length);
      const s = secret(seed * 100000 + made++), key = bytes32('key' + seed, made++);
      const t = exec('issueRecover', wr, key, s.commit);
      if (t.result === 0 && exec('recover', wr, key, s.commit, t.token) === 0) { w.seq[wr]++; w.secret[wr] = s.secret; }
    } else if (dice < 755) { // revoke a voice and give the persona a new door
      const wr = r.int(w.seq.length);
      if (w.persona.length < 16 && exec('revoke', wr) === 0) {
        w.revoked[wr] = 1;
        const persona = w.persona[wr];
        incept(persona === 0 ? 2 : persona === 255 ? 4 : 1, nextInstance++, 1 + r.int(4), persona);
      }
    } else if (dice < 775) { // a consented change of who a companion is
      const q = 1 + r.int(3), core = TOPICS.map(() => r.int(5) - 2), give = TOPICS.map(() => r.int(3));
      const name = ['Simoa', 'Mika', 'Neris'][q - 1];
      const t = exec('issueRedefine', q, text(name), core, give);
      const sys = w.persona.map((x, i) => i).filter(i => (w.persona[i] === 255 || w.persona[i] === 0) && !w.revoked[i]);
      const wr = sys.length ? r.pick(sys) : 4;
      exec('redefine', wr, w.seq[wr] ?? 0, q, text(name), core, give, r.int(10) ? t.token : new Uint8Array(16));
    } else if (dice < 790) {
      exec('forget', r.int(5) - 1, r.int(5) - 1, r.int(TOPICS.length + 1) - 1);
    } else if (dice < 940) { // hostile calls: wrong writers, stale keys, bad ranges, bad lengths
      stats.hostile++;
      const k = r.int(9);
      if (k === 0) exec('say', r.int(20) - 2, r.int(4) - 1, r.int(7) - 1, r.int(9) - 1, r.int(9) - 4, r.int(64) - 16);
      else if (k === 1) exec('tell', r.int(20) - 2, r.int(3), r.int(7) - 1, r.int(7) - 1, r.int(9) - 1, r.int(64) - 16);
      else if (k === 2) exec('userLine', r.int(20) - 2, r.int(3), text(r.pick(LINES)[0]), r.int(9) - 2, r.int(9) - 4, r.int(64) - 16);
      else if (k === 3) exec('userLine', 0, w.seq[0] ?? 0, new Uint8Array(600), -1, 0, 2, r.pick([-1, 513, 600, 1 << 20]));
      else if (k === 4) exec('incept', r.int(7) - 1, r.int(300) - 20, r.int(18) - 1, r.int(260) - 2, bytes32('k', r.int(5)), bytes32('k', r.int(5)));
      else if (k === 5) exec('rotate', r.int(20) - 2, bytes32('x', step), bytes32('key' + seed, 0), bytes32('y', step));
      else if (k === 6) exec('label', 0, text('late label'));
      else if (k === 7) exec('confirm', 0, w.seq[0] ?? 0, r.int(9) - 2, r.int(9) - 4, bytes32('l', step).slice(0, 16), bytes32('t', step).slice(0, 16));
      else exec('redefine', 4, w.seq[4] ?? 0, r.int(6) - 1, text('X'.repeat(r.int(30))), [9, 9, 9, 9, 9, 9], [0, 0, 0, 0, 0, 0], new Uint8Array(16));
    } else { // queries go through both implementations too
      const k = r.int(6);
      if (k === 0) exec('viewGet', r.int(5), r.int(5), r.int(TOPICS.length + 1));
      else if (k === 1) exec('writerGet', r.int(18) - 1);
      else if (k === 2) exec('fingerprint', r.int(5));
      else if (k === 3) exec('definition');
      else if (k === 4) exec('verbatim', text(r.pick(LINES)[0]));
      else exec('info');
    }
    // The propositions, on every step.
    for (let x = 1; x < 4; x++) for (let k = 0; k < TOPICS.length; k++) {
      const e = p.j.expressed(x, k), c = p.j.core(x, k), g = p.j.give(x, k);
      assert.ok(e !== NONE && e >= c - g && e <= c + g && e >= -2 && e <= 2, 'band');
    }
    for (let x = 1; x < 4; x++) for (let y = x + 1; y < 4; y++) {
      let d = 0;
      for (let k = 0; k < TOPICS.length; k++) d += Math.abs(p.j.expressed(x, k) - p.j.expressed(y, k));
      assert.ok(p.j.distanceBetween(x, y) >= 1 && d >= p.j.distanceBetween(x, y), 'blur');
    }
    if (step % 25 === 0) {
      for (let h = 1; h < 4; h++) for (let a = 1; a < 4; a++) for (let k = 0; k < TOPICS.length; k++) {
        if (a === h) continue;
        const v = p.j.viewGet(h, a, k);
        if (v.result === 1 && !v.bytes[33]) {
          const value = (v.bytes[8] << 24) >> 24;
          assert.ok(value >= p.j.core(a, k) - p.j.give(a, k) && value <= p.j.core(a, k) + p.j.give(a, k), 'view out of band');
        }
      }
    }
  }
  const bytes = p.save();
  // Cross-load: the C store loads what the JavaScript store saved and the other way round.
  const q = await Pair.create();
  assert.equal(q.c.load(p.j.save().bytes), 0);
  assert.equal(q.j.load(p.c.save().bytes), 0);
  assert.equal(hex(q.save()), hex(bytes));
  return { seed, head: hex(p.c.headBytes().bytes), file: hex(await crypto.subtle.digest('SHA-256', bytes)), size: bytes.length,
    info: p.j.info(), stats };
}

const out = [];
for (let seed = 1; seed <= SEEDS; seed++) out.push(await history(seed));
const frozen = out.slice(0, 3).map(({ seed, head, file, size }) => ({ seed, calls: CALLS, head, file, size }));
// Vectors are frozen from the full run only (4,000 calls per seed), and written only on request.
if (CALLS === 4000 && process.env.UPDATE_VECTORS === '1') {
  writeFileSync(VECTORS, JSON.stringify(frozen, null, 1) + '\n');
} else if (CALLS === 4000 && existsSync(VECTORS)) {
  assert.deepEqual(frozen, JSON.parse(readFileSync(VECTORS, 'utf8')), 'frozen vectors changed');
}
const total = (key) => out.reduce((n, o) => n + o.stats[key], 0);
const sum = (key) => { const m = {}; for (const o of out) for (const [k, v] of Object.entries(o.stats[key])) m[k] = (m[k] || 0) + v; return m; };
console.log(JSON.stringify({ test: 'differential', result: 'pass', seeds: SEEDS, callsPerSeed: CALLS, calls: total('calls'),
  hostile: total('hostile'), reloadForks: total('forks'), callsCheckedAgainstAReloadedStore: total('forkCalls'),
  accepted: sum('accepted'), refused: sum('refused'), frozenVectors: frozen.length,
  finalViews: out.map(o => o.info[11]), finalWriters: out.map(o => o.info[8]), fileSizes: out.map(o => o.size) }, null, 1));
