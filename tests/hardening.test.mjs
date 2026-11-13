// Regressions for the findings of an independent read of the code, and the capacity limits.
// Each check runs in both implementations unless it is about one of them.
import assert from 'node:assert/strict';
import { Pair, define, text, bytes32, secret, hex, sha } from './lib.mjs';
import { E, LOAD, FILE_MAX, NONE } from '../oracle/anchor.mjs';

const results = [];
const check = async (name, fn) => { await fn(); results.push(name); };
const redigest = f => { const g = Uint8Array.from(f); g.set(sha(g.subarray(0, g.length - 32)), g.length - 32); return g; };
const both = (p, bytes) => [p.c.load(bytes), p.j.load(bytes)];

async function small(opts = {}) {
  const p = await Pair.create();
  assert.equal(define(p, { persons: 3, traits: 1, labels: [['tea']], names: ['Ana', 'Bo'], cores: [[1], [-2]], gives: [[1], [0]], ...opts }), 0);
  return p;
}
// Offsets in a saved file of the small world (one trait "tea", companions "Ana" and "Bo").
function offsets(f) {
  const rc = f[92];
  let at = 93 + 16 * rc;
  at += 1 + 1 + 3; // trait 0: count, length, "tea"
  const ana = at; at += 2 + 3 + 3; const bo = at; at += 2 + 2 + 3;
  return { ana: { core: ana + 5, give: ana + 6, expressed: ana + 7 }, bo: { core: bo + 4, expressed: bo + 6 }, writers: at };
}

await check('the oracle keeps copies, never views of the caller\'s buffers', async () => {
  const p = await small();
  const key = Buffer.from(bytes32('key', 0)), next = Buffer.from(secret(0).commit), keep = Uint8Array.from(key);
  assert.equal(p.call('incept', 2, 0, 0, 0, key, next), 0);
  key.fill(7); next.fill(9);
  assert.equal(p.call('incept', 4, 0, 0, 255, keep, secret(1).commit), E.DIGEST, 'the same key twice');
  const file = Buffer.from(p.save());
  const q = await Pair.create();
  assert.equal(q.call('load', file), 0);
  file.fill(0);
  q.call('episode');
  q.save();
});

await check('a forged expression is refused: sigma 0, before any episode, beyond reach, too few voices', async () => {
  const sigma0 = await small({ sn: 0, sd: 1 });
  let f = sigma0.save(), o = offsets(f), g = Uint8Array.from(f);
  g[o.ana.expressed] = 2;
  assert.deepEqual(both(sigma0, redigest(g)), [LOAD.PERSON, LOAD.PERSON]);
  const fresh = await small();
  f = fresh.save(); o = offsets(f); g = Uint8Array.from(f);
  g[o.ana.expressed] = 0;
  assert.deepEqual(both(fresh, redigest(g)), [LOAD.PERSON, LOAD.PERSON], 'episode 0, version 1');
  const wide = await small({ gives: [[2], [0]], cores: [[1], [-2]] }); // band -1..2, still 1 apart from Bo
  wide.call('episode');
  f = wide.save(); o = offsets(f); g = Uint8Array.from(f);
  g[o.ana.expressed] = 0xff; // -1: inside the band, two steps from the core
  assert.deepEqual(both(wide, redigest(g)), [LOAD.PERSON, LOAD.PERSON], 'two steps at sigma 3/10');
  g[o.ana.expressed] = 0;
  assert.deepEqual(both(wide, redigest(g)), [0, 0], 'one step is reachable and is accepted');
  const lone = await Pair.create();
  assert.equal(define(lone, { persons: 2, traits: 1, labels: [['tea']], names: ['Ana'], cores: [[0]], gives: [[1]] }), 0);
  lone.call('episode');
  f = lone.save(); g = Uint8Array.from(f);
  g[93 + 16 * f[92] + 5 + 2 + 3 + 2] = 1; // Ana's expressed byte
  assert.deepEqual(both(lone, redigest(g)), [LOAD.PERSON, LOAD.PERSON], 'one other person can never make two voices');
});

await check('a forged level that time would have worn down is refused', async () => {
  const p = await small();
  for (let i = 0; i < 2; i++) assert.ok(p.call('incept', 1, i + 1, 1, i + 1, bytes32('key', i), secret(i).commit) >= 0);
  assert.equal(p.call('say', 0, 0, 1, 0, 1, 0b100), 1); // Ana (writer 0) tells Bo
  for (let i = 0; i < 5; i++) p.call('episode');
  const f = p.save();
  const views = f.length - 32 - 32;
  assert.equal(f[views + 6], 3, 'level 8 after five episodes is 3');
  const g = Uint8Array.from(f);
  g[views + 6] = 16;
  assert.deepEqual(both(p, redigest(g)), [LOAD.VIEW, LOAD.VIEW]);
  g[views + 6] = 11;
  assert.deepEqual(both(p, redigest(g)), [0, 0], 'eleven is reachable: renewed three more times, then five episodes');
});

await check('the journal ring must hold the last min(events, 32) entries, chained with their positions', async () => {
  const p = await small();
  for (let i = 0; i < 40; i++) p.call('episode');
  const f = p.save();
  assert.equal(f[92], 32);
  const events = f[16] | (f[17] << 8) | (f[18] << 16) | (f[19] << 24);
  // Fold the oldest kept entry into the base and drop it from the ring: a shorter ring.
  const base = f.slice(28, 60), oldest = f.slice(93, 109);
  const index = events - 32 + 1;
  const newBase = sha(Uint8Array.from([...base, ...oldest, index & 255, (index >> 8) & 255, (index >> 16) & 255, index >>> 24]));
  const g = Uint8Array.from([...f.slice(0, 28), ...newBase, ...f.slice(60, 92), 31, ...f.slice(109)]);
  assert.deepEqual(both(p, redigest(g)), [LOAD.JOURNAL, LOAD.JOURNAL]);
  // A different count with the same entries no longer folds to the head.
  const h = Uint8Array.from(f);
  h[16] = (events + 1) & 255;
  assert.deepEqual(both(p, redigest(h)), [LOAD.JOURNAL, LOAD.JOURNAL]);
});

await check('counters must account for every accepted act', async () => {
  const p = await small();
  for (let i = 0; i < 3; i++) p.call('issueConfirm', 0, 1, bytes32('l', i).slice(0, 16));
  const f = p.save();
  const g = Uint8Array.from(f);
  g[24] += 200; // tokens issued
  assert.deepEqual(both(p, redigest(g)), [LOAD.COUNTER, LOAD.COUNTER]);
  const h = Uint8Array.from(f);
  const events = h[16];
  h[20] = events - 1; // refused: nearly everything
  assert.deepEqual(both(p, redigest(h)), [LOAD.COUNTER, LOAD.COUNTER]);
});

await check('files longer than any store can save are refused the same way by the binding and the oracle', async () => {
  const p = await Pair.create();
  assert.deepEqual(both(p, new Uint8Array(300000)), [LOAD.LONG, LOAD.LONG]);
  const over = new Uint8Array(FILE_MAX + 1); over.set(text('ANCH'), 0); over[4] = 1;
  assert.deepEqual(both(p, over), [LOAD.LONG, LOAD.LONG]);
  const at = new Uint8Array(FILE_MAX); at.set(text('ANCH'), 0); at[4] = 1;
  assert.deepEqual(both(p, at), [LOAD.DIGEST, LOAD.DIGEST]);
});

await check('lean refuses what C cannot represent, without writing anything', async () => {
  const p = await small();
  const before = p.save();
  const { lean } = await import('../oracle/anchor.mjs');
  for (const [values, levels] of [[new Array(703616).fill(0), new Array(703616).fill(1)], [[254, 254], [8, 8]],
    [[1, 1], [8, 8, 8]], [[1, 1], [8, 300]], [[1.5, 1], [8, 8]], [[0, 0, 0, 0, 0, 0, 0, 0], [1, 1, 1, 1, 1, 1, 1, 1]]]) {
    assert.equal(p.c.lean(0, 2, values, levels, 10, 10, 16, 2), NONE, 'C');
    assert.equal(lean(0, 2, values, levels, 10, 10, 16, 2), NONE, 'JavaScript');
  }
  assert.equal(hex(p.save()), hex(before), 'the store is untouched');
});

await check('a buffer shorter than its stated length is an error in both, whatever the state', async () => {
  const p = await Pair.create(); // not even initialised
  const short = new Uint8Array(2);
  for (const call of [s => s.label(0, short, 5), s => s.verbatim(short, 9), s => s.define(1, short, [0], [0], 5),
    s => s.userLine(0, 0, short, -1, 0, 2, 9), s => s.redefine(0, 0, 1, short, [0], [0], new Uint8Array(16), 5),
    s => s.issueRedefine(1, short, [0], [0], 5)]) {
    assert.throws(() => call(p.c), TypeError);
    assert.throws(() => call(p.j), TypeError);
  }
});

await check('a refused init changes nothing', async () => {
  const p = await small();
  const before = p.save();
  assert.equal(p.call('init', 0, 1, 3, 10, 16, 2, 1), E.ARG);
  assert.equal(p.call('init', 4, 1, 11, 10, 16, 2, 1), E.ARG);
  assert.equal(hex(p.save()), hex(before));
  assert.equal(p.c.info()[1], 1, 'still sealed');
});

await check('a token can be spent with 64 entries between issue and use, not 65', async () => {
  const p = await small();
  assert.equal(p.call('incept', 4, 0, 0, 255, bytes32('sys', 0), secret(50).commit), 0);
  for (const gap of [64, 65]) {
    const core = [gap === 64 ? 0 : 1], give = [1];
    const t = p.call('issueRedefine', 1, text('Ana'), core, give);
    for (let i = 0; i < gap; i++) p.call('forget', 1, 0, 0);
    const r = p.call('redefine', 0, 0, 1, text('Ana'), core, give, t.token);
    assert.equal(r, gap === 64 ? 0 : E.TOKEN, 'gap ' + gap);
  }
});

await check('every table full: the file is exactly FILE_MAX bytes, and one more of each is refused', async () => {
  const p = await Pair.create();
  assert.equal(p.call('init', 8, 64, 3, 10, 16, 2, 1), 0);
  const label = (k, j) => ('t' + String(k).padStart(2, '0') + ' l' + j + ' ').padEnd(32, 'x');
  for (let k = 0; k < 64; k++) for (let j = 0; j < 4; j++) assert.equal(p.call('label', k, text(label(k, j))), 0);
  for (let q = 1; q < 8; q++) {
    const core = Array.from({ length: 64 }, (_, k) => (k < 3 ? (((q >> k) & 1) ? 2 : -2) : 0));
    assert.equal(p.call('define', q, text(('Companion ' + q).padEnd(24, '.')), core, new Array(64).fill(0)), 0);
  }
  assert.equal(p.call('seal'), 0);
  const doors = [[2, 0, 0], ...Array.from({ length: 7 }, (_, i) => [1, i + 1, i + 1]), ...Array.from({ length: 8 }, (_, i) => [4, i, 255])];
  doors.forEach(([ch, inst, persona], i) => assert.equal(p.call('incept', ch, inst, 1, persona, bytes32('cap-key', i), secret(1000 + i).commit), i));
  let s = secret(1015).secret;
  for (let i = 0; i < 496; i++) {
    const nx = secret(2000 + i);
    assert.equal(p.call('rotate', 15, s, bytes32('cap-rot', i), nx.commit), 0);
    s = nx.secret;
  }
  assert.equal(p.c.info()[9], 1024);
  assert.equal(p.call('rotate', 15, s, bytes32('cap-rot', 999), secret(9999).commit), E.FULL);
  assert.equal(p.call('incept', 4, 99, 1, 255, bytes32('cap-key', 99), secret(99).commit), E.FULL);
  for (let i = 0; i < 9; i++) assert.equal(p.call('issueConfirm', 0, 1, bytes32('cap-line', i).slice(0, 16)).result, 0);
  assert.equal(p.c.info()[10], 8, 'eight outstanding; the oldest gave way');
  for (let k = 0; k < 64; k++) assert.equal(p.call('userLine', 0, 0, text('i love ' + label(k, 0)), -1, 0, 0b11111110), 1);
  for (let q = 1; q < 8; q++) for (let k = 0; k < 64; k++) assert.equal(p.call('say', q, 0, q, k, p.j.expressed(q, k), 0b11111110 & ~(1 << q)), 6);
  assert.equal(p.c.info()[11], 7 * 7 * 64);
  const f = p.save();
  assert.equal(f.length, FILE_MAX);
  const q2 = await Pair.create();
  assert.equal(q2.call('load', f), 0);
  assert.equal(hex(q2.save()), hex(f));
});

console.log(JSON.stringify({ test: 'hardening', result: 'pass', checks: results.length, names: results }, null, 1));
