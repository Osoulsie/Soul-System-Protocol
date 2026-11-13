// Every history of up to four events over a small world, run in C and in JavaScript together.
// After every step the propositions are checked against a shadow model kept by this test alone.
//
// World: the user (0) and two companions, Ana (1: core 1, give 1) and Bo (2: core -2, give 0), one
// trait "tea". Writers: 0 user, 1 Ana, 2 Bo, 3 a second voice for Ana (another root: a model switch),
// 4 the system. Sixteen events cover speaking in and out of character, the user's word and readings
// of it, retelling, revocation, rotation, consent, forgetting and redefinition.
import assert from 'node:assert/strict';
import { Pair, define, text, bytes32, secret, hex, sha } from './lib.mjs';
import { lean, CLS, NONE } from '../oracle/anchor.mjs';

const DEPTH = Number(process.env.SMALL_DEPTH || 4);
const READING_LINE = text('Mika thinks I love tea');
const READING_ID = sha(READING_LINE).slice(0, 16);

async function world() {
  const p = await Pair.create();
  assert.equal(define(p, { persons: 3, traits: 1, labels: [['tea']], names: ['Ana', 'Bo'], cores: [[1], [-2]], gives: [[1], [0]] }), 0);
  const writers = [[2, 0, 0, 0], [1, 1, 1, 1], [1, 2, 1, 2], [1, 3, 2, 1], [4, 0, 3, 255]];
  writers.forEach(([ch, inst, root, persona], i) => {
    assert.equal(p.call('incept', ch, inst, root, persona, bytes32('key', i), secret(i).commit), i);
  });
  return p;
}

const view = (p, h, a) => {
  const v = p.j.viewGet(h, a, 0);
  if (v.result !== 1) return null;
  const b = v.bytes;
  return { cls: b[3], depth: b[4], level: b[6], corever: b[7], value: (b[8] << 24) >> 24, fallen: b[32], stale: b[33], line: hex(b.slice(16, 32)) };
};

// The shadow: what the test itself expects, built only from the events it sent and their results.
function freshShadow() {
  return { word: [null, null, null], reading: [null, null, null], core: [null, [1, 1], [-2, 0]], version: [0, 1, 1],
    secret: [0, 1, 2, 3, 4].map(i => secret(i).secret), seq: [0, 0, 0, 0, 0], revoked: [0, 0, 0, 0, 0], step: 0 };
}

const EVENTS = [
  ['episode', (p) => p.call('episode')],
  ['Ana says what she expresses', (p, s) => p.call('say', 1, s.seq[1], 1, 0, p.j.expressed(1, 0), 0b100)],
  ['Ana says 2', (p, s) => p.call('say', 1, s.seq[1], 1, 0, 2, 0b100)],
  ['Bo says what he expresses', (p, s) => p.call('say', 2, s.seq[2], 2, 0, p.j.expressed(2, 0), 0b010)],
  ['user: I love tea', (p, s) => p.call('userLine', 0, s.seq[0], text('I love tea'), -1, 0, 0b110)],
  ['user: I hate tea', (p, s) => p.call('userLine', 0, s.seq[0], text('I hate tea'), -1, 0, 0b110)],
  ['user: Mika thinks I love tea', (p, s) => p.call('userLine', 0, s.seq[0], READING_LINE, 0, 2, 0b110)],
  ['user to Ana: I like tea!', (p, s) => p.call('userLine', 0, s.seq[0], text('I like tea!'), -1, 0, 0b010)],
  ['Ana tells Bo about the user', (p, s) => p.call('tell', 1, s.seq[1], 1, 0, 0, 0b100)],
  ['Bo tells Ana about the user', (p, s) => p.call('tell', 2, s.seq[2], 2, 0, 0, 0b010)],
  ['revoke Ana\'s first voice', (p) => p.call('revoke', 1)],
  ['Ana speaks through her second voice', (p, s) => p.call('say', 3, s.seq[3], 1, 0, p.j.expressed(1, 0), 0b100)],
  ['rotate Bo\'s key', (p, s) => {
    const fresh = secret(1000 + s.step);
    const r = p.call('rotate', 2, s.secret[2], bytes32('rotkey', s.step), fresh.commit);
    if (r === 0) s.secret[2] = fresh.secret;
    return r;
  }],
  ['the user confirms the reading', (p, s) => {
    const t = p.call('issueConfirm', 0, 2, READING_ID);
    assert.equal(t.result, 0);
    return p.call('confirm', 0, s.seq[0], 0, 2, READING_ID, t.token);
  }],
  ['forget everything about the user', (p) => p.call('forget', -1, 0, -1)],
  ['redefine Ana, with consent', (p, s) => {
    const next = s.core[1][0] === 1 ? [0, 1] : [1, 1];
    const t = p.call('issueRedefine', 1, text('Ana'), [next[0]], [next[1]]);
    assert.equal(t.result, 0);
    return p.call('redefine', 4, s.seq[4], 1, text('Ana'), [next[0]], [next[1]], t.token);
  }],
];

const stats = { sequences: 0, steps: 0, accepted: new Array(EVENTS.length).fill(0), refused: new Array(EVENTS.length).fill(0),
  leans: 0, retold: 0, confirmed: 0, staleViews: 0, fallenViews: 0, reloads: 0 };

function bandOk(p, x) {
  const e = p.j.expressed(x, 0), c = p.j.core(x, 0), g = p.j.give(x, 0);
  return e >= c - g && e <= c + g && e >= -2 && e <= 2;
}

function expectedSnapshot(p, x) {
  const values = [], levels = [];
  for (let a = 0; a < 3; a++) {
    if (a === x) continue;
    const v = view(p, x, a);
    if (v && v.cls === CLS.FIRST && !v.fallen && !v.stale) { values.push(v.value); levels.push(v.level); }
  }
  return lean(p.j.core(x, 0), p.j.give(x, 0), values, levels, 3, 10, 16, 2);
}

async function run(sequence) {
  const p = await world();
  const s = freshShadow();
  for (const index of sequence) {
    s.step++;
    const before = { e: [null, p.j.expressed(1, 0), p.j.expressed(2, 0)], src: [null, view(p, 1, 0), view(p, 2, 0)],
      ids: [0, 1, 2, 3, 4].map(w => hex(p.j.writerGet(w).bytes.slice(8, 40))) };
    const r = EVENTS[index][1](p, s);
    const ok = (typeof r === 'number' ? r : r.result) >= 0;
    stats.steps++;
    (ok ? stats.accepted : stats.refused)[index]++;

    // Update the shadow from the event and its result.
    if (ok) {
      if (index === 4 || index === 5) { for (const h of [1, 2]) { s.word[h] = index === 4 ? 2 : -2; s.reading[h] = null; } }
      if (index === 7) { s.word[1] = 1; s.reading[1] = null; }
      if (index === 6) for (const h of [1, 2]) if (s.word[h] === null) s.reading[h] = 2;
      if (index === 13) {
        for (const h of [1, 2]) if (s.reading[h] === 2) { s.word[h] = 2; s.reading[h] = null; stats.confirmed++; }
        assert.equal(r, 0 + [1, 2].filter(h => s.word[h] === 2 && before.src[h] && before.src[h].cls === CLS.READ).length);
      }
      if (index === 14) { s.word = [null, null, null]; s.reading = [null, null, null]; }
      if (index === 10) s.revoked[1] = 1;
      if (index === 12) s.seq[2]++;
      if (index === 15) { s.core[1] = s.core[1][0] === 1 ? [0, 1] : [1, 1]; s.version[1]++; }
    }

    // A: every expressed value lies in the band; the two never come closer than their distance.
    for (const x of [1, 2]) assert.ok(bandOk(p, x), 'band');
    assert.ok(Math.abs(p.j.expressed(1, 0) - p.j.expressed(2, 0)) >= p.j.distanceBetween(1, 2), 'distance');
    assert.ok(p.j.distanceBetween(1, 2) >= 1);
    // A: cores change only by a consented redefinition.
    for (const x of [1, 2]) assert.deepEqual([p.j.core(x, 0), p.j.give(x, 0)], s.core[x], 'core changed');
    // A: within an episode the expressed value changes only when that companion is redefined;
    // at an episode it is exactly the rule applied to her core and her live first-hand voices.
    for (const x of [1, 2]) {
      if (index === 0 && ok) {
        const want = expectedSnapshot(p, x);
        assert.equal(p.j.expressed(x, 0), want, 'snapshot');
        if (want !== p.j.core(x, 0)) stats.leans++;
      } else if (!(index === 15 && ok && x === 1)) {
        assert.equal(p.j.expressed(x, 0), before.e[x], 'expressed changed inside an episode');
      }
    }
    // A: every live, current first-hand view of a companion lies in her band; old ones are stale.
    for (const [h, a] of [[1, 2], [2, 1]]) {
      const v = view(p, h, a);
      if (!v) continue;
      if (v.stale) stats.staleViews++;
      if (v.fallen) stats.fallenViews++;
      if (!v.stale) {
        const c = p.j.core(a, 0), g = p.j.give(a, 0);
        assert.ok(v.value >= c - g && v.value <= c + g, 'a current view of her is out of her band');
      }
      assert.equal(v.stale, v.corever !== s.version[a] ? 1 : 0);
    }
    // C: the user's word is exactly the last word each holder heard; a reading never stands in for it.
    for (const h of [1, 2]) {
      const v = view(p, h, 0);
      if (s.word[h] !== null) {
        assert.ok(v && v.cls === CLS.FIRST && v.value === s.word[h], 'the user\'s word drifted');
      } else {
        assert.ok(!v || v.cls !== CLS.FIRST, 'a word appeared that the user never said');
      }
      if (s.reading[h] !== null) assert.ok(v && v.cls === CLS.READ && v.value === s.reading[h], 'reading');
    }
    // C: a retelling carries exactly what the teller held.
    if ((index === 8 || index === 9) && ok) {
      const teller = index === 8 ? 1 : 2, listener = index === 8 ? 2 : 1;
      const src = before.src[teller], v = view(p, listener, 0), was = before.src[listener];
      if (r === 1) {
        assert.ok(v.cls === CLS.TOLD && v.value === src.value && v.depth === src.depth + 1 && v.line === src.line, 'retelling changed');
        stats.retold++;
      } else {
        assert.equal(r, 0);
        assert.ok(was && !was.fallen && (was.cls !== CLS.TOLD || was.depth < src.depth + 1), 'a retelling was kept out without cause');
      }
    }
    // B: writer identities never change; keys change only by rotation; superseded keys cannot write.
    for (let w = 0; w < 5; w++) {
      assert.equal(hex(p.j.writerGet(w).bytes.slice(8, 40)), before.ids[w], 'identity changed');
      const b = p.j.writerGet(w).bytes;
      assert.equal(b[6] | (b[7] << 8), s.seq[w], 'key sequence');
      assert.equal(b[4], s.revoked[w], 'revocation');
    }
    if (index === 3 && s.seq[2] > 0) {
      const stale = p.call('say', 2, 0, 2, 0, p.j.expressed(2, 0), 0b010);
      assert.equal(stale, -4, 'a superseded key wrote');
    }
  }
  // Saved bytes agree, and a reload reproduces them exactly in both implementations.
  const bytes = p.save();
  const q = await Pair.create();
  assert.equal(q.call('load', bytes), 0);
  assert.equal(hex(q.save()), hex(bytes));
  stats.reloads++;
  stats.sequences++;
}

function* sequences(depth) {
  if (depth === 0) { yield []; return; }
  for (const rest of sequences(depth - 1)) {
    yield rest;
    if (rest.length === depth - 1) for (let i = 0; i < EVENTS.length; i++) yield [...rest, i];
  }
}

const seen = new Set();
for (const seq of sequences(DEPTH)) {
  const key = seq.join(',');
  if (seen.has(key)) continue;
  seen.add(key);
  await run(seq);
}
console.log(JSON.stringify({ test: 'small histories', result: 'pass', depth: DEPTH, events: EVENTS.length,
  sequences: stats.sequences, steps: stats.steps, leans: stats.leans, retold: stats.retold, confirmed: stats.confirmed,
  staleViewsSeen: stats.staleViews, fallenViewsSeen: stats.fallenViews, reloads: stats.reloads,
  perEvent: EVENTS.map(([name], i) => ({ event: name, accepted: stats.accepted[i], refused: stats.refused[i] })) }, null, 1));
