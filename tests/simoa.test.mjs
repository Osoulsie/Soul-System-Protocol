// Simoa 10.15.0: the three companions' own stances on all 31 crew-talk topics, taken from the shipped
// stage bundle (tests/fixtures/simoa-10.15.0-topics.json records its SHA-256). Gives follow 10.15.0's
// rule: a stance of -2 or 2 never moves, any other may move one step. Then the drift cases that were
// reproduced against the shipped 10.15.0 code are run through this store, and a long simulation
// measures how far each companion actually goes from herself.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Pair, define, text, bytes32, secret, giveOf, rng, root, sha } from './lib.mjs';
import { E, LINE, CLS } from '../oracle/anchor.mjs';

const fixture = JSON.parse(readFileSync(new URL('tests/fixtures/simoa-10.15.0-topics.json', root), 'utf8'));
const topics = fixture.topics;
assert.equal(topics.length, 31);
const K = topics.length, SIMOA = 1, MIKA = 2, NERIS = 3, USER = 0;
const T = Object.fromEntries(topics.map((t, k) => [t.id, k]));
const cores = [0, 1, 2].map(i => topics.map(t => t.stance[i]));
const gives = cores.map(c => c.map(giveOf));

async function simoa() {
  const p = await Pair.create();
  assert.equal(define(p, { persons: 4, traits: K, labels: topics.map(t => [t.label]), names: ['Simoa', 'Mika', 'Neris'], cores, gives }), 0);
  [[2, 0, 0, USER], [1, 1, 1, SIMOA], [1, 2, 1, MIKA], [1, 3, 1, NERIS]].forEach(([ch, inst, rt, persona], i) =>
    assert.equal(p.call('incept', ch, inst, rt, persona, bytes32('simoa-key', i), secret(500 + i).commit), i));
  return p;
}
const view = (p, h, a, k) => {
  const v = p.j.viewGet(h, a, k);
  return v.result === 1 ? { cls: v.bytes[3], value: (v.bytes[8] << 24) >> 24, was: (v.bytes[9] << 24) >> 24, auth: v.bytes[5], depth: v.bytes[4] } : null;
};
const bit = (...ps) => ps.reduce((m, x) => m | (1 << x), 0);

const p = await simoa();
const distances = { simoaMika: p.j.distanceBetween(SIMOA, MIKA), simoaNeris: p.j.distanceBetween(SIMOA, NERIS), mikaNeris: p.j.distanceBetween(MIKA, NERIS) };
assert.deepEqual(distances, { simoaMika: 14, simoaNeris: 9, mikaNeris: 9 });

// 1. "I love tea", then "I like tea": 10.15.0 held 1.5 and showed "You love tea". Here: "like", before "love".
p.call('userLine', 0, 0, text('I love tea'), -1, 0, bit(SIMOA, MIKA, NERIS));
p.call('userLine', 0, 0, text('I like tea'), -1, 0, bit(SIMOA, MIKA, NERIS));
for (const h of [SIMOA, MIKA, NERIS]) assert.deepEqual([view(p, h, USER, T.tea).value, view(p, h, USER, T.tea).was], [1, 2]);

// 2. Lines 10.15.0 stored as the user's own stance at full authority are readings here.
for (const [line, k, v] of [['Mika thinks I love storms', T.storms, 2], ['My brother says I hate tea', T.tea, -2],
  ['I love storms, said nobody ever', T.storms, 2]]) {
  assert.equal(p.call('userLine', 0, 0, text(line), k, v, bit(SIMOA)), LINE.READING, line);
}
assert.equal(view(p, SIMOA, USER, T.storms).cls, CLS.READ);
assert.deepEqual([view(p, SIMOA, USER, T.tea).cls, view(p, SIMOA, USER, T.tea).value], [CLS.FIRST, 1], 'the word "like" stands');

// 3. A retelling carries what the teller holds; there is no value to pass.
assert.equal(p.call('tell', SIMOA, 0, SIMOA, USER, T.tea, bit(MIKA)), 0, 'Mika has the user\'s own word already');
p.call('userLine', 0, 0, text('I love music'), -1, 0, bit(SIMOA));
assert.equal(p.call('tell', SIMOA, 0, SIMOA, USER, T.music, bit(MIKA)), 1);
assert.deepEqual([view(p, MIKA, USER, T.music).cls, view(p, MIKA, USER, T.music).value], [CLS.TOLD, 2]);

// 4. In 10.15.0, Mika and Neris could be recorded hating rain although both like or love it.
assert.equal(p.call('say', MIKA, 0, MIKA, T.rain, -2, bit(SIMOA)), E.CHARACTER);
assert.equal(p.call('say', NERIS, 0, NERIS, T.rain, -2, bit(SIMOA)), E.CHARACTER);

// 5. One value per conversation. Simoa dislikes storms (-1); the user and Neris love them.
p.call('userLine', 0, 0, text('I love storms'), -1, 0, bit(SIMOA));
p.call('say', NERIS, 0, NERIS, T.storms, 2, bit(SIMOA));
assert.equal(p.j.expressed(SIMOA, T.storms), -1, 'mid-conversation she is who she was when it began');
assert.equal(p.call('say', SIMOA, 0, SIMOA, T.storms, 0, bit(MIKA)), E.NOTNOW);
p.call('episode');
assert.equal(p.j.expressed(SIMOA, T.storms), 0, 'at the next conversation she has softened one step');
assert.equal(p.call('say', SIMOA, 0, SIMOA, T.storms, -1, bit(MIKA)), E.NOTNOW);
assert.equal(p.call('say', SIMOA, 0, SIMOA, T.storms, 0, bit(MIKA)), 1);

// 6. Writer identities: an empty key store must not mint a new identity on the same door.
assert.equal(p.call('incept', 1, 2, 1, MIKA, bytes32('new-device', 1), secret(600).commit), E.DOOR);
const t = p.call('issueRecover', MIKA, bytes32('new-device', 1), secret(600).commit);
assert.equal(p.call('recover', MIKA, bytes32('new-device', 1), secret(600).commit, t.token), 0);

// 7. A long life: 2,000 conversations. Everyone speaks in character; the user says what they like,
//    sometimes plainly, sometimes in a way that is only a reading; the companions retell; now and then
//    the user confirms a reading or asks them to forget. Measure how far anyone goes from herself.
const q = await simoa();
const r = rng(1015);
const maxDrift = [0, 0, 0, 0], moved = [0, 0, 0, 0];
let minPair = Infinity, conversations = 0, lines = 0;
const verbs = ['hate', "don't like", 'am undecided about', 'like', 'love'];
for (let c = 0; c < 2000; c++) {
  q.call('episode');
  conversations++;
  for (let i = 0; i < 12; i++) {
    const k = r.int(K), who = r.int(4);
    if (who === 0) {
      const v = r.int(5) - 2;
      const plain = 'I ' + verbs[v + 2] + ' ' + topics[k].label;
      const said = r.int(4) ? plain : 'honestly, ' + plain;
      q.call('userLine', 0, 0, text(said), k, v, bit(SIMOA, MIKA, NERIS));
      if (r.int(10) === 0) {
        const id = sha(text(said)).slice(0, 16), tk = q.call('issueConfirm', k, v, id);
        q.call('confirm', 0, 0, k, v, id, tk.token);
      }
    } else if (r.int(3)) {
      assert.equal(q.call('say', who, 0, who, k, q.j.expressed(who, k), bit(SIMOA, MIKA, NERIS) & ~bit(who)) >= 0, true);
    } else {
      let a = r.int(4);
      if (a === who) a = 0;
      q.call('tell', who, 0, who, a, k, bit(SIMOA, MIKA, NERIS) & ~bit(who, a));
    }
    lines++;
  }
  if (r.int(50) === 0) q.call('forget', -1, -1, r.int(K));
  for (let x = 1; x < 4; x++) for (let k = 0; k < K; k++) {
    const d = Math.abs(q.j.expressed(x, k) - cores[x - 1][k]);
    maxDrift[x] = Math.max(maxDrift[x], d);
    if (d) moved[x]++;
    assert.ok(d <= gives[x - 1][k]);
  }
  for (const [x, y] of [[1, 2], [1, 3], [2, 3]]) {
    let s = 0;
    for (let k = 0; k < K; k++) s += Math.abs(q.j.expressed(x, k) - q.j.expressed(y, k));
    minPair = Math.min(minPair, s - q.j.distanceBetween(x, y));
    assert.ok(s >= q.j.distanceBetween(x, y));
  }
}
const coreUnchanged = [SIMOA, MIKA, NERIS].every(x => topics.every((_, k) => q.j.core(x, k) === cores[x - 1][k]));
assert.ok(coreUnchanged);
console.log(JSON.stringify({ test: 'simoa 10.15.0', result: 'pass', topics: K, stageBundleSha256: fixture.stage_bundle_sha256,
  distances, conversations, lines, maxStepsFromCore: { simoa: maxDrift[1], mika: maxDrift[2], neris: maxDrift[3] },
  traitConversationsLeaned: { simoa: moved[1], mika: moved[2], neris: moved[3] },
  smallestMarginAboveGuaranteedDistance: minPair, coresUnchanged: coreUnchanged }, null, 1));
