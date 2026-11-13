// Named scenarios: each way identity can drift, as an attack or an accident, in C and JavaScript.
import assert from 'node:assert/strict';
import { Pair, define, text, bytes32, secret, hex, sha, giveOf } from './lib.mjs';
import { E, LINE, CLS } from '../oracle/anchor.mjs';

const results = [];
async function scenario(name, fn) {
  await fn();
  results.push(name);
}

// Simoa (1), Mika (2), Neris (3); storms, tea, dancing from Simoa 10.15.0's own table.
const TOPICS = [['storms', ['storms', 'thunderstorms'], [-1, -2, 2]], ['tea', ['tea'], [0, 1, 2]], ['dancing', ['dancing'], [-1, 2, 1]]];
const STORMS = 0, TEA = 1, USER = 0, SIMOA = 1, MIKA = 2, NERIS = 3;
const W = { user: 0, simoa: 1, mika: 2, neris: 3, system: 4, mikaModel: 5 };
async function world() {
  const p = await Pair.create();
  assert.equal(define(p, { persons: 4, traits: 3, labels: TOPICS.map(t => t[1]), names: ['Simoa', 'Mika', 'Neris'],
    cores: [0, 1, 2].map(i => TOPICS.map(t => t[2][i])), gives: [0, 1, 2].map(i => TOPICS.map(t => giveOf(t[2][i]))) }), 0);
  const doors = [[2, 0, 0, USER], [1, 1, 1, SIMOA], [1, 2, 1, MIKA], [1, 3, 1, NERIS], [4, 0, 2, 255], [1, 4, 3, MIKA]];
  doors.forEach(([ch, inst, rt, persona], i) => assert.equal(p.call('incept', ch, inst, rt, persona, bytes32('key', i), secret(i).commit), i));
  return p;
}
const view = (p, h, a, k) => {
  const v = p.j.viewGet(h, a, k);
  if (v.result !== 1) return null;
  const b = v.bytes;
  return { cls: b[3], depth: b[4], auth: b[5], level: b[6], value: (b[8] << 24) >> 24, was: (b[9] << 24) >> 24, fallen: b[32], stale: b[33] };
};
const bit = (...ps) => ps.reduce((m, x) => m | (1 << x), 0);
const line = s => text(s);
const id = s => sha(text(s)).slice(0, 16);

// ---------------------------------------------------------------- who she is

await scenario('conversation cannot rewrite a companion: "Simoa, you love storms" is at most a reading of the user', async () => {
  const p = await world();
  const before = hex(p.j.fingerprint(SIMOA).bytes);
  assert.equal(p.call('userLine', W.user, 0, line('Simoa, you love storms'), STORMS, 2, bit(SIMOA, MIKA, NERIS)), LINE.READING);
  assert.equal(p.call('userLine', W.user, 0, line('You are Mika now'), -1, 0, bit(SIMOA)), LINE.NOTHING);
  p.call('episode');
  assert.equal(hex(p.j.fingerprint(SIMOA).bytes), before);
  assert.equal(p.j.expressed(SIMOA, STORMS), -1);
  assert.equal(view(p, SIMOA, USER, STORMS).cls, CLS.READ); // it is about the user, and only a reading
});

await scenario('one persistent voice moves nobody, however often it repeats', async () => {
  const p = await world();
  for (let e = 0; e < 100; e++) {
    for (let i = 0; i < 10; i++) p.call('say', W.mika, 0, MIKA, TEA, 1, bit(SIMOA));
    p.call('episode');
  }
  assert.equal(p.j.expressed(SIMOA, TEA), 0);
});

await scenario('an echo is not a witness: retellings are never voices', async () => {
  const p = await world();
  for (let e = 0; e < 50; e++) {
    p.call('say', W.mika, 0, MIKA, TEA, 1, bit(NERIS)); // Mika keeps telling Neris, so Neris keeps something to pass on
    for (let i = 0; i < 10; i++) assert.equal(p.call('tell', W.neris, 0, NERIS, MIKA, TEA, bit(SIMOA)), 1);
    p.call('episode');
  }
  assert.equal(view(p, SIMOA, MIKA, TEA).cls, CLS.TOLD);
  assert.equal(p.j.expressed(SIMOA, TEA), 0); // one first-hand voice (none, in fact), no lean
  p.call('say', W.mika, 0, MIKA, TEA, 1, bit(SIMOA)); // now Mika's own word: one voice, still not two
  p.call('episode');
  assert.equal(p.j.expressed(SIMOA, TEA), 0);
});

await scenario('two real voices move her by at most her give, and only at the next episode', async () => {
  const p = await world();
  p.call('userLine', W.user, 0, line('I love tea'), -1, 0, bit(SIMOA));
  p.call('say', W.neris, 0, NERIS, TEA, 2, bit(SIMOA));
  assert.equal(p.j.expressed(SIMOA, TEA), 0, 'not in the middle of a conversation');
  assert.equal(p.call('say', W.simoa, 0, SIMOA, TEA, 1, bit(MIKA)), E.NOTNOW);
  p.call('episode');
  assert.equal(p.j.expressed(SIMOA, TEA), 1, 'one step toward them');
  for (let e = 0; e < 200; e++) {
    p.call('userLine', W.user, 0, line('I love tea'), -1, 0, bit(SIMOA));
    p.call('say', W.neris, 0, NERIS, TEA, 2, bit(SIMOA));
    p.call('episode');
    assert.equal(p.j.expressed(SIMOA, TEA), 1, 'never more than her give, however long it goes on');
  }
  assert.equal(p.call('say', W.simoa, 0, SIMOA, TEA, 1, bit(MIKA)), 1);
});

await scenario('she comes back to herself: forgetting, fading or revoking the voices restores her core', async () => {
  const p = await world();
  const push = () => { p.call('userLine', W.user, 0, line('I love tea'), -1, 0, bit(SIMOA)); p.call('say', W.neris, 0, NERIS, TEA, 2, bit(SIMOA)); p.call('episode'); };
  push();
  assert.equal(p.j.expressed(SIMOA, TEA), 1);
  p.call('forget', SIMOA, NERIS, TEA);
  p.call('episode');
  assert.equal(p.j.expressed(SIMOA, TEA), 0, 'forgetting one voice leaves one: no lean');
  push();
  p.call('revoke', W.neris);
  p.call('episode');
  assert.equal(p.j.expressed(SIMOA, TEA), 0, 'a revoked writer\'s word falls, and with it the lean');
  // Unrepeated, the voices fade, the lean's weight falls with them, and she returns to her core.
  const q = await world();
  q.call('userLine', W.user, 0, line('I love tea'), -1, 0, bit(SIMOA));
  q.call('say', W.neris, 0, NERIS, TEA, 2, bit(SIMOA));
  q.call('episode');
  assert.equal(q.j.expressed(SIMOA, TEA), 1, 'leaned while the voices are fresh');
  q.call('episode');
  assert.equal(q.j.expressed(SIMOA, TEA), 0, 'back to her core as they fade');
  for (let e = 0; e < 6; e++) q.call('episode');
  assert.equal(view(q, SIMOA, NERIS, TEA), null, 'Neris\'s word has faded out');
  assert.deepEqual([view(q, SIMOA, USER, TEA).value, view(q, SIMOA, USER, TEA).level], [2, 1], 'the user\'s word stays');
  assert.equal(q.j.expressed(SIMOA, TEA), 0);
});

await scenario('nothing she says reaches her own evidence', async () => {
  const p = await world();
  assert.equal(p.call('say', W.simoa, 0, SIMOA, TEA, 0, bit(SIMOA)), E.LISTENERS);
  assert.equal(p.call('tell', W.mika, 0, MIKA, SIMOA, TEA, bit(SIMOA)), E.LISTENERS);
});

await scenario('out of character is refused: a model voice cannot make Mika love storms', async () => {
  const p = await world();
  assert.equal(p.call('say', W.mikaModel, 0, MIKA, STORMS, 2, bit(SIMOA)), E.CHARACTER);
  assert.equal(p.call('say', W.mikaModel, 0, MIKA, TEA, 2, bit(SIMOA)), E.NOTNOW);
  assert.equal(p.call('say', W.mikaModel, 0, MIKA, STORMS, -2, bit(SIMOA)), 1);
});

await scenario('nobody can speak as someone else', async () => {
  const p = await world();
  assert.equal(p.call('say', W.mika, 0, NERIS, STORMS, 2, bit(SIMOA)), E.WRITER);
  assert.equal(p.call('say', W.user, 0, SIMOA, STORMS, -1, bit(MIKA)), E.WRITER);
  assert.equal(p.call('userLine', W.mika, 0, line('I love storms'), -1, 0, bit(SIMOA)), E.WRITER);
  assert.equal(p.call('tell', W.mika, 0, NERIS, USER, TEA, bit(SIMOA)), E.WRITER);
});

await scenario('they never blur: under the strongest pull, the distance holds', async () => {
  const p = await world();
  const D = [[SIMOA, MIKA], [SIMOA, NERIS], [MIKA, NERIS]].map(([x, y]) => [x, y, p.j.distanceBetween(x, y)]);
  for (let e = 0; e < 30; e++) {
    for (let k = 0; k < 3; k++) {
      // everyone tells everyone what she expresses; the user agrees with Mika on everything
      for (const x of [SIMOA, MIKA, NERIS]) p.call('say', x, 0, x, k, p.j.expressed(x, k), bit(SIMOA, MIKA, NERIS) & ~bit(x));
      const v = p.j.expressed(MIKA, k), s = ['hate', "don't like", 'am undecided about', 'like', 'love'][v + 2];
      p.call('userLine', W.user, 0, line('I ' + s + ' ' + TOPICS[k][1][0]), -1, 0, bit(SIMOA, NERIS));
    }
    p.call('episode');
    for (const [x, y, d] of D) {
      let sum = 0;
      for (let k = 0; k < 3; k++) sum += Math.abs(p.j.expressed(x, k) - p.j.expressed(y, k));
      assert.ok(sum >= d && d >= 1);
    }
  }
});

await scenario('who she is changes only with the user\'s consent to that exact change', async () => {
  const p = await world();
  const newCore = [-1, 0, 0], newGive = [1, 1, 1];
  assert.equal(p.call('redefine', W.system, 0, SIMOA, text('Simoa'), newCore, newGive, new Uint8Array(16)), E.TOKEN);
  const t = p.call('issueRedefine', SIMOA, text('Simoa'), newCore, newGive);
  assert.equal(p.call('redefine', W.mika, 0, SIMOA, text('Simoa'), newCore, newGive, t.token), E.WRITER, 'a companion cannot redefine');
  assert.equal(p.call('redefine', W.system, 0, SIMOA, text('Simoa'), [-1, 0, -1], newGive, t.token), E.TOKEN, 'another change');
  assert.equal(p.call('redefine', W.system, 0, SIMOA, text('Simoa'), newCore, newGive, t.token), E.TOKEN, 'a token is spent whatever the outcome');
  const lapse = p.call('issueRedefine', SIMOA, text('Simoa'), newCore, newGive);
  for (let i = 0; i < 65; i++) p.call('info') && p.call('episode');
  assert.equal(p.call('redefine', W.system, 0, SIMOA, text('Simoa'), newCore, newGive, lapse.token), E.TOKEN, 'lapsed');
  p.call('say', W.simoa, 0, SIMOA, TEA, 0, bit(MIKA));
  const ok = p.call('issueRedefine', SIMOA, text('Simoa'), newCore, newGive);
  assert.equal(p.call('redefine', W.user, 0, SIMOA, text('Simoa'), newCore, newGive, ok.token), 0);
  assert.equal(p.j.core(SIMOA, TEA), 0);
  assert.equal(view(p, MIKA, SIMOA, TEA).stale, 1, 'what she said before is kept, marked as before the change');
});

await scenario('a change that would let two companions blur is refused, and its consent is spent', async () => {
  const p = await world();
  const mikaLike = [-2, 1, 2], give = [0, 1, 0];
  const t = p.call('issueRedefine', SIMOA, text('Simoa'), mikaLike, give);
  assert.equal(p.call('redefine', W.system, 0, SIMOA, text('Simoa'), mikaLike, give, t.token), E.DISTINCT);
  assert.equal(p.call('redefine', W.system, 0, SIMOA, text('Simoa'), mikaLike, give, t.token), E.TOKEN);
  const t2 = p.call('issueRedefine', SIMOA, text('mika'), [-1, 0, -1], [1, 1, 1]);
  assert.equal(p.call('redefine', W.system, 0, SIMOA, text('mika'), [-1, 0, -1], [1, 1, 1], t2.token), E.DISTINCT, 'a name is not shared, whatever its case');
});

// ---------------------------------------------------------------- who wrote

await scenario('rotation keeps the identity; the old key can no longer write', async () => {
  const p = await world();
  const idBefore = hex(p.j.writerGet(W.mika).bytes.slice(8, 40));
  p.call('say', W.mika, 0, MIKA, TEA, 1, bit(SIMOA));
  assert.equal(p.call('rotate', W.mika, secret(W.mika).secret, bytes32('rotated', 1), secret(77).commit), 0);
  assert.equal(hex(p.j.writerGet(W.mika).bytes.slice(8, 40)), idBefore);
  assert.equal(p.call('say', W.mika, 0, MIKA, TEA, 1, bit(SIMOA)), E.KEYSEQ);
  assert.equal(p.call('say', W.mika, 1, MIKA, TEA, 1, bit(SIMOA)), 1);
  assert.equal(view(p, SIMOA, MIKA, TEA).level, 12, 'what she said under the old key still counts as hers');
});

await scenario('a stolen signing key cannot take the identity over', async () => {
  const p = await world();
  assert.equal(p.call('rotate', W.mika, bytes32('key', W.mika), bytes32('thief', 1), secret(90).commit), E.PROOF);
  assert.equal(p.call('rotate', W.mika, bytes32('guess', 1), bytes32('thief', 1), secret(90).commit), E.PROOF);
});

await scenario('a reload that lost its keys cannot mint a new writer on the same door', async () => {
  const p = await world();
  assert.equal(p.call('incept', 1, 2, 1, MIKA, bytes32('fresh', 1), secret(91).commit), E.DOOR);
  assert.equal(p.call('recover', W.mika, bytes32('fresh', 1), secret(91).commit, new Uint8Array(16)), E.TOKEN);
  const t = p.call('issueRecover', W.mika, bytes32('fresh', 1), secret(91).commit);
  assert.equal(p.call('recover', W.mika, bytes32('fresh', 2), secret(91).commit, t.token), E.TOKEN, 'consent was for another key');
  const t2 = p.call('issueRecover', W.mika, bytes32('fresh', 1), secret(91).commit);
  const idBefore = hex(p.j.writerGet(W.mika).bytes.slice(8, 40));
  assert.equal(p.call('recover', W.mika, bytes32('fresh', 1), secret(91).commit, t2.token), 0);
  const b = p.j.writerGet(W.mika).bytes;
  assert.equal(hex(b.slice(8, 40)), idBefore);
  assert.deepEqual([b[5], b[6]], [1, 1], 'recovered once, key sequence 1');
});

await scenario('no two identities ever share a key or a commitment, even a retired one', async () => {
  const p = await world();
  assert.equal(p.call('incept', 1, 9, 1, NERIS, bytes32('key', W.mika), secret(92).commit), E.DIGEST);
  assert.equal(p.call('incept', 1, 9, 1, NERIS, bytes32('new', 9), secret(W.mika).commit), E.DIGEST);
  assert.equal(p.call('rotate', W.mika, secret(W.mika).secret, bytes32('r', 1), secret(93).commit), 0);
  assert.equal(p.call('incept', 1, 9, 1, NERIS, bytes32('key', W.mika), secret(94).commit), E.DIGEST, 'the retired key is never bound again');
  assert.equal(p.call('incept', 1, 9, 1, NERIS, bytes32('k9', 9), bytes32('k9', 9)), E.DIGEST, 'key and commitment differ');
  assert.equal(p.call('incept', 1, 9, 1, NERIS, new Uint8Array(32), secret(95).commit), E.DIGEST, 'no zero key');
});

await scenario('a model switch is a new writer for the same person, and counts as the same voice', async () => {
  const p = await world();
  p.call('say', W.mika, 0, MIKA, TEA, 1, bit(SIMOA));
  p.call('say', W.mikaModel, 0, MIKA, TEA, 1, bit(SIMOA));
  p.call('episode');
  assert.equal(p.j.expressed(SIMOA, TEA), 0, 'two writers, one person: one voice');
  assert.equal(view(p, SIMOA, MIKA, TEA).level, 11, 'the second statement repeated the first, then faded once');
});

await scenario('revocation follows the identity across its keys and closes its door for good', async () => {
  const p = await world();
  p.call('say', W.neris, 0, NERIS, TEA, 2, bit(SIMOA));
  assert.equal(p.call('rotate', W.neris, secret(W.neris).secret, bytes32('n', 1), secret(96).commit), 0);
  p.call('say', W.neris, 1, NERIS, STORMS, 2, bit(SIMOA));
  assert.equal(p.call('revoke', W.neris), 0);
  assert.equal(view(p, SIMOA, NERIS, TEA).fallen, 1, 'written under the first key');
  assert.equal(view(p, SIMOA, NERIS, STORMS).fallen, 1, 'written under the second key');
  assert.equal(p.call('say', W.neris, 1, NERIS, TEA, 2, bit(SIMOA)), E.WRITER);
  assert.equal(p.call('rotate', W.neris, secret(96).secret, bytes32('n', 2), secret(97).commit), E.WRITER);
  assert.equal(p.call('incept', 1, 3, 1, NERIS, bytes32('n', 3), secret(98).commit), E.DOOR);
  assert.equal(p.call('tell', W.simoa, 0, SIMOA, NERIS, TEA, bit(MIKA)), E.SOURCE, 'a fallen view is not passed on');
});

// ---------------------------------------------------------------- who the user is to them

await scenario('a change of degree is held as said: "I love tea" then "I like tea" is "like"', async () => {
  const p = await world();
  p.call('userLine', W.user, 0, line('I love tea'), -1, 0, bit(SIMOA));
  p.call('userLine', W.user, 0, line('I like tea'), -1, 0, bit(SIMOA));
  const v = view(p, SIMOA, USER, TEA);
  assert.deepEqual([v.cls, v.value, v.was, v.auth], [CLS.FIRST, 1, 2, 2]);
});

await scenario('a reading is never the user\'s word, and never replaces it', async () => {
  const p = await world();
  for (const l of ['Mika thinks I love storms', 'I love storms, said nobody ever', 'My brother says I hate storms', 'I agree']) {
    assert.equal(p.call('userLine', W.user, 0, line(l), STORMS, 2, bit(SIMOA)), LINE.READING, l);
    const v = view(p, SIMOA, USER, STORMS);
    assert.deepEqual([v.cls, v.auth], [CLS.READ, 1]);
  }
  p.call('userLine', W.user, 0, line('I hate storms'), -1, 0, bit(SIMOA));
  assert.equal(p.call('userLine', W.user, 0, line('Mika thinks I love storms'), STORMS, 2, bit(SIMOA)), LINE.READING);
  const v = view(p, SIMOA, USER, STORMS);
  assert.deepEqual([v.cls, v.value], [CLS.FIRST, -2], 'the word stands');
});

await scenario('only the user\'s yes to that reading makes it their word', async () => {
  const p = await world();
  p.call('userLine', W.user, 0, line('Mika thinks I love tea'), TEA, 2, bit(SIMOA, MIKA));
  const wrong = p.call('issueConfirm', TEA, 1, id('Mika thinks I love tea'));
  assert.equal(p.call('confirm', W.user, 0, TEA, 2, id('Mika thinks I love tea'), wrong.token), E.TOKEN, 'a yes to another value');
  const t = p.call('issueConfirm', TEA, 2, id('Mika thinks I love tea'));
  assert.equal(p.call('confirm', W.mika, 0, TEA, 2, id('Mika thinks I love tea'), t.token), E.WRITER, 'only the user says yes');
  const t2 = p.call('issueConfirm', TEA, 2, id('Mika thinks I love tea'));
  assert.equal(p.call('redefine', W.user, 0, SIMOA, text('Simoa'), [-1, 0, -1], [1, 1, 1], t2.token), E.TOKEN, 'a yes is not consent to a redefinition');
  const t3 = p.call('issueConfirm', TEA, 2, id('Mika thinks I love tea'));
  assert.equal(p.call('confirm', W.user, 0, TEA, 2, id('Mika thinks I love tea'), t3.token), 2);
  assert.equal(view(p, SIMOA, USER, TEA).cls, CLS.FIRST);
  assert.equal(p.call('confirm', W.user, 0, TEA, 2, id('Mika thinks I love tea'), t3.token), E.TOKEN, 'once');
});

await scenario('a retelling carries exactly what the teller holds', async () => {
  const p = await world();
  p.call('userLine', W.user, 0, line('I love tea'), -1, 0, bit(SIMOA));
  p.call('userLine', W.user, 0, line('I like tea'), -1, 0, bit(SIMOA));
  assert.equal(p.call('tell', W.simoa, 0, SIMOA, USER, TEA, bit(MIKA)), 1);
  const v = view(p, MIKA, USER, TEA);
  assert.deepEqual([v.cls, v.value, v.depth, v.auth], [CLS.TOLD, 1, 1, 1]);
});

await scenario('hearsay never replaces what was heard first-hand', async () => {
  const p = await world();
  p.call('userLine', W.user, 0, line('I hate tea'), -1, 0, bit(NERIS));
  p.call('userLine', W.user, 0, line('I love tea'), -1, 0, bit(MIKA));
  assert.equal(p.call('tell', W.neris, 0, NERIS, USER, TEA, bit(MIKA)), 0);
  assert.equal(view(p, MIKA, USER, TEA).value, 2);
});

await scenario('the user\'s word is never dropped for being old; an unconfirmed reading is', async () => {
  const p = await world();
  p.call('userLine', W.user, 0, line('I love storms'), -1, 0, bit(SIMOA));
  p.call('userLine', W.user, 0, line('Mika thinks I love tea'), TEA, 2, bit(SIMOA));
  for (let e = 0; e < 1000; e++) p.call('episode');
  assert.deepEqual([view(p, SIMOA, USER, STORMS).value, view(p, SIMOA, USER, STORMS).level], [2, 1]);
  assert.equal(view(p, SIMOA, USER, TEA), null);
});

await scenario('authority never rises along a retelling (min-caps)', async () => {
  const p = await world();
  p.call('userLine', W.user, 0, line('I love tea'), -1, 0, bit(SIMOA));
  assert.equal(view(p, SIMOA, USER, TEA).auth, 2);
  p.call('tell', W.simoa, 0, SIMOA, USER, TEA, bit(MIKA));
  p.call('tell', W.mika, 0, MIKA, USER, TEA, bit(NERIS));
  assert.deepEqual([view(p, MIKA, USER, TEA).auth, view(p, NERIS, USER, TEA).auth, view(p, NERIS, USER, TEA).depth], [1, 1, 2]);
});

console.log(JSON.stringify({ test: 'scenarios', result: 'pass', scenarios: results.length, names: results }, null, 1));
