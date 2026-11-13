// Every single-bit change to one saved file, loaded by C (WebAssembly) and by JavaScript.
// As they are: all must be refused. With the trailing digest recomputed: each is refused or accepted
// by both implementations alike, and accepted ones are listed by the field they fell in, so it is
// plain which fields only the digest binds.
import assert from 'node:assert/strict';
import { Pair, define, text, bytes32, secret, hex, sha, giveOf } from './lib.mjs';

const TOPICS = [['storms', ['storms', 'thunderstorms'], [-1, -2, 2]], ['tea', ['tea'], [0, 1, 2]], ['dancing', ['dancing'], [-1, 2, 1]]];
const p = await Pair.create();
assert.equal(define(p, { persons: 4, traits: 3, labels: TOPICS.map(t => t[1]), names: ['Simoa', 'Mika', 'Neris'],
  cores: [0, 1, 2].map(i => TOPICS.map(t => t[2][i])), gives: [0, 1, 2].map(i => TOPICS.map(t => giveOf(t[2][i]))) }), 0);
[[2, 0, 0, 0], [1, 1, 1, 1], [1, 2, 1, 2], [1, 3, 1, 3], [4, 0, 2, 255]].forEach(([ch, inst, rt, persona], i) =>
  assert.equal(p.call('incept', ch, inst, rt, persona, bytes32('key', i), secret(i).commit), i));
// A small history that leaves every kind of record in the file.
p.call('userLine', 0, 0, text('I love storms'), -1, 0, 0b1110);
p.call('userLine', 0, 0, text('Mika thinks I love tea'), 1, 2, 0b1110);
p.call('say', 2, 0, 2, 0, -2, 0b1010);
p.call('say', 3, 0, 3, 0, 2, 0b0110);
p.call('episode');
p.call('say', 1, 0, 1, 0, p.j.expressed(1, 0), 0b1100);
p.call('tell', 1, 0, 1, 2, 0, 0b1000);
p.call('tell', 2, 0, 2, 0, 0, 0b0010);
assert.equal(p.call('rotate', 2, secret(2).secret, bytes32('key', 22), secret(22).commit), 0);
const t = p.call('issueRecover', 3, bytes32('key', 33), secret(33).commit);
assert.equal(p.call('recover', 3, bytes32('key', 33), secret(33).commit, t.token), 0);
p.call('issueConfirm', 1, 2, sha(text('Mika thinks I love tea')).slice(0, 16));
p.call('say', 1, 0, 1, 0, 0, 0b0010);
const bytes = p.save();

// The file's fields, from the layout in docs/identity-anchors.md.
function fields(b) {
  const out = [];
  let at = 0;
  const add = (name, n) => { out.push([name, at, at + n]); at += n; };
  add('magic and format', 6); add('parameters', 8); add('counters', 14); add('journal base and head', 64);
  add('journal ring count', 1); add('journal ring', 16 * b[at - 1 + 0]);
  for (let k = 0; k < 3; k++) { const c = b[at]; add('trait label count', 1); for (let j = 0; j < c; j++) { const l = b[at]; add('trait label', 1 + l); } }
  for (let q = 1; q < 4; q++) { const nl = b[at + 1]; add('person version and name', 2 + nl); add('core', 3); add('give', 3); add('expressed', 3); }
  const wc = b[at]; add('writer count', 1);
  for (let i = 0; i < wc; i++) { add('writer door and status', 6); add('writer key sequence', 2); add('writer id', 32); add('writer current key', 32); add('writer next commitment', 32); add('writer first key', 32); add('writer first commitment', 32); }
  const uc = b[at] | (b[at + 1] << 8); add('bound digest count', 2);
  for (let i = 0; i < uc; i++) add('bound digest', 32);
  const tc = b[at]; add('token count', 1);
  for (let i = 0; i < tc; i++) { add('token kind and time', 5); add('token target', 32); add('token value', 16); }
  const vc = b[at] | (b[at + 1] << 8); add('view count', 2);
  for (let i = 0; i < vc; i++) { add('view place', 3); add('view class, depth, authority', 3); add('view level', 1); add('view core version', 1); add('view value', 1); add('view before', 1); add('view episodes', 4); add('view writers', 2); add('view line', 16); }
  add('trailing digest', 32);
  assert.equal(at, b.length, 'field map covers the file');
  return out;
}
const map = fields(bytes);
const fieldOf = i => map.find(([, a, b]) => i >= a && i < b)[0];

const c = (await Pair.create()).c, j = (await Pair.create()).j;
let flips = 0, refusedAsIs = 0, refusedRecomputed = 0;
const acceptedBy = {}, codes = {};
for (let i = 0; i < bytes.length; i++) {
  for (let bit = 0; bit < 8; bit++) {
    const b = bytes.slice();
    b[i] ^= 1 << bit;
    flips++;
    const a1 = c.load(b), a2 = j.load(b);
    assert.equal(a1, a2, 'C and JS disagree on a flip at byte ' + i);
    assert.ok(a1 < 0, 'a changed file was accepted as it is');
    refusedAsIs++;
    if (i >= bytes.length - 32) continue;
    b.set(sha(b.subarray(0, b.length - 32)), b.length - 32);
    const r1 = c.load(b), r2 = j.load(b);
    assert.equal(r1, r2, 'C and JS disagree with the digest recomputed, byte ' + i + ' (' + fieldOf(i) + ')');
    codes[r1] = (codes[r1] || 0) + 1;
    if (r1 < 0) refusedRecomputed++;
    else {
      const f = fieldOf(i);
      acceptedBy[f] = (acceptedBy[f] || 0) + 1;
      // An accepted file is a valid store: it saves back to exactly the bytes that were loaded.
      assert.equal(hex(c.save().bytes), hex(b));
      assert.equal(hex(j.save().bytes), hex(b));
    }
  }
}
const recomputed = flips - 256;
console.log(JSON.stringify({ test: 'bit flips', result: 'pass', fileBytes: bytes.length, flips, refusedAsIs,
  withDigestRecomputed: recomputed, refusedWithDigestRecomputed: refusedRecomputed, acceptedWithDigestRecomputed: recomputed - refusedRecomputed,
  acceptedByField: acceptedBy, refusalCodes: codes }, null, 1));
