// The verbatim gate: a user line is the user's word only if it is the statement word for word.
// C (WebAssembly), the JavaScript oracle and a regular-expression reference must agree.
import assert from 'node:assert/strict';
import { Pair, define, text, rng } from './lib.mjs';

const LABELS = [['storms', 'thunderstorms', 'thunder'], ['tea', 'green tea'], ['black coffee', 'coffee'],
  ['the archive', 'archives'], ["rock 'n' roll", 'rock-n-roll']];
const p = await Pair.create();
assert.equal(define(p, {
  persons: 3, traits: LABELS.length, labels: LABELS, names: ['Ana', 'Bo'],
  cores: [[1, 1, 1, 1, 1], [-2, -2, -2, -2, -2]], gives: [[1, 1, 1, 1, 1], [0, 0, 0, 0, 0]],
}), 0);

const VERBS = [['love', 2], ['like', 1], ['am undecided about', 0], ['do not like', -1], ["don't like", -1], ['hate', -2]];
const labelTrait = new Map();
LABELS.forEach((list, k) => list.forEach(l => labelTrait.set(l, k)));

// Reference written with regular expressions over the string form of the line.
function reference(line) {
  let s = line.replace(/’/g, "'").replace(/[A-Z]/g, c => c.toLowerCase());
  s = s.replace(/[ \t\n\r]+/g, ' ').replace(/^ /, '').replace(/ $/, '');
  s = s.replace(/[.!]+$/, '').replace(/ +$/, '');
  const m = /^i (love|like|am undecided about|do not like|don't like|hate) (.+)$/.exec(s);
  if (!m || !labelTrait.has(m[2])) return null;
  return { trait: labelTrait.get(m[2]), value: VERBS.find(([v]) => v === m[1])[1] };
}

let lines = 0, words = 0;
function check(line) {
  const bytes = text(line);
  const got = p.call('verbatim', bytes);
  const ref = reference(line);
  assert.deepEqual(got.result === 1 ? { trait: got.trait, value: got.value } : null, ref, JSON.stringify(line));
  lines++;
  if (ref) words++;
  return ref;
}

// Every statement, in many spellings that are still the statement.
const spellings = [s => s, s => s.toUpperCase(), s => s[0].toUpperCase() + s.slice(1), s => '  ' + s + '  ',
  s => s.replace(/ /g, '   '), s => s.replace(/ /g, '\t'), s => s + '.', s => s + '!', s => s + '!!!', s => s + '...',
  s => s + ' !', s => s + '.!.', s => '\n' + s + '\r\n', s => s.replace("'", '’')];
// And near misses that are not.
const misses = [s => s + '?', s => s + ',', s => 'Mika thinks ' + s, s => 'Well, ' + s, s => s + ' too',
  s => s + ', said nobody ever', s => s + ' :)', s => s.replace(/^i /, 'I really '), s => s.replace(/^i /, 'I used to '),
  s => s + 's', s => s.slice(0, -1), s => s.replace(/ /, '  x '), s => 'My brother says ' + s, s => s + ' and tea',
  s => s.replace(/^i/, 'we'), s => s.replace(/^i /, 'I don\'t really '), s => s.replace(/ /g, ' '),
  s => s + '…', s => s.replace(/e/, 'é')];

for (const [verb, value] of VERBS) {
  for (const [label, trait] of labelTrait) {
    const base = 'i ' + verb + ' ' + label;
    for (const f of spellings) {
      const r = check(f(base));
      if (f(base).includes('’') && !base.includes("'")) continue;
      assert.deepEqual(r, { trait, value }, 'should be the word: ' + JSON.stringify(f(base)));
    }
    for (const f of misses) assert.equal(check(f(base)), null, 'should not be the word: ' + JSON.stringify(f(base)));
  }
}

// The 10.15.0 reader stored each of these as the user's own stance at full authority.
for (const line of ['Mika thinks I love storms', 'My brother says I hate tea', 'I love storms, said nobody ever',
  'I used to love storms', 'I agree', 'I love rainy days', 'I really love storms', "I don't love tea"]) {
  assert.equal(check(line), null, line);
}
for (const [line, want] of [['I love storms!', { trait: 0, value: 2 }], ['i don’t like tea', { trait: 1, value: -1 }],
  ['I am undecided about the archive.', { trait: 3, value: 0 }], ["I hate rock 'n' roll", { trait: 4, value: -2 }]]) {
  assert.deepEqual(check(line), want, line);
}

// Each statement names exactly one trait and value: no two (verb, label) pairs spell the same line.
const seen = new Map();
for (const [verb] of VERBS) for (const label of labelTrait.keys()) {
  const s = 'i ' + verb + ' ' + label;
  assert.ok(!seen.has(s), 'two statements spell ' + s);
  seen.set(s, true);
}

// Random byte-level damage to statements: C and JS agree on every one (the reference needs text).
const r = rng(7);
let mutations = 0;
const statements = [...seen.keys()];
for (let i = 0; i < 40000; i++) {
  const b = Array.from(text(r.pick(statements)));
  const kind = r.int(4);
  if (kind === 0 && b.length) b[r.int(b.length)] ^= 1 << r.int(8);
  else if (kind === 1) b.splice(r.int(b.length + 1), 0, r.pick([32, 9, 46, 33, 63, 39, 0xe2, 0x80, 0x99, 65 + r.int(26), r.int(256)]));
  else if (kind === 2 && b.length) b.splice(r.int(b.length), 1);
  else b.push(...text(r.pick(['', '.', '!', ' ', '’', '?'])));
  p.call('verbatim', Uint8Array.from(b));
  mutations++;
}
// Lengths at and beyond the limit.
assert.equal(p.call('verbatim', new Uint8Array(512).fill(32)).result, 0);
assert.equal(p.call('verbatim', new Uint8Array(513).fill(32), 513).result, -1);
assert.equal(p.call('verbatim', new Uint8Array(0)).result, 0);

console.log(JSON.stringify({ test: 'verbatim', result: 'pass', lines, words, notWords: lines - words, mutations,
  statements: statements.length, implementations: ['C in WebAssembly', 'JavaScript oracle', 'regular-expression reference'] }));
