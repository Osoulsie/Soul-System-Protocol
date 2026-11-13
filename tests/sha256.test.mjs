// SHA-256 three ways: the C code inside dist/anchor.wasm, the JavaScript oracle, and node:crypto.
import assert from 'node:assert/strict';
import { WasmAnchorStore } from '../host/anchor-wasm.mjs';
import { sha256 as jsSha } from '../oracle/sha256.mjs';
import { wasmModule, hex, sha, text, rng } from './lib.mjs';

const c = await WasmAnchorStore.create(wasmModule);
const check = (m, label) => {
  const want = hex(sha(m));
  assert.equal(hex(c.sha256(m)), want, 'C: ' + label);
  assert.equal(hex(jsSha(m)), want, 'JS: ' + label);
};

const known = [
  ['', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
  ['abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
  ['abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq', '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'],
  ['abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu',
    'cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1'],
];
for (const [m, want] of known) {
  assert.equal(hex(c.sha256(text(m))), want);
  assert.equal(hex(jsSha(text(m))), want);
}

const r = rng(20261113);
let messages = 0;
for (let len = 0; len <= 1100; len++) {
  for (let i = 0; i < 3; i++) {
    const m = Uint8Array.from({ length: len }, () => r.int(256));
    check(m, 'random length ' + len);
    messages++;
  }
}
for (const len of [65535, 65536, 65537, 131072, 200000]) {
  const m = Uint8Array.from({ length: len }, () => r.int(256));
  check(m, 'large length ' + len);
  messages++;
}
console.log(JSON.stringify({ test: 'sha256', result: 'pass', knownAnswers: known.length, randomMessages: messages,
  lengths: '0..1100 (3 each) and 5 lengths up to 200,000 bytes', implementations: ['C in WebAssembly', 'JavaScript oracle', 'node:crypto'] }));
