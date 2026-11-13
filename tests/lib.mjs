// Shared test support: run the C build (through WebAssembly) and the JavaScript oracle in
// lockstep, comparing every result and the journal head after every call.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import { AnchorStore } from '../oracle/anchor.mjs';
import { compileAnchor, WasmAnchorStore } from '../host/anchor-wasm.mjs';

export const root = new URL('../', import.meta.url);
export const wasmBytes = readFileSync(new URL('dist/anchor.wasm', root));
export const wasmModule = await compileAnchor(wasmBytes);

export const hex = b => Buffer.from(b).toString('hex');
export const sha = b => new Uint8Array(createHash('sha256').update(b).digest());
export const text = s => new TextEncoder().encode(s);

/** Deterministic 32-byte value number i in a family f (never all zero). */
export function bytes32(f, i) {
  return sha(text('anchor-test|' + f + '|' + i));
}

/** A rotation secret and the commitment that it opens. */
export function secret(i) { const s = bytes32('secret', i); return { secret: s, commit: sha(s) }; }

/** Small seeded generator (xorshift32), identical everywhere it is used. */
export function rng(seed) {
  let x = seed >>> 0 || 1;
  const next = () => { x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0; return x; };
  const r = () => next() / 4294967296;
  r.int = n => next() % n;
  r.pick = list => list[next() % list.length];
  return r;
}

const plain = v => {
  if (v instanceof Uint8Array) return 'b:' + hex(v);
  if (Array.isArray(v)) return v.map(plain);
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, plain(x)]));
  return v;
};

/** A C store and an oracle store driven together. Every call is checked for agreement. */
export class Pair {
  static async create() {
    const p = new Pair();
    p.c = await WasmAnchorStore.create(wasmModule);
    p.j = new AnchorStore();
    p.calls = 0;
    return p;
  }

  call(name, ...args) {
    const a = this.c[name](...args);
    const b = this.j[name](...args);
    this.calls++;
    const pa = plain(a), pb = plain(b);
    try {
      assert.deepEqual(pa, pb);
      assert.equal(hex(this.c.headBytes().bytes), hex(this.j.headBytes().bytes));
    } catch (e) {
      e.message = 'C and JavaScript disagree on ' + name + '(' + JSON.stringify(plain(args)) + '): C=' +
        JSON.stringify(pa) + ' JS=' + JSON.stringify(pb) + '\n' + e.message;
      throw e;
    }
    return a;
  }

  /** Saved bytes from both; they must be identical. */
  save() {
    const a = this.c.save(), b = this.j.save();
    assert.equal(a.result, b.result, 'save result');
    assert.equal(hex(a.bytes), hex(b.bytes), 'saved bytes differ');
    return a.bytes;
  }
}

/** Defines a store: n persons (user + n-1 companions), the given traits and cores. */
export function define(p, { persons, traits, labels, names, cores, gives, sn = 3, sd = 10, sat = 16, m = 2, delta = 1 }) {
  assert.equal(p.call('init', persons, traits, sn, sd, sat, m, delta), 0);
  for (let k = 0; k < traits; k++) for (const l of labels[k]) assert.equal(p.call('label', k, text(l)), 0, 'label ' + l);
  for (let q = 1; q < persons; q++) assert.equal(p.call('define', q, text(names[q - 1]), cores[q - 1], gives[q - 1]), 0);
  return p.call('seal');
}

export const giveOf = c => (Math.abs(c) === 2 ? 0 : 1);
