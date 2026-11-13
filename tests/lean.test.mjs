// The lean rule, exhaustively over small cases: C (WebAssembly), the JavaScript oracle, and a third
// implementation in exact rational arithmetic must agree, and the rule's properties must hold:
// the band, two voices, oddness, order of voices, monotonicity, sigma = 0 and the one-step bound.
import assert from 'node:assert/strict';
import { WasmAnchorStore } from '../host/anchor-wasm.mjs';
import { lean } from '../oracle/anchor.mjs';
import { wasmModule } from './lib.mjs';

const c = await WasmAnchorStore.create(wasmModule);

// Reference in exact fractions: h = sigma * min(S, sat) / sat, mean = T / S,
// u = (1 - h) * core + h * mean, rounded half away from zero, then held to [core - give, core + give].
function reference(core, give, values, levels, sn, sd, sat, m) {
  if (values.length < m) return core;
  let S = 0n, T = 0n;
  values.forEach((v, i) => { S += BigInt(levels[i]); T += BigInt(levels[i]) * BigInt(v); });
  const frac = (n, d) => { const g = gcd(n, d) || 1n; return [n / g, d / g]; };
  const gcd = (a, b) => (b === 0n ? (a < 0n ? -a : a) : gcd(b, a % b));
  const x = S < BigInt(sat) ? S : BigInt(sat);
  const [hn, hd] = frac(BigInt(sn) * x, BigInt(sd) * BigInt(sat));          // h
  const [mn, md] = frac(T, S);                                                // mean
  // u = core + h * (mean - core) = core + hn*(mn - core*md) / (hd*md)
  const [dn, dd] = frac(hn * (mn - BigInt(core) * md), hd * md);
  const [un, ud] = frac(BigInt(core) * dd + dn, dd);
  const neg = un < 0n, a = neg ? -un : un;
  let q = a / ud;
  if (2n * (a - q * ud) >= ud) q += 1n;
  const r = Number(neg ? -q : q);
  return Math.max(-2, Math.min(2, Math.max(core - give, Math.min(core + give, r))));
}

const params = [[3, 10, 16, 2], [1, 1, 16, 2], [1, 2, 1, 2], [3, 10, 64, 3], [0, 1, 16, 2], [7, 10, 8, 2], [1, 1, 1, 2]];
const allValues = [-2, -1, 0, 1, 2];
const allLevels = Array.from({ length: 16 }, (_, i) => i + 1);

function* voiceSets() {
  yield [[], []];
  for (const v of allValues) for (const l of allLevels) yield [[v], [l]];
  for (const v1 of allValues) for (const l1 of allLevels) for (const v2 of allValues) for (const l2 of allLevels) yield [[v1, v2], [l1, l2]];
  const few = [1, 5, 16];
  for (const v1 of allValues) for (const l1 of few) for (const v2 of allValues) for (const l2 of few) for (const v3 of allValues) for (const l3 of few) {
    yield [[v1, v2, v3], [l1, l2, l3]];
  }
}

let cases = 0, oddness = 0, monotoneVoice = 0, monotoneCore = 0, permutations = 0;
for (const [sn, sd, sat, m] of params) {
  for (let core = -2; core <= 2; core++) {
    for (let give = 0; give <= 2; give++) {
      for (const [values, levels] of voiceSets()) {
        const e = lean(core, give, values, levels, sn, sd, sat, m);
        assert.equal(c.lean(core, give, values, levels, sn, sd, sat, m), e, 'C and JS differ');
        assert.equal(reference(core, give, values, levels, sn, sd, sat, m), e, 'reference differs');
        cases++;
        // A1: inside the band, inside the scale.
        assert.ok(Math.abs(e - core) <= give && e >= -2 && e <= 2);
        // Fewer than m first-hand voices: the core, exactly.
        if (values.length < m) assert.equal(e, core);
        // sigma = 0, or every voice at the core: the core.
        if (sn === 0 || values.every(v => v === core)) assert.equal(e, core);
        // With sigma <= 3/10 she never moves more than one step, whatever her give.
        if (sn * 10 <= 3 * sd) assert.ok(Math.abs(e - core) <= 1);
        // Oddness: negating the core and every voice negates the result.
        assert.equal(lean(0 - core, give, values.map(v => 0 - v), levels, sn, sd, sat, m), 0 - e);
        oddness++;
        // Order of voices does not matter.
        if (values.length >= 2) {
          const rev = lean(core, give, [...values].reverse(), [...levels].reverse(), sn, sd, sat, m);
          assert.equal(rev, e);
          permutations++;
        }
        // Raising one voice never lowers her.
        for (let i = 0; i < values.length; i++) {
          if (values[i] === 2) continue;
          const up = values.slice();
          up[i]++;
          assert.ok(lean(core, give, up, levels, sn, sd, sat, m) >= e);
          monotoneVoice++;
        }
        // Raising the core never lowers her.
        if (core < 2) {
          assert.ok(lean(core + 1, give, values, levels, sn, sd, sat, m) >= e);
          monotoneCore++;
        }
      }
    }
  }
}
// Invalid inputs are refused the same way.
for (const bad of [[3, 0, [], []], [0, 3, [], []], [0, 0, [3, 0], [1, 1]], [0, 0, [0, 0], [0, 1]], [0, 0, [0, 0], [17, 1]]]) {
  assert.equal(c.lean(bad[0], bad[1], bad[2], bad[3], 3, 10, 16, 2), -128);
  assert.equal(lean(bad[0], bad[1], bad[2], bad[3], 3, 10, 16, 2), -128);
}
console.log(JSON.stringify({ test: 'lean', result: 'pass', cases, parameterSets: params.length, oddness, permutations,
  monotoneInVoice: monotoneVoice, monotoneInCore: monotoneCore,
  coverage: 'core -2..2, give 0..2, 0-2 voices with every value and every level 1..16, 3 voices with levels {1,5,16}' }));
