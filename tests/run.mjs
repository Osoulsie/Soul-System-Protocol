// Runs every suite and writes tests/RESULTS.json: what ran, on what, and what each suite reported.
// Usage: node tests/run.mjs            (expects ./build.sh to have been run)
//        SKIP_NATIVE=1 node tests/run.mjs   (when no C compiler is available)
import { spawnSync, execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';

const root = new URL('../', import.meta.url);
const path = p => new URL(p, root).pathname;
const suites = ['sha256', 'lean', 'verbatim', 'scenarios', 'hardening', 'simoa', 'differential', 'bitflip', 'small'];
const version = (cmd, args) => { try { return execFileSync(cmd, args, { encoding: 'utf8' }).split('\n')[0].trim(); } catch { return null; } };
const record = {
  date: new Date().toISOString().slice(0, 10),
  node: process.version,
  clang: version('clang', ['--version']),
  gcc: version('gcc', ['--version']),
  wasmSha256: createHash('sha256').update(readFileSync(path('dist/anchor.wasm'))).digest('hex'),
  wasmBytes: readFileSync(path('dist/anchor.wasm')).length,
  suites: {},
};
let failed = 0;
const json = out => { const at = out.indexOf('{'); return at >= 0 ? JSON.parse(out.slice(at)) : null; };

if (!process.env.SKIP_NATIVE) {
  if (!existsSync(path('build/native-test'))) { console.error('build/native-test missing: run ./build.sh'); process.exit(1); }
  const t = Date.now();
  const r = spawnSync(path('build/native-test'), { encoding: 'utf8' });
  const ok = r.status === 0;
  record.suites.native = { result: ok ? 'pass' : 'fail', seconds: (Date.now() - t) / 1000, sanitizers: 'address,undefined',
    report: r.stdout.trim().split('\n') };
  console.log((ok ? 'pass ' : 'FAIL ') + 'native (' + record.suites.native.seconds + ' s)');
  if (!ok) { failed++; console.error(r.stderr.slice(0, 4000)); }
}
for (const name of suites) {
  const t = Date.now();
  const r = spawnSync(process.execPath, [path('tests/' + name + '.test.mjs')], { encoding: 'utf8', env: process.env, maxBuffer: 1 << 26 });
  const ok = r.status === 0;
  record.suites[name] = { ...(ok ? json(r.stdout) : { result: 'fail', error: r.stderr.slice(0, 4000) }), seconds: (Date.now() - t) / 1000 };
  console.log((ok ? 'pass ' : 'FAIL ') + name + ' (' + record.suites[name].seconds + ' s)');
  if (!ok) { failed++; console.error(r.stderr.slice(0, 4000)); }
}
record.result = failed ? 'fail' : 'pass';
writeFileSync(path('tests/RESULTS.json'), JSON.stringify(record, null, 1) + '\n');
console.log(failed ? failed + ' suite(s) failed' : 'all suites passed; tests/RESULTS.json written');
process.exit(failed ? 1 : 0);
