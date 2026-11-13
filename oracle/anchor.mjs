// Identity anchors: a storage rule for identity that cannot drift.
// Independent JavaScript implementation of the rule in docs/identity-anchors.md.
// No dependencies; runs in browsers and Node. It is meant to agree with src/anchor.c on every
// result, every journal head and every saved byte, and tests/ check that it does.
//
// It is written from the description, not translated from the C: views live in a Map, the
// verbatim check generates candidate statements instead of parsing, and the journal ring is an
// array. Integer arguments are coerced the way a WebAssembly call coerces them (ToInt32).

import { sha256 } from './sha256.mjs';

export const PERSONS = 8, TRAITS = 64, WRITERS = 16, TOKENS = 8, RING = 32, USED = 1024;
export const LABELS = 4, LABEL_MAX = 32, NAME_MAX = 24, LINE_MAX = 512, DEPTH_MAX = 7;
export const LEVEL_NEW = 8, LEVEL_REPEAT = 4, LEVEL_MAX = 16, LAPSE = 64, NONE = -128;
export const VIEW_BYTES = 32, WRITER_BYTES = 168;
// The largest file a store can save (see AN_FILE_MAX in src/anchor.h).
export const FILE_MAX = 92 + (1 + 32 * 16) + 64 * (1 + 4 * 33) + 7 * (2 + 24 + 3 * 64) + (1 + 16 * 168) +
  (2 + 1024 * 32) + (1 + 8 * 53) + (2 + 7 * 7 * 64 * 32) + 32;
export const CHANNEL = Object.freeze({ EXTERNAL: 0, AGENT: 1, USER: 2, TOOL: 3, SYSTEM: 4 });
export const NO_PERSONA = 255;
export const CLS = Object.freeze({ FIRST: 1, READ: 2, TOLD: 3 });
export const KIND = Object.freeze({ CONFIRM: 1, REDEFINE: 2, RECOVER: 3 });
export const LINE = Object.freeze({ WORD: 1, READING: 2, NOTHING: 3 });
export const E = Object.freeze({
  OK: 0, ARG: -1, STATE: -2, WRITER: -3, KEYSEQ: -4, CHARACTER: -5, NOTNOW: -6, SOURCE: -7,
  TOKEN: -8, DISTINCT: -9, DOOR: -10, DIGEST: -11, PROOF: -12, FULL: -13, LISTENERS: -14,
});
export const LOAD = Object.freeze({
  SHORT: -20, MAGIC: -21, DIGEST: -22, PARAM: -23, COUNTER: -24, JOURNAL: -25, TRAIT: -26,
  PERSON: -27, WRITER: -28, USED: -29, TOKEN: -30, VIEW: -31, LONG: -32,
});
export const OP = Object.freeze({
  INIT: 1, LABEL: 2, DEFINE: 3, SEAL: 4, INCEPT: 5, ROTATE: 6, RECOVER: 7, REVOKE: 8, EPISODE: 9,
  SAY: 10, TELL: 11, LINE: 12, CONFIRM: 13, REDEFINE: 14, ISSUE_CONFIRM: 15, ISSUE_REDEFINE: 16,
  ISSUE_RECOVER: 17, FORGET: 18,
});

const VERBS = [['love', 2], ['like', 1], ['am undecided about', 0], ['do not like', -1], ["don't like", -1], ['hate', -2]];

// ------------------------------------------------------------------- bytes

const ascii = s => Uint8Array.from(s, c => c.charCodeAt(0));
const i8 = v => (v << 24) >> 24;
const u8 = v => v & 255;
const u16le = v => [v & 255, (v >>> 8) & 255];
const u32le = v => [v & 255, (v >>> 8) & 255, (v >>> 16) & 255, (v >>>= 0) >>> 24];

function concat(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

function equal(a, b, n = Math.max(a.length, b.length)) {
  if (a.length < n || b.length < n) return false;
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return false;
  return true;
}

const isZero = a => { for (const x of a) if (x !== 0) return false; return true; };

// Fixed-size arguments are copied: the store never keeps a view of the caller's memory.
function need32(x, name) {
  if (!(x instanceof Uint8Array) || x.length !== 32) throw new TypeError(name + ' must be a Uint8Array(32)');
  return Uint8Array.from(x);
}

function need16(x, name) {
  if (!(x instanceof Uint8Array) || x.length !== 16) throw new TypeError(name + ' must be a Uint8Array(16)');
  return Uint8Array.from(x);
}

// Bytes [0, len) of a variable-length argument, when len is a valid length for it.
function prefix(bytes, len, max) {
  if (len < 0 || len > max) return null;
  if (!bytes || bytes.length < len) throw new TypeError('argument shorter than its length');
  return Uint8Array.from(bytes.subarray ? bytes.subarray(0, len) : bytes.slice(0, len));
}

function coreBytes(core, K) { return Int8Array.from({ length: K }, (_, k) => i8(core[k])); }
function giveBytes(give, K) { return Uint8Array.from({ length: K }, (_, k) => u8(give[k])); }

class Record {
  constructor(op) { this.b = [op, 0, 0, 0, 0]; }
  i32(v) { this.b.push(...u32le(v | 0)); return this; }
  raw(bytes) { for (const x of bytes) this.b.push(x & 255); return this; }
}

// ------------------------------------------------------------- pure rules

const nameValid = (n, len) => len >= 1 && len <= NAME_MAX && n !== null &&
  Array.prototype.every.call(n.subarray(0, len), c => c >= 0x20 && c !== 0x7f) && n[0] !== 32 && n[len - 1] !== 32;

const foldByte = c => (c >= 65 && c <= 90 ? c + 32 : c);
const namesEqual = (a, b) => a.length === b.length && a.every((c, i) => foldByte(c) === foldByte(b[i]));

function labelValid(t, len) {
  if (len < 1 || len > LABEL_MAX || t === null) return false;
  for (let i = 0; i < len; i++) {
    const c = t[i];
    const ok = (c >= 97 && c <= 122) || (c >= 48 && c <= 57) || c === 32 || c === 45 || c === 39;
    if (!ok) return false;
    if (c === 32 && (i === 0 || i === len - 1 || t[i - 1] === 32)) return false;
  }
  return true;
}

/** D(X,Y): the least total distance the two can ever be apart. */
export function distance(K, c1, g1, c2, g2) {
  let d = 0;
  for (let k = 0; k < K; k++) d += Math.max(0, Math.abs(c1[k] - c2[k]) - g1[k] - g2[k]);
  return d;
}

/** The expressed value of one trait, from the core, the give and first-hand voices. */
export function lean(core, give, values, levels, sigmaNum, sigmaDen, saturation, voicesMin) {
  const count = values.length;
  if (count > PERSONS - 1 || levels.length !== count) return NONE;
  // Only integers, as C's types allow.
  if (![core, give, sigmaNum, sigmaDen, saturation, voicesMin, ...values, ...levels].every(Number.isInteger)) return NONE;
  if (core < -2 || core > 2 || give < 0 || give > 2) return NONE;
  if (sigmaDen < 1 || sigmaDen > 100 || sigmaNum < 0 || sigmaNum > sigmaDen || saturation < 1 ||
      saturation > 64 || voicesMin < 2 || voicesMin > 7) return NONE;
  for (let i = 0; i < count; i++) {
    if (values[i] < -2 || values[i] > 2 || levels[i] < 1 || levels[i] > LEVEL_MAX) return NONE;
  }
  if (count < voicesMin) return core | 0;
  let S = 0, T = 0;
  for (let i = 0; i < count; i++) { S += levels[i]; T += levels[i] * values[i]; }
  // u = (1 - h) core + h mean, as U / D; rounded half away from zero; then held inside the band.
  const D = sigmaDen * saturation * S;
  const U = core * D + sigmaNum * Math.min(S, saturation) * (T - core * S);
  let r = Math.floor((2 * Math.abs(U) + D) / (2 * D));
  if (U < 0) r = -r;
  r = Math.max(core - give, Math.min(core + give, r));
  return Math.max(-2, Math.min(2, r)) | 0;
}

function normalize(line, len) {
  const out = [];
  let space = false;
  for (let i = 0; i < len; i++) {
    let c = line[i];
    if (c === 0xe2 && i + 2 < len && line[i + 1] === 0x80 && line[i + 2] === 0x99) { c = 39; i += 2; }
    else if (c === 9 || c === 10 || c === 13) c = 32;
    else c = foldByte(c);
    if (c === 32) { space = true; continue; }
    if (space && out.length > 0) out.push(32);
    space = false;
    out.push(c);
  }
  while (out.length && (out[out.length - 1] === 46 || out[out.length - 1] === 33)) out.pop();
  while (out.length && out[out.length - 1] === 32) out.pop();
  return out;
}

/** First 16 bytes of SHA-256 of a line: how a line is named everywhere in the store. */
export function lineId(line, len = line.length) {
  len |= 0;
  const bytes = prefix(line, len, LINE_MAX);
  return bytes === null ? null : sha256(bytes).slice(0, 16);
}

const writerIdOf = (channel, instance, root, persona, key0, next0, index) =>
  sha256(concat(ascii('anchor writer v1'), [channel, instance, root, persona], key0, next0, u32le(index)));

const confirmTarget = (trait, value, line) =>
  sha256(concat(ascii('anchor confirm v1'), [u8(trait), u8(value)], line));

// ------------------------------------------------------------------- store

export class AnchorStore {
  constructor() { this.#reset(); }

  #reset() {
    this.ready = false; this.sealed = false;
    this.n = 0; this.K = 0; this.sn = 0; this.sd = 0; this.sat = 0; this.m = 0; this.delta = 0;
    this.episodeNo = 0; this.events = 0; this.refused = 0; this.issued = 0;
    this.base = new Uint8Array(32); this.head = new Uint8Array(32); this.ring = [];
    this.labels = []; this.people = []; this.writers = []; this.used = []; this.tokens = [];
    this.views = new Map();
  }

  #blocked() {
    if (!this.ready) return E.STATE;
    if (this.events === 0xffffffff) return E.FULL;
    return 0;
  }

  #journal(record, result) {
    const r = result | 0;
    const b = record.b;
    b[1] = r & 255; b[2] = (r >>> 8) & 255; b[3] = (r >>> 16) & 255; b[4] = (r >>> 24) & 255;
    const d = sha256(Uint8Array.from(b));
    const entry = new Uint8Array(16);
    entry[0] = b[0];
    entry[1] = r & 255;
    entry.set(d.subarray(0, 14), 2);
    // Each entry is chained with its position, so a head kept elsewhere also fixes the count.
    if (this.ring.length === RING) this.base = sha256(concat(this.base, this.ring.shift(), u32le(this.events - RING + 1)));
    this.ring.push(entry);
    this.head = sha256(concat(this.head, entry, u32le(this.events + 1)));
    this.events = (this.events + 1) >>> 0;
    if (r < 0 && this.refused !== 0xffffffff) this.refused++;
    return r;
  }

  #isCompanion(p) { return p >= 1 && p < this.n; }
  #key(h, a, k) { return (h * PERSONS + a) * TRAITS + k; }
  #revokedMask() { let m = 0; this.writers.forEach((w, i) => { if (w.revoked) m |= 1 << i; }); return m; }
  #fallen(v, rm) { return (v.wset & rm) !== 0; }
  #stale(v, a) { return a !== 0 && v.corever !== this.people[a].version; }
  #live(v, a, rm) { return !this.#fallen(v, rm) && !this.#stale(v, a); }

  #labelTaken(t) { return this.labels.some(list => list.some(l => equal(l, t))); }

  #defValid(name, nameLen, core, give) {
    if (!nameValid(name, nameLen)) return false;
    for (let k = 0; k < this.K; k++) if (core[k] < -2 || core[k] > 2 || give[k] > 2) return false;
    return true;
  }

  #distinctDefinitions() {
    for (let p = 1; p < this.n; p++) for (let q = p + 1; q < this.n; q++) {
      const a = this.people[p], b = this.people[q];
      if (namesEqual(a.name, b.name)) return false;
      if (distance(this.K, a.core, a.give, b.core, b.give) < this.delta) return false;
    }
    return true;
  }

  #fingerprint(p, version, name, core, give) {
    return sha256(concat(ascii('anchor core v1'), [p, version, name.length], name, [this.K],
      Uint8Array.from(core, u8), Uint8Array.from(give)));
  }

  #snapshot(x, rm) {
    const person = this.people[x];
    for (let k = 0; k < this.K; k++) {
      const values = [], levels = [];
      for (let a = 0; a < this.n; a++) {
        if (a === x) continue;
        const v = this.views.get(this.#key(x, a, k));
        if (!v || v.cls !== CLS.FIRST || !this.#live(v, a, rm)) continue;
        values.push(v.value);
        levels.push(v.level);
      }
      person.expressed[k] = lean(person.core[k], person.give[k], values, levels, this.sn, this.sd, this.sat, this.m);
    }
  }

  #admit(rm, h, a, k, cls, value, depth, auth, wset, corever, line) {
    const key = this.#key(h, a, k);
    const v = this.views.get(key);
    const live = v !== undefined && this.#live(v, a, rm);
    if (live) {
      if (cls === CLS.READ && v.cls === CLS.FIRST) return 0;
      if (cls === CLS.TOLD && (v.cls !== CLS.TOLD || depth > v.depth)) return 0;
    }
    let level, keep, was, born;
    if (!live || v.cls !== cls) {
      level = LEVEL_NEW; keep = wset; was = NONE; born = this.episodeNo;
    } else if (v.value === value) {
      level = Math.min(LEVEL_MAX, v.level + LEVEL_REPEAT); keep = v.wset | wset; was = v.was; born = v.born;
    } else {
      level = LEVEL_NEW; keep = wset; was = cls === CLS.FIRST ? v.value : NONE; born = v.born;
    }
    this.views.set(key, {
      cls, value, depth, auth, level, corever, was, born, last: this.episodeNo,
      wset: keep & 0xffff, line: Uint8Array.from(line.subarray(0, 16)),
    });
    return 1;
  }

  #listenersOk(mask, exclude) {
    const m = mask >>> 0;
    const companions = ((1 << this.n) - 1) & ~1;
    return m !== 0 && (m & ~companions) === 0 && (m & exclude) === 0;
  }

  #writerOk(w, keyseq) {
    if (w < 0 || w >= this.writers.length || this.writers[w].revoked) return E.WRITER;
    if (keyseq !== this.writers[w].seq) return E.KEYSEQ;
    return E.OK;
  }

  #verbatim(line, len) {
    if (len < 0 || len > LINE_MAX) return null;
    const t = normalize(line, len);
    for (const [verb, value] of VERBS) {
      for (let k = 0; k < this.K; k++) {
        for (const label of this.labels[k]) {
          const candidate = concat(ascii('i ' + verb + ' '), label);
          if (equal(candidate, t)) return { trait: k, value };
        }
      }
    }
    return null;
  }

  #issue(kind, target) {
    if (this.issued === 0xffffffff) return { result: E.FULL, token: new Uint8Array(16) };
    const token = sha256(concat(ascii('anchor token v1'), [kind], target, this.head, u32le(this.issued))).slice(0, 16);
    if (this.tokens.some(t => equal(t.token, token))) return { result: E.FULL, token: new Uint8Array(16) };
    if (this.tokens.length === TOKENS) this.tokens.shift();
    this.tokens.push({ kind, issued: (this.events + 1) >>> 0, target: Uint8Array.from(target), token });
    this.issued = (this.issued + 1) >>> 0;
    return { result: E.OK, token: Uint8Array.from(token) };
  }

  #spend(kind, target, token) {
    const i = this.tokens.findIndex(t => equal(t.token, token));
    if (i < 0) return E.TOKEN;
    const [t] = this.tokens.splice(i, 1);
    return t.kind === kind && equal(t.target, target) && this.events - t.issued <= LAPSE ? E.OK : E.TOKEN;
  }

  #usedHas(d) { return this.used.some(u => equal(u, d)); }
  #freshPair(key, next) {
    return !isZero(key) && !isZero(next) && !equal(key, next) && !this.#usedHas(key) && !this.#usedHas(next);
  }
  #bindingOk(channel, persona) {
    if (channel === CHANNEL.USER) return persona === 0;
    if (channel === CHANNEL.AGENT) return this.#isCompanion(persona);
    return persona === NO_PERSONA;
  }

  #recoverTarget(w, key, next) {
    return sha256(concat(ascii('anchor recover v1'), w.id, u16le(w.seq), key, next));
  }

  // ------------------------------------------------------------ definition

  init(persons, traits, sigmaNum, sigmaDen, saturation, voicesMin, distinctMin) {
    persons |= 0; traits |= 0; sigmaNum |= 0; sigmaDen |= 0; saturation |= 0; voicesMin |= 0; distinctMin |= 0;
    // Invalid arguments change nothing; valid ones start a new, empty store.
    if (persons < 2 || persons > PERSONS || traits < 1 || traits > TRAITS || sigmaDen < 1 || sigmaDen > 100 ||
        sigmaNum < 0 || sigmaNum > sigmaDen || saturation < 1 || saturation > 64 || voicesMin < 2 ||
        voicesMin > 7 || distinctMin < 1 || distinctMin > 255) return E.ARG;
    this.#reset();
    Object.assign(this, { n: persons, K: traits, sn: sigmaNum, sd: sigmaDen, sat: saturation, m: voicesMin, delta: distinctMin });
    this.ready = true;
    this.base = sha256(ascii('anchor journal v1'));
    this.head = this.base.slice();
    this.labels = Array.from({ length: traits }, () => []);
    this.people = Array.from({ length: persons }, () => ({
      defined: false, version: 0, name: new Uint8Array(0), core: new Int8Array(traits),
      give: new Uint8Array(traits), expressed: new Int8Array(traits),
    }));
    const r = new Record(OP.INIT).i32(persons).i32(traits).i32(sigmaNum).i32(sigmaDen).i32(saturation)
      .i32(voicesMin).i32(distinctMin);
    return this.#journal(r, E.OK);
  }

  label(trait, label, len = label.length) {
    trait |= 0; len |= 0;
    const bytes = prefix(label, len, LABEL_MAX);
    const blocked = this.#blocked();
    if (blocked) return blocked;
    const r = new Record(OP.LABEL).i32(trait).i32(len);
    if (bytes) r.raw(bytes);
    if (this.sealed) return this.#journal(r, E.STATE);
    if (trait < 0 || trait >= this.K || !labelValid(bytes, len)) return this.#journal(r, E.ARG);
    if (this.labels[trait].length === LABELS) return this.#journal(r, E.FULL);
    if (this.#labelTaken(bytes)) return this.#journal(r, E.DISTINCT);
    this.labels[trait].push(bytes);
    return this.#journal(r, E.OK);
  }

  #definitionRecord(r, name, nameLen, core, give) {
    r.i32(nameLen);
    if (name) r.raw(name);
    r.raw(Uint8Array.from(core, u8));
    r.raw(give);
  }

  define(person, name, core, give, nameLen = name.length) {
    person |= 0; nameLen |= 0;
    const nm = prefix(name, nameLen, NAME_MAX);
    const blocked = this.#blocked();
    if (blocked) return blocked;
    const c = coreBytes(core, this.K), g = giveBytes(give, this.K);
    const r = new Record(OP.DEFINE).i32(person);
    this.#definitionRecord(r, nm, nameLen, c, g);
    if (this.sealed) return this.#journal(r, E.STATE);
    if (!this.#isCompanion(person)) return this.#journal(r, E.ARG);
    const p = this.people[person];
    if (p.defined) return this.#journal(r, E.STATE);
    if (!this.#defValid(nm, nameLen, c, g)) return this.#journal(r, E.ARG);
    Object.assign(p, { defined: true, version: 1, name: nm, core: c, give: g, expressed: Int8Array.from(c) });
    return this.#journal(r, E.OK);
  }

  seal() {
    const blocked = this.#blocked();
    if (blocked) return blocked;
    const r = new Record(OP.SEAL);
    if (this.sealed) return this.#journal(r, E.STATE);
    if (this.labels.some(l => l.length === 0)) return this.#journal(r, E.STATE);
    for (let p = 1; p < this.n; p++) if (!this.people[p].defined) return this.#journal(r, E.STATE);
    if (!this.#distinctDefinitions()) return this.#journal(r, E.DISTINCT);
    for (let p = 1; p < this.n; p++) this.#snapshot(p, 0);
    this.sealed = true;
    return this.#journal(r, E.OK);
  }

  // --------------------------------------------------------------- writers

  incept(channel, instance, root, persona, key, next) {
    channel |= 0; instance |= 0; root |= 0; persona |= 0;
    key = need32(key, 'key'); next = need32(next, 'next');
    const blocked = this.#blocked();
    if (blocked) return blocked;
    const r = new Record(OP.INCEPT).i32(channel).i32(instance).i32(root).i32(persona).raw(key).raw(next);
    if (!this.sealed) return this.#journal(r, E.STATE);
    if (channel < 0 || channel > CHANNEL.SYSTEM || instance < 0 || instance > 255 || root < 0 || root > 15 ||
        !this.#bindingOk(channel, persona)) return this.#journal(r, E.ARG);
    if (this.writers.some(w => w.channel === channel && w.instance === instance)) return this.#journal(r, E.DOOR);
    if (!this.#freshPair(key, next)) return this.#journal(r, E.DIGEST);
    if (this.writers.length === WRITERS || this.used.length + 2 > USED) return this.#journal(r, E.FULL);
    const index = this.writers.length;
    this.writers.push({
      channel, instance, root, persona, revoked: 0, recovered: 0, seq: 0,
      id: writerIdOf(channel, instance, root, persona, key, next, index),
      key: key.slice(), next: next.slice(), key0: key.slice(), next0: next.slice(),
    });
    this.used.push(key.slice(), next.slice());
    return this.#journal(r, index);
  }

  rotate(w, secret, key, next) {
    w |= 0;
    secret = need32(secret, 'secret'); key = need32(key, 'key'); next = need32(next, 'next');
    const blocked = this.#blocked();
    if (blocked) return blocked;
    const r = new Record(OP.ROTATE).i32(w).raw(secret).raw(key).raw(next);
    if (!this.sealed) return this.#journal(r, E.STATE);
    if (w < 0 || w >= this.writers.length || this.writers[w].revoked) return this.#journal(r, E.WRITER);
    const x = this.writers[w];
    if (!equal(sha256(secret), x.next)) return this.#journal(r, E.PROOF);
    if (x.seq === 0xffff) return this.#journal(r, E.FULL);
    if (!this.#freshPair(key, next)) return this.#journal(r, E.DIGEST);
    if (this.used.length + 2 > USED) return this.#journal(r, E.FULL);
    x.key = key.slice(); x.next = next.slice(); x.seq++;
    this.used.push(key.slice(), next.slice());
    return this.#journal(r, E.OK);
  }

  recover(w, key, next, token) {
    w |= 0;
    key = need32(key, 'key'); next = need32(next, 'next'); token = need16(token, 'token');
    const blocked = this.#blocked();
    if (blocked) return blocked;
    const r = new Record(OP.RECOVER).i32(w).raw(key).raw(next).raw(token);
    if (!this.sealed) return this.#journal(r, E.STATE);
    if (w < 0 || w >= this.writers.length || this.writers[w].revoked) return this.#journal(r, E.WRITER);
    const x = this.writers[w];
    const spent = this.#spend(KIND.RECOVER, this.#recoverTarget(x, key, next), token);
    if (spent) return this.#journal(r, spent);
    if (x.seq === 0xffff) return this.#journal(r, E.FULL);
    if (!this.#freshPair(key, next)) return this.#journal(r, E.DIGEST);
    if (this.used.length + 2 > USED) return this.#journal(r, E.FULL);
    x.key = key.slice(); x.next = next.slice(); x.seq++;
    if (x.recovered !== 255) x.recovered++;
    this.used.push(key.slice(), next.slice());
    return this.#journal(r, E.OK);
  }

  revoke(w) {
    w |= 0;
    const blocked = this.#blocked();
    if (blocked) return blocked;
    const r = new Record(OP.REVOKE).i32(w);
    if (!this.sealed) return this.#journal(r, E.STATE);
    if (w < 0 || w >= this.writers.length || this.writers[w].revoked) return this.#journal(r, E.WRITER);
    this.writers[w].revoked = 1;
    return this.#journal(r, E.OK);
  }

  // ---------------------------------------------------------- conversation

  episode() {
    const blocked = this.#blocked();
    if (blocked) return blocked;
    const r = new Record(OP.EPISODE);
    if (!this.sealed) return this.#journal(r, E.STATE);
    if (this.episodeNo !== 0xffff) this.episodeNo++;
    let dropped = 0;
    for (const [key, v] of this.views) {
      const about = Math.floor(key / TRAITS) % PERSONS;
      if (v.level > 1) v.level--;
      else if (!(v.cls === CLS.FIRST && about === 0)) { this.views.delete(key); dropped++; }
    }
    const rm = this.#revokedMask();
    for (let p = 1; p < this.n; p++) this.#snapshot(p, rm);
    return this.#journal(r, dropped);
  }

  say(w, keyseq, person, trait, value, listeners) {
    w |= 0; keyseq |= 0; person |= 0; trait |= 0; value |= 0; listeners |= 0;
    const blocked = this.#blocked();
    if (blocked) return blocked;
    const r = new Record(OP.SAY).i32(w).i32(keyseq).i32(person).i32(trait).i32(value).i32(listeners);
    if (!this.sealed) return this.#journal(r, E.STATE);
    const wr = this.#writerOk(w, keyseq);
    if (wr) return this.#journal(r, wr);
    if (!this.#isCompanion(person) || this.writers[w].persona !== person) return this.#journal(r, E.WRITER);
    if (trait < 0 || trait >= this.K || value < -2 || value > 2) return this.#journal(r, E.ARG);
    if (!this.#listenersOk(listeners, 1 << person)) return this.#journal(r, E.LISTENERS);
    const p = this.people[person];
    if (value < p.core[trait] - p.give[trait] || value > p.core[trait] + p.give[trait]) return this.#journal(r, E.CHARACTER);
    if (value !== p.expressed[trait]) return this.#journal(r, E.NOTNOW);
    const rm = this.#revokedMask();
    let n = 0;
    for (let h = 1; h < this.n; h++) {
      if (listeners & (1 << h)) n += this.#admit(rm, h, person, trait, CLS.FIRST, value, 0, 1, 1 << w, p.version, new Uint8Array(16));
    }
    return this.#journal(r, n);
  }

  tell(w, keyseq, teller, about, trait, listeners) {
    w |= 0; keyseq |= 0; teller |= 0; about |= 0; trait |= 0; listeners |= 0;
    const blocked = this.#blocked();
    if (blocked) return blocked;
    const r = new Record(OP.TELL).i32(w).i32(keyseq).i32(teller).i32(about).i32(trait).i32(listeners);
    if (!this.sealed) return this.#journal(r, E.STATE);
    const wr = this.#writerOk(w, keyseq);
    if (wr) return this.#journal(r, wr);
    if (!this.#isCompanion(teller) || this.writers[w].persona !== teller) return this.#journal(r, E.WRITER);
    if (about < 0 || about >= this.n || about === teller || trait < 0 || trait >= this.K) return this.#journal(r, E.ARG);
    if (!this.#listenersOk(listeners, (1 << teller) | (1 << about))) return this.#journal(r, E.LISTENERS);
    const rm = this.#revokedMask();
    const src = this.views.get(this.#key(teller, about, trait));
    if (!src || !this.#live(src, about, rm) || src.depth >= DEPTH_MAX) return this.#journal(r, E.SOURCE);
    const carried = { ...src, line: src.line.slice() };
    let n = 0;
    for (let h = 1; h < this.n; h++) {
      if (listeners & (1 << h)) {
        n += this.#admit(rm, h, about, trait, CLS.TOLD, carried.value, carried.depth + 1, Math.min(carried.auth, 1),
          carried.wset | (1 << w), carried.corever, carried.line);
      }
    }
    return this.#journal(r, n);
  }

  userLine(w, keyseq, line, hintTrait, hintValue, listeners, len = line.length) {
    w |= 0; keyseq |= 0; hintTrait |= 0; hintValue |= 0; listeners |= 0; len |= 0;
    const bytes = prefix(line, len, LINE_MAX);
    const blocked = this.#blocked();
    if (blocked) return blocked;
    const r = new Record(OP.LINE).i32(w).i32(keyseq).i32(len);
    if (bytes) r.raw(bytes);
    r.i32(hintTrait).i32(hintValue).i32(listeners);
    if (!this.sealed) return this.#journal(r, E.STATE);
    const wr = this.#writerOk(w, keyseq);
    if (wr) return this.#journal(r, wr);
    if (this.writers[w].persona !== 0) return this.#journal(r, E.WRITER);
    if (bytes === null) return this.#journal(r, E.ARG);
    if (!(hintTrait === -1 || (hintTrait >= 0 && hintTrait < this.K && hintValue >= -2 && hintValue <= 2))) {
      return this.#journal(r, E.ARG);
    }
    if (!this.#listenersOk(listeners, 1)) return this.#journal(r, E.LISTENERS);
    const id = sha256(bytes);
    const rm = this.#revokedMask();
    const word = this.#verbatim(bytes, len);
    let result;
    if (word) {
      for (let h = 1; h < this.n; h++) {
        if (listeners & (1 << h)) this.#admit(rm, h, 0, word.trait, CLS.FIRST, word.value, 0, 2, 1 << w, 0, id);
      }
      result = LINE.WORD;
    } else if (hintTrait >= 0) {
      for (let h = 1; h < this.n; h++) {
        if (listeners & (1 << h)) this.#admit(rm, h, 0, hintTrait, CLS.READ, hintValue, 0, 1, 1 << w, 0, id);
      }
      result = LINE.READING;
    } else {
      result = LINE.NOTHING;
    }
    return this.#journal(r, result);
  }

  confirm(w, keyseq, trait, value, line, token) {
    w |= 0; keyseq |= 0; trait |= 0; value |= 0;
    line = need16(line, 'line'); token = need16(token, 'token');
    const blocked = this.#blocked();
    if (blocked) return blocked;
    const r = new Record(OP.CONFIRM).i32(w).i32(keyseq).i32(trait).i32(value).raw(line).raw(token);
    if (!this.sealed) return this.#journal(r, E.STATE);
    const wr = this.#writerOk(w, keyseq);
    if (wr) return this.#journal(r, wr);
    if (this.writers[w].persona !== 0) return this.#journal(r, E.WRITER);
    if (trait < 0 || trait >= this.K || value < -2 || value > 2) return this.#journal(r, E.ARG);
    const spent = this.#spend(KIND.CONFIRM, confirmTarget(trait, value, line), token);
    if (spent) return this.#journal(r, spent);
    const rm = this.#revokedMask();
    let n = 0;
    for (let h = 1; h < this.n; h++) {
      const v = this.views.get(this.#key(h, 0, trait));
      if (v && v.cls === CLS.READ && v.value === value && equal(v.line, line) && this.#live(v, 0, rm)) {
        n += this.#admit(rm, h, 0, trait, CLS.FIRST, value, 0, 2, 1 << w, 0, line);
      }
    }
    return this.#journal(r, n);
  }

  redefine(w, keyseq, person, name, core, give, token, nameLen = name.length) {
    w |= 0; keyseq |= 0; person |= 0; nameLen |= 0;
    token = need16(token, 'token');
    const nm = prefix(name, nameLen, NAME_MAX);
    const blocked = this.#blocked();
    if (blocked) return blocked;
    const c = coreBytes(core, this.K), g = giveBytes(give, this.K);
    const r = new Record(OP.REDEFINE).i32(w).i32(keyseq).i32(person);
    this.#definitionRecord(r, nm, nameLen, c, g);
    r.raw(token);
    if (!this.sealed) return this.#journal(r, E.STATE);
    const wr = this.#writerOk(w, keyseq);
    if (wr) return this.#journal(r, wr);
    const ch = this.writers[w].channel;
    if (ch !== CHANNEL.USER && ch !== CHANNEL.SYSTEM) return this.#journal(r, E.WRITER);
    if (!this.#isCompanion(person) || !this.#defValid(nm, nameLen, c, g)) return this.#journal(r, E.ARG);
    const p = this.people[person];
    if (p.version === 255) return this.#journal(r, E.FULL);
    const spent = this.#spend(KIND.REDEFINE, this.#fingerprint(person, p.version + 1, nm, c, g), token);
    if (spent) return this.#journal(r, spent);
    for (let q = 1; q < this.n; q++) {
      if (q === person) continue;
      const o = this.people[q];
      if (namesEqual(nm, o.name) || distance(this.K, c, g, o.core, o.give) < this.delta) return this.#journal(r, E.DISTINCT);
    }
    Object.assign(p, { version: p.version + 1, name: nm, core: c, give: g });
    this.#snapshot(person, this.#revokedMask());
    return this.#journal(r, E.OK);
  }

  forget(holder, about, trait) {
    holder |= 0; about |= 0; trait |= 0;
    const blocked = this.#blocked();
    if (blocked) return blocked;
    const r = new Record(OP.FORGET).i32(holder).i32(about).i32(trait);
    if (!this.sealed) return this.#journal(r, E.STATE);
    if ((holder !== -1 && !this.#isCompanion(holder)) || (about !== -1 && (about < 0 || about >= this.n)) ||
        (trait !== -1 && (trait < 0 || trait >= this.K))) return this.#journal(r, E.ARG);
    let n = 0;
    for (const key of [...this.views.keys()]) {
      const k = key % TRAITS, a = Math.floor(key / TRAITS) % PERSONS, h = Math.floor(key / (TRAITS * PERSONS));
      if ((holder === -1 || h === holder) && (about === -1 || a === about) && (trait === -1 || k === trait)) {
        this.views.delete(key);
        n++;
      }
    }
    return this.#journal(r, n);
  }

  // --------------------------------------------------------------- consent

  issueConfirm(trait, value, line) {
    trait |= 0; value |= 0;
    line = need16(line, 'line');
    const blocked = this.#blocked();
    if (blocked) return { result: blocked, token: new Uint8Array(16) };
    const r = new Record(OP.ISSUE_CONFIRM).i32(trait).i32(value).raw(line);
    if (!this.sealed) return { result: this.#journal(r, E.STATE), token: new Uint8Array(16) };
    if (trait < 0 || trait >= this.K || value < -2 || value > 2) return { result: this.#journal(r, E.ARG), token: new Uint8Array(16) };
    const out = this.#issue(KIND.CONFIRM, confirmTarget(trait, value, line));
    return { result: this.#journal(r, out.result), token: out.token };
  }

  issueRedefine(person, name, core, give, nameLen = name.length) {
    person |= 0; nameLen |= 0;
    const nm = prefix(name, nameLen, NAME_MAX);
    const blocked = this.#blocked();
    if (blocked) return { result: blocked, token: new Uint8Array(16) };
    const c = coreBytes(core, this.K), g = giveBytes(give, this.K);
    const r = new Record(OP.ISSUE_REDEFINE).i32(person);
    this.#definitionRecord(r, nm, nameLen, c, g);
    if (!this.sealed) return { result: this.#journal(r, E.STATE), token: new Uint8Array(16) };
    if (!this.#isCompanion(person) || !this.#defValid(nm, nameLen, c, g)) return { result: this.#journal(r, E.ARG), token: new Uint8Array(16) };
    const p = this.people[person];
    if (p.version === 255) return { result: this.#journal(r, E.FULL), token: new Uint8Array(16) };
    const out = this.#issue(KIND.REDEFINE, this.#fingerprint(person, p.version + 1, nm, c, g));
    return { result: this.#journal(r, out.result), token: out.token };
  }

  issueRecover(w, key, next) {
    w |= 0;
    key = need32(key, 'key'); next = need32(next, 'next');
    const blocked = this.#blocked();
    if (blocked) return { result: blocked, token: new Uint8Array(16) };
    const r = new Record(OP.ISSUE_RECOVER).i32(w).raw(key).raw(next);
    if (!this.sealed) return { result: this.#journal(r, E.STATE), token: new Uint8Array(16) };
    if (w < 0 || w >= this.writers.length || this.writers[w].revoked) return { result: this.#journal(r, E.WRITER), token: new Uint8Array(16) };
    const out = this.#issue(KIND.RECOVER, this.#recoverTarget(this.writers[w], key, next));
    return { result: this.#journal(r, out.result), token: out.token };
  }

  // --------------------------------------------------------------- queries

  expressed(person, trait) {
    person |= 0; trait |= 0;
    if (!this.sealed || !this.#isCompanion(person) || trait < 0 || trait >= this.K) return NONE;
    return this.people[person].expressed[trait];
  }

  core(person, trait) {
    person |= 0; trait |= 0;
    if (!this.sealed || !this.#isCompanion(person) || trait < 0 || trait >= this.K) return NONE;
    return this.people[person].core[trait];
  }

  give(person, trait) {
    person |= 0; trait |= 0;
    if (!this.sealed || !this.#isCompanion(person) || trait < 0 || trait >= this.K) return NONE;
    return this.people[person].give[trait];
  }

  #viewBytes(h, a, k, v) {
    return Uint8Array.from([h, a, k, v.cls, v.depth, v.auth, v.level, v.corever, u8(v.value), u8(v.was),
      ...u16le(v.born), ...u16le(v.last), ...u16le(v.wset), ...v.line]);
  }

  viewGet(holder, about, trait) {
    holder |= 0; about |= 0; trait |= 0;
    const bytes = new Uint8Array(VIEW_BYTES + 2);
    if (!this.sealed || !this.#isCompanion(holder) || about < 0 || about >= this.n || about === holder ||
        trait < 0 || trait >= this.K) return { result: -1, bytes };
    const v = this.views.get(this.#key(holder, about, trait));
    if (!v) return { result: 0, bytes };
    bytes.set(this.#viewBytes(holder, about, trait, v));
    bytes[VIEW_BYTES] = this.#fallen(v, this.#revokedMask()) ? 1 : 0;
    bytes[VIEW_BYTES + 1] = this.#stale(v, about) ? 1 : 0;
    return { result: 1, bytes };
  }

  #writerBytes(w) {
    return concat([w.channel, w.instance, w.root, w.persona, w.revoked, w.recovered, ...u16le(w.seq)],
      w.id, w.key, w.next, w.key0, w.next0);
  }

  writerGet(w) {
    w |= 0;
    if (!this.sealed || w < 0 || w >= this.writers.length) return { result: 0, bytes: new Uint8Array(WRITER_BYTES) };
    return { result: 1, bytes: this.#writerBytes(this.writers[w]) };
  }

  fingerprint(person) {
    person |= 0;
    if (!this.sealed) return { result: E.STATE, bytes: new Uint8Array(32) };
    if (!this.#isCompanion(person)) return { result: E.ARG, bytes: new Uint8Array(32) };
    const p = this.people[person];
    return { result: E.OK, bytes: this.#fingerprint(person, p.version, p.name, p.core, p.give) };
  }

  definition() {
    if (!this.sealed) return { result: E.STATE, bytes: new Uint8Array(32) };
    const parts = [ascii('anchor definition v1'), [this.n, this.K, this.sn, this.sd, this.sat, this.m, this.delta]];
    for (const list of this.labels) {
      parts.push([list.length]);
      for (const l of list) parts.push([l.length], l);
    }
    for (let p = 1; p < this.n; p++) parts.push(this.fingerprint(p).bytes);
    return { result: E.OK, bytes: sha256(concat(...parts)) };
  }

  headBytes() {
    if (!this.ready) return { result: E.STATE, bytes: new Uint8Array(32) };
    return { result: E.OK, bytes: this.head.slice() };
  }

  info() {
    return [this.ready ? 1 : 0, this.sealed ? 1 : 0, this.n, this.K, this.episodeNo, this.events, this.refused,
      this.issued, this.writers.length, this.used.length, this.tokens.length, this.views.size];
  }

  distanceBetween(p, q) {
    p |= 0; q |= 0;
    if (!this.sealed || !this.#isCompanion(p) || !this.#isCompanion(q) || p === q) return -1;
    const a = this.people[p], b = this.people[q];
    return distance(this.K, a.core, a.give, b.core, b.give);
  }

  verbatim(line, len = line.length) {
    len |= 0;
    const bytes = prefix(line, len, LINE_MAX);
    if (!this.ready || len < 0 || len > LINE_MAX) return { result: -1, trait: -1, value: NONE };
    const word = this.#verbatim(bytes, len);
    return word ? { result: 1, trait: word.trait, value: word.value } : { result: 0, trait: -1, value: NONE };
  }

  // ----------------------------------------------------------- persistence

  #body() {
    const out = [];
    const B = v => out.push(v & 255);
    const all = bytes => { for (const x of bytes) out.push(x & 255); };
    all(ascii('ANCH')); all(u16le(1));
    all([this.n, this.K, this.sn, this.sd, this.sat, this.m, this.delta, 1]);
    all(u16le(this.episodeNo)); all(u32le(this.events)); all(u32le(this.refused)); all(u32le(this.issued));
    all(this.base); all(this.head);
    B(this.ring.length);
    for (const e of this.ring) all(e);
    for (const list of this.labels) {
      B(list.length);
      for (const l of list) { B(l.length); all(l); }
    }
    for (let p = 1; p < this.n; p++) {
      const x = this.people[p];
      B(x.version); B(x.name.length); all(x.name);
      all(Uint8Array.from(x.core, u8)); all(x.give); all(Uint8Array.from(x.expressed, u8));
    }
    B(this.writers.length);
    for (const w of this.writers) all(this.#writerBytes(w));
    all(u16le(this.used.length));
    for (const d of this.used) all(d);
    B(this.tokens.length);
    for (const t of this.tokens) { B(t.kind); all(u32le(t.issued)); all(t.target); all(t.token); }
    const keys = [...this.views.keys()].sort((x, y) => x - y);
    all(u16le(keys.length));
    for (const key of keys) {
      const k = key % TRAITS, a = Math.floor(key / TRAITS) % PERSONS, h = Math.floor(key / (TRAITS * PERSONS));
      all(this.#viewBytes(h, a, k, this.views.get(key)));
    }
    return Uint8Array.from(out);
  }

  saveSize() { return this.sealed ? this.#body().length + 32 : E.STATE; }

  save() {
    if (!this.sealed) return { result: E.STATE, bytes: new Uint8Array(0) };
    const body = this.#body();
    const bytes = concat(body, sha256(body));
    return { result: bytes.length, bytes };
  }

  /** Loads a saved store. Nothing in the file is taken on trust; on any refusal this store is unchanged. */
  load(bytes) {
    const result = AnchorStore.#parse(bytes);
    if (typeof result === 'number') return result;
    this.#reset();
    Object.assign(this, result);
    return E.OK;
  }

  static #parse(input) {
    if (input.length > FILE_MAX) return LOAD.LONG;
    const b = Uint8Array.from(input); // a copy: nothing loaded may alias the caller's buffer
    const len = b.length;
    if (len < 128) return LOAD.SHORT;
    if (b[0] !== 65 || b[1] !== 78 || b[2] !== 67 || b[3] !== 72 || b[4] !== 1 || b[5] !== 0) return LOAD.MAGIC;
    if (!equal(sha256(b.subarray(0, len - 32)), b.subarray(len - 32))) return LOAD.DIGEST;
    const end = len - 32;
    let p = 6;
    const has = k => k >= 0 && p + k <= end;
    const g8 = () => b[p++];
    const g16 = () => { const v = b[p] | (b[p + 1] << 8); p += 2; return v; };
    const g32 = () => { const v = (b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] << 24)) >>> 0; p += 4; return v; };
    const take = k => { const v = b.slice(p, p + k); p += k; return v; };
    const st = {};
    const n = g8(), K = g8(), sn = g8(), sd = g8(), sat = g8(), m = g8(), delta = g8();
    if (n < 2 || n > PERSONS || K < 1 || K > TRAITS || sd < 1 || sd > 100 || sn > sd || sat < 1 || sat > 64 ||
        m < 2 || m > 7 || delta < 1 || g8() !== 1) return LOAD.PARAM;
    Object.assign(st, { ready: true, sealed: true, n, K, sn, sd, sat, m, delta });
    st.episodeNo = g16(); st.events = g32(); st.refused = g32(); st.issued = g32();
    if (st.refused > st.events) return LOAD.COUNTER;
    st.base = take(32); st.head = take(32);
    if (!has(1)) return LOAD.SHORT;
    const rc = g8();
    if (rc !== Math.min(st.events, RING)) return LOAD.JOURNAL;
    if (!has(16 * rc)) return LOAD.SHORT;
    st.ring = [];
    let fold = st.base;
    for (let i = 0; i < rc; i++) {
      const e = take(16);
      st.ring.push(e);
      fold = sha256(concat(fold, e, u32le(st.events - rc + 1 + i)));
    }
    if (!equal(fold, st.head)) return LOAD.JOURNAL;
    st.labels = [];
    let labelCount = 0;
    for (let k = 0; k < K; k++) {
      if (!has(1)) return LOAD.SHORT;
      const c = g8();
      if (c < 1 || c > LABELS) return LOAD.TRAIT;
      const list = [];
      for (let j = 0; j < c; j++) {
        if (!has(1)) return LOAD.SHORT;
        const l = g8();
        if (l < 1 || l > LABEL_MAX) return LOAD.TRAIT;
        if (!has(l)) return LOAD.SHORT;
        const t = take(l);
        if (!labelValid(t, l) || st.labels.some(x => x.some(y => equal(y, t))) || list.some(y => equal(y, t))) return LOAD.TRAIT;
        list.push(t);
        labelCount++;
      }
      st.labels.push(list);
    }
    st.people = [{ defined: false, version: 0, name: new Uint8Array(0), core: new Int8Array(K), give: new Uint8Array(K), expressed: new Int8Array(K) }];
    // What she expresses is at most floor(4 sigma + 1/2) steps from her core, and is her core exactly
    // when she can never have voicesMin voices, or before any snapshot but the one at sealing.
    const reach = Math.floor((8 * sn + sd) / (2 * sd));
    let redefined = 0;
    for (let q = 1; q < n; q++) {
      if (!has(2)) return LOAD.SHORT;
      const version = g8(), nl = g8();
      if (version < 1 || nl < 1 || nl > NAME_MAX) return LOAD.PERSON;
      if (!has(nl)) return LOAD.SHORT;
      const name = take(nl);
      if (!nameValid(name, nl)) return LOAD.PERSON;
      if (!has(3 * K)) return LOAD.SHORT;
      const core = Int8Array.from(take(K), i8), give = take(K), expressed = Int8Array.from(take(K), i8);
      for (let k = 0; k < K; k++) {
        const lo = core[k] - give[k], hi = core[k] + give[k], e = expressed[k], step = Math.abs(e - core[k]);
        if (core[k] < -2 || core[k] > 2 || give[k] > 2 || e < lo || e > hi || e < -2 || e > 2) return LOAD.PERSON;
        if (step > reach || (step !== 0 && (n - 1 < m || (st.episodeNo === 0 && version === 1)))) return LOAD.PERSON;
      }
      st.people.push({ defined: true, version, name, core, give: Uint8Array.from(give), expressed });
      redefined += version - 1;
    }
    {
      const probe = new AnchorStore();
      Object.assign(probe, { n, K, delta, people: st.people });
      if (!probe.#distinctDefinitions()) return LOAD.PERSON;
    }
    if (!has(1)) return LOAD.SHORT;
    const wc = g8();
    if (wc > WRITERS) return LOAD.WRITER;
    st.writers = [];
    const isCompanion = q => q >= 1 && q < n;
    const bindingOk = (ch, persona) => (ch === CHANNEL.USER ? persona === 0 : ch === CHANNEL.AGENT ? isCompanion(persona) : persona === NO_PERSONA);
    let seqsum = 0, revoked = 0;
    for (let i = 0; i < wc; i++) {
      if (!has(WRITER_BYTES)) return LOAD.SHORT;
      const w = { channel: g8(), instance: g8(), root: g8(), persona: g8(), revoked: g8(), recovered: g8(), seq: g16() };
      w.id = take(32); w.key = take(32); w.next = take(32); w.key0 = take(32); w.next0 = take(32);
      if (w.channel > CHANNEL.SYSTEM || w.root > 15 || !bindingOk(w.channel, w.persona) || w.revoked > 1 ||
          w.recovered > w.seq) return LOAD.WRITER;
      if (isZero(w.key) || isZero(w.next) || isZero(w.key0) || isZero(w.next0) || equal(w.key, w.next) ||
          equal(w.key0, w.next0)) return LOAD.WRITER;
      if (w.seq === 0 ? !(equal(w.key, w.key0) && equal(w.next, w.next0)) : (equal(w.key, w.key0) || equal(w.next, w.next0))) {
        return LOAD.WRITER;
      }
      if (!equal(writerIdOf(w.channel, w.instance, w.root, w.persona, w.key0, w.next0, i), w.id)) return LOAD.WRITER;
      if (st.writers.some(x => x.channel === w.channel && x.instance === w.instance)) return LOAD.WRITER;
      seqsum += w.seq;
      revoked += w.revoked;
      st.writers.push(w);
    }
    const bound = [];
    for (const w of st.writers) {
      bound.push(w.key0, w.next0);
      if (w.seq > 0) bound.push(w.key, w.next);
    }
    for (let i = 0; i < bound.length; i++) for (let j = i + 1; j < bound.length; j++) {
      if (equal(bound[i], bound[j])) return LOAD.WRITER;
    }
    if (!has(2)) return LOAD.SHORT;
    const uc = g16();
    if (uc > USED || uc !== 2 * (wc + seqsum)) return LOAD.USED;
    if (!has(32 * uc)) return LOAD.SHORT;
    st.used = [];
    for (let i = 0; i < uc; i++) {
      const d = take(32);
      if (isZero(d) || st.used.some(x => equal(x, d))) return LOAD.USED;
      st.used.push(d);
    }
    const inUsed = d => st.used.some(x => equal(x, d));
    for (const w of st.writers) {
      if (!inUsed(w.key) || !inUsed(w.next) || !inUsed(w.key0) || !inUsed(w.next0)) return LOAD.USED;
    }
    // Each of these was an accepted journal entry.
    if (st.events - st.refused < 2 + labelCount + (n - 1) + wc + seqsum + revoked + redefined + st.issued + st.episodeNo) {
      return LOAD.COUNTER;
    }
    if (!has(1)) return LOAD.SHORT;
    const tc = g8();
    if (tc > TOKENS || tc > st.issued) return LOAD.TOKEN;
    st.tokens = [];
    for (let i = 0; i < tc; i++) {
      if (!has(53)) return LOAD.SHORT;
      const t = { kind: g8(), issued: g32(), target: take(32), token: take(16) };
      if (t.kind < KIND.CONFIRM || t.kind > KIND.RECOVER || t.issued > st.events ||
          (i > 0 && t.issued <= st.tokens[i - 1].issued)) return LOAD.TOKEN;
      if (st.tokens.some(x => equal(x.token, t.token))) return LOAD.TOKEN;
      st.tokens.push(t);
    }
    if (!has(2)) return LOAD.SHORT;
    const vc = g16();
    if (vc > (n - 1) * (n - 1) * K) return LOAD.VIEW;
    st.views = new Map();
    let prev = -1;
    for (let i = 0; i < vc; i++) {
      if (!has(VIEW_BYTES)) return LOAD.SHORT;
      const vb = take(VIEW_BYTES);
      const [h, a, k, cls, depth, auth, level, corever] = vb;
      const value = i8(vb[8]), was = i8(vb[9]);
      const born = vb[10] | (vb[11] << 8), last = vb[12] | (vb[13] << 8), wset = vb[14] | (vb[15] << 8);
      const line = vb.slice(16, 32);
      if (!isCompanion(h) || a >= n || a === h || k >= K) return LOAD.VIEW;
      const key = (h * PERSONS + a) * TRAITS + k;
      if (key <= prev) return LOAD.VIEW;
      prev = key;
      if (cls < CLS.FIRST || cls > CLS.TOLD || value < -2 || value > 2 || level < 1 || level > LEVEL_MAX ||
          born > last || last > st.episodeNo) return LOAD.VIEW;
      if (was !== NONE && !(cls === CLS.FIRST && was >= -2 && was <= 2 && was !== value)) return LOAD.VIEW;
      // A level falls by one each episode since it was last renewed; only the user's word stops at 1.
      const ceiling = LEVEL_MAX - (st.episodeNo - last);
      if (cls === CLS.FIRST && a === 0 ? level > 1 && level > ceiling : level > ceiling) return LOAD.VIEW;
      if (wset === 0 || (wset >> wc) !== 0) return LOAD.VIEW;
      const writersIn = st.writers.filter((_, i2) => (wset >> i2) & 1);
      if (cls === CLS.FIRST) {
        if (depth !== 0 || auth !== (a === 0 ? 2 : 1) || writersIn.some(w => w.persona !== a)) return LOAD.VIEW;
      } else if (cls === CLS.READ) {
        if (a !== 0 || depth !== 0 || auth !== 1 || writersIn.some(w => w.persona !== 0)) return LOAD.VIEW;
      } else if (depth < 1 || depth > DEPTH_MAX || auth !== 1) {
        return LOAD.VIEW;
      }
      if (a === 0 ? corever !== 0 || isZero(line) : corever < 1 || corever > st.people[a].version || !isZero(line)) {
        return LOAD.VIEW;
      }
      if (a !== 0 && corever === st.people[a].version) {
        const x = st.people[a];
        if (value < x.core[k] - x.give[k] || value > x.core[k] + x.give[k]) return LOAD.VIEW;
      }
      st.views.set(key, { cls, value, depth, auth, level, corever, was, born, last, wset, line });
    }
    if (p !== end) return LOAD.SHORT;
    return st;
  }
}
