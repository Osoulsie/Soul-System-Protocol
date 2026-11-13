// Binding for dist/anchor.wasm with the same interface as oracle/anchor.mjs.
// Each WasmAnchorStore is its own WebAssembly instance, so stores never share memory.
// The module imports nothing; this binding only copies bytes in and out of its scratch area.

const A = 0, B = 4096, C = 8192, D = 12288, OUT = 16384;

export async function compileAnchor(bytes) {
  const module = await WebAssembly.compile(bytes);
  if (WebAssembly.Module.imports(module).length !== 0) throw new Error('anchor.wasm must import nothing');
  return module;
}

export class WasmAnchorStore {
  static async create(module) {
    const instance = await WebAssembly.instantiate(module, {});
    return new WasmAnchorStore(instance);
  }

  constructor(instance) {
    this.x = instance.exports;
    this.s = this.x.an_global();
    this.base = this.x.an_scratch();
    this.size = this.x.an_scratch_size();
  }

  #bytes() { return new Uint8Array(this.x.memory.buffer); }

  // Copies the bytes C will read: all of them when 0 <= len <= max, none otherwise.
  #put(at, bytes, len, max) {
    if (len >= 0 && len <= max) {
      if (!bytes || bytes.length < len) throw new TypeError('argument shorter than its length');
      this.#bytes().set(bytes.subarray ? bytes.subarray(0, len) : bytes.slice(0, len), this.base + at);
    }
    return this.base + at;
  }

  #fixed(at, bytes, n) {
    if (!(bytes instanceof Uint8Array) || bytes.length !== n) throw new TypeError('expected Uint8Array(' + n + ')');
    this.#bytes().set(bytes, this.base + at);
    return this.base + at;
  }

  // Per-trait bytes. C reads exactly K of them; entries past the array are 0, as in the oracle.
  #traitBytes(at, values, signed) {
    const out = new Uint8Array(64);
    for (let k = 0; k < 64 && k < values.length; k++) out[k] = (signed ? (values[k] << 24) >> 24 : values[k]) & 255;
    this.#bytes().set(out, this.base + at);
    return this.base + at;
  }

  #infoPtr() { return this.base + OUT + 4096; }
  #out(n) { return this.#bytes().slice(this.base + OUT, this.base + OUT + n); }

  init(persons, traits, sn, sd, sat, m, delta) { return this.x.an_init(this.s, persons, traits, sn, sd, sat, m, delta); }
  label(trait, label, len = label.length) { return this.x.an_label(this.s, trait, this.#put(A, label, len | 0, 32), len); }
  define(person, name, core, give, nameLen = name.length) {
    return this.x.an_define(this.s, person, this.#put(A, name, nameLen | 0, 24), nameLen, this.#traitBytes(B, core, true), this.#traitBytes(C, give, false));
  }
  seal() { return this.x.an_seal(this.s); }

  incept(channel, instance, root, persona, key, next) {
    return this.x.an_incept(this.s, channel, instance, root, persona, this.#fixed(A, key, 32), this.#fixed(B, next, 32));
  }
  rotate(w, secret, key, next) {
    return this.x.an_rotate(this.s, w, this.#fixed(A, secret, 32), this.#fixed(B, key, 32), this.#fixed(C, next, 32));
  }
  recover(w, key, next, token) {
    return this.x.an_recover(this.s, w, this.#fixed(A, key, 32), this.#fixed(B, next, 32), this.#fixed(C, token, 16));
  }
  revoke(w) { return this.x.an_revoke(this.s, w); }

  episode() { return this.x.an_episode(this.s); }
  say(w, keyseq, person, trait, value, listeners) { return this.x.an_say(this.s, w, keyseq, person, trait, value, listeners); }
  tell(w, keyseq, teller, about, trait, listeners) { return this.x.an_tell(this.s, w, keyseq, teller, about, trait, listeners); }
  userLine(w, keyseq, line, hintTrait, hintValue, listeners, len = line.length) {
    return this.x.an_user_line(this.s, w, keyseq, this.#put(A, line, len | 0, 512), len, hintTrait, hintValue, listeners);
  }
  confirm(w, keyseq, trait, value, line, token) {
    return this.x.an_confirm(this.s, w, keyseq, trait, value, this.#fixed(A, line, 16), this.#fixed(B, token, 16));
  }
  redefine(w, keyseq, person, name, core, give, token, nameLen = name.length) {
    return this.x.an_redefine(this.s, w, keyseq, person, this.#put(A, name, nameLen | 0, 24), nameLen,
      this.#traitBytes(B, core, true), this.#traitBytes(C, give, false), this.#fixed(D, token, 16));
  }
  forget(holder, about, trait) { return this.x.an_forget(this.s, holder, about, trait); }

  issueConfirm(trait, value, line) {
    const result = this.x.an_issue_confirm(this.s, trait, value, this.#fixed(A, line, 16), this.base + OUT);
    return { result, token: this.#out(16) };
  }
  issueRedefine(person, name, core, give, nameLen = name.length) {
    const result = this.x.an_issue_redefine(this.s, person, this.#put(A, name, nameLen | 0, 24), nameLen,
      this.#traitBytes(B, core, true), this.#traitBytes(C, give, false), this.base + OUT);
    return { result, token: this.#out(16) };
  }
  issueRecover(w, key, next) {
    const result = this.x.an_issue_recover(this.s, w, this.#fixed(A, key, 32), this.#fixed(B, next, 32), this.base + OUT);
    return { result, token: this.#out(16) };
  }

  expressed(person, trait) { return this.x.an_expressed(this.s, person, trait); }
  core(person, trait) { return this.x.an_core(this.s, person, trait); }
  give(person, trait) { return this.x.an_give(this.s, person, trait); }
  viewGet(holder, about, trait) {
    const result = this.x.an_view_get(this.s, holder, about, trait, this.base + OUT);
    return { result, bytes: this.#out(34) };
  }
  writerGet(w) {
    const result = this.x.an_writer_get(this.s, w, this.base + OUT);
    return { result, bytes: this.#out(168) };
  }
  fingerprint(person) { const result = this.x.an_fingerprint(this.s, person, this.base + OUT); return { result, bytes: this.#out(32) }; }
  definition() { const result = this.x.an_definition(this.s, this.base + OUT); return { result, bytes: this.#out(32) }; }
  headBytes() { const result = this.x.an_head(this.s, this.base + OUT); return { result, bytes: this.#out(32) }; }
  info() {
    this.x.an_info(this.s, this.#infoPtr());
    const b = this.#bytes(), at = this.#infoPtr(), out = [];
    for (let i = 0; i < 12; i++) out.push((b[at + 4 * i] | (b[at + 4 * i + 1] << 8) | (b[at + 4 * i + 2] << 16) | (b[at + 4 * i + 3] << 24)) >>> 0);
    return out;
  }
  distanceBetween(p, q) { return this.x.an_distance(this.s, p, q); }
  verbatim(line, len = line.length) {
    const result = this.x.an_verbatim(this.s, this.#put(A, line, len | 0, 512), len, this.base + OUT);
    const v = new DataView(this.x.memory.buffer, this.base + OUT, 8);
    return { result, trait: v.getInt32(0, true), value: v.getInt32(4, true) };
  }
  lineId(line, len = line.length) {
    const result = this.x.an_line_id(this.#put(A, line, len | 0, 512), len, this.base + OUT);
    return result === 0 ? this.#out(16) : null;
  }
  // Arguments C cannot represent (more than seven voices, values outside int8, levels outside uint8,
  // mismatched lengths) are refused here as the oracle refuses them, without touching memory.
  lean(core, give, values, levels, sn, sd, sat, m) {
    const fits = (v, lo, hi) => Number.isInteger(v) && v >= lo && v <= hi;
    if (values.length > 7 || levels.length !== values.length || !values.every(v => fits(v, -128, 127)) ||
        !levels.every(l => fits(l, 0, 255))) return -128;
    const b = this.#bytes();
    for (let i = 0; i < values.length; i++) { b[this.base + A + i] = values[i] & 255; b[this.base + B + i] = levels[i]; }
    return this.x.an_lean(core, give, values.length, this.base + A, this.base + B, sn, sd, sat, m);
  }

  /** SHA-256 computed by the C code inside the module (messages up to the scratch size). */
  sha256(bytes) {
    if (bytes.length > this.size - 64) throw new RangeError('message larger than the scratch area');
    this.#bytes().set(bytes, this.base + 64);
    this.x.an_sha256(this.base + 64, bytes.length, this.base);
    return this.#bytes().slice(this.base, this.base + 32);
  }

  saveSize() { return this.x.an_save_size(this.s); }
  save() {
    const result = this.x.an_save(this.s, this.base, this.size);
    return { result, bytes: result > 0 ? this.#bytes().slice(this.base, this.base + result) : new Uint8Array(0) };
  }
  load(bytes) {
    if (bytes.length > this.size) return -32; // longer than any file (AN_L_LONG), as C would answer
    this.#bytes().set(bytes, this.base);
    return this.x.an_load(this.s, this.base, bytes.length);
  }
}
