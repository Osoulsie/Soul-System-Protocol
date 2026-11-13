/* Identity anchors: a storage rule for identity that cannot drift.
 * Freestanding C17. See anchor.h for the interface and docs/identity-anchors.md for the rule.
 *
 * Every mutating call after an_init appends exactly one journal entry, whether it is
 * accepted or refused, unless the store is not initialised or its event counter is spent.
 * Queries never change anything. No call allocates, and no call reads outside its arguments. */
#include "anchor.h"
#include "sha256.h"

/* ------------------------------------------------------------------ bytes */

static void cp(uint8_t *d, const uint8_t *s, int n) {
  int i;
  for (i = 0; i < n; i++) d[i] = s[i];
}

static void zero(void *p, unsigned n) {
  uint8_t *d = (uint8_t *)p;
  unsigned i;
  for (i = 0; i < n; i++) d[i] = 0;
}

static int same(const uint8_t *a, const uint8_t *b, int n) {
  int i;
  for (i = 0; i < n; i++)
    if (a[i] != b[i]) return 0;
  return 1;
}

static int allzero(const uint8_t *a, int n) {
  int i;
  for (i = 0; i < n; i++)
    if (a[i]) return 0;
  return 1;
}

static int fold(int c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; }

/* A byte read back as a signed 8-bit value, without relying on implementation-defined casts. */
static int s8(int v) { return v >= 128 ? v - 256 : v; }

/* Hash of a domain string followed by fields, written into out. */
static void dom_begin(an_sha256_ctx *c, const char *domain) {
  int n = 0;
  while (domain[n]) n++;
  an_sha256_init(c);
  an_sha256_update(c, (const uint8_t *)domain, (uint32_t)n);
}

static void h_u8(an_sha256_ctx *c, int v) {
  uint8_t b = (uint8_t)v;
  an_sha256_update(c, &b, 1);
}

static void h_u16(an_sha256_ctx *c, unsigned v) {
  uint8_t b[2];
  b[0] = (uint8_t)v;
  b[1] = (uint8_t)(v >> 8);
  an_sha256_update(c, b, 2);
}

static void h_u32(an_sha256_ctx *c, uint32_t v) {
  uint8_t b[4];
  b[0] = (uint8_t)v;
  b[1] = (uint8_t)(v >> 8);
  b[2] = (uint8_t)(v >> 16);
  b[3] = (uint8_t)(v >> 24);
  an_sha256_update(c, b, 4);
}

/* ---------------------------------------------------------------- journal */

#define REC_MAX 640

typedef struct {
  uint8_t b[REC_MAX];
  int n;
} rec_t;

static void r_u8(rec_t *r, int v) { r->b[r->n++] = (uint8_t)v; }

static void r_i32(rec_t *r, int v) {
  uint32_t u = (uint32_t)v;
  r->b[r->n++] = (uint8_t)u;
  r->b[r->n++] = (uint8_t)(u >> 8);
  r->b[r->n++] = (uint8_t)(u >> 16);
  r->b[r->n++] = (uint8_t)(u >> 24);
}

static void r_bytes(rec_t *r, const uint8_t *p, int n) {
  int i;
  for (i = 0; i < n; i++) r->b[r->n++] = p[i];
}

static void r_begin(rec_t *r, int op) {
  r->n = 0;
  r_u8(r, op);
  r_i32(r, 0); /* the result, filled in by journal() */
}

/* Entry = op, result byte, first 14 bytes of SHA-256(record). head <- SHA-256(head || entry). */
static int journal(an_store *s, rec_t *r, int result) {
  uint8_t d[32], e[16], buf[48];
  uint32_t u = (uint32_t)result;
  r->b[1] = (uint8_t)u;
  r->b[2] = (uint8_t)(u >> 8);
  r->b[3] = (uint8_t)(u >> 16);
  r->b[4] = (uint8_t)(u >> 24);
  an_sha256(r->b, (uint32_t)r->n, d);
  e[0] = r->b[0];
  e[1] = (uint8_t)u;
  cp(e + 2, d, 14);
  if (s->ring_count == AN_RING) {
    cp(buf, s->base, 32);
    cp(buf + 32, s->ring[s->ring_first], 16);
    an_sha256(buf, 48, s->base);
    s->ring_first = (uint8_t)((s->ring_first + 1) % AN_RING);
    s->ring_count--;
  }
  cp(s->ring[(s->ring_first + s->ring_count) % AN_RING], e, 16);
  s->ring_count++;
  cp(buf, s->head, 32);
  cp(buf + 32, e, 16);
  an_sha256(buf, 48, s->head);
  s->events++;
  if (result < 0 && s->refused != 0xFFFFFFFFu) s->refused++;
  return result;
}

/* Calls on a store that is not initialised, or whose event counter is spent, change nothing. */
#define PROLOGUE(s)                                  \
  do {                                               \
    if (!(s)->ready) return AN_E_STATE;              \
    if ((s)->events == 0xFFFFFFFFu) return AN_E_FULL; \
  } while (0)

/* ------------------------------------------------------------- validation */

static int name_valid(const uint8_t *n, int len) {
  int i;
  if (len < 1 || len > AN_NAME_MAX) return 0;
  for (i = 0; i < len; i++)
    if (n[i] < 0x20 || n[i] == 0x7F) return 0;
  return n[0] != ' ' && n[len - 1] != ' ';
}

static int names_equal(const uint8_t *a, int la, const uint8_t *b, int lb) {
  int i;
  if (la != lb) return 0;
  for (i = 0; i < la; i++)
    if (fold(a[i]) != fold(b[i])) return 0;
  return 1;
}

static int label_char(int c) {
  return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == ' ' || c == '-' || c == '\'';
}

static int label_valid(const uint8_t *t, int len) {
  int i;
  if (len < 1 || len > AN_LABEL_MAX) return 0;
  for (i = 0; i < len; i++)
    if (!label_char(t[i])) return 0;
  if (t[0] == ' ' || t[len - 1] == ' ') return 0;
  for (i = 1; i < len; i++)
    if (t[i] == ' ' && t[i - 1] == ' ') return 0;
  return 1;
}

static int label_exists(const an_store *s, const uint8_t *t, int len) {
  int k, j;
  for (k = 0; k < s->traits; k++)
    for (j = 0; j < s->trait[k].count; j++)
      if (s->trait[k].len[j] == len && same(s->trait[k].text[j], t, len)) return 1;
  return 0;
}

static int def_valid(const an_store *s, const uint8_t *name, int name_len, const int8_t *core,
                     const uint8_t *give) {
  int k;
  if (!name_valid(name, name_len)) return 0;
  for (k = 0; k < s->traits; k++)
    if (core[k] < -2 || core[k] > 2 || give[k] > 2) return 0;
  return 1;
}

static int is_companion(const an_store *s, int p) { return p >= 1 && p < s->persons; }

/* D(X,Y) = sum over traits of max(0, |cX - cY| - gX - gY): the least total distance two
 * companions can ever be apart, whatever they hear (Proposition A7). */
static int dist_arrays(int traits, const int8_t *c1, const uint8_t *g1, const int8_t *c2,
                       const uint8_t *g2) {
  int k, d = 0;
  for (k = 0; k < traits; k++) {
    int x = c1[k] - c2[k];
    if (x < 0) x = -x;
    x -= g1[k] + g2[k];
    if (x > 0) d += x;
  }
  return d;
}

/* Every pair of companions has distinct names and distance at least distinct_min. */
static int definitions_distinct(const an_store *s) {
  int p, q;
  for (p = 1; p < s->persons; p++)
    for (q = p + 1; q < s->persons; q++) {
      const an_person *a = &s->person[p], *b = &s->person[q];
      if (names_equal(a->name, a->name_len, b->name, b->name_len)) return 0;
      if (dist_arrays(s->traits, a->core, a->give, b->core, b->give) < s->distinct_min) return 0;
    }
  return 1;
}

static void fingerprint_of(const an_store *s, int p, int version, const uint8_t *name, int name_len,
                           const int8_t *core, const uint8_t *give, uint8_t out[32]) {
  an_sha256_ctx c;
  int k;
  dom_begin(&c, "anchor core v1");
  h_u8(&c, p);
  h_u8(&c, version);
  h_u8(&c, name_len);
  an_sha256_update(&c, name, (uint32_t)name_len);
  h_u8(&c, s->traits);
  for (k = 0; k < s->traits; k++) h_u8(&c, core[k]);
  for (k = 0; k < s->traits; k++) h_u8(&c, give[k]);
  an_sha256_final(&c, out);
}

/* ------------------------------------------------------------- the lean */

/* The expressed value of one trait: the core, leaned toward the weighted mean of at least
 * voices_min first-hand voices, and never further from the core than the give.
 *   S = sum of levels, T = sum of level*value, h = sigma * min(S, sat) / sat,
 *   u = (1 - h) * core + h * T/S = U/D with D = sd*sat*S and U = core*D + sn*min(S,sat)*(T - core*S),
 *   e = clamp(round_half_away_from_zero(u), core - give, core + give), within -2..2.
 * Integers only: |U| <= 4,300,800 and D <= 716,800, so 2|U| + D fits easily in 32 bits. */
static int lean_core(int core, int give, int count, const int *val, const int *lvl, int sn, int sd,
                     int sat, int m) {
  int i, S = 0, T = 0, x, D, U, a, r;
  if (count < m) return core;
  for (i = 0; i < count; i++) {
    S += lvl[i];
    T += lvl[i] * val[i];
  }
  x = S < sat ? S : sat;
  D = sd * sat * S;
  U = core * D + sn * x * (T - core * S);
  a = U < 0 ? -U : U;
  r = (2 * a + D) / (2 * D);
  if (U < 0) r = -r;
  if (r < core - give) r = core - give;
  if (r > core + give) r = core + give;
  if (r < -2) r = -2;
  if (r > 2) r = 2;
  return r;
}

int an_lean(int core, int give, int count, const int8_t *values, const uint8_t *levels, int sigma_num,
            int sigma_den, int saturation, int voices_min) {
  int val[AN_PERSONS], lvl[AN_PERSONS], i;
  if (core < -2 || core > 2 || give < 0 || give > 2 || count < 0 || count > AN_PERSONS - 1)
    return AN_NONE;
  if (sigma_den < 1 || sigma_den > 100 || sigma_num < 0 || sigma_num > sigma_den || saturation < 1 ||
      saturation > 64 || voices_min < 2 || voices_min > 7)
    return AN_NONE;
  for (i = 0; i < count; i++) {
    if (values[i] < -2 || values[i] > 2 || levels[i] < 1 || levels[i] > AN_LEVEL_MAX) return AN_NONE;
    val[i] = values[i];
    lvl[i] = levels[i];
  }
  return lean_core(core, give, count, val, lvl, sigma_num, sigma_den, saturation, voices_min);
}

static unsigned revoked_mask(const an_store *s) {
  unsigned m = 0;
  int w;
  for (w = 0; w < s->writer_count; w++)
    if (s->writer[w].revoked) m |= 1u << w;
  return m;
}

/* A view is live unless a writer in its provenance is revoked (fallen) or, for a view about a
 * companion, it was made under an earlier version of her core (stale). */
static int view_fallen(const an_view *v, unsigned rm) { return (v->wset & rm) != 0; }

static int view_stale(const an_store *s, const an_view *v, int about) {
  return about != 0 && v->corever != s->person[about].version;
}

static int view_live(const an_store *s, const an_view *v, int about, unsigned rm) {
  return !view_fallen(v, rm) && !view_stale(s, v, about);
}

/* Recompute what companion x expresses on every trait: her core, her give, and the live
 * first-hand views she holds about others. Nothing else is read; nothing she said is read. */
static void snapshot(an_store *s, int x, unsigned rm) {
  int k, a;
  an_person *p = &s->person[x];
  for (k = 0; k < s->traits; k++) {
    int val[AN_PERSONS], lvl[AN_PERSONS], c = 0;
    for (a = 0; a < s->persons; a++) {
      const an_view *v;
      if (a == x) continue;
      v = &s->view[x][a][k];
      if (!v->used || v->cls != AN_FIRST || !view_live(s, v, a, rm)) continue;
      val[c] = v->value;
      lvl[c] = v->level;
      c++;
    }
    p->expressed[k] = (int8_t)lean_core(p->core[k], p->give[k], c, val, lvl, s->sigma_num,
                                        s->sigma_den, s->saturation, s->voices_min);
  }
}

/* --------------------------------------------------------------- admission */

/* Put a view into holder h's slot about a on trait k. Returns 1 if it was taken, 0 if a live
 * view of higher standing kept its place. FIRST takes any slot; READ takes READ or TOLD;
 * TOLD takes TOLD of the same or a greater depth. A fallen or stale view gives way to anything. */
static int admit(an_store *s, unsigned rm, int h, int a, int k, int cls, int value, int depth,
                 int auth, unsigned wset, int corever, const uint8_t line[16]) {
  an_view *v = &s->view[h][a][k];
  int live = v->used && view_live(s, v, a, rm);
  if (live) {
    if (cls == AN_READ && v->cls == AN_FIRST) return 0;
    if (cls == AN_TOLD && (v->cls != AN_TOLD || depth > v->depth)) return 0;
  }
  if (!live || v->cls != cls) {
    v->level = AN_LEVEL_NEW;
    v->wset = (uint16_t)wset;
    v->was = (int8_t)AN_NONE;
    v->born = s->episode;
  } else if (v->value == value) {
    int l = v->level + AN_LEVEL_REPEAT;
    v->level = (uint8_t)(l > AN_LEVEL_MAX ? AN_LEVEL_MAX : l);
    v->wset = (uint16_t)(v->wset | wset);
  } else {
    v->level = AN_LEVEL_NEW;
    v->wset = (uint16_t)wset;
    v->was = (int8_t)(cls == AN_FIRST ? v->value : AN_NONE);
  }
  v->used = 1;
  v->cls = (uint8_t)cls;
  v->value = (int8_t)value;
  v->depth = (uint8_t)depth;
  v->auth = (uint8_t)auth;
  v->corever = (uint8_t)corever;
  v->last = s->episode;
  cp(v->line, line, 16);
  return 1;
}

/* Listeners are companions only, never the speaker, the teller or the subject. */
static int listeners_ok(const an_store *s, int mask, unsigned exclude) {
  unsigned m = (unsigned)mask;
  unsigned companions = ((1u << s->persons) - 1u) & ~1u;
  return m != 0 && (m & ~companions) == 0 && (m & exclude) == 0;
}

static int writer_ok(const an_store *s, int w, int keyseq) {
  if (w < 0 || w >= s->writer_count || s->writer[w].revoked) return AN_E_WRITER;
  if (keyseq != (int)s->writer[w].seq) return AN_E_KEYSEQ;
  return AN_OK;
}

/* ------------------------------------------------------------- the user's word */

/* Lowercase ASCII, read U+2019 as an apostrophe, collapse runs of space, tab, CR and LF into
 * one space, trim, then drop a trailing run of '.' and '!' and any spaces before it. */
static int normalize(const uint8_t *in, int len, uint8_t *out) {
  int i, n = 0, space = 0;
  for (i = 0; i < len; i++) {
    int c = in[i];
    if (c == 0xE2 && i + 2 < len && in[i + 1] == 0x80 && in[i + 2] == 0x99) {
      c = '\'';
      i += 2;
    } else if (c == '\t' || c == '\n' || c == '\r') {
      c = ' ';
    } else {
      c = fold(c);
    }
    if (c == ' ') {
      space = 1;
      continue;
    }
    if (space && n > 0) out[n++] = ' ';
    space = 0;
    out[n++] = (uint8_t)c;
  }
  while (n > 0 && (out[n - 1] == '.' || out[n - 1] == '!')) n--;
  while (n > 0 && out[n - 1] == ' ') n--;
  return n;
}

static const char *const VERB[6] = {"love", "like", "am undecided about", "do not like", "don't like",
                                    "hate"};
static const int VERB_VALUE[6] = {2, 1, 0, -1, -1, -2};

/* A line is the user's word on a trait only if, once normalised, it is exactly
 * "i <verb> <label>" for one of the six verbs and one label of that trait. */
static int verbatim(const an_store *s, const uint8_t *line, int len, int *trait, int *value) {
  uint8_t t[AN_LINE_MAX];
  int n, j, k, l;
  if (len < 0 || len > AN_LINE_MAX) return 0;
  n = normalize(line, len, t);
  if (n < 2 || t[0] != 'i' || t[1] != ' ') return 0;
  for (j = 0; j < 6; j++) {
    int vl = 0, at = 2, ll;
    while (VERB[j][vl]) vl++;
    if (n < at + vl + 2) continue;
    if (!same(t + at, (const uint8_t *)VERB[j], vl) || t[at + vl] != ' ') continue;
    ll = n - (at + vl + 1);
    for (k = 0; k < s->traits; k++)
      for (l = 0; l < s->trait[k].count; l++)
        if (s->trait[k].len[l] == ll && same(s->trait[k].text[l], t + at + vl + 1, ll)) {
          *trait = k;
          *value = VERB_VALUE[j];
          return 1;
        }
  }
  return 0;
}

/* ----------------------------------------------------------------- tokens */

static void confirm_target(int trait, int value, const uint8_t line_id[16], uint8_t out[32]) {
  an_sha256_ctx c;
  dom_begin(&c, "anchor confirm v1");
  h_u8(&c, trait);
  h_u8(&c, value);
  an_sha256_update(&c, line_id, 16);
  an_sha256_final(&c, out);
}

static void recover_target(const an_writer *w, const uint8_t key[32], const uint8_t next[32],
                           uint8_t out[32]) {
  an_sha256_ctx c;
  dom_begin(&c, "anchor recover v1");
  an_sha256_update(&c, w->id, 32);
  h_u16(&c, w->seq);
  an_sha256_update(&c, key, 32);
  an_sha256_update(&c, next, 32);
  an_sha256_final(&c, out);
}

static void token_remove(an_store *s, int i) {
  int j;
  for (j = i; j + 1 < s->token_count; j++) {
    an_token *d = &s->token[j];
    const an_token *f = &s->token[j + 1];
    d->kind = f->kind;
    d->issued = f->issued;
    cp(d->target, f->target, 32);
    cp(d->token, f->token, 16);
  }
  s->token_count--;
  zero(&s->token[s->token_count], (unsigned)sizeof(an_token));
}

/* Issue: derive from kind, target, the journal head and the serial; the oldest token gives way
 * when the table is full. The caller journals the call afterwards, so issued = events + 1. */
static int issue(an_store *s, int kind, const uint8_t target[32], uint8_t out[16]) {
  an_sha256_ctx c;
  uint8_t d[32];
  int i;
  if (s->issued == 0xFFFFFFFFu) return AN_E_FULL;
  dom_begin(&c, "anchor token v1");
  h_u8(&c, kind);
  an_sha256_update(&c, target, 32);
  an_sha256_update(&c, s->head, 32);
  h_u32(&c, s->issued);
  an_sha256_final(&c, d);
  for (i = 0; i < s->token_count; i++)
    if (same(s->token[i].token, d, 16)) return AN_E_FULL;
  if (s->token_count == AN_TOKENS) token_remove(s, 0);
  i = s->token_count++;
  s->token[i].kind = (uint8_t)kind;
  s->token[i].issued = s->events + 1u;
  cp(s->token[i].target, target, 32);
  cp(s->token[i].token, d, 16);
  s->issued++;
  cp(out, d, 16);
  return AN_OK;
}

/* Spend: a token that is presented is used up whatever the outcome. */
static int spend(an_store *s, int kind, const uint8_t target[32], const uint8_t token[16]) {
  int i;
  for (i = 0; i < s->token_count; i++)
    if (same(s->token[i].token, token, 16)) {
      int ok = s->token[i].kind == kind && same(s->token[i].target, target, 32) &&
               s->events - s->token[i].issued <= AN_LAPSE;
      token_remove(s, i);
      return ok ? AN_OK : AN_E_TOKEN;
    }
  return AN_E_TOKEN;
}

/* ------------------------------------------------------------ definition */

int an_init(an_store *s, int persons, int traits, int sigma_num, int sigma_den, int saturation,
            int voices_min, int distinct_min) {
  rec_t r;
  zero(s, (unsigned)sizeof(an_store));
  if (persons < 2 || persons > AN_PERSONS || traits < 1 || traits > AN_TRAITS || sigma_den < 1 ||
      sigma_den > 100 || sigma_num < 0 || sigma_num > sigma_den || saturation < 1 || saturation > 64 ||
      voices_min < 2 || voices_min > 7 || distinct_min < 1 || distinct_min > 255)
    return AN_E_ARG;
  s->persons = (uint8_t)persons;
  s->traits = (uint8_t)traits;
  s->sigma_num = (uint8_t)sigma_num;
  s->sigma_den = (uint8_t)sigma_den;
  s->saturation = (uint8_t)saturation;
  s->voices_min = (uint8_t)voices_min;
  s->distinct_min = (uint8_t)distinct_min;
  s->ready = 1;
  an_sha256((const uint8_t *)"anchor journal v1", 17, s->base);
  cp(s->head, s->base, 32);
  r_begin(&r, AN_OP_INIT);
  r_i32(&r, persons);
  r_i32(&r, traits);
  r_i32(&r, sigma_num);
  r_i32(&r, sigma_den);
  r_i32(&r, saturation);
  r_i32(&r, voices_min);
  r_i32(&r, distinct_min);
  return journal(s, &r, AN_OK);
}

int an_label(an_store *s, int trait, const uint8_t *label, int len) {
  rec_t r;
  an_trait *t;
  PROLOGUE(s);
  r_begin(&r, AN_OP_LABEL);
  r_i32(&r, trait);
  r_i32(&r, len);
  if (len >= 0 && len <= AN_LABEL_MAX) r_bytes(&r, label, len);
  if (s->sealed) return journal(s, &r, AN_E_STATE);
  if (trait < 0 || trait >= s->traits || !label_valid(label, len)) return journal(s, &r, AN_E_ARG);
  t = &s->trait[trait];
  if (t->count == AN_LABELS) return journal(s, &r, AN_E_FULL);
  if (label_exists(s, label, len)) return journal(s, &r, AN_E_DISTINCT);
  t->len[t->count] = (uint8_t)len;
  cp(t->text[t->count], label, len);
  t->count++;
  return journal(s, &r, AN_OK);
}

static void rec_definition(rec_t *r, const an_store *s, const uint8_t *name, int name_len,
                           const int8_t *core, const uint8_t *give) {
  int k;
  r_i32(r, name_len);
  if (name_len >= 0 && name_len <= AN_NAME_MAX) r_bytes(r, name, name_len);
  for (k = 0; k < s->traits; k++) r_u8(r, core[k]);
  for (k = 0; k < s->traits; k++) r_u8(r, give[k]);
}

int an_define(an_store *s, int person, const uint8_t *name, int name_len, const int8_t *core,
              const uint8_t *give) {
  rec_t r;
  an_person *p;
  int k;
  PROLOGUE(s);
  r_begin(&r, AN_OP_DEFINE);
  r_i32(&r, person);
  rec_definition(&r, s, name, name_len, core, give);
  if (s->sealed) return journal(s, &r, AN_E_STATE);
  if (!is_companion(s, person)) return journal(s, &r, AN_E_ARG);
  p = &s->person[person];
  if (p->defined) return journal(s, &r, AN_E_STATE);
  if (!def_valid(s, name, name_len, core, give)) return journal(s, &r, AN_E_ARG);
  p->defined = 1;
  p->version = 1;
  p->name_len = (uint8_t)name_len;
  cp(p->name, name, name_len);
  for (k = 0; k < s->traits; k++) {
    p->core[k] = core[k];
    p->give[k] = give[k];
    p->expressed[k] = core[k];
  }
  return journal(s, &r, AN_OK);
}

int an_seal(an_store *s) {
  rec_t r;
  int k, p;
  PROLOGUE(s);
  r_begin(&r, AN_OP_SEAL);
  if (s->sealed) return journal(s, &r, AN_E_STATE);
  for (k = 0; k < s->traits; k++)
    if (s->trait[k].count == 0) return journal(s, &r, AN_E_STATE);
  for (p = 1; p < s->persons; p++)
    if (!s->person[p].defined) return journal(s, &r, AN_E_STATE);
  if (!definitions_distinct(s)) return journal(s, &r, AN_E_DISTINCT);
  for (p = 1; p < s->persons; p++) snapshot(s, p, 0);
  s->sealed = 1;
  return journal(s, &r, AN_OK);
}

/* ---------------------------------------------------------------- writers */

static int used_has(const an_store *s, const uint8_t d[32]) {
  int i;
  for (i = 0; i < s->used_count; i++)
    if (same(s->used[i], d, 32)) return 1;
  return 0;
}

static void used_add(an_store *s, const uint8_t d[32]) { cp(s->used[s->used_count++], d, 32); }

/* A fresh pair: both non-zero, different, and never bound to any identity before. */
static int fresh_pair(const an_store *s, const uint8_t key[32], const uint8_t next[32]) {
  return !allzero(key, 32) && !allzero(next, 32) && !same(key, next, 32) && !used_has(s, key) &&
         !used_has(s, next);
}

static void writer_id(int channel, int instance, int root, int persona, const uint8_t key0[32],
                      const uint8_t next0[32], uint32_t index, uint8_t out[32]) {
  an_sha256_ctx c;
  dom_begin(&c, "anchor writer v1");
  h_u8(&c, channel);
  h_u8(&c, instance);
  h_u8(&c, root);
  h_u8(&c, persona);
  an_sha256_update(&c, key0, 32);
  an_sha256_update(&c, next0, 32);
  h_u32(&c, index);
  an_sha256_final(&c, out);
}

/* A user door voices the user; an agent door voices exactly one companion; other doors voice
 * nobody. The binding is fixed for the writer's life. */
static int binding_ok(const an_store *s, int channel, int persona) {
  if (channel == AN_USER) return persona == 0;
  if (channel == AN_AGENT) return is_companion(s, persona);
  return persona == AN_NO_PERSONA;
}

int an_incept(an_store *s, int channel, int instance, int root, int persona, const uint8_t key[32],
              const uint8_t next[32]) {
  rec_t r;
  an_writer *w;
  int i;
  PROLOGUE(s);
  r_begin(&r, AN_OP_INCEPT);
  r_i32(&r, channel);
  r_i32(&r, instance);
  r_i32(&r, root);
  r_i32(&r, persona);
  r_bytes(&r, key, 32);
  r_bytes(&r, next, 32);
  if (!s->sealed) return journal(s, &r, AN_E_STATE);
  if (channel < 0 || channel > AN_SYSTEM || instance < 0 || instance > 255 || root < 0 || root > 15 ||
      !binding_ok(s, channel, persona))
    return journal(s, &r, AN_E_ARG);
  for (i = 0; i < s->writer_count; i++)
    if (s->writer[i].channel == channel && s->writer[i].instance == instance)
      return journal(s, &r, AN_E_DOOR);
  if (!fresh_pair(s, key, next)) return journal(s, &r, AN_E_DIGEST);
  if (s->writer_count == AN_WRITERS || s->used_count + 2 > AN_USED) return journal(s, &r, AN_E_FULL);
  i = s->writer_count++;
  w = &s->writer[i];
  w->channel = (uint8_t)channel;
  w->instance = (uint8_t)instance;
  w->root = (uint8_t)root;
  w->persona = (uint8_t)persona;
  w->revoked = 0;
  w->recovered = 0;
  w->seq = 0;
  cp(w->key, key, 32);
  cp(w->next, next, 32);
  cp(w->key0, key, 32);
  cp(w->next0, next, 32);
  writer_id(channel, instance, root, persona, key, next, (uint32_t)i, w->id);
  used_add(s, key);
  used_add(s, next);
  return journal(s, &r, i);
}

int an_rotate(an_store *s, int w, const uint8_t secret[32], const uint8_t key[32],
              const uint8_t next[32]) {
  rec_t r;
  uint8_t d[32];
  an_writer *x;
  PROLOGUE(s);
  r_begin(&r, AN_OP_ROTATE);
  r_i32(&r, w);
  r_bytes(&r, secret, 32);
  r_bytes(&r, key, 32);
  r_bytes(&r, next, 32);
  if (!s->sealed) return journal(s, &r, AN_E_STATE);
  if (w < 0 || w >= s->writer_count || s->writer[w].revoked) return journal(s, &r, AN_E_WRITER);
  x = &s->writer[w];
  an_sha256(secret, 32, d);
  if (!same(d, x->next, 32)) return journal(s, &r, AN_E_PROOF);
  if (x->seq == 0xFFFFu) return journal(s, &r, AN_E_FULL);
  if (!fresh_pair(s, key, next)) return journal(s, &r, AN_E_DIGEST);
  if (s->used_count + 2 > AN_USED) return journal(s, &r, AN_E_FULL);
  cp(x->key, key, 32);
  cp(x->next, next, 32);
  x->seq++;
  used_add(s, key);
  used_add(s, next);
  return journal(s, &r, AN_OK);
}

int an_recover(an_store *s, int w, const uint8_t key[32], const uint8_t next[32],
               const uint8_t token[16]) {
  rec_t r;
  uint8_t target[32];
  an_writer *x;
  int e;
  PROLOGUE(s);
  r_begin(&r, AN_OP_RECOVER);
  r_i32(&r, w);
  r_bytes(&r, key, 32);
  r_bytes(&r, next, 32);
  r_bytes(&r, token, 16);
  if (!s->sealed) return journal(s, &r, AN_E_STATE);
  if (w < 0 || w >= s->writer_count || s->writer[w].revoked) return journal(s, &r, AN_E_WRITER);
  x = &s->writer[w];
  recover_target(x, key, next, target);
  e = spend(s, AN_RECOVER, target, token);
  if (e) return journal(s, &r, e);
  if (x->seq == 0xFFFFu) return journal(s, &r, AN_E_FULL);
  if (!fresh_pair(s, key, next)) return journal(s, &r, AN_E_DIGEST);
  if (s->used_count + 2 > AN_USED) return journal(s, &r, AN_E_FULL);
  cp(x->key, key, 32);
  cp(x->next, next, 32);
  x->seq++;
  if (x->recovered != 0xFFu) x->recovered++;
  used_add(s, key);
  used_add(s, next);
  return journal(s, &r, AN_OK);
}

int an_revoke(an_store *s, int w) {
  rec_t r;
  PROLOGUE(s);
  r_begin(&r, AN_OP_REVOKE);
  r_i32(&r, w);
  if (!s->sealed) return journal(s, &r, AN_E_STATE);
  if (w < 0 || w >= s->writer_count || s->writer[w].revoked) return journal(s, &r, AN_E_WRITER);
  s->writer[w].revoked = 1;
  return journal(s, &r, AN_OK);
}

/* ----------------------------------------------------------- conversation */

int an_episode(an_store *s) {
  rec_t r;
  int h, a, k, dropped = 0;
  unsigned rm;
  PROLOGUE(s);
  r_begin(&r, AN_OP_EPISODE);
  if (!s->sealed) return journal(s, &r, AN_E_STATE);
  if (s->episode != 0xFFFFu) s->episode++;
  for (h = 1; h < s->persons; h++)
    for (a = 0; a < s->persons; a++)
      for (k = 0; k < s->traits; k++) {
        an_view *v = &s->view[h][a][k];
        if (!v->used) continue;
        if (v->level > 1) {
          v->level--;
        } else if (!(v->cls == AN_FIRST && a == 0)) { /* the user's word is never dropped */
          zero(v, (unsigned)sizeof(an_view));
          dropped++;
        }
      }
  rm = revoked_mask(s);
  for (h = 1; h < s->persons; h++) snapshot(s, h, rm);
  return journal(s, &r, dropped);
}

int an_say(an_store *s, int w, int keyseq, int person, int trait, int value, int listeners) {
  rec_t r;
  static const uint8_t noline[16] = {0};
  int e, h, n = 0, c, g;
  unsigned rm;
  PROLOGUE(s);
  r_begin(&r, AN_OP_SAY);
  r_i32(&r, w);
  r_i32(&r, keyseq);
  r_i32(&r, person);
  r_i32(&r, trait);
  r_i32(&r, value);
  r_i32(&r, listeners);
  if (!s->sealed) return journal(s, &r, AN_E_STATE);
  e = writer_ok(s, w, keyseq);
  if (e) return journal(s, &r, e);
  if (!is_companion(s, person) || s->writer[w].persona != person) return journal(s, &r, AN_E_WRITER);
  if (trait < 0 || trait >= s->traits || value < -2 || value > 2) return journal(s, &r, AN_E_ARG);
  if (!listeners_ok(s, listeners, 1u << person)) return journal(s, &r, AN_E_LISTENERS);
  c = s->person[person].core[trait];
  g = s->person[person].give[trait];
  if (value < c - g || value > c + g) return journal(s, &r, AN_E_CHARACTER);
  if (value != s->person[person].expressed[trait]) return journal(s, &r, AN_E_NOTNOW);
  rm = revoked_mask(s);
  for (h = 1; h < s->persons; h++)
    if ((unsigned)listeners & (1u << h))
      n += admit(s, rm, h, person, trait, AN_FIRST, value, 0, 1, 1u << w, s->person[person].version,
                 noline);
  return journal(s, &r, n);
}

int an_tell(an_store *s, int w, int keyseq, int teller, int about, int trait, int listeners) {
  rec_t r;
  const an_view *src;
  int e, h, n = 0, value, depth, auth, corever;
  unsigned rm, wset;
  uint8_t line[16];
  PROLOGUE(s);
  r_begin(&r, AN_OP_TELL);
  r_i32(&r, w);
  r_i32(&r, keyseq);
  r_i32(&r, teller);
  r_i32(&r, about);
  r_i32(&r, trait);
  r_i32(&r, listeners);
  if (!s->sealed) return journal(s, &r, AN_E_STATE);
  e = writer_ok(s, w, keyseq);
  if (e) return journal(s, &r, e);
  if (!is_companion(s, teller) || s->writer[w].persona != teller) return journal(s, &r, AN_E_WRITER);
  if (about < 0 || about >= s->persons || about == teller || trait < 0 || trait >= s->traits)
    return journal(s, &r, AN_E_ARG);
  if (!listeners_ok(s, listeners, (1u << teller) | (1u << about)))
    return journal(s, &r, AN_E_LISTENERS);
  rm = revoked_mask(s);
  src = &s->view[teller][about][trait];
  if (!src->used || !view_live(s, src, about, rm) || src->depth >= AN_DEPTH_MAX)
    return journal(s, &r, AN_E_SOURCE);
  /* A retelling carries exactly what the teller holds: value, provenance, core version, line. */
  value = src->value;
  depth = src->depth + 1;
  auth = src->auth < 1 ? src->auth : 1;
  corever = src->corever;
  wset = (unsigned)src->wset | (1u << w);
  cp(line, src->line, 16);
  for (h = 1; h < s->persons; h++)
    if ((unsigned)listeners & (1u << h))
      n += admit(s, rm, h, about, trait, AN_TOLD, value, depth, auth, wset, corever, line);
  return journal(s, &r, n);
}

int an_user_line(an_store *s, int w, int keyseq, const uint8_t *line, int len, int hint_trait,
                 int hint_value, int listeners) {
  rec_t r;
  uint8_t id[32];
  int e, h, k, v, result;
  unsigned rm;
  PROLOGUE(s);
  r_begin(&r, AN_OP_LINE);
  r_i32(&r, w);
  r_i32(&r, keyseq);
  r_i32(&r, len);
  if (len >= 0 && len <= AN_LINE_MAX) r_bytes(&r, line, len);
  r_i32(&r, hint_trait);
  r_i32(&r, hint_value);
  r_i32(&r, listeners);
  if (!s->sealed) return journal(s, &r, AN_E_STATE);
  e = writer_ok(s, w, keyseq);
  if (e) return journal(s, &r, e);
  if (s->writer[w].persona != 0) return journal(s, &r, AN_E_WRITER);
  if (len < 0 || len > AN_LINE_MAX) return journal(s, &r, AN_E_ARG);
  if (!(hint_trait == -1 ||
        (hint_trait >= 0 && hint_trait < s->traits && hint_value >= -2 && hint_value <= 2)))
    return journal(s, &r, AN_E_ARG);
  if (!listeners_ok(s, listeners, 1u)) return journal(s, &r, AN_E_LISTENERS);
  an_sha256(line, (uint32_t)len, id);
  rm = revoked_mask(s);
  if (verbatim(s, line, len, &k, &v)) {
    for (h = 1; h < s->persons; h++)
      if ((unsigned)listeners & (1u << h)) admit(s, rm, h, 0, k, AN_FIRST, v, 0, 2, 1u << w, 0, id);
    result = AN_WORD;
  } else if (hint_trait >= 0) {
    for (h = 1; h < s->persons; h++)
      if ((unsigned)listeners & (1u << h))
        admit(s, rm, h, 0, hint_trait, AN_READ, hint_value, 0, 1, 1u << w, 0, id);
    result = AN_READING;
  } else {
    result = AN_NOTHING;
  }
  return journal(s, &r, result);
}

int an_confirm(an_store *s, int w, int keyseq, int trait, int value, const uint8_t line_id[16],
               const uint8_t token[16]) {
  rec_t r;
  uint8_t target[32];
  int e, h, n = 0;
  unsigned rm;
  PROLOGUE(s);
  r_begin(&r, AN_OP_CONFIRM);
  r_i32(&r, w);
  r_i32(&r, keyseq);
  r_i32(&r, trait);
  r_i32(&r, value);
  r_bytes(&r, line_id, 16);
  r_bytes(&r, token, 16);
  if (!s->sealed) return journal(s, &r, AN_E_STATE);
  e = writer_ok(s, w, keyseq);
  if (e) return journal(s, &r, e);
  if (s->writer[w].persona != 0) return journal(s, &r, AN_E_WRITER);
  if (trait < 0 || trait >= s->traits || value < -2 || value > 2) return journal(s, &r, AN_E_ARG);
  confirm_target(trait, value, line_id, target);
  e = spend(s, AN_CONFIRM, target, token);
  if (e) return journal(s, &r, e);
  rm = revoked_mask(s);
  for (h = 1; h < s->persons; h++) {
    const an_view *v = &s->view[h][0][trait];
    if (v->used && v->cls == AN_READ && v->value == value && same(v->line, line_id, 16) &&
        view_live(s, v, 0, rm))
      n += admit(s, rm, h, 0, trait, AN_FIRST, value, 0, 2, 1u << w, 0, line_id);
  }
  return journal(s, &r, n);
}

int an_redefine(an_store *s, int w, int keyseq, int person, const uint8_t *name, int name_len,
                const int8_t *core, const uint8_t *give, const uint8_t token[16]) {
  rec_t r;
  uint8_t target[32];
  an_person *p;
  int e, q, k;
  PROLOGUE(s);
  r_begin(&r, AN_OP_REDEFINE);
  r_i32(&r, w);
  r_i32(&r, keyseq);
  r_i32(&r, person);
  rec_definition(&r, s, name, name_len, core, give);
  r_bytes(&r, token, 16);
  if (!s->sealed) return journal(s, &r, AN_E_STATE);
  e = writer_ok(s, w, keyseq);
  if (e) return journal(s, &r, e);
  if (s->writer[w].channel != AN_USER && s->writer[w].channel != AN_SYSTEM)
    return journal(s, &r, AN_E_WRITER);
  if (!is_companion(s, person) || !def_valid(s, name, name_len, core, give))
    return journal(s, &r, AN_E_ARG);
  p = &s->person[person];
  if (p->version == 0xFFu) return journal(s, &r, AN_E_FULL);
  fingerprint_of(s, person, p->version + 1, name, name_len, core, give, target);
  e = spend(s, AN_REDEFINE, target, token);
  if (e) return journal(s, &r, e);
  for (q = 1; q < s->persons; q++) {
    const an_person *o = &s->person[q];
    if (q == person) continue;
    if (names_equal(name, name_len, o->name, o->name_len) ||
        dist_arrays(s->traits, core, give, o->core, o->give) < s->distinct_min)
      return journal(s, &r, AN_E_DISTINCT);
  }
  p->version++;
  p->name_len = (uint8_t)name_len;
  zero(p->name, AN_NAME_MAX);
  cp(p->name, name, name_len);
  for (k = 0; k < s->traits; k++) {
    p->core[k] = core[k];
    p->give[k] = give[k];
  }
  snapshot(s, person, revoked_mask(s));
  return journal(s, &r, AN_OK);
}

int an_forget(an_store *s, int holder, int about, int trait) {
  rec_t r;
  int h, a, k, n = 0;
  PROLOGUE(s);
  r_begin(&r, AN_OP_FORGET);
  r_i32(&r, holder);
  r_i32(&r, about);
  r_i32(&r, trait);
  if (!s->sealed) return journal(s, &r, AN_E_STATE);
  if ((holder != -1 && !is_companion(s, holder)) || (about != -1 && (about < 0 || about >= s->persons)) ||
      (trait != -1 && (trait < 0 || trait >= s->traits)))
    return journal(s, &r, AN_E_ARG);
  for (h = 1; h < s->persons; h++)
    for (a = 0; a < s->persons; a++)
      for (k = 0; k < s->traits; k++) {
        an_view *v = &s->view[h][a][k];
        if (!v->used || (holder != -1 && h != holder) || (about != -1 && a != about) ||
            (trait != -1 && k != trait))
          continue;
        zero(v, (unsigned)sizeof(an_view));
        n++;
      }
  return journal(s, &r, n);
}

/* ----------------------------------------------------------------- consent */

int an_issue_confirm(an_store *s, int trait, int value, const uint8_t line_id[16], uint8_t out[16]) {
  rec_t r;
  uint8_t target[32];
  zero(out, 16);
  PROLOGUE(s);
  r_begin(&r, AN_OP_ISSUE_CONFIRM);
  r_i32(&r, trait);
  r_i32(&r, value);
  r_bytes(&r, line_id, 16);
  if (!s->sealed) return journal(s, &r, AN_E_STATE);
  if (trait < 0 || trait >= s->traits || value < -2 || value > 2) return journal(s, &r, AN_E_ARG);
  confirm_target(trait, value, line_id, target);
  return journal(s, &r, issue(s, AN_CONFIRM, target, out));
}

int an_issue_redefine(an_store *s, int person, const uint8_t *name, int name_len, const int8_t *core,
                      const uint8_t *give, uint8_t out[16]) {
  rec_t r;
  uint8_t target[32];
  zero(out, 16);
  PROLOGUE(s);
  r_begin(&r, AN_OP_ISSUE_REDEFINE);
  r_i32(&r, person);
  rec_definition(&r, s, name, name_len, core, give);
  if (!s->sealed) return journal(s, &r, AN_E_STATE);
  if (!is_companion(s, person) || !def_valid(s, name, name_len, core, give))
    return journal(s, &r, AN_E_ARG);
  if (s->person[person].version == 0xFFu) return journal(s, &r, AN_E_FULL);
  fingerprint_of(s, person, s->person[person].version + 1, name, name_len, core, give, target);
  return journal(s, &r, issue(s, AN_REDEFINE, target, out));
}

int an_issue_recover(an_store *s, int w, const uint8_t key[32], const uint8_t next[32],
                     uint8_t out[16]) {
  rec_t r;
  uint8_t target[32];
  zero(out, 16);
  PROLOGUE(s);
  r_begin(&r, AN_OP_ISSUE_RECOVER);
  r_i32(&r, w);
  r_bytes(&r, key, 32);
  r_bytes(&r, next, 32);
  if (!s->sealed) return journal(s, &r, AN_E_STATE);
  if (w < 0 || w >= s->writer_count || s->writer[w].revoked) return journal(s, &r, AN_E_WRITER);
  recover_target(&s->writer[w], key, next, target);
  return journal(s, &r, issue(s, AN_RECOVER, target, out));
}

/* ----------------------------------------------------------------- queries */

int an_expressed(const an_store *s, int person, int trait) {
  if (!s->sealed || !is_companion(s, person) || trait < 0 || trait >= s->traits) return AN_NONE;
  return s->person[person].expressed[trait];
}

int an_core(const an_store *s, int person, int trait) {
  if (!s->sealed || !is_companion(s, person) || trait < 0 || trait >= s->traits) return AN_NONE;
  return s->person[person].core[trait];
}

int an_give(const an_store *s, int person, int trait) {
  if (!s->sealed || !is_companion(s, person) || trait < 0 || trait >= s->traits) return AN_NONE;
  return s->person[person].give[trait];
}

static void view_bytes(int h, int a, int k, const an_view *v, uint8_t *o) {
  o[0] = (uint8_t)h;
  o[1] = (uint8_t)a;
  o[2] = (uint8_t)k;
  o[3] = v->cls;
  o[4] = v->depth;
  o[5] = v->auth;
  o[6] = v->level;
  o[7] = v->corever;
  o[8] = (uint8_t)v->value;
  o[9] = (uint8_t)v->was;
  o[10] = (uint8_t)v->born;
  o[11] = (uint8_t)(v->born >> 8);
  o[12] = (uint8_t)v->last;
  o[13] = (uint8_t)(v->last >> 8);
  o[14] = (uint8_t)v->wset;
  o[15] = (uint8_t)(v->wset >> 8);
  cp(o + 16, v->line, 16);
}

int an_view_get(const an_store *s, int holder, int about, int trait, uint8_t out[AN_VIEW_BYTES + 2]) {
  const an_view *v;
  zero(out, AN_VIEW_BYTES + 2);
  if (!s->sealed || !is_companion(s, holder) || about < 0 || about >= s->persons || about == holder ||
      trait < 0 || trait >= s->traits)
    return -1;
  v = &s->view[holder][about][trait];
  if (!v->used) return 0;
  view_bytes(holder, about, trait, v, out);
  out[AN_VIEW_BYTES] = (uint8_t)view_fallen(v, revoked_mask(s));
  out[AN_VIEW_BYTES + 1] = (uint8_t)view_stale(s, v, about);
  return 1;
}

static void writer_bytes(const an_writer *w, uint8_t *o) {
  o[0] = w->channel;
  o[1] = w->instance;
  o[2] = w->root;
  o[3] = w->persona;
  o[4] = w->revoked;
  o[5] = w->recovered;
  o[6] = (uint8_t)w->seq;
  o[7] = (uint8_t)(w->seq >> 8);
  cp(o + 8, w->id, 32);
  cp(o + 40, w->key, 32);
  cp(o + 72, w->next, 32);
  cp(o + 104, w->key0, 32);
  cp(o + 136, w->next0, 32);
}

int an_writer_get(const an_store *s, int w, uint8_t out[AN_WRITER_BYTES]) {
  zero(out, AN_WRITER_BYTES);
  if (!s->sealed || w < 0 || w >= s->writer_count) return 0;
  writer_bytes(&s->writer[w], out);
  return 1;
}

int an_fingerprint(const an_store *s, int person, uint8_t out[32]) {
  const an_person *p;
  zero(out, 32);
  if (!s->sealed) return AN_E_STATE;
  if (!is_companion(s, person)) return AN_E_ARG;
  p = &s->person[person];
  fingerprint_of(s, person, p->version, p->name, p->name_len, p->core, p->give, out);
  return AN_OK;
}

int an_definition(const an_store *s, uint8_t out[32]) {
  an_sha256_ctx c;
  uint8_t f[32];
  int k, j, p;
  zero(out, 32);
  if (!s->sealed) return AN_E_STATE;
  dom_begin(&c, "anchor definition v1");
  h_u8(&c, s->persons);
  h_u8(&c, s->traits);
  h_u8(&c, s->sigma_num);
  h_u8(&c, s->sigma_den);
  h_u8(&c, s->saturation);
  h_u8(&c, s->voices_min);
  h_u8(&c, s->distinct_min);
  for (k = 0; k < s->traits; k++) {
    h_u8(&c, s->trait[k].count);
    for (j = 0; j < s->trait[k].count; j++) {
      h_u8(&c, s->trait[k].len[j]);
      an_sha256_update(&c, s->trait[k].text[j], s->trait[k].len[j]);
    }
  }
  for (p = 1; p < s->persons; p++) {
    an_fingerprint(s, p, f);
    an_sha256_update(&c, f, 32);
  }
  an_sha256_final(&c, out);
  return AN_OK;
}

int an_head(const an_store *s, uint8_t out[32]) {
  zero(out, 32);
  if (!s->ready) return AN_E_STATE;
  cp(out, s->head, 32);
  return AN_OK;
}

static int view_count(const an_store *s) {
  int h, a, k, n = 0;
  for (h = 1; h < s->persons; h++)
    for (a = 0; a < s->persons; a++)
      for (k = 0; k < s->traits; k++) n += s->view[h][a][k].used;
  return n;
}

int an_info(const an_store *s, uint32_t out[AN_INFO_WORDS]) {
  out[0] = s->ready;
  out[1] = s->sealed;
  out[2] = s->persons;
  out[3] = s->traits;
  out[4] = s->episode;
  out[5] = s->events;
  out[6] = s->refused;
  out[7] = s->issued;
  out[8] = s->writer_count;
  out[9] = s->used_count;
  out[10] = s->token_count;
  out[11] = (uint32_t)view_count(s);
  return AN_OK;
}

int an_distance(const an_store *s, int p, int q) {
  if (!s->sealed || !is_companion(s, p) || !is_companion(s, q) || p == q) return -1;
  return dist_arrays(s->traits, s->person[p].core, s->person[p].give, s->person[q].core,
                     s->person[q].give);
}

int an_verbatim(const an_store *s, const uint8_t *line, int len, int out[2]) {
  int k, v;
  out[0] = -1;
  out[1] = AN_NONE;
  if (!s->ready || len < 0 || len > AN_LINE_MAX) return -1;
  if (!verbatim(s, line, len, &k, &v)) return 0;
  out[0] = k;
  out[1] = v;
  return 1;
}

int an_line_id(const uint8_t *line, int len, uint8_t out[16]) {
  uint8_t d[32];
  zero(out, 16);
  if (len < 0 || len > AN_LINE_MAX) return -1;
  an_sha256(line, (uint32_t)len, d);
  cp(out, d, 16);
  return 0;
}

/* -------------------------------------------------------------- persistence */

/* Writes the file body (without the trailing digest) when o is not null; always returns its size.
 * Layout, little-endian: docs/identity-anchors.md, "The saved file". */
static int emit(const an_store *s, uint8_t *o) {
  int n = 0, i, k, j, p, h, a;
#define B(v)                        \
  do {                              \
    if (o) o[n] = (uint8_t)(v);     \
    n++;                            \
  } while (0)
#define U16(v)                      \
  do {                              \
    unsigned v_ = (unsigned)(v);    \
    B(v_);                          \
    B(v_ >> 8);                     \
  } while (0)
#define U32(v)                      \
  do {                              \
    uint32_t v_ = (uint32_t)(v);    \
    B(v_);                          \
    B(v_ >> 8);                     \
    B(v_ >> 16);                    \
    B(v_ >> 24);                    \
  } while (0)
#define BYTES(ptr, len)                           \
  do {                                            \
    int i_;                                       \
    for (i_ = 0; i_ < (int)(len); i_++) B((ptr)[i_]); \
  } while (0)
  B('A'); B('N'); B('C'); B('H');
  U16(1);
  B(s->persons); B(s->traits); B(s->sigma_num); B(s->sigma_den);
  B(s->saturation); B(s->voices_min); B(s->distinct_min); B(1);
  U16(s->episode);
  U32(s->events);
  U32(s->refused);
  U32(s->issued);
  BYTES(s->base, 32);
  BYTES(s->head, 32);
  B(s->ring_count);
  for (i = 0; i < s->ring_count; i++) BYTES(s->ring[(s->ring_first + i) % AN_RING], 16);
  for (k = 0; k < s->traits; k++) {
    B(s->trait[k].count);
    for (j = 0; j < s->trait[k].count; j++) {
      B(s->trait[k].len[j]);
      BYTES(s->trait[k].text[j], s->trait[k].len[j]);
    }
  }
  for (p = 1; p < s->persons; p++) {
    const an_person *x = &s->person[p];
    B(x->version);
    B(x->name_len);
    BYTES(x->name, x->name_len);
    for (k = 0; k < s->traits; k++) B((uint8_t)x->core[k]);
    for (k = 0; k < s->traits; k++) B(x->give[k]);
    for (k = 0; k < s->traits; k++) B((uint8_t)x->expressed[k]);
  }
  B(s->writer_count);
  for (i = 0; i < s->writer_count; i++) {
    uint8_t wb[AN_WRITER_BYTES];
    writer_bytes(&s->writer[i], wb);
    BYTES(wb, AN_WRITER_BYTES);
  }
  U16(s->used_count);
  for (i = 0; i < s->used_count; i++) BYTES(s->used[i], 32);
  B(s->token_count);
  for (i = 0; i < s->token_count; i++) {
    B(s->token[i].kind);
    U32(s->token[i].issued);
    BYTES(s->token[i].target, 32);
    BYTES(s->token[i].token, 16);
  }
  U16(view_count(s));
  for (h = 1; h < s->persons; h++)
    for (a = 0; a < s->persons; a++)
      for (k = 0; k < s->traits; k++)
        if (s->view[h][a][k].used) {
          uint8_t vb[AN_VIEW_BYTES];
          view_bytes(h, a, k, &s->view[h][a][k], vb);
          BYTES(vb, AN_VIEW_BYTES);
        }
#undef B
#undef U16
#undef U32
#undef BYTES
  return n;
}

int an_save_size(const an_store *s) {
  if (!s->sealed) return AN_E_STATE;
  return emit(s, 0) + 32;
}

int an_save(const an_store *s, uint8_t *out, int cap) {
  int n;
  if (!s->sealed) return AN_E_STATE;
  n = emit(s, 0);
  if (cap < n + 32) return AN_E_FULL;
  emit(s, out);
  an_sha256(out, (uint32_t)n, out + n);
  return n + 32;
}

/* The loader takes nothing on trust. It checks every range and every invariant the rule
 * maintains, in file order, into a staging store, and changes the target only on success. */
static an_store an_stage;

typedef struct {
  const uint8_t *b;
  int p, end;
} rd_t;

static int need(const rd_t *r, int n) { return n >= 0 && r->p + n <= r->end; }
static int g8(rd_t *r) { return r->b[r->p++]; }
static int g16(rd_t *r) {
  int v = r->b[r->p] | (r->b[r->p + 1] << 8);
  r->p += 2;
  return v;
}
static uint32_t g32(rd_t *r) {
  uint32_t v = (uint32_t)r->b[r->p] | ((uint32_t)r->b[r->p + 1] << 8) |
               ((uint32_t)r->b[r->p + 2] << 16) | ((uint32_t)r->b[r->p + 3] << 24);
  r->p += 4;
  return v;
}
static void gbytes(rd_t *r, uint8_t *d, int n) {
  cp(d, r->b + r->p, n);
  r->p += n;
}

static int in_band(const an_person *x, int k, int v) {
  return v >= x->core[k] - x->give[k] && v <= x->core[k] + x->give[k] && v >= -2 && v <= 2;
}

int an_load(an_store *s, const uint8_t *in, int len) {
  an_store *t = &an_stage;
  rd_t r;
  uint8_t d[32], buf[48];
  int i, j, k, p, n, K, sn, sd, sat, m, delta, rc, wc, uc, tc, vc, prev;
  uint32_t seqsum = 0;
  if (len < 128) return AN_L_SHORT;
  if (in[0] != 'A' || in[1] != 'N' || in[2] != 'C' || in[3] != 'H' || in[4] != 1 || in[5] != 0)
    return AN_L_MAGIC;
  an_sha256(in, (uint32_t)(len - 32), d);
  if (!same(d, in + len - 32, 32)) return AN_L_DIGEST;
  zero(t, (unsigned)sizeof(an_store));
  r.b = in;
  r.p = 6;
  r.end = len - 32;
  n = g8(&r); K = g8(&r); sn = g8(&r); sd = g8(&r); sat = g8(&r); m = g8(&r); delta = g8(&r);
  if (n < 2 || n > AN_PERSONS || K < 1 || K > AN_TRAITS || sd < 1 || sd > 100 || sn > sd ||
      sat < 1 || sat > 64 || m < 2 || m > 7 || delta < 1 || g8(&r) != 1)
    return AN_L_PARAM;
  t->persons = (uint8_t)n; t->traits = (uint8_t)K; t->sigma_num = (uint8_t)sn;
  t->sigma_den = (uint8_t)sd; t->saturation = (uint8_t)sat; t->voices_min = (uint8_t)m;
  t->distinct_min = (uint8_t)delta;
  t->episode = (uint16_t)g16(&r);
  t->events = g32(&r);
  t->refused = g32(&r);
  t->issued = g32(&r);
  if (t->refused > t->events) return AN_L_COUNTER;
  gbytes(&r, t->base, 32);
  gbytes(&r, t->head, 32);
  /* journal */
  if (!need(&r, 1)) return AN_L_SHORT;
  rc = g8(&r);
  if (rc > AN_RING || (uint32_t)rc > t->events) return AN_L_JOURNAL;
  if (!need(&r, 16 * rc)) return AN_L_SHORT;
  cp(d, t->base, 32);
  for (i = 0; i < rc; i++) {
    gbytes(&r, t->ring[i], 16);
    cp(buf, d, 32);
    cp(buf + 32, t->ring[i], 16);
    an_sha256(buf, 48, d);
  }
  if (!same(d, t->head, 32)) return AN_L_JOURNAL;
  t->ring_first = 0;
  t->ring_count = (uint8_t)rc;
  /* traits */
  for (k = 0; k < K; k++) {
    an_trait *x = &t->trait[k];
    int c;
    if (!need(&r, 1)) return AN_L_SHORT;
    c = g8(&r);
    if (c < 1 || c > AN_LABELS) return AN_L_TRAIT;
    for (j = 0; j < c; j++) {
      int l;
      if (!need(&r, 1)) return AN_L_SHORT;
      l = g8(&r);
      if (l < 1 || l > AN_LABEL_MAX) return AN_L_TRAIT;
      if (!need(&r, l)) return AN_L_SHORT;
      if (!label_valid(r.b + r.p, l) || label_exists(t, r.b + r.p, l)) return AN_L_TRAIT;
      x->len[j] = (uint8_t)l;
      gbytes(&r, x->text[j], l);
      x->count++;
    }
  }
  /* persons */
  for (p = 1; p < n; p++) {
    an_person *x = &t->person[p];
    int nl;
    if (!need(&r, 2)) return AN_L_SHORT;
    x->version = (uint8_t)g8(&r);
    nl = g8(&r);
    if (x->version < 1 || nl < 1 || nl > AN_NAME_MAX) return AN_L_PERSON;
    if (!need(&r, nl)) return AN_L_SHORT;
    if (!name_valid(r.b + r.p, nl)) return AN_L_PERSON;
    x->name_len = (uint8_t)nl;
    gbytes(&r, x->name, nl);
    if (!need(&r, 3 * K)) return AN_L_SHORT;
    for (k = 0; k < K; k++) x->core[k] = (int8_t)s8(g8(&r));
    for (k = 0; k < K; k++) x->give[k] = (uint8_t)g8(&r);
    for (k = 0; k < K; k++) x->expressed[k] = (int8_t)s8(g8(&r));
    for (k = 0; k < K; k++)
      if (x->core[k] < -2 || x->core[k] > 2 || x->give[k] > 2 || !in_band(x, k, x->expressed[k]))
        return AN_L_PERSON;
    x->defined = 1;
  }
  if (!definitions_distinct(t)) return AN_L_PERSON;
  /* writers */
  if (!need(&r, 1)) return AN_L_SHORT;
  wc = g8(&r);
  if (wc > AN_WRITERS) return AN_L_WRITER;
  for (i = 0; i < wc; i++) {
    an_writer *w = &t->writer[i];
    if (!need(&r, AN_WRITER_BYTES)) return AN_L_SHORT;
    w->channel = (uint8_t)g8(&r);
    w->instance = (uint8_t)g8(&r);
    w->root = (uint8_t)g8(&r);
    w->persona = (uint8_t)g8(&r);
    w->revoked = (uint8_t)g8(&r);
    w->recovered = (uint8_t)g8(&r);
    w->seq = (uint16_t)g16(&r);
    gbytes(&r, w->id, 32);
    gbytes(&r, w->key, 32);
    gbytes(&r, w->next, 32);
    gbytes(&r, w->key0, 32);
    gbytes(&r, w->next0, 32);
    if (w->channel > AN_SYSTEM || w->root > 15 || !binding_ok(t, w->channel, w->persona) ||
        w->revoked > 1 || w->recovered > w->seq)
      return AN_L_WRITER;
    if (allzero(w->key, 32) || allzero(w->next, 32) || allzero(w->key0, 32) || allzero(w->next0, 32) ||
        same(w->key, w->next, 32) || same(w->key0, w->next0, 32))
      return AN_L_WRITER;
    if (w->seq == 0 ? !(same(w->key, w->key0, 32) && same(w->next, w->next0, 32))
                    : (same(w->key, w->key0, 32) || same(w->next, w->next0, 32)))
      return AN_L_WRITER;
    writer_id(w->channel, w->instance, w->root, w->persona, w->key0, w->next0, (uint32_t)i, d);
    if (!same(d, w->id, 32)) return AN_L_WRITER;
    for (j = 0; j < i; j++)
      if (t->writer[j].channel == w->channel && t->writer[j].instance == w->instance)
        return AN_L_WRITER;
    seqsum += w->seq;
  }
  t->writer_count = (uint8_t)wc;
  /* no digest is bound to two identities, nor twice to one */
  {
    const uint8_t *list[4 * AN_WRITERS];
    int ln = 0;
    for (i = 0; i < wc; i++) {
      const an_writer *w = &t->writer[i];
      list[ln++] = w->key0;
      list[ln++] = w->next0;
      if (w->seq > 0) {
        list[ln++] = w->key;
        list[ln++] = w->next;
      }
    }
    for (i = 0; i < ln; i++)
      for (j = i + 1; j < ln; j++)
        if (same(list[i], list[j], 32)) return AN_L_WRITER;
  }
  /* digests ever bound */
  if (!need(&r, 2)) return AN_L_SHORT;
  uc = g16(&r);
  if (uc > AN_USED || (uint32_t)uc != 2u * ((uint32_t)wc + seqsum)) return AN_L_USED;
  if (!need(&r, 32 * uc)) return AN_L_SHORT;
  for (i = 0; i < uc; i++) {
    gbytes(&r, t->used[i], 32);
    if (allzero(t->used[i], 32)) return AN_L_USED;
    for (j = 0; j < i; j++)
      if (same(t->used[i], t->used[j], 32)) return AN_L_USED;
  }
  t->used_count = (uint16_t)uc;
  for (i = 0; i < wc; i++) {
    const an_writer *w = &t->writer[i];
    if (!used_has(t, w->key) || !used_has(t, w->next) || !used_has(t, w->key0) ||
        !used_has(t, w->next0))
      return AN_L_USED;
  }
  /* tokens */
  if (!need(&r, 1)) return AN_L_SHORT;
  tc = g8(&r);
  if (tc > AN_TOKENS || (uint32_t)tc > t->issued) return AN_L_TOKEN;
  for (i = 0; i < tc; i++) {
    an_token *x = &t->token[i];
    if (!need(&r, 53)) return AN_L_SHORT;
    x->kind = (uint8_t)g8(&r);
    x->issued = g32(&r);
    gbytes(&r, x->target, 32);
    gbytes(&r, x->token, 16);
    if (x->kind < AN_CONFIRM || x->kind > AN_RECOVER || x->issued > t->events ||
        (i > 0 && x->issued <= t->token[i - 1].issued))
      return AN_L_TOKEN;
    for (j = 0; j < i; j++)
      if (same(t->token[j].token, x->token, 16)) return AN_L_TOKEN;
  }
  t->token_count = (uint8_t)tc;
  /* views */
  if (!need(&r, 2)) return AN_L_SHORT;
  vc = g16(&r);
  if (vc > (n - 1) * (n - 1) * K) return AN_L_VIEW;
  prev = -1;
  for (i = 0; i < vc; i++) {
    uint8_t vb[AN_VIEW_BYTES];
    int h, a, idx, cls, depth, auth, level, corever, value, was, wset, born, last, b;
    an_view *v;
    if (!need(&r, AN_VIEW_BYTES)) return AN_L_SHORT;
    gbytes(&r, vb, AN_VIEW_BYTES);
    h = vb[0]; a = vb[1]; k = vb[2]; cls = vb[3]; depth = vb[4]; auth = vb[5]; level = vb[6];
    corever = vb[7]; value = s8(vb[8]); was = s8(vb[9]);
    born = vb[10] | (vb[11] << 8); last = vb[12] | (vb[13] << 8); wset = vb[14] | (vb[15] << 8);
    if (!is_companion(t, h) || a >= n || a == h || k >= K) return AN_L_VIEW;
    idx = (h * AN_PERSONS + a) * AN_TRAITS + k;
    if (idx <= prev) return AN_L_VIEW;
    prev = idx;
    if (cls < AN_FIRST || cls > AN_TOLD || value < -2 || value > 2 || level < 1 ||
        level > AN_LEVEL_MAX || born > last || last > t->episode)
      return AN_L_VIEW;
    if (was != AN_NONE && !(cls == AN_FIRST && was >= -2 && was <= 2 && was != value)) return AN_L_VIEW;
    if (wset == 0 || (wset >> wc) != 0) return AN_L_VIEW;
    if (cls == AN_FIRST) {
      if (depth != 0 || auth != (a == 0 ? 2 : 1)) return AN_L_VIEW;
      for (b = 0; b < wc; b++)
        if ((wset >> b) & 1)
          if (t->writer[b].persona != a) return AN_L_VIEW;
    } else if (cls == AN_READ) {
      if (a != 0 || depth != 0 || auth != 1) return AN_L_VIEW;
      for (b = 0; b < wc; b++)
        if ((wset >> b) & 1)
          if (t->writer[b].persona != 0) return AN_L_VIEW;
    } else {
      if (depth < 1 || depth > AN_DEPTH_MAX || auth != 1) return AN_L_VIEW;
    }
    if (a == 0 ? (corever != 0 || allzero(vb + 16, 16))
               : (corever < 1 || corever > t->person[a].version || !allzero(vb + 16, 16)))
      return AN_L_VIEW;
    if (a != 0 && corever == t->person[a].version && !in_band(&t->person[a], k, value))
      return AN_L_VIEW;
    v = &t->view[h][a][k];
    v->used = 1;
    v->cls = (uint8_t)cls;
    v->depth = (uint8_t)depth;
    v->auth = (uint8_t)auth;
    v->level = (uint8_t)level;
    v->corever = (uint8_t)corever;
    v->value = (int8_t)value;
    v->was = (int8_t)was;
    v->born = (uint16_t)born;
    v->last = (uint16_t)last;
    v->wset = (uint16_t)wset;
    cp(v->line, vb + 16, 16);
  }
  if (r.p != r.end) return AN_L_SHORT;
  t->ready = 1;
  t->sealed = 1;
  cp((uint8_t *)s, (const uint8_t *)t, (int)sizeof(an_store));
  return AN_OK;
}
