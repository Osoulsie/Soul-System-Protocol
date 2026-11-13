/* Native checks of the C store, meant to run under AddressSanitizer and UndefinedBehaviorSanitizer.
 *
 * - SHA-256 known answers (FIPS 180-4 examples and one million 'a').
 * - A long history with every operation. Writers are kept bound and current most of the time, so
 *   the accepting paths run as often as the refusing ones; one call in eight is deliberately wrong.
 * - After every step: each companion's expressed value is inside her band, and no two companions
 *   are closer than the guaranteed distance. Every 97 steps: save, reload, save again; the bytes
 *   must be identical and the history continues from the reloaded store.
 * - Every truncation of a saved file, 4,000 single-bit corruptions (with and without the digest
 *   recomputed) and 2,000 structured garbage files are handed to the loader.
 * Agreement with the JavaScript implementation is checked by the JavaScript tests. */
#include <stdio.h>
#include <string.h>
#include "../src/anchor.h"
#include "../src/sha256.h"

static int failures = 0;
#define CHECK(c)                                                            \
  do {                                                                      \
    if (!(c)) {                                                             \
      fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #c); \
      failures++;                                                           \
    }                                                                       \
  } while (0)

static uint32_t rs = 0x9e3779b9u;
static uint32_t rnd(void) {
  rs ^= rs << 13;
  rs ^= rs >> 17;
  rs ^= rs << 5;
  return rs;
}
static int pick(int n) { return (int)(rnd() % (uint32_t)n); }

static void hexeq(const uint8_t *d, const char *want) {
  char got[65];
  int i;
  for (i = 0; i < 32; i++) sprintf(got + 2 * i, "%02x", d[i]);
  CHECK(strcmp(got, want) == 0);
}

static void sha_known_answers(void) {
  static uint8_t million[1000000];
  uint8_t d[32];
  an_sha256((const uint8_t *)"", 0, d);
  hexeq(d, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  an_sha256((const uint8_t *)"abc", 3, d);
  hexeq(d, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  an_sha256((const uint8_t *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, d);
  hexeq(d, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  an_sha256((const uint8_t *)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            112, d);
  hexeq(d, "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
  memset(million, 'a', sizeof million);
  an_sha256(million, (uint32_t)sizeof million, d);
  hexeq(d, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

/* 32 bytes derived from (family, i); never all zero in practice. */
static void fill32(uint8_t *b, uint32_t family, uint32_t i) {
  uint8_t in[8];
  in[0] = (uint8_t)family; in[1] = (uint8_t)(family >> 8); in[2] = (uint8_t)(family >> 16); in[3] = (uint8_t)(family >> 24);
  in[4] = (uint8_t)i; in[5] = (uint8_t)(i >> 8); in[6] = (uint8_t)(i >> 16); in[7] = (uint8_t)(i >> 24);
  an_sha256(in, 8, b);
}

static an_store A, B;
static uint8_t file[1 << 18], file2[1 << 18];

static const char *LINES[] = {"I love storms", "i hate tea!", "I do not like storms.", "I don't like tea",
                              "I am undecided about storms", "Mika thinks I love storms", "I love storms?",
                              "  I   LOVE   thunderstorms  !!", "I like tea", "I don\xe2\x80\x99t like storms", ""};
#define NLINES ((int)(sizeof LINES / sizeof LINES[0]))

/* The writers this history keeps: for each person the writer that voices them now, plus a system writer. */
static int voice[4], sys_writer, next_instance = 10;
static uint32_t seed_of[AN_WRITERS], made = 1000;

static int incept_for(int persona) {
  uint8_t key[32], next[32], sec[32];
  int ch = persona == 0 ? AN_USER : persona == AN_NO_PERSONA ? AN_SYSTEM : AN_AGENT;
  uint32_t s = made++;
  int w;
  fill32(key, 1, made++);
  fill32(sec, 2, s);
  an_sha256(sec, 32, next);
  w = an_incept(&A, ch, next_instance++, persona == 0 ? 0 : 1 + pick(3), persona, key, next);
  if (w >= 0) seed_of[w] = s;
  return w;
}

static int seq(int w) { return w >= 0 && w < A.writer_count ? (int)A.writer[w].seq : 0; }

/* Journal entries and acceptances since `mark`, attributed to operation `op`; `mark` moves on. */
static uint32_t calls[14], accepted[14];
static void tally(int op, uint32_t mark[AN_INFO_WORDS]) {
  uint32_t now[AN_INFO_WORDS];
  an_info(&A, now);
  calls[op] += now[5] - mark[5];
  accepted[op] += (now[5] - mark[5]) - (now[6] - mark[6]);
  memcpy(mark, now, sizeof now);
}

static int listeners_without(int a, int b) {
  int m = 0, p;
  for (p = 1; p < 4; p++)
    if (p != a && p != b && pick(3)) m |= 1 << p;
  if (!m)
    for (p = 1; p < 4; p++)
      if (p != a && p != b) return 1 << p;
  return m;
}

static void history(void) {
  static const int8_t core[3][2] = {{-1, 0}, {-2, 2}, {2, 2}};
  static const uint8_t give[3][2] = {{1, 0}, {0, 0}, {0, 0}};
  static const char *opname[14] = {"say", "line", "tell", "episode", "confirm", "rotate", "recover",
                                   "revoke", "redefine", "forget", "wrong", "query", "issue", "incept"};
  const char *names[3] = {"Simoa", "Mika", "Neris"};
  uint8_t key[32], next[32], sec[32], tok[16], line_id[16];
  int step, q, n, reloads = 0, len = 0, i;
  uint32_t peak_views = 0;
  CHECK(an_init(&A, 4, 2, 3, 10, 16, 2, 1) == AN_OK);
  CHECK(an_label(&A, 0, (const uint8_t *)"storms", 6) == AN_OK);
  CHECK(an_label(&A, 0, (const uint8_t *)"thunderstorms", 13) == AN_OK);
  CHECK(an_label(&A, 1, (const uint8_t *)"tea", 3) == AN_OK);
  for (q = 0; q < 3; q++)
    CHECK(an_define(&A, q + 1, (const uint8_t *)names[q], (int)strlen(names[q]), core[q], give[q]) == AN_OK);
  CHECK(an_seal(&A) == AN_OK);
  for (q = 0; q < 4; q++) CHECK((voice[q] = incept_for(q)) >= 0);
  CHECK((sys_writer = incept_for(AN_NO_PERSONA)) >= 0);

  for (step = 0; step < 60000; step++) {
    int dice = pick(100), op;
    uint32_t mark[AN_INFO_WORDS], after[AN_INFO_WORDS];
    an_info(&A, mark);
    if (dice < 25) { /* a companion speaks, in character nine times in ten */
      int p = 1 + pick(3), k = pick(2);
      int v = pick(10) ? an_expressed(&A, p, k) : pick(5) - 2;
      op = 0;
      an_say(&A, voice[p], seq(voice[p]), p, k, v, listeners_without(p, -1));
    } else if (dice < 45) { /* the user says something */
      const char *l = LINES[pick(NLINES)];
      op = 1;
      an_user_line(&A, voice[0], seq(voice[0]), (const uint8_t *)l, (int)strlen(l), pick(3) - 1, pick(5) - 2,
                   listeners_without(-1, -1));
    } else if (dice < 60) { /* a companion retells what she holds */
      int p = 1 + pick(3), a = pick(4);
      op = 2;
      if (a == p) a = 0;
      an_tell(&A, voice[p], seq(voice[p]), p, a, pick(2), listeners_without(p, a));
    } else if (dice < 68) {
      op = 3;
      an_episode(&A);
    } else if (dice < 76) { /* the user's yes to a reading */
      const char *l = LINES[pick(NLINES)];
      int k = pick(2), v = pick(5) - 2;
      op = 4;
      an_line_id((const uint8_t *)l, (int)strlen(l), line_id);
      if (an_issue_confirm(&A, k, v, line_id, tok) == AN_OK) {
        tally(12, mark);
        if (pick(8) == 0) tok[pick(16)] ^= 1; /* a token that was never issued */
        an_confirm(&A, voice[0], seq(voice[0]), k, v, line_id, tok);
      }
    } else if (dice < 80) { /* rotate a current writer, with the right secret most of the time */
      int w = pick(5) < 4 ? voice[pick(4)] : sys_writer;
      uint32_t s = made++;
      uint8_t ns[32];
      op = 5;
      fill32(sec, 2, pick(10) ? seed_of[w] : made++);
      fill32(key, 1, made++);
      fill32(ns, 2, s);
      an_sha256(ns, 32, next);
      if (an_rotate(&A, w, sec, key, next) == AN_OK) seed_of[w] = s;
    } else if (dice < 83) { /* recover a writer whose secret was lost, with consent */
      int w = voice[pick(4)];
      uint32_t s = made++;
      uint8_t ns[32];
      op = 6;
      fill32(key, 1, made++);
      fill32(ns, 2, s);
      an_sha256(ns, 32, next);
      if (an_issue_recover(&A, w, key, next, tok) == AN_OK) {
        tally(12, mark);
        if (an_recover(&A, w, key, next, tok) == AN_OK) seed_of[w] = s;
      }
    } else if (dice < 84) { /* revoke a voice and give the persona a new one on a fresh door */
      int p = pick(4);
      op = 7;
      if (A.writer_count < AN_WRITERS && A.used_count + 2 <= AN_USED && an_revoke(&A, voice[p]) == AN_OK) {
        int w;
        tally(7, mark);
        w = incept_for(p);
        tally(13, mark);
        if (w >= 0) voice[p] = w;
      }
    } else if (dice < 87) { /* a consented change of who a companion is */
      int p = 1 + pick(3), k;
      int8_t c2[2];
      uint8_t g2[2];
      op = 8;
      for (k = 0; k < 2; k++) {
        c2[k] = (int8_t)(pick(5) - 2);
        g2[k] = (uint8_t)pick(3);
      }
      if (an_issue_redefine(&A, p, (const uint8_t *)names[p - 1], (int)strlen(names[p - 1]), c2, g2, tok) == AN_OK) {
        tally(12, mark);
        an_redefine(&A, pick(2) ? voice[0] : sys_writer, pick(2) ? seq(voice[0]) : seq(sys_writer), p,
                    (const uint8_t *)names[p - 1], (int)strlen(names[p - 1]), c2, g2, tok);
      }
    } else if (dice < 88) {
      op = 9;
      an_forget(&A, pick(5) - 1, pick(5) - 1, pick(3) - 1);
    } else if (dice < 96) { /* deliberately wrong calls of every kind */
      const char *l = LINES[pick(NLINES)];
      op = 10;
      switch (pick(8)) {
        case 0: an_say(&A, pick(18) - 1, pick(4) - 1, pick(6) - 1, pick(4) - 1, pick(7) - 3, (int)rnd()); break;
        case 1: an_tell(&A, pick(18) - 1, pick(3), pick(6) - 1, pick(6) - 1, pick(4) - 1, (int)rnd()); break;
        case 2: an_user_line(&A, pick(18) - 1, pick(3), (const uint8_t *)l, pick(4) ? (int)strlen(l) : 513 + pick(100),
                             pick(5) - 2, pick(9) - 4, (int)rnd()); break;
        case 3: fill32(sec, 9, made++); fill32(key, 1, made++); fill32(next, 1, made++);
                an_rotate(&A, pick(18) - 1, sec, key, next); break;
        case 4: fill32(key, 1, made++); an_incept(&A, pick(7) - 1, pick(300) - 20, pick(18) - 1, pick(260) - 2, key, pick(2) ? key : next); break;
        case 5: an_label(&A, 0, (const uint8_t *)"late", 4); an_seal(&A); break;
        case 6: { uint8_t t32[32]; fill32(t32, 3, made++); memcpy(tok, t32, 16);
                  an_confirm(&A, voice[0], seq(voice[0]), pick(4) - 1, pick(7) - 3, line_id, tok); } break;
        default: an_forget(&A, pick(9) - 3, pick(9) - 3, pick(9) - 3); break;
      }
    } else { /* queries never change anything */
      uint8_t out[AN_WRITER_BYTES];
      int o2[2];
      op = 11;
      an_view_get(&A, pick(5), pick(5), pick(3), out);
      an_writer_get(&A, pick(17), out);
      an_fingerprint(&A, pick(5), out);
      an_definition(&A, out);
      {
        const char *l = LINES[pick(NLINES)];
        an_verbatim(&A, (const uint8_t *)l, (int)strlen(l), o2);
      }
      an_head(&A, out);
    }
    tally(op, mark);
    an_info(&A, after);
    if (after[11] > peak_views) peak_views = after[11];
    /* every expressed value lies inside the band; no two companions come closer than their distance */
    for (q = 1; q < 4; q++)
      for (n = 0; n < 2; n++) {
        int e = an_expressed(&A, q, n), c = an_core(&A, q, n), g = an_give(&A, q, n);
        CHECK(e >= c - g && e <= c + g && e >= -2 && e <= 2);
      }
    for (q = 1; q < 4; q++)
      for (n = q + 1; n < 4; n++) {
        int d = 0, k;
        for (k = 0; k < 2; k++) {
          int x = an_expressed(&A, q, k) - an_expressed(&A, n, k);
          d += x < 0 ? -x : x;
        }
        CHECK(an_distance(&A, q, n) >= 1 && d >= an_distance(&A, q, n));
      }
    if (step % 97 == 0) {
      int len2;
      len = an_save(&A, file, (int)sizeof file);
      CHECK(len > 0);
      CHECK(an_load(&B, file, len) == AN_OK);
      len2 = an_save(&B, file2, (int)sizeof file2);
      CHECK(len2 == len && memcmp(file, file2, (size_t)len) == 0);
      memcpy(&A, &B, sizeof A); /* continue from the reloaded store */
      reloads++;
    }
  }

  len = an_save(&A, file, (int)sizeof file);
  CHECK(len > 0);
  {
    int cut, refused_flip = 0, refused_recomputed = 0, accepted_recomputed = 0;
    for (cut = 0; cut < len; cut++) CHECK(an_load(&B, file, cut) < 0);
    for (i = 0; i < 4000; i++) {
      int at = pick(len), lr;
      uint8_t old = file[at];
      file[at] = (uint8_t)(file[at] ^ (1u << pick(8)));
      lr = an_load(&B, file, len);
      CHECK(lr == AN_L_DIGEST || lr == AN_L_MAGIC);
      refused_flip += lr < 0;
      if (at < len - 32) {
        an_sha256(file, (uint32_t)(len - 32), file + len - 32);
        lr = an_load(&B, file, len);
        if (lr < 0) refused_recomputed++; else accepted_recomputed++;
      }
      file[at] = old;
      an_sha256(file, (uint32_t)(len - 32), file + len - 32);
    }
    CHECK(an_load(&B, file, len) == AN_OK);
    for (i = 0; i < 2000; i++) { /* garbage behind a valid header, digest made to match */
      int glen = 128 + pick(4000), j;
      for (j = 0; j < glen - 32; j++) file2[j] = (uint8_t)rnd();
      file2[0] = 'A'; file2[1] = 'N'; file2[2] = 'C'; file2[3] = 'H'; file2[4] = 1; file2[5] = 0;
      an_sha256(file2, (uint32_t)(glen - 32), file2 + glen - 32);
      CHECK(an_load(&B, file2, glen) < 0);
    }
    {
      uint32_t info[AN_INFO_WORDS];
      an_info(&A, info);
      printf("{\"steps\":60000,\"reloads\":%d,\"saved_bytes\":%d,\"events\":%u,\"refused\":%u,\"writers\":%u,"
             "\"views_now\":%u,\"views_peak\":%u,\"flips_refused\":%d,\"flips_with_digest_refused\":%d,"
             "\"flips_with_digest_accepted\":%d}\n",
             reloads, len, info[5], info[6], info[8], info[11], peak_views, refused_flip, refused_recomputed,
             accepted_recomputed);
    }
  }
  for (i = 0; i < 14; i++) printf("  %-8s journaled %6u accepted %6u\n", opname[i], calls[i], accepted[i]);
}

int main(void) {
  sha_known_answers();
  history();
  if (failures) {
    fprintf(stderr, "%d native checks failed\n", failures);
    return 1;
  }
  printf("native checks passed\n");
  return 0;
}
