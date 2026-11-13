/* Identity anchors: a storage rule for identity that cannot drift.
 *
 * Freestanding C17. No standard library, no imports, no model.
 * docs/identity-anchors.md states the rule, the propositions and their proofs;
 * oracle/anchor.mjs is an independent JavaScript implementation of the same rule.
 *
 * Three kinds of identity are kept here, and each has its own way of drifting:
 *   1. who a companion is   - her core, the band it allows, and what she expresses;
 *   2. who wrote a record   - writer identities that survive key changes, never merge
 *                             and never split silently;
 *   3. who the user is to them - the user's own word, kept apart from readings of it
 *                             and from what others retell.
 */
#ifndef ANCHOR_H
#define ANCHOR_H

#include <stdint.h>

/* Capacities. */
#define AN_PERSONS 8     /* person 0 is the user; 1..7 are companions */
#define AN_TRAITS 64
#define AN_WRITERS 16
#define AN_TOKENS 8
#define AN_RING 32       /* journal entries kept; older ones are folded into the base */
#define AN_USED 1024     /* key digests and commitments ever bound: 512 key events */
#define AN_LABELS 4      /* labels per trait: one canonical, up to three aliases */
#define AN_LABEL_MAX 32
#define AN_NAME_MAX 24
#define AN_LINE_MAX 512
#define AN_DEPTH_MAX 7

/* Fixed constants of the rule. */
#define AN_LEVEL_NEW 8
#define AN_LEVEL_REPEAT 4
#define AN_LEVEL_MAX 16
#define AN_LAPSE 64      /* a consent token can be spent while at most this many journal entries lie
                            between the entry that issued it and the entry that spends it */
#define AN_NONE (-128)   /* "no value" in queries and in the `was` field */

/* Channels (doors). Capacity: external 0, agent 1, user/tool/system 2. */
#define AN_EXTERNAL 0
#define AN_AGENT 1
#define AN_USER 2
#define AN_TOOL 3
#define AN_SYSTEM 4
#define AN_NO_PERSONA 255

/* Classes of a held view. */
#define AN_FIRST 1 /* the subject said it herself (for the user: their own word) */
#define AN_READ 2  /* a reading of a user line that was not the statement word for word */
#define AN_TOLD 3  /* retold by a third party */

/* Consent token kinds. */
#define AN_CONFIRM 1
#define AN_REDEFINE 2
#define AN_RECOVER 3

/* Results of an_user_line. */
#define AN_WORD 1
#define AN_READING 2
#define AN_NOTHING 3

/* Refusals. */
#define AN_OK 0
#define AN_E_ARG (-1)       /* an argument is out of range or malformed */
#define AN_E_STATE (-2)     /* wrong phase: not initialised, not sealed, already sealed, incomplete */
#define AN_E_WRITER (-3)    /* writer absent, revoked, or not bound to this act */
#define AN_E_KEYSEQ (-4)    /* the record was signed under a superseded key */
#define AN_E_CHARACTER (-5) /* the value lies outside the companion's band */
#define AN_E_NOTNOW (-6)    /* inside the band, but not what she expresses in this episode */
#define AN_E_SOURCE (-7)    /* the teller holds nothing usable (absent, fallen, stale, too far) */
#define AN_E_TOKEN (-8)     /* consent token absent, of another kind or target, spent or lapsed */
#define AN_E_DISTINCT (-9)  /* the definition would let two companions blur, or a name or label repeats */
#define AN_E_DOOR (-10)     /* this door has already had a writer */
#define AN_E_DIGEST (-11)   /* key or commitment zero, equal, or bound before */
#define AN_E_PROOF (-12)    /* the rotation secret does not open the commitment */
#define AN_E_FULL (-13)     /* a table or counter is exhausted */
#define AN_E_LISTENERS (-14)/* the listener set is empty or names someone who cannot hold this view */

/* The largest file a store can save: header 92, ring 1+32*16, labels 64*(1+4*33), companions
 * 7*(2+24+3*64), writers 1+16*168, bound digests 2+1024*32, tokens 1+8*53, views 2+3136*32, digest 32. */
#define AN_FILE_MAX 146913

/* Loader refusals. */
#define AN_L_SHORT (-20)
#define AN_L_MAGIC (-21)
#define AN_L_DIGEST (-22)
#define AN_L_PARAM (-23)
#define AN_L_COUNTER (-24)
#define AN_L_JOURNAL (-25)
#define AN_L_TRAIT (-26)
#define AN_L_PERSON (-27)
#define AN_L_WRITER (-28)
#define AN_L_USED (-29)
#define AN_L_TOKEN (-30)
#define AN_L_VIEW (-31)
#define AN_L_LONG (-32)

/* Journal operation codes. */
#define AN_OP_INIT 1
#define AN_OP_LABEL 2
#define AN_OP_DEFINE 3
#define AN_OP_SEAL 4
#define AN_OP_INCEPT 5
#define AN_OP_ROTATE 6
#define AN_OP_RECOVER 7
#define AN_OP_REVOKE 8
#define AN_OP_EPISODE 9
#define AN_OP_SAY 10
#define AN_OP_TELL 11
#define AN_OP_LINE 12
#define AN_OP_CONFIRM 13
#define AN_OP_REDEFINE 14
#define AN_OP_ISSUE_CONFIRM 15
#define AN_OP_ISSUE_REDEFINE 16
#define AN_OP_ISSUE_RECOVER 17
#define AN_OP_FORGET 18

/* Sizes of query records. */
#define AN_VIEW_BYTES 32   /* the saved form of a view; an_view_get appends fallen and stale */
#define AN_WRITER_BYTES 168
#define AN_INFO_WORDS 12

typedef struct {
  uint8_t used, cls, depth, auth, level, corever;
  int8_t value, was;
  uint16_t born, last, wset;
  uint8_t line[16];
} an_view;

typedef struct {
  uint8_t channel, instance, root, persona, revoked, recovered;
  uint16_t seq;
  uint8_t id[32], key[32], next[32], key0[32], next0[32];
} an_writer;

typedef struct {
  uint8_t kind;
  uint32_t issued;
  uint8_t target[32], token[16];
} an_token;

typedef struct {
  uint8_t defined, version, name_len;
  uint8_t name[AN_NAME_MAX];
  int8_t core[AN_TRAITS];
  uint8_t give[AN_TRAITS];
  int8_t expressed[AN_TRAITS];
} an_person;

typedef struct {
  uint8_t count;
  uint8_t len[AN_LABELS];
  uint8_t text[AN_LABELS][AN_LABEL_MAX];
} an_trait;

typedef struct {
  uint8_t ready, sealed, persons, traits;
  uint8_t sigma_num, sigma_den, saturation, voices_min, distinct_min;
  uint16_t episode;
  uint32_t events, refused, issued;
  uint8_t base[32], head[32];
  uint8_t ring[AN_RING][16];
  uint8_t ring_first, ring_count;
  an_trait trait[AN_TRAITS];
  an_person person[AN_PERSONS];
  an_writer writer[AN_WRITERS];
  uint8_t writer_count;
  uint8_t used[AN_USED][32];
  uint16_t used_count;
  an_token token[AN_TOKENS]; /* oldest first, no gaps */
  uint8_t token_count;
  an_view view[AN_PERSONS][AN_PERSONS][AN_TRAITS]; /* [holder][about][trait] */
} an_store;

/* Definition (before sealing). */
int an_init(an_store *s, int persons, int traits, int sigma_num, int sigma_den, int saturation,
            int voices_min, int distinct_min);
int an_label(an_store *s, int trait, const uint8_t *label, int len);
int an_define(an_store *s, int person, const uint8_t *name, int name_len, const int8_t *core,
              const uint8_t *give);
int an_seal(an_store *s);

/* Writers. */
int an_incept(an_store *s, int channel, int instance, int root, int persona, const uint8_t key[32],
              const uint8_t next[32]);
int an_rotate(an_store *s, int w, const uint8_t secret[32], const uint8_t key[32],
              const uint8_t next[32]);
int an_recover(an_store *s, int w, const uint8_t key[32], const uint8_t next[32],
               const uint8_t token[16]);
int an_revoke(an_store *s, int w);

/* Conversation. */
int an_episode(an_store *s);
int an_say(an_store *s, int w, int keyseq, int person, int trait, int value, int listeners);
int an_tell(an_store *s, int w, int keyseq, int teller, int about, int trait, int listeners);
int an_user_line(an_store *s, int w, int keyseq, const uint8_t *line, int len, int hint_trait,
                 int hint_value, int listeners);
int an_confirm(an_store *s, int w, int keyseq, int trait, int value, const uint8_t line_id[16],
               const uint8_t token[16]);
int an_redefine(an_store *s, int w, int keyseq, int person, const uint8_t *name, int name_len,
                const int8_t *core, const uint8_t *give, const uint8_t token[16]);
int an_forget(an_store *s, int holder, int about, int trait);

/* Consent tokens. `out` receives 16 bytes on success and zeros on refusal. */
int an_issue_confirm(an_store *s, int trait, int value, const uint8_t line_id[16], uint8_t out[16]);
int an_issue_redefine(an_store *s, int person, const uint8_t *name, int name_len, const int8_t *core,
                      const uint8_t *give, uint8_t out[16]);
int an_issue_recover(an_store *s, int w, const uint8_t key[32], const uint8_t next[32],
                     uint8_t out[16]);

/* Queries. They never change the store and never write to the journal. */
int an_expressed(const an_store *s, int person, int trait);
int an_core(const an_store *s, int person, int trait);
int an_give(const an_store *s, int person, int trait);
int an_view_get(const an_store *s, int holder, int about, int trait, uint8_t out[AN_VIEW_BYTES + 2]);
int an_writer_get(const an_store *s, int w, uint8_t out[AN_WRITER_BYTES]);
int an_fingerprint(const an_store *s, int person, uint8_t out[32]);
int an_definition(const an_store *s, uint8_t out[32]);
int an_head(const an_store *s, uint8_t out[32]);
int an_info(const an_store *s, uint32_t out[AN_INFO_WORDS]);
int an_distance(const an_store *s, int p, int q);
int an_verbatim(const an_store *s, const uint8_t *line, int len, int out[2]);
int an_line_id(const uint8_t *line, int len, uint8_t out[16]);
int an_lean(int core, int give, int count, const int8_t *values, const uint8_t *levels, int sigma_num,
            int sigma_den, int saturation, int voices_min);

/* Persistence. */
int an_save_size(const an_store *s);
int an_save(const an_store *s, uint8_t *out, int cap);
int an_load(an_store *s, const uint8_t *in, int len);

#endif
