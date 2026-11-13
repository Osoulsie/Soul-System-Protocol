# Identity Anchors: a storage rule for identity that cannot drift

13 November 2026 · Soul System Protocol

## Abstract

A companion that remembers can stop being herself. Three things drift, and each has its own mechanism. **Who she is** drifts when what she says about herself is computed from what she said last time, when others' opinions pull her a step at a time without limit, when one voice repeated or retold counts as many, or when two companions are pulled until they cannot be told apart. **Who wrote a record** drifts when an identity is a key, so that a lost key, a new device or a model switch makes the same source a new writer, two sources share one, and a revocation stays behind with the old key. **Who the user is to them** drifts when a parser's reading of a line is stored as the user's own word, when a retelling changes on the way, or when a change of mind is averaged with what came before.

This paper describes **identity anchors**, a storage rule that holds all three in place, and one implementation of it: freestanding C compiled to WebAssembly, an independent JavaScript implementation that agrees with it byte for byte, and tests. The rule is small:

- A companion's **core** is fixed, and changes only with the user's consent to that exact change. What she **expresses** is computed afresh at each conversation from her core and the first-hand views of at least two other people, and never leaves a **band** around the core.
- A **writer** is an identity fixed at inception; keys change under it by pre-committed rotation or consented recovery; no key is ever bound twice; a door is used once.
- The **user's word** is what the user said, word for word. Anything else read from a line is a **reading**, which never replaces the word and becomes it only with the user's yes. A retelling copies what the teller holds.

Each property is stated and proved (sections 4 to 6). The proofs are written out and have not been checked by a machine. The code is tested, exhaustively over small cases and at random over large ones; it is not verified. Section 10 says which claim rests on which kind of evidence, and section 11 what the rule does not do.

The rule extends **recursive min-caps** (`a(v) = min(cap(o(v)), min a(p))`), which bounds what a record may be used for. Min-caps does not bound what a record *says* about who someone is. Anchors do, and every view they keep still obeys min-caps (section 7).

## 1. Introduction

Simoa 10.15.0 has three companions, Simoa, Mika and Neris, a crew memory in C with a JavaScript reference, and a kernel whose agents carry signed passports. Much of it already resists drift. A companion's own view moves at most one step from her nature, and a nature of -2 or 2 never moves. First-hand evidence outranks retellings. The crew's reader does not let the user assert a companion's tastes. The C and JavaScript `lean` functions agree on 4.5 million comparisons made for this paper.

The cases below were reproduced against the shipped 10.15.0 code (section 8 says how). Each is a way identity drifts:

1. The user says "I love tea", then "I like tea". The memory holds 1.5, and the sheet reads "You love tea".
2. The reader stores "Mika thinks I love storms", "My brother says I hate tea" and "I love storms, said nobody ever" as the user's own stance, at the user's authority, kept until the user changes it.
3. A retelling's value is whatever the caller passes. The memory stored "Mika loves storms" in Simoa from Neris, while Neris held, first-hand, that Mika hates them.
4. The memory records a companion "saying" something about herself that contradicts her nature (Mika hating rain, which she likes). Nothing checks a statement against who she is.
5. In one conversation a companion's stance on a subject has three sources: crew talk reads the snapshot taken when the conversation began, the Text scene reads the live lean, and the Eat scene reads her innate taste.
6. SoulShield keys its stored identities by the page's path. When nothing is stored there (cleared storage, a new device, the same app served from another path), it mints new keys and passports for the host and all three companions, with no link to the old ones.

**What is claimed.** A store under this rule keeps each companion within a stated band of her definition on every history, however long. It never lets conversation change a definition. It keeps any two companions at least a stated distance apart. It keeps writer identities through key changes, never merging or silently splitting them. It keeps the user's word exactly as said. Each claim is a proposition with a proof, and each is tested.

**What is not claimed.** The rule says nothing about truth. It trusts the host to stamp the channel a write came through and to verify signatures. It does not stop code inside the same trust boundary. It does not model a language model's wording, only stances on declared traits and names. It is not yet wired into Simoa. Section 11 has the full list.

## 2. Three kinds of drift

**Companion drift.** Let `c_X(k)` be what companion X is defined to be on trait k, and `e_X(k)` what she expresses. She drifts if `e_X(k)` can leave a bound around `c_X(k)`, or if her definition changes through any channel other than a deliberate redefinition. It also counts as drift if her expression depends on her own past expression, so that changes compound, or if two companions can come to express the same thing on everything.

**Writer drift.** A writer drifts if a change of key, device or model makes the same source a new identity (a split). It also drifts if two sources come to share an identity (a merge), if an identity changes when its key does, or if a revocation does not follow the identity to its new keys.

**User-picture drift.** A companion's picture of the user drifts if what she holds as the user's own word on a subject is anything other than the last thing the user said to her, plainly, on it.

## 3. The construction

### 3.1 Persons, traits, cores and bands

A store has persons `0..n-1` (n ≤ 8): person 0 is the user, the rest are companions. It has traits `0..K-1` (K ≤ 64), each with one to four labels, such as `tea`, or `storms` and `thunderstorms`. Every label is distinct across the whole store.

Each companion X has a name and, for each trait k, a **core** `c_X(k)` in -2..2 (hates, does not like, undecided, likes, loves) and a **give** `g_X(k)` in 0..2. Her **band** is

```text
B_X(k) = [c_X(k) - g_X(k), c_X(k) + g_X(k)] ∩ [-2, 2]
```

The **distance** between companions X and Y is

```text
D(X, Y) = Σ_k max(0, |c_X(k) - c_Y(k)| - g_X(k) - g_Y(k))
```

Sealing a definition requires distinct names (case-insensitive) and `D(X, Y) ≥ δ` for every pair, with δ ≥ 1 a parameter. Under 10.15.0's own rule (a stance of ±2 never moves, any other may move one step), Simoa's 31 topics give D = 14 for Simoa and Mika, 9 for Simoa and Neris, and 9 for Mika and Neris.

### 3.2 Views

A companion H holds at most one **view** about each other person A on each trait k. No companion holds a view about herself. A view has a value, a class, a depth, an authority, a level (1..16, its weight), the version of A's core when it was made, the set of writers it stands on, the episode it was made and last renewed, the value it replaced (if it corrected one), and a 16-byte line identifier.

| Class | Made by | Authority | Depth |
| --- | --- | --- | --- |
| FIRST | A said it to H herself; for the user, their own word | 2 for the user, 1 for a companion | 0 |
| READ | a reading of a user line that was not the statement word for word | 1 | 0 |
| TOLD | a third person passed on what she held | min(1, the source's) | source's + 1 |

A new view takes H's slot as follows. Here "live" means that no writer the view stands on is revoked (otherwise it has **fallen**). For a view about a companion, it also means it was made under her current core version (otherwise it is **stale**).

- FIRST takes any slot. If the slot held a live FIRST of another value, that value is kept as "before".
- READ takes a slot holding READ or TOLD, never a live FIRST.
- TOLD takes a slot holding TOLD of the same or greater depth, never a live FIRST or READ.
- A fallen or stale view gives way to anything.

A repeat of the same value raises the level by 4 (at most 16); anything else starts at 8. At each episode every level falls by one, and a view at level 1 is dropped, except the user's FIRST views, which stay at 1 for good.

### 3.3 Episodes and what she expresses

An **episode** is a conversation. At its start the store fades levels and then recomputes, for every companion X and trait k, what she expresses. Her **voices** are the live FIRST views she holds about other persons on k. With σ = σn/σd ≤ 1, saturation W and at least m voices (m ≥ 2):

```text
S = Σ level,  T = Σ level · value,  h = σ · min(S, W) / W,  u = (1 - h) · c + h · T/S
e = clamp( round_half_away_from_zero(u), c - g, c + g )        (and e = c when there are fewer than m voices)
```

All of this is integer arithmetic: `u = U/D` with `D = σd·W·S` and `U = c·D + σn·min(S,W)·(T − c·S)`, and `|U| ≤ 4,300,800`. It has the shape of 10.15.0's Friedkin–Johnsen lean: `u = (1 − h)·nature + h·mean`, rounded half away from zero and clamped. There are three changes. Only first-hand voices count, the weights are integer levels, and the one-step clamp becomes a per-trait give. The defaults are σ = 3/10, W = 16 and m = 2.

The result is stored and does not change until the next episode, except when she is redefined. A companion's first-hand statement about herself is admitted only if it equals what she expresses in this episode. Outside her band it is refused as out of character; inside the band but different, it is refused as "not now".

### 3.4 Writers

A **writer** is registered at a **door** (a channel and an instance number) with a **root class** and a **persona**. A user door voices the user, an agent door voices exactly one companion, and other doors (tool, system, external) voice nobody. Its identity is

```text
id = SHA-256("anchor writer v1" ‖ channel ‖ instance ‖ root ‖ persona ‖ key₀ ‖ next₀ ‖ index)
```

`key₀` is the digest of its first public key. `next₀` is SHA-256 of a secret the writer keeps for its first rotation, a pre-rotation commitment as in KERI. The identity never changes afterwards.

- **Rotation** presents the secret whose SHA-256 is the current commitment, a new key digest and a new commitment.
- **Recovery** (when the secret is lost) needs the user's consent to that exact new key and commitment.
- **Revocation** is the host's. It needs no consent because it only lowers.
- **Inception** is refused on a door that has ever had a writer, and for any key or commitment that has ever been bound to anyone.

Every record names the writer and the key sequence it was signed under; a superseded sequence is refused.

### 3.5 The user's word

A user line is the user's **word** on trait k with value v if and only if, after normalisation, it is exactly `i <verb> <label>`:

- **Verbs:** `love` (2), `like` (1), `am undecided about` (0), `do not like` or `don't like` (-1), `hate` (-2).
- **Labels:** any label of trait k.
- **Normalisation:** ASCII lower case; U+2019 read as an apostrophe; runs of space, tab, CR and LF collapsed and trimmed; then a trailing run of `.` and `!` dropped.

The store makes this decision itself, from the line. The host's parser supplies a proposition only as a hint. If the line is not a word, the hint is kept as a READ: the companion's understanding, at authority 1. It becomes the word only when the user confirms it with a single-use token bound to the trait, the value and the line.

### 3.6 Consent

A consent token is issued when the user is shown exactly what will happen. It is derived from the journal head, its kind (confirm, redefine, recover) and a digest of its exact target, and it lapses after 64 further journal entries. A presented token is spent whatever the outcome. A token of one kind is refused for another, and a token for one target is refused for any other.

### 3.7 The journal and the saved file

Every mutating call after initialisation writes exactly one 16-byte journal entry, whether it was accepted or refused: the operation, the result byte, and the first 14 bytes of SHA-256 over the operation's arguments. The one exception is a store whose event counter is spent (2³² − 1 entries), which refuses everything and writes nothing. The head moves by `h ← SHA-256(h ‖ entry)`. The store keeps the last 32 entries and folds older ones into a base digest. The saved file (Appendix A) ends with SHA-256 of everything before it, and the loader checks every invariant in this paper before it changes anything.

## 4. Companions: what the rule guarantees

Write `F_X(k)` for X's voices on k (section 3.3) and `L(c, g, F)` for the rule.

**Proposition A1 (bounded).** In every reachable state, `e_X(k) ∈ B_X(k)`.

*Proof.* `e_X(k)` is written in three places only. At definition and sealing it is set to `c_X(k)`, which lies in the band. When the snapshot is taken (at each episode, and when X is redefined) it is set to `L(c, g, F)`, which clamps to `[c − g, c + g]`. Since `u` is a weighted mean of `c` and voice values, all in -2..2, `u` and its rounding lie in -2..2. On load, a file with `e ∉ B` is refused. Core and give change only at redefinition, which recomputes `e` in the same step. ∎

**Proposition A2 (conversation cannot change who she is).** Name, core and give change only by a redefinition. That requires a live user or system writer on its current key, an unspent, unlapsed redefine token whose target is the fingerprint of exactly the new definition at the next version, and that the new definition keeps every name distinct and every distance at least δ.

*Proof.* No other operation writes the person table after sealing. Speaking, retelling, user lines, confirmation, episodes, forgetting, writer operations and token issue touch views, writers, tokens and the journal only. ∎

**Proposition A3 (no self-echo).** `e_X` depends only on X's core, give and views X holds about others. Nothing X says enters it.

*Proof.* `F_X(k)` reads slots `(X, a, k)` with `a ≠ X`. A statement or retelling by X writes only at listeners other than X (the listener set must exclude the speaker, the teller and the subject). User lines and confirmations write views about the user. ∎

**Proposition A4 (restoration).** At an episode, if X holds live FIRST views on k from fewer than m persons, `e_X(k) = c_X(k)`.

*Proof.* The first case of `L`. Forgetting removes a voice. Revoking its writer makes it fall, redefining its subject makes it stale, and fading drops it. Once fewer than m voices remain, the next episode restores the core. ∎

**Proposition A5 (no compounding).** At each episode, `e_X(k) = L(c_X(k), g_X(k), F_X(k))`. The previous expression is not an input, so changes cannot accumulate, and two histories that reach the same core and voices express the same thing.

*Proof.* By the definition of the snapshot. An update anchored at the previous expression, `e ← L(e_prev, …)`, could move a step every episode without limit; this one cannot. ∎

**Proposition A6 (in character).** Every live view about a companion Y holds a value in `B_Y(k)` under her current core. A live FIRST view about her holds exactly what she expressed in the episode in which she said it.

*Proof.* A FIRST view about Y is admitted only by Y's own statement. That statement is refused unless its value equals her current expression, which lies in her band (A1). The view records her core version. A TOLD view copies its source's value and core version, and a stale or fallen source cannot be retold. If Y is redefined, her version rises and every earlier view of her becomes stale, so it is no longer live. Views are otherwise changed only by a later admission at the same slot (which re-establishes the property), fading (level only) or forgetting. The loader refuses a file in which a current view of a companion lies outside her band. ∎

**Proposition A7 (no blur).** For companions X ≠ Y, in every reachable state, `Σ_k |e_X(k) − e_Y(k)| ≥ D(X, Y) ≥ δ ≥ 1`. No two companions ever express the same thing on every trait.

*Proof.* By A1 each value lies in its band. The distance between `[c_X − g_X, c_X + g_X]` and `[c_Y − g_Y, c_Y + g_Y]` is `max(0, |c_X − c_Y| − g_X − g_Y)`, and intersecting with -2..2 can only increase it. Sum over k. `D ≥ δ` is checked at sealing, at every accepted redefinition and on load. ∎

**Proposition A8 (one self per conversation).** Between two episodes, `e_X` changes only if X is redefined. Every activity that reads `e_X` (crew talk, a scene, a model's prompt) sees the same value, and any first-hand statement that contradicts it is refused.

*Proof.* Only the snapshot and redefinition write `e`. The statement check is section 3.3. ∎

**Proposition A9 (one voice is one voice).** However often one person repeats a view to X, and however many others retell it, X does not move unless at least m distinct persons have each told her their own view first-hand.

*Proof.* There is one slot per `(X, a, k)`, so each person contributes at most one voice. Retellings are TOLD and are never voices. A person is a persona, not a writer. B7 shows that new writers cannot make new persons. ∎

**Proposition A10 (one step).** With σ ≤ 3/10, `|e_X(k) − c_X(k)| ≤ 1` whatever the give.

*Proof.* `|u − c| = h·|T/S − c| ≤ 0.3 · 4 = 1.2 < 1.5`. Rounding a number within 1.2 of an integer c gives a value within 1 of c. ∎

**The rule's shape.** `L` is odd: negating the core and every voice negates the result, because `u` negates, rounding half away from zero is odd, and the band is symmetric. It is non-decreasing in each voice value and in the core. `u` is non-decreasing in each (its coefficients h and 1 − h are non-negative), rounding is monotone, and both band limits rise with the core. An earlier draft rounded the step `u − c` instead of `u`. The exhaustive test found that this broke monotonicity in the core: at σ = 1, with voices averaging 0.5, a core of 0 expressed 1 while a core of 1 expressed 0. The present rule rounds `u`, as 10.15.0 does.

## 5. Writers

**Proposition B1 (stable identity).** A writer's id, door, root class and persona never change.

*Proof.* No operation writes them after inception. The loader recomputes the id from the first key, the first commitment, the door, the root, the persona and the index, and refuses a mismatch. ∎

**Proposition B2 (a stolen signing key cannot take over).** A writer's key and commitment change only by rotation, which presents a preimage of the current commitment, or by recovery, which spends the user's token for that exact new key and commitment. The signing key is an input to neither.

*Proof.* By the two operations. With SHA-256 preimage resistance, an attacker who holds the signing key but not the rotation secret cannot rotate. Recovery shows the user the new key before they consent. ∎

**Proposition B3 (no merge).** No key digest or commitment is ever bound to two identities, nor twice to one.

*Proof.* Inception, rotation and recovery each bind a key and a commitment that must be non-zero, different from each other and absent from the set of everything ever bound. Both are then added to that set, which never shrinks. Ids include the index. The loader checks that every first and current digest is distinct, that all are in the set, and that the set holds exactly `2 × (writers + Σ key sequences)` entries. ∎

**Proposition B4 (no silent split).** A door has at most one writer, ever.

*Proof.* Inception is refused for any door used by any writer, live or revoked, and writers are never removed. ∎

A host that lost its keys therefore cannot make a second identity for the same door. It must rotate (with the secret), recover (with the user's consent), or open a new door. A new door is an explicit act that the journal records.

**Proposition B5 (revocation follows the identity).** After revoking w, every view whose writer set contains w has fallen, whichever of w's keys it was written under. w cannot write, rotate or recover, and its door stays used.

*Proof.* "Fallen" is defined by the writer set, not the key. Every write checks revocation first, and the door check counts revoked writers. A fallen view is not a voice (A4), cannot be retold, and cannot be confirmed. ∎

**Proposition B6 (a superseded key cannot write).** Every write names a key sequence, and any but the writer's current one is refused.

*Proof.* By the check. This assumes the host verified the record's signature against the key of that sequence (section 11). ∎

**Proposition B7 (voices are persons).** A writer voices at most one persona for life, and a FIRST view about A is admitted only from a writer bound to A. So the number of voices any holder can have on a trait is at most n − 1, however many writers, keys or models exist.

*Proof.* The binding is fixed at inception and checked on every statement. This is the counting argument of min-caps' Lemma 6, with persons in place of root classes. A model switch registers a new writer for the same person. It cannot create a new person, and its statements are held to her expression like any other. ∎

## 6. The user's picture

**Proposition C1 (the user's word is exact).** If companion H holds a live FIRST view about the user on k, its value is the last *word* on k that H received: a verbatim line or a confirmed reading. Nothing else changes it.

*Proof.* FIRST views about the user are admitted only from a verbatim line or a confirmation. A READ or TOLD view cannot take a slot holding a live FIRST view. Fading changes the level and never drops the user's FIRST views. Forgetting removes the view, and revoking the user's writer makes it fall. A later word replaces it and keeps the old value as "before". ∎

**Proposition C2 (a reading is not a word).** A user line that is not verbatim yields at most a READ view at authority 1. It never replaces a live word, is never a voice, and becomes a word only by the user's yes to that trait, value and line.

*Proof.* Sections 3.2, 3.3 and 3.6. ∎

**Proposition C3 (a word is literal, and names one thing).** A line is the word `(k, v)` exactly when its normalisation equals `"i " + verb(v) + " " + label` for a label of k. No line is two words.

*Proof.* The first word after `i ` determines the verb (`love`, `like`, `am`, `do`, `don't`, `hate`), and the rest must then match exactly. Labels are distinct across the store. ∎

**Proposition C4 (a retelling copies).** A TOLD view holds the teller's value at the moment of telling, at one more remove, at authority `min(1, source)`, standing on the source's writers and the teller's. The operation has no value parameter.

*Proof.* By the operation. ∎

**Proposition C5 (hearsay never replaces first-hand).** A TOLD view never replaces a live FIRST or READ view, and replaces a TOLD view only at the same or a smaller remove.

*Proof.* Section 3.2. ∎

**Proposition C6 (the user's word is kept).** The user's FIRST views are never dropped for being old.

*Proof.* Fading stops them at level 1. ∎

## 7. Relation to recursive min-caps

Every view's authority is the min-caps rule applied to it. A FIRST view has the capacity of its writer's channel (2 for the user, 1 for a companion). A READ is the store's reading of a user line, worth 1. A TOLD view has `min(cap(agent), a(source)) = min(1, a(source))`. A fallen view has effective authority 0, which is min-caps' Proposition 4. Nothing in the store raises an authority, which is min-caps' Proposition 1.

Min-caps bounds what a record may be used for. Anchors bound what the store may hold about who someone is: a band, a distance, a definition that conversation cannot reach, an identity that survives its keys, and a word that is kept as said. The two compose. An agent-written record can never outrank the user's word (min-caps). Nothing at all, of any authority, can move a companion out of her band or rewrite her definition without the user's consent (anchors).

## 8. Simoa 10.15.0

### 8.1 What was found, and what changes

Each 10.15.0 row was reproduced by loading the shipped stage bundle (SHA-256 `dce10b40…2a05`, as in its build manifest) into Node and calling its own functions, with the C memory engine instantiated as the stage instantiates it.

| | 10.15.0 (reproduced) | With anchors |
| --- | --- | --- |
| "I love tea", then "I like tea" | holds 1.5; the sheet says "You love tea" | holds "like", before "love" |
| "Mika thinks I love storms" | the user loves storms, at the user's authority, kept for good | a reading at authority 1, never the word unless the user says yes |
| "My brother says I hate tea"; "I love storms, said nobody ever" | the user's own stance | readings |
| "I agree" | takes the previous speaker's polarity as the user's own | at most a reading |
| A retelling | the value is whatever the caller passes; the Text scene passes the teller's value rounded to a whole step | the teller's value, exactly; there is no value to pass |
| Mika "says" she hates rain (her nature: likes) | stored as her first-hand view, and it pulls the others | refused: out of character |
| One subject in one conversation | crew talk: snapshot; Text scene: live lean; Eat scene: innate taste | one value per conversation, for everything |
| Storage empty for this path | new keys and passports for the host and all three companions, unlinked | the door already has a writer: rotate, recover with consent, or open a new door explicitly |
| The kernel's learner (10.15.0's gap log, GAP-LAB-001) | "combines a shared prior with per-character context" | not reachable here: the kernel ships as a binary |

10.15.0 already had a bounded lean (one step, ±2 never moves), the precedence of first-hand over retold, and a reader that does not let the user assert a companion's tastes. Its 31-topic table already keeps the three apart under that rule (D = 14, 9, 9).

### 8.2 Plugging it in

| 10.15.0 | Anchors |
| --- | --- |
| a companion's stance heard by listeners (`hear`, kind `said`) | `an_say(writer, keyseq, speaker, trait, an_expressed(speaker, trait), listeners)` |
| a user's stance (`hear`, kind `user`) | `an_user_line(user writer, keyseq, the raw line, hint trait, hint value, listeners)` |
| a report or gossip (`tell`, kind `told`) | `an_tell(writer, keyseq, teller, about, trait, listeners)` |
| `episode()` and `leanings()` at the start of crew talk | `an_episode()`, then `an_expressed()` for crew talk, every scene and every prompt |
| `view()` and `tastes()` | `an_expressed()` |
| "Forget …" | `an_forget(holder, about, trait)` |
| "Did you mean you love tea?" (new) | `an_issue_confirm` when it is shown, `an_confirm` on the yes |
| SoulShield passports | one writer per door; keep the rotation secret encrypted; on lost keys, recovery with consent, never a new identity on the same door; verify each signature before calling the store, and pass the key sequence it was verified under |
| (new) | keep `an_definition()`, each `an_fingerprint()` and the journal head outside the device |

Unknown subjects get a derived opinion in 10.15.0. Here every trait is declared when the store is defined, and a store with more traits is a new store.

## 9. Implementation

| File | What |
| --- | --- |
| `src/anchor.h`, `src/anchor.c` | the store: freestanding C17, no library, no allocation |
| `src/sha256.c` | SHA-256 |
| `src/wasm.c` | one store and a scratch area per WebAssembly instance |
| `dist/anchor.wasm` | 48,328 bytes, no imports, reproducible: SHA-256 `eaca3c9a691f8868ba27a6117e744a2ba5be490dd7bb19ce849f2c1097937cf0` with clang 18.1.3 and `./build.sh` |
| `oracle/anchor.mjs`, `oracle/sha256.mjs` | the independent JavaScript implementation; no dependencies; runs in a browser |
| `host/anchor-wasm.mjs` | a binding for the WebAssembly with the oracle's interface |

The module imports nothing. It cannot reach a network, a clock, a file or a model. It compiles cleanly under gcc 13 and clang 18 with `-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Wcast-qual -Werror`. It takes about 170 KB of memory per store.

## 10. Evidence

No claim here is machine-checked. Each rests on a proof written above or on a test of the code. The counts are from `tests/RESULTS.json`, written by `node tests/run.mjs` on 13 November 2026 (Node 22.23.4, clang 18.1.3, gcc 13.3.0).

| Claim | Rests on | Detail |
| --- | --- | --- |
| A1–A10, B1–B7, C1–C6 | proof on paper | sections 4 to 6, not checked by a proof assistant |
| The rule `L` and its shape | exhaustive test | 1,034,880 cases over seven parameter sets: C equals JavaScript equals a third implementation in exact rationals; band, two voices, σ = 0, one step at σ ≤ 3/10, oddness, order of voices (1,026,375), monotone in each voice (1,932,420 checks) and in the core (827,904) |
| A1, A2, A6, A7, A8; B1, B5, B6; C1, C2, C4 in the code | exhaustive test, small cases | every history of up to four events over 16 events (69,905 histories, 274,960 steps) in a world of two companions and five writers: after every step the band, the distance, unchanged cores, unchanged expression inside an episode, the snapshot equal to the rule, current views in band, the user's word equal to a shadow model kept by the test, exact retellings (1,014), confirmations (2,235), stable ids, key sequences and revocations |
| The same, at scale | random test | 12 seeds × 4,000 steps (51,944 calls, 7,151 hostile) in a world of three companions and six of Simoa's topics: band and distance after every step, current views in band every 25 steps |
| The verbatim gate | generated test | 2,190 lines (928 words in 14 spellings, 1,262 near misses) checked three ways (C, JavaScript, a regular-expression reference); 40,000 byte-level mutations, C equals JavaScript |
| Named attacks | scenario tests | 24, each run in both implementations: persona injection, one persistent voice, echoes, two voices for 200 conversations, restoration three ways, self-echo, out of character, impersonation, blur under maximum pull, consent (missing, wrong writer, other change, reuse, lapse), blur by redefinition, rotation, key theft, a reload that lost its keys, retired-key reuse, model switch, revocation across keys, degree change, readings, confirmation (wrong value, wrong writer, wrong kind, reuse), exact retelling, hearsay, the user's word after 1,000 episodes, authority along retellings |
| C and JavaScript agree | differential test | after every one of 51,944 calls: the same result and the same journal head; the same saved bytes; cross-loading each other's files; three histories frozen as vectors |
| Save and reload change nothing | differential test | 180 reloaded stores ran 11,673 calls in lockstep with the originals, with identical results and heads; all 69,905 small histories and 619 native round trips reload to identical bytes |
| A saved file takes nothing on trust | bit-flip test | all 18,968 single-bit changes to one 2,371-byte file refused as they are, by both, with the same codes; with the digest recomputed, 17,080 refused and 1,632 accepted, listed below |
| Memory safety | sanitizers | 60,000 native steps (13,719 statements, 12,080 user lines, 8,389 retellings, 4,242 confirmations, 274 rotations, 222 recoveries, 357 redefinitions accepted) under AddressSanitizer and UndefinedBehaviorSanitizer, 619 reloads, every truncation of a saved file, 4,000 corruptions, 2,000 garbage files: no report |
| SHA-256 | known answers, random test | the FIPS examples and one million 'a' (native); 3,308 random messages up to 200,000 bytes, C equals JavaScript equals node:crypto |
| Simoa's table | fixture from the shipped bundle | distances 14, 9, 9; 2,000 conversations (24,000 lines): no companion ever more than one step from her core, cores unchanged, every pair above its distance |

**What the bit flips show.** With the trailing digest recomputed, a change is refused when it breaks a rule the loader can check, and that covers 91% of them. The 1,632 accepted ones fell in the following fields:

- line identifiers (768), token targets and values (384)
- counters (79), view levels and episodes (58)
- labels (139), names and versions (129)
- parameters (16)
- core (5), give (12) and expressed (5) values that keep every band and distance
- view values (8)
- the remaining 29 in views' "before" values and places, writer status, and token kinds and times

Each is a state the rule allows, which the digest alone binds. Someone who can rewrite the file and recompute its digest can therefore change a definition within the rules. Only a fingerprint or journal head kept elsewhere detects that (section 11).

**What a differential test does not show.** Two implementations written by one author from one description can share a misunderstanding. The exhaustive tests against the exact-rational reference, the regular-expression reference and the shadow model are what tie the code to the rule, and they stop at the sizes given.

**Not done.** A machine-checked proof. Integration into Simoa and a test in its browser UI. Any test on a phone. Review by anyone other than the author.

## 11. Limits

- **It says nothing about truth.** The user can be wrong in their own word; a companion's view of the user can be stale hearsay, marked as such.
- **It trusts the host** to stamp the channel of every write, to bind writers to the right persona, and to verify each record's signature against the key sequence it names. A host that skips verification defeats B6. Code running inside the same trust boundary can call anything.
- **Pre-rotation protects the signing key, not the rotation secret.** Whoever holds the current rotation secret can rotate the identity. Recovery rests on the user's consent, not on possession, and the store counts how often an identity was recovered.
- **It is bounded.** 8 persons, 64 traits, 4 labels per trait, 16 writers in the store's life (doors are never reused), 512 key events (1,024 bound digests), 8 outstanding tokens. When full, it refuses; existing keys keep working.
- **The verbatim gate is English and strict.** Six verbs, ASCII labels, no intensifiers ("I really love tea" is a reading). Everything else needs the user's yes, which needs a place in the interface.
- **Line identifiers are not secret.** A short line can be found from its identifier by guessing. The store keeps no line text, but its identifiers are not a privacy measure.
- **A file-level attacker who recomputes the digest** can make any change the rules allow (section 10). Pin `an_definition()`, the fingerprints and the journal head outside the device, as the min-caps paper's seal does for its journal.
- **Only stances and names are identity here.** How a language model words her replies, her style, her backstory, and anything not declared as a trait are not modelled. The rule gates what she states about her declared traits.
- **Revocation takes effect on expression at the next episode.** Within a conversation the snapshot stands; the host can start a new episode at once.
- **It does not reach the 10.8.0 kernel's learner**, whose shared prior across the three companions is in the 10.15.0 gap log. That needs the kernel source.
- **The evidence has the limits section 10 gives.** Proofs on paper, tests of the code, one author.

## 12. Conclusion

Identity drift has three mechanisms, and each can be stopped by structure rather than by instructions:

- a companion's expression computed from a fixed core and fresh evidence, inside a band, with definitions apart by a margin that no history can close
- an identity that is an inception, not a key
- a word that is the user's only when it is what they said

The rule is a few hundred lines of C and an equal amount of JavaScript. Both are tested against each other and against independent references, exhaustively where the cases are small. What is established: the propositions above with written proofs, and implementations that agree on every case tried. What is not: a machine-checked proof, the integration into Simoa, and review by anyone else. Those are the next three things to do, in that order.

## Appendix A. The saved file

All integers little-endian. Fields in order:

| Field | Bytes |
| --- | --- |
| `ANCH`, format 1 | 6 |
| persons, traits, σn, σd, saturation, voices, distance, sealed (= 1) | 8 |
| episode (u16), events, refused, tokens issued (u32 each) | 14 |
| journal base, journal head | 64 |
| ring count, then that many 16-byte entries, oldest first | 1 + 16·r |
| per trait: label count, then for each label its length and bytes | variable |
| per companion: version, name length, name, core[K], give[K], expressed[K] | 2 + name + 3K |
| writer count, then per writer: channel, instance, root, persona, revoked, recovered, key sequence (u16), id, key, next, first key, first next | 1 + 168·w |
| bound-digest count (u16), then 32 bytes each | 2 + 32·u |
| token count, then per token: kind, issued (u32), target (32), token (16) | 1 + 53·t |
| view count (u16), then per view in (holder, about, trait) order: holder, about, trait, class, depth, authority, level, core version, value, before, made (u16), renewed (u16), writers (u16), line (16) | 2 + 32·v |
| SHA-256 of all the above | 32 |

## Appendix B. Interface

Definition: `an_init`, `an_label`, `an_define`, `an_seal`. Writers: `an_incept`, `an_rotate`, `an_recover`, `an_revoke`. Conversation: `an_episode`, `an_say`, `an_tell`, `an_user_line`, `an_confirm`, `an_redefine`, `an_forget`. Consent: `an_issue_confirm`, `an_issue_redefine`, `an_issue_recover`. Queries: `an_expressed`, `an_core`, `an_give`, `an_view_get`, `an_writer_get`, `an_fingerprint`, `an_definition`, `an_head`, `an_info`, `an_distance`, `an_verbatim`, `an_line_id`, `an_lean`. Persistence: `an_save_size`, `an_save`, `an_load`. Refusal codes are in `src/anchor.h`. The JavaScript oracle has the same operations in camel case.

## References

1. The Recursive Min-Caps paper (11 November 2026), supplied with this work: the rule `a(v) = min(cap(o(v)), min a(p))`, its Propositions 1 and 4 and Lemma 6.
2. Simoa 10.15.0, distribution revision 10.15.0-h1 (`GUIDE-10.15.0.md`, `KNOWN_GAPS.md`, `USER_INVARIANTS.md`, `HARDENING-10.15.0-h1.md`, the stage bundle and SoulShield host in `index.html`), supplied with this work and read for section 8.
3. Friedkin, N. E. and Johnsen, E. C. Social influence and opinions. *Journal of Mathematical Sociology* 15(3–4), 1990. The anchored opinion model behind 10.15.0's lean and section 3.3. (Cited from memory; not re-read.)
4. Smith, S. M. *Key Event Receipt Infrastructure (KERI)*. arXiv:1907.02143, 2019. Pre-rotation: committing to the digest of the next key so that a stolen signing key cannot rotate an identity. (Cited from memory; not re-read.)
5. NIST FIPS 180-4, *Secure Hash Standard*, 2015. SHA-256 and its example vectors, used by `tests/native.c`.
