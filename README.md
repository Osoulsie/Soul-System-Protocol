# Soul System Protocol: identity anchors

A storage rule, and its implementation, that keeps three kinds of identity from drifting:

| Drift | What happens | What the rule does |
| --- | --- | --- |
| **Who she is** | a companion's tastes wander a step at a time; one voice repeated or retold pulls her; she says one thing in one scene and another in the next; two companions blur; conversation rewrites her | a fixed **core** per trait and a **band** around it; what she expresses is recomputed each conversation from the core and the first-hand views of at least two other people, never leaves the band, and is the same for every activity in that conversation; definitions stay a set distance apart; only the user's consent to an exact redefinition changes a core |
| **Who wrote it** | a lost key, a new device or a model switch makes the same source a new writer; two sources share one; revocation stays with the old key | an identity is its inception, not its key: keys change by pre-committed rotation or consented recovery; no key is ever bound twice; a door is used once; revocation follows the identity |
| **Who the user is to them** | a parser's reading becomes the user's word; a retelling changes on the way; "I love tea" then "I like tea" leaves "love" | a line is the user's word only if it is the statement word for word; anything else is a reading until the user says yes; a retelling copies what the teller holds; the latest word is kept as said |

The rule, its propositions and their proofs, what was found in Simoa 10.15.0, the evidence and the limits are in **[docs/identity-anchors.md](docs/identity-anchors.md)**. It extends the recursive min-caps rule (`a(v) = min(cap(o(v)), min a(p))`); every view it keeps still obeys min-caps.

## Layout

| Path | What |
| --- | --- |
| `src/anchor.h`, `src/anchor.c` | the store: freestanding C17, no library, no allocation, no imports |
| `src/sha256.c`, `src/sha256.h` | SHA-256 |
| `src/wasm.c` | WebAssembly glue: one store and a scratch area per instance |
| `dist/anchor.wasm` | the built module (48,328 bytes; SHA-256 `eaca3c9a691f8868ba27a6117e744a2ba5be490dd7bb19ce849f2c1097937cf0`, reproducible with clang 18.1.3) |
| `oracle/anchor.mjs`, `oracle/sha256.mjs` | an independent JavaScript implementation; no dependencies; runs in a browser |
| `host/anchor-wasm.mjs` | a binding for `dist/anchor.wasm` with the same interface as the oracle |
| `tests/` | the test suites, the Simoa 10.15.0 fixture, frozen vectors and `RESULTS.json` from the last full run |
| `build.sh` | builds `dist/anchor.wasm` and the native sanitizer test |

## Build and test

```sh
./build.sh            # clang with the wasm32 target and wasm-ld; gcc for the native sanitizer build
node tests/run.mjs    # every suite (about 3 minutes); writes tests/RESULTS.json
```

`node tests/run.mjs` needs Node 18 or later and nothing else. `SKIP_NATIVE=1` skips the C sanitizer run when no C compiler is available; the JavaScript suites test the committed `dist/anchor.wasm`. A single suite runs with, for example, `node tests/scenarios.test.mjs`.

| Suite | What it checks |
| --- | --- |
| `native` | 60,000 steps of every operation in C under AddressSanitizer and UndefinedBehaviorSanitizer; save and reload every 97 steps; every truncation and thousands of corruptions of a saved file |
| `sha256` | the C and JavaScript SHA-256 against node:crypto |
| `lean` | the expression rule over 1,034,880 cases against an exact-rational reference, with its properties |
| `verbatim` | which lines are the user's word, three ways |
| `small` | every history of up to four events over 16, with every proposition checked after every step against a shadow model |
| `differential` | 12 long random histories, C and JavaScript after every call, save/load transparency, frozen vectors |
| `bitflip` | every single-bit change to a saved file |
| `scenarios` | 24 named ways identity can drift, each refused or bounded |
| `simoa` | Simoa 10.15.0's own 31-topic table: distances, the reproduced 10.15.0 cases, 2,000 conversations |

## Using it

```js
import { AnchorStore } from './oracle/anchor.mjs';           // or WasmAnchorStore from host/anchor-wasm.mjs
const s = new AnchorStore();
s.init(4, 2, 3, 10, 16, 2, 1);                               // user + 3 companions, 2 traits, sigma 3/10, saturation 16, 2 voices, distance 1
s.label(0, bytes('storms')); s.label(1, bytes('dancing'));   // their stances below are Simoa 10.15.0's own
s.define(1, bytes('Simoa'), [-1, -1], [1, 1]);               // core and give per trait
s.define(2, bytes('Mika'), [-2, 2], [0, 0]);
s.define(3, bytes('Neris'), [2, 1], [0, 1]);
s.seal();                                                    // refused if two definitions could ever blur
s.incept(2, 0, 0, 0, keyDigest, nextCommitment);             // the user's writer (channel, instance, root class, persona)
// ... one writer per companion, then each conversation:
s.episode();
s.say(w, keySeq, 1, 0, s.expressed(1, 0), listeners);        // a companion speaks, in character
s.userLine(u, keySeq, bytes('I love storms'), -1, 0, listeners); // the user's word, or a reading
```

How it plugs into Simoa's crew memory and SoulShield is set out in section 8 of the paper.
