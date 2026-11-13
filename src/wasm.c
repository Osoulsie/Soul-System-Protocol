/* WebAssembly glue: one store per instance and a scratch area for byte arguments.
 * The module imports nothing. It cannot reach a network, a clock, a file or a model. */
#include "anchor.h"

#define AN_SCRATCH 262144

an_store *an_global(void);
uint8_t *an_scratch(void);
int an_scratch_size(void);

static an_store store;
static uint8_t scratch[AN_SCRATCH];

an_store *an_global(void) { return &store; }
uint8_t *an_scratch(void) { return scratch; }
int an_scratch_size(void) { return AN_SCRATCH; }
