#ifndef RANDGEN_H
#define RANDGEN_H

/* Fill given buffer with semi-strong randomness */
void random_fill(void *buf, size_t size);

/* may be called multiple times,
   and are called by default in lib_init */
void random_init(void);
void random_deinit(void);

#ifdef DEBUG
/* Debug helper to make random tests reproduceable. 0=got seed, -1=failure. */
int rand_get_last_seed(unsigned int *seed_r);
#endif

#endif
