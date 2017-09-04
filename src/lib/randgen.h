#ifndef RANDGEN_H
#define RANDGEN_H

/* Fill given buffer with semi-strong randomness */
void random_fill(void *buf, size_t size);

/* may be called multiple times,
   and are called by default in lib_init */
void random_init(void);
void random_deinit(void);

#endif
