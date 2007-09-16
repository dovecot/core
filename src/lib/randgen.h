#ifndef RANDGEN_H
#define RANDGEN_H

/* Fill given buffer with semi-strong randomness, usually from /dev/urandom. */
void random_fill(void *buf, size_t size);
/* Fill given buffer with weak randomness, ie. with rand(). This is better if
   no real randomness is required, as reading from /dev/urandom usually also
   consumes /dev/random entropy, which may disturb other processes. */
void random_fill_weak(void *buf, size_t size);

/* may be called multiple times */
void random_init(void);
void random_deinit(void);

#endif
