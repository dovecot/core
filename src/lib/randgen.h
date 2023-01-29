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

/* Internal for unit test:

   Use a small buffer when reading randomness. This is mainly to make small
   random reads more efficient, such as i_rand*(). When reading larger amount
   of randomness this buffer is bypassed.

   There doesn't seem to be a big difference in Linux system CPU usage when
   buffer size is above 16 bytes. Double it just to be safe. Avoid it being
   too large anyway so we don't unnecessarily waste CPU and memory. */
#define RANDOM_READ_BUFFER_SIZE 32

#endif
