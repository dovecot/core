#ifndef RAND_H
#define RAND_H

/* Wrap srand() so that we can reproduce fuzzed tests */

/* If we have seeded the prng precisely once, and we remember what
 * value that was with, then we can reproduce any failing test cases
 * that depend on that randomness by forcing the seed value (e.g. 
 * in a debugger, by putting a breakpoint on rand_set_seed()).
 */

/* Number of times we've been seeded */ 
int rand_get_seed_count(void);
/* That last seed */
unsigned int rand_get_last_seed(void);
/* Actually seed the prng (could add char* for name of function?) */
void rand_set_seed(unsigned int s);

#ifdef HAVE_ARC4RANDOM

int arc4random_rand(void);
#define rand arc4random_rand

#endif

#endif
