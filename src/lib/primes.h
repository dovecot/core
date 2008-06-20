#ifndef PRIMES_H
#define PRIMES_H

/* Returns a prime close to specified number, or the number itself if it's
   a prime. Note that the returned value may be smaller than requested! */
unsigned int primes_closest(unsigned int num) ATTR_CONST;

#endif
