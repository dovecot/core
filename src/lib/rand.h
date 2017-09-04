#ifndef RAND_H
#define RAND_H

#ifdef HAVE_ARC4RANDOM

int arc4random_rand(void);
#define rand arc4random_rand

#endif

#endif
