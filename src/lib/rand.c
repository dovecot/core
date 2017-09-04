/* Copyright (c) 2014-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"

#ifdef HAVE_ARC4RANDOM
#ifdef HAVE_LIBBSD
#include <bsd/stdlib.h>
#endif

/* this returns [0,RAND_MAX), to keep it compatible with rand() */
int arc4random_rand(void) {
	return (int)(arc4random() % ((unsigned)RAND_MAX + 1));
}
#endif
