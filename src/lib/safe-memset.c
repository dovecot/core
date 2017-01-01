/* Copyright (c) 2002-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "safe-memset.h"

void safe_memset(void *data, int c, size_t size)
{
	volatile unsigned int volatile_zero_idx = 0;
	volatile unsigned char *p = data;

	if (size == 0)
		return;

	do {
		memset(data, c, size);
	} while (p[volatile_zero_idx] != c);
}
