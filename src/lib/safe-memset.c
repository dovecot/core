/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "safe-memset.h"

void safe_memset(void *data, int c, size_t size)
{
	volatile unsigned char *p = data;

	for (; size > 0; size--)
		*p++ = (unsigned char)c;
}
