/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "primes.h"

void test_primes(void)
{
	unsigned int i, j, num;
	bool success;

	success = primes_closest(0) > 0;
	for (num = 1; num < 1024; num++) {
		if (primes_closest(num) < num)
			success = FALSE;
	}
	for (i = 10; i < 32; i++) {
		num = (1 << i) - 100;
		for (j = 0; j < 200; j++, num++) {
			if (primes_closest(num) < num)
				success = FALSE;
		}
	}
	test_out("primes_closest()", success);
}
