/* Copyright (c) 2001-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "env-util.h"
#include "hostpid.h"
#include "process-title.h"

#include <stdlib.h>
#include <time.h>

size_t nearest_power(size_t num)
{
	size_t n = 1;

	i_assert(num <= ((size_t)1 << (BITS_IN_SIZE_T-1)));

	while (n < num) n <<= 1;
	return n;
}

void lib_init(void)
{
	/* standard way to get rand() return different values. */
	srand((unsigned int) time(NULL));

	data_stack_init();
	hostpid_init();
}

void lib_deinit(void)
{
	data_stack_deinit();
	env_deinit();
	failures_deinit();
	process_title_deinit();
}
