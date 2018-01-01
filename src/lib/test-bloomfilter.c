/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "randgen.h"
#include "bloomfilter.h"

void test_bloomfilter(void)
{
	test_begin("bloomfilter");
	struct bloomfilter *bf = i_bloomfilter_create(18);
	const char *const strings[] = {
		"correct", "horse", "battery", "staple", NULL
	};

	/* set some items */
	bloomfilter_set_strings(bf, strings);
	bloomfilter_set_int(bf, 500);

	/* make sure they exist */
	for(unsigned int i = 0; strings[i] != NULL; i++) {
		test_assert(bloomfilter_has_string(bf, strings[i]));
	}

	test_assert(bloomfilter_has_int(bf, 500));

	/* make sure nothing bad happens with non-existing items */
	(void)bloomfilter_has_string(bf, "hello, world");

	test_assert(bloomfilter_estimated_item_count(bf) == 5);

	bloomfilter_unref(&bf);

	test_end();
}
