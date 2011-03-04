/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "crc32.h"

void test_crc32(void)
{
	const char str[] = "foo\0bar";

	test_begin("crc32");
	test_assert(crc32_str(str) == 0x8c736521);
	test_assert(crc32_data(str, sizeof(str)) == 0x32c9723d);
	test_end();
}
