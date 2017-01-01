/* Copyright (c) 2014-2017 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "guid.h"

void test_guid(void)
{
	static const guid_128_t test_guid =
	{ 0x01, 0x23, 0x45, 0x67, 0x89,
	  0xab, 0xcd, 0xef,
	  0xAB, 0xCD, 0xEF,
	  0x00, 0x00, 0x00, 0x00, 0x00 };
	guid_128_t guid1, guid2, guid3;
	const char *str;
	char guidbuf[GUID_128_SIZE*2 + 2];
	unsigned int i;

	test_begin("guid_128_generate()");
	guid_128_generate(guid1);
	guid_128_generate(guid2);
	test_assert(!guid_128_equals(guid1, guid2));
	test_assert(guid_128_cmp(guid1, guid2) != 0);
	test_end();

	test_begin("guid_128_is_empty()");
	test_assert(!guid_128_is_empty(guid1));
	test_assert(!guid_128_is_empty(guid2));
	guid_128_generate(guid3);
	guid_128_empty(guid3);
	test_assert(guid_128_is_empty(guid3));
	test_end();

	test_begin("guid_128_copy()");
	guid_128_copy(guid3, guid1);
	test_assert(guid_128_equals(guid3, guid1));
	test_assert(!guid_128_equals(guid3, guid2));
	guid_128_copy(guid3, guid2);
	test_assert(!guid_128_equals(guid3, guid1));
	test_assert(guid_128_equals(guid3, guid2));
	test_end();

	test_begin("guid_128_to_string()");
	str = guid_128_to_string(guid1);
	test_assert(guid_128_from_string(str, guid3) == 0);
	test_assert(guid_128_equals(guid3, guid1));
	test_end();

	test_begin("guid_128_from_string()");
	/* empty */
	memset(guidbuf, '0', GUID_128_SIZE*2);
	guidbuf[GUID_128_SIZE*2] = '\0';
	guidbuf[GUID_128_SIZE*2+1] = '\0';
	test_assert(guid_128_from_string(guidbuf, guid3) == 0);
	test_assert(guid_128_is_empty(guid3));
	/* too large */
	guidbuf[GUID_128_SIZE*2] = '0';
	test_assert(guid_128_from_string(guidbuf, guid3) < 0);
	/* too small */
	guidbuf[GUID_128_SIZE*2-1] = '\0';
	test_assert(guid_128_from_string(guidbuf, guid3) < 0);
	/* reset to normal */
	guidbuf[GUID_128_SIZE*2-1] = '0';
	guidbuf[GUID_128_SIZE*2] = '\0';
	test_assert(guid_128_from_string(guidbuf, guid3) == 0);
	/* upper + lowercase hex chars */
	i_assert(GUID_128_SIZE*2 > 16 + 6);
	for (i = 0; i < 10; i++)
		guidbuf[i] = '0' + i;
	for (i = 0; i < 6; i++)
		guidbuf[10 + i] = 'a' + i;
	for (i = 0; i < 6; i++)
		guidbuf[16 + i] = 'A' + i;
	test_assert(guid_128_from_string(guidbuf, guid3) == 0);
	test_assert(guid_128_equals(guid3, test_guid));
	/* non-hex chars */
	guidbuf[0] = 'g';
	test_assert(guid_128_from_string(guidbuf, guid3) < 0);
	guidbuf[0] = ' ';
	test_assert(guid_128_from_string(guidbuf, guid3) < 0);
	test_end();
}
