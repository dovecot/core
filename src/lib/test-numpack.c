/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "buffer.h"
#include "numpack.h"

#include <stdlib.h>

static struct test {
	uint64_t input;
	uint8_t output[10];
	unsigned int output_size;
} tests[] = {
	{ 0xffffffff, { 0xff, 0xff, 0xff, 0xff, 0xf }, 5 },
	{ 0, { 0 }, 1 },
	{ 0x7f, { 0x7f }, 1 },
	{ 0x80, { 0x80, 1 }, 2 },
	{ 0x81, { 0x81, 1 }, 2 },
	{ 0xdeadbeefcafe, { 0xfe, 0x95, 0xbf, 0xf7, 0xdb, 0xd5, 0x37 }, 7 },
	{ 0xffffffffffffffff, { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1 }, 10 },
	{ 0xfffffffe, { 0xfe, 0xff, 0xff, 0xff, 0xf }, 5 },
};

void test_numpack(void)
{
	buffer_t *buf = buffer_create_dynamic(pool_datastack_create(), 32);
	unsigned int i;
	const uint8_t *p, *end;
	uint64_t num;

	test_begin("numpack");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		buffer_set_used_size(buf, 0);
		numpack_encode(buf, tests[i].input);
		test_assert(buf->used == tests[i].output_size &&
			    memcmp(buf->data, tests[i].output,
				   tests[i].output_size) == 0);

		p = buf->data; end = p + buf->used;
		test_assert(numpack_decode(&p, end, &num) == 0);
		test_assert(num == tests[i].input);
	}
	test_end();
}
