/* Copyright (c) 2013-2017 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "buffer.h"
#include "numpack.h"


static struct test {
	uint64_t input;
	uint8_t output[10];
	unsigned int output_size;
} enc_tests[] = {
	{ 0xffffffff, { 0xff, 0xff, 0xff, 0xff, 0xf }, 5 },
	{ 0, { 0 }, 1 },
	{ 0x7f, { 0x7f }, 1 },
	{ 0x80, { 0x80, 1 }, 2 },
	{ 0x81, { 0x81, 1 }, 2 },
	{ 0xdeadbeefcafe, { 0xfe, 0x95, 0xbf, 0xf7, 0xdb, 0xd5, 0x37 }, 7 },
	{ 0xffffffffffffffff, { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1 }, 10 },
	{ 0xfffffffe, { 0xfe, 0xff, 0xff, 0xff, 0xf }, 5 },
};
static struct fail {
	uint8_t input[11];
	unsigned int input_size;
} dec_fails[] = {
	{ { 0 }, 0 },    /* has no termination byte */
	{ { 0x80 }, 1 },  /* ditto */
	{ { 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 }, 10 }, /* ditto*/
	{ { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2 }, 10 }, /* overflow */
	{ { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f }, 11 }, /* ditto */
};

void test_numpack(void)
{
	buffer_t *buf = buffer_create_dynamic(pool_datastack_create(), 32);
	unsigned int i;
	const uint8_t *p, *end;
	uint64_t num;
	uint64_t magic=0x9669699669969669;

	test_begin("numpack (good)");
	for (i = 0; i < N_ELEMENTS(enc_tests); i++) {
		buffer_set_used_size(buf, 0);
		numpack_encode(buf, enc_tests[i].input);
		test_assert_idx(buf->used == enc_tests[i].output_size, i);
		test_assert_idx(memcmp(buf->data, enc_tests[i].output,
				     enc_tests[i].output_size) == 0,
			      i);

		p = buf->data; end = p + buf->used;
		test_assert_idx(numpack_decode(&p, end, &num) == 0, i);
		test_assert_idx(num == enc_tests[i].input, i);
	}
	test_end();

	test_begin("numpack (bad)");
	for (i = 0; i < N_ELEMENTS(dec_fails); i++) {
		p = dec_fails[i].input; end = p + dec_fails[i].input_size;
		num = magic;
		test_assert_idx(numpack_decode(&p, end, &num) == -1, i);
		test_assert_idx(p == dec_fails[i].input && num == magic, i);
	}
	test_end();
}
