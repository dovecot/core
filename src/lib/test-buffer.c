/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "buffer.h"

static void test_buffer_random(void)
{
#define BUF_TEST_SIZE (1024*2)
#define BUF_TEST_COUNT 1000
	buffer_t *buf;
	unsigned char *p, testdata[BUF_TEST_SIZE], shadowbuf[BUF_TEST_SIZE];
	unsigned int i, shadowbuf_size;
	size_t pos, pos2, size, size2;
	int test = -1;
	bool zero;

	buf = buffer_create_dynamic(default_pool, 1);
	for (i = 0; i < BUF_TEST_SIZE; i++)
		testdata[i] = i_rand();
	memset(shadowbuf, 0, sizeof(shadowbuf));

	shadowbuf_size = 0;
	for (i = 0; i < BUF_TEST_COUNT; i++) {
		if (buf->used == BUF_TEST_SIZE) {
			size = shadowbuf_size = i_rand_limit(buf->used - 1);
			buffer_set_used_size(buf, size);
			memset(shadowbuf + shadowbuf_size, 0,
			       BUF_TEST_SIZE - shadowbuf_size);
			i_assert(buf->used < BUF_TEST_SIZE);
		}

		test = i_rand_limit(7);
		zero = i_rand_limit(10) == 0;
		switch (test) {
		case 0:
			pos = i_rand_limit(BUF_TEST_SIZE - 1);
			size = i_rand_limit(BUF_TEST_SIZE - pos);
			if (!zero) {
				buffer_write(buf, pos, testdata, size);
				memcpy(shadowbuf + pos, testdata, size);
			} else {
				buffer_write_zero(buf, pos, size);
				memset(shadowbuf + pos, 0, size);
			}
			if (pos + size > shadowbuf_size)
				shadowbuf_size = pos + size;
			break;
		case 1:
			size = i_rand_limit(BUF_TEST_SIZE - buf->used);
			if (!zero) {
				buffer_append(buf, testdata, size);
				memcpy(shadowbuf + shadowbuf_size,
				       testdata, size);
			} else {
				buffer_append_zero(buf, size);
				memset(shadowbuf + shadowbuf_size, 0, size);
			}
			shadowbuf_size += size;
			break;
		case 2:
			pos = i_rand_limit(BUF_TEST_SIZE - 1);
			size = i_rand_limit(BUF_TEST_SIZE - I_MAX(buf->used, pos));
			if (!zero) {
				buffer_insert(buf, pos, testdata, size);
				memmove(shadowbuf + pos + size,
					shadowbuf + pos,
					BUF_TEST_SIZE - (pos + size));
				memcpy(shadowbuf + pos, testdata, size);
			} else {
				buffer_insert_zero(buf, pos, size);
				memmove(shadowbuf + pos + size,
					shadowbuf + pos,
					BUF_TEST_SIZE - (pos + size));
				memset(shadowbuf + pos, 0, size);
			}
			if (pos < shadowbuf_size)
				shadowbuf_size += size;
			else
				shadowbuf_size = pos + size;
			break;
		case 3:
			pos = i_rand_limit(BUF_TEST_SIZE - 1);
			size = i_rand_limit(BUF_TEST_SIZE - pos);
			buffer_delete(buf, pos, size);
			if (pos < shadowbuf_size) {
				if (pos + size > shadowbuf_size)
					size = shadowbuf_size - pos;
				memmove(shadowbuf + pos,
					shadowbuf + pos + size,
					BUF_TEST_SIZE - (pos + size));

				shadowbuf_size -= size;
				memset(shadowbuf + shadowbuf_size, 0,
				       BUF_TEST_SIZE - shadowbuf_size);
			}
			break;
		case 4:
			pos = i_rand_limit(BUF_TEST_SIZE - 1);
			size = i_rand_limit(BUF_TEST_SIZE - pos);
			size2 = i_rand_limit(BUF_TEST_SIZE -
					     I_MAX(buf->used, pos));
			buffer_replace(buf, pos, size, testdata, size2);
			if (pos < shadowbuf_size) {
				if (pos + size > shadowbuf_size)
					size = shadowbuf_size - pos;
				memmove(shadowbuf + pos,
					shadowbuf + pos + size,
					BUF_TEST_SIZE - (pos + size));

				shadowbuf_size -= size;
				memset(shadowbuf + shadowbuf_size, 0,
				       BUF_TEST_SIZE - shadowbuf_size);
			}
			memmove(shadowbuf + pos + size2,
				shadowbuf + pos,
				BUF_TEST_SIZE - (pos + size2));
			memcpy(shadowbuf + pos, testdata, size2);
			if (pos < shadowbuf_size)
				shadowbuf_size += size2;
			else
				shadowbuf_size = pos + size2;
			break;
		case 5:
			if (shadowbuf_size <= 1)
				break;
			pos = i_rand_limit(shadowbuf_size - 1); /* dest */
			pos2 = i_rand_limit(shadowbuf_size - 1); /* source */
			size = i_rand_limit(shadowbuf_size - I_MAX(pos, pos2));
			buffer_copy(buf, pos, buf, pos2, size);
			memmove(shadowbuf + pos,
				shadowbuf + pos2, size);
			if (pos > pos2 && pos + size > shadowbuf_size)
				shadowbuf_size = pos + size;
			break;
		case 6:
			pos = i_rand_limit(BUF_TEST_SIZE - 1);
			size = i_rand_limit(BUF_TEST_SIZE - pos);
			p = buffer_get_space_unsafe(buf, pos, size);
			memcpy(p, testdata, size);
			memcpy(shadowbuf + pos, testdata, size);
			if (pos + size > shadowbuf_size)
				shadowbuf_size = pos + size;
			break;
		}
		i_assert(shadowbuf_size <= BUF_TEST_SIZE);

		if (buf->used != shadowbuf_size ||
		    memcmp(buf->data, shadowbuf, buf->used) != 0)
			break;
	}
	if (i == BUF_TEST_COUNT)
		test_out("buffer", TRUE);
	else {
		test_out_reason("buffer", FALSE,
			t_strdup_printf("round %u test %d failed", i, test));
	}
	buffer_free(&buf);
}

static void test_buffer_write(void)
{
	buffer_t *buf;

	test_begin("buffer_write");
	buf = t_buffer_create(8);
	buffer_write(buf, 5, buf, 0);
	test_assert(buf->used == 5);
	test_end();
}

static void test_buffer_set_used_size(void)
{
	buffer_t *buf;

	test_begin("buffer_set_used_size");
	buf = t_buffer_create(8);
	memset(buffer_append_space_unsafe(buf, 7), 'a', 7);
	buffer_set_used_size(buf, 4);
	test_assert(memcmp(buffer_get_space_unsafe(buf, 0, 7), "aaaa\0\0\0", 7) == 0);
	memset(buffer_get_space_unsafe(buf, 4, 7), 'b', 7);
	buffer_set_used_size(buf, 10);
	test_assert(memcmp(buffer_append_space_unsafe(buf, 1), "\0", 1) == 0);
	buffer_set_used_size(buf, 11);
	test_assert(memcmp(buffer_get_space_unsafe(buf, 0, 11), "aaaabbbbbb\0", 11) == 0);
	test_end();
}


#if 0

/* this code is left here to produce the output found in
 * buffer.h should it be needed for debugging purposes */
#include "str.h"
#include "hex-binary.h"
static const char *binary_to_10(const unsigned char *data, size_t size)
{
	string_t *str = t_str_new(size*8);

	for (size_t i = 0; i < size; i++) {
		for (int j = 0; j < 8; j++) {
			if ((data[i] & (1 << (7-j))) != 0)
				str_append_c(str, '1');
			else
				str_append_c(str, '0');
		}
	}
	return str_c(str);
}

static void test_foo(void)
{
	buffer_t *buf = buffer_create_dynamic(default_pool, 100);

	for (int i = 1; i <= 24; i++) {
		buffer_set_used_size(buf, 0);
		buffer_append_c(buf, 0xff);
		buffer_append_c(buf, 0xff);
		buffer_append_c(buf, 0xff);
		buffer_truncate_rshift_bits(buf, i);
		printf("%2d bits: %24s %s\n", i,
		       binary_to_hex(buf->data, buf->used),
		       binary_to_10(buf->data, buf->used));
	}
}

#endif

static void test_buffer_truncate_bits(void)
{
	buffer_t *buf;
	test_begin("buffer_test_truncate_bits");

	struct {
		buffer_t input;
		size_t bits;
		buffer_t output;
	} test_cases[] = {
                { { "\xff\xff\xff", 3, {0} },  0, { "",  0, {0} } },
                { { "\xff\xff\xff", 3, {0} },  1, { "\x01", 1, {0} } },
                { { "\xff\xff\xff", 3, {0} },  2, { "\x03", 1, {0} } },
                { { "\xff\xff\xff", 3, {0} },  3, { "\x07", 1, {0} } },
                { { "\xff\xff\xff", 3, {0} },  4, { "\x0f", 1, {0} } },
                { { "\xff\xff\xff", 3, {0} },  5, { "\x1f", 1, {0} } },
                { { "\xff\xff\xff", 3, {0} },  6, { "\x3f", 1, {0} } },
                { { "\xff\xff\xff", 3, {0} },  7, { "\x7f", 1, {0} } },
                { { "\xff\xff\xff", 3, {0} },  8, { "\xff", 1, {0} } },
                { { "\xff\xff\xff", 3, {0} },  9, { "\x01\xff", 2, {0} } },
                { { "\xff\xff\xff", 3, {0} }, 10, { "\x03\xff", 2, {0} } },
                { { "\xff\xff\xff", 3, {0} }, 11, { "\x07\xff", 2, {0} } },
                { { "\xff\xff\xff", 3, {0} }, 12, { "\x0f\xff", 2, {0} } },
                { { "\xff\xff\xff", 3, {0} }, 13, { "\x1f\xff", 2, {0} } },
                { { "\xff\xff\xff", 3, {0} }, 14, { "\x3f\xff", 2, {0} } },
                { { "\xff\xff\xff", 3, {0} }, 15, { "\x7f\xff", 2, {0} } },
                { { "0123456789", 10, {0} }, 16, { "01",  2, {0} } },
                { { "0123456789", 10, {0} }, 24, { "012",  3, {0} } },
                { { "0123456789", 10, {0} }, 32, { "0123",  4, {0} } },
                { { "0123456789", 10, {0} }, 40, { "01234",  5, {0} } },
                { { "0123456789", 10, {0} }, 48, { "012345",  6, {0} } },
                { { "0123456789", 10, {0} }, 56, { "0123456",  7, {0} } },
                { { "0123456789", 10, {0} }, 64, { "01234567",  8, {0} } },
                { { "0123456789", 10, {0} }, 72, { "012345678",  9, {0} } },
		{ { "0123456789", 10, {0} }, 80, { "0123456789", 10, {0} } },

		{ { "\x58\x11\xed\x02\x4d\x87\x4a\xe2\x5c\xb2\xfa\x69\xf0\xa9\x46\x2e\x04\xca\x5d\x82", 20, {0} },
		  13,
		  { "\x0b\x02", 2, {0} }
		},

		/* special test cases for auth policy */

		{ { "\x34\x40\xc8\xc9\x3a\xb6\xe7\xc4\x3f\xc1\xc3\x4d\xd5\x56\xa3\xea\xfb\x5a\x33\x57\xac\x11\x39\x2c\x71\xcb\xee\xbb\xc8\x66\x2f\x64", 32, {0} },
		  12,
		  { "\x03\x44", 2, {0} }
		},

		{ { "\x49\xe5\x8a\x88\x76\xd3\x25\x68\xc9\x89\x4a\xe0\x64\xe4\x04\xf4\xf9\x13\xec\x88\x97\x47\x30\x7f\x3f\xcd\x8f\x74\x4f\x40\xd1\x25", 32, {0} },
                  12,
                  { "\x04\x9e", 2, {0} }
                },

		{ { "\x08\x3c\xdc\x14\x61\x80\x1c\xe8\x43\x81\x98\xfa\xc0\x64\x04\x7a\xa2\x73\x25\x6e\xe6\x4b\x85\x42\xd0\xe2\x78\xd7\x91\xb4\x89\x3f", 32, {0} },
                  12,
                  { "\x00\x83", 2, {0} }
                },

	};

	buf = t_buffer_create(10);

	for(size_t i = 0; i < N_ELEMENTS(test_cases); i++) {
		buffer_set_used_size(buf, 0);
		buffer_copy(buf, 0, &test_cases[i].input, 0, (size_t)-1);
		buffer_truncate_rshift_bits(buf, test_cases[i].bits);
		test_assert_idx(buffer_cmp(buf, &test_cases[i].output) == TRUE, i);
	}

	test_end();
}

static void test_buffer_replace(void)
{
	const char orig_input[] = "123456789";
	const char data[] = "abcdefghij";
	buffer_t *buf, *buf2;
	unsigned int init_size, pos, size, data_size;

	test_begin("buffer_replace()");
	for (init_size = 0; init_size <= sizeof(orig_input)-1; init_size++) {
		for (pos = 0; pos < sizeof(orig_input)+1; pos++) {
			for (size = 0; size < sizeof(orig_input)+1; size++) {
				for (data_size = 0; data_size <= sizeof(data)-1; data_size++) T_BEGIN {
					buf = buffer_create_dynamic(pool_datastack_create(), 4);
					buf2 = buffer_create_dynamic(pool_datastack_create(), 4);
					buffer_append(buf, orig_input, init_size);
					buffer_append(buf2, orig_input, init_size);

					buffer_replace(buf, pos, size, data, data_size);
					buffer_delete(buf2, pos, size);
					buffer_insert(buf2, pos, data, data_size);
					test_assert(buf->used == buf2->used &&
						    memcmp(buf->data, buf2->data, buf->used) == 0);
				} T_END;
			}
		}
	}

	test_end();
}

void test_buffer(void)
{
	test_buffer_random();
	test_buffer_write();
	test_buffer_set_used_size();
	test_buffer_truncate_bits();
	test_buffer_replace();
}
