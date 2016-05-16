/* Copyright (c) 2007-2016 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "buffer.h"

static void test_buffer_random(void)
{
#define BUF_TEST_SIZE (1024*2)
#define BUF_TEST_COUNT 1000
	buffer_t *buf;
	unsigned char *p, testdata[BUF_TEST_SIZE], shadowbuf[BUF_TEST_SIZE];
	unsigned int i, shadowbuf_size;
	size_t pos, pos2, size;
	int test = -1;
	bool zero;

	buf = buffer_create_dynamic(default_pool, 1);
	for (i = 0; i < BUF_TEST_SIZE; i++)
		testdata[i] = rand();
	memset(shadowbuf, 0, sizeof(shadowbuf));

	shadowbuf_size = 0;
	for (i = 0; i < BUF_TEST_COUNT; i++) {
		if (buf->used == BUF_TEST_SIZE) {
			size = shadowbuf_size = rand() % (buf->used - 1);
			buffer_set_used_size(buf, size);
			memset(shadowbuf + shadowbuf_size, 0,
			       BUF_TEST_SIZE - shadowbuf_size);
			i_assert(buf->used < BUF_TEST_SIZE);
		}

		test = rand() % 6;
		zero = rand() % 10 == 0;
		switch (test) {
		case 0:
			pos = rand() % (BUF_TEST_SIZE-1);
			size = rand() % (BUF_TEST_SIZE - pos);
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
			size = rand() % (BUF_TEST_SIZE - buf->used);
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
			pos = rand() % (BUF_TEST_SIZE-1);
			size = rand() % (BUF_TEST_SIZE - I_MAX(buf->used, pos));
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
			pos = rand() % (BUF_TEST_SIZE-1);
			size = rand() % (BUF_TEST_SIZE - pos);
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
			if (shadowbuf_size <= 1)
				break;
			pos = rand() % (shadowbuf_size-1); /* dest */
			pos2 = rand() % (shadowbuf_size-1); /* source */
			size = rand() % (shadowbuf_size - I_MAX(pos, pos2));
			buffer_copy(buf, pos, buf, pos2, size);
			memmove(shadowbuf + pos,
				shadowbuf + pos2, size);
			if (pos > pos2 && pos + size > shadowbuf_size)
				shadowbuf_size = pos + size;
			break;
		case 5:
			pos = rand() % (BUF_TEST_SIZE-1);
			size = rand() % (BUF_TEST_SIZE - pos);
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

static void test_buffer_set_used_size(void)
{
	buffer_t *buf;

	test_begin("buffer_set_used_size");
	buf = buffer_create_dynamic(pool_datastack_create(), 8);
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

void test_buffer(void)
{
	test_buffer_random();
	test_buffer_set_used_size();
}
