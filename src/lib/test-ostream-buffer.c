/* Copyright (c) 2017 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "buffer.h"
#include "str.h"
#include "randgen.h"
#include "istream.h"
#include "ostream.h"

#define MAX_BUFSIZE 256

static void test_ostream_buffer_random_once(void)
{
	buffer_t *buffer;
	struct ostream *output;
	char buf[MAX_BUFSIZE*4], randbuf[MAX_BUFSIZE];
	unsigned int i, offset, size;

	buffer = buffer_create_dynamic(default_pool, 8);

	memset(buf, 0, sizeof(buf));

	output = o_stream_create_buffer(buffer);
	o_stream_cork(output);

	size = i_rand_minmax(1, MAX_BUFSIZE);
	random_fill(randbuf, size);
	memcpy(buf, randbuf, size);
	test_assert(o_stream_send(output, buf, size) > 0);

	for (i = 0; i < 10; i++) {
		offset = i_rand_limit(MAX_BUFSIZE * 3);
		size = i_rand_minmax(1, MAX_BUFSIZE);
		random_fill(randbuf, size);
		memcpy(buf + offset, randbuf, size);
		test_assert(o_stream_pwrite(output, randbuf, size, offset) == 0);
		if (i_rand_limit(10) == 0)
			test_assert(o_stream_flush(output) > 0);
	}

	o_stream_uncork(output);
	test_assert(o_stream_nfinish(output) == 0);

	i_assert(buffer->used <= MAX_BUFSIZE*4);
	test_assert(memcmp(buf, buffer->data, buffer->used) == 0);

	o_stream_unref(&output);
	buffer_free(&buffer);
}

static void test_ostream_buffer_random(void)
{
	unsigned int i;

	test_begin("ostream buffer pwrite random");
	for (i = 0; i < 100; i++) T_BEGIN {
		test_ostream_buffer_random_once();
	} T_END;
	test_end();
}

static void test_ostream_buffer_size(void)
{
	struct ostream *output;
	string_t *str = t_str_new(64);

	test_begin("ostream buffer size/available");
	output = o_stream_create_buffer(str);
	test_assert(o_stream_get_buffer_used_size(output) == 0);
	test_assert(o_stream_get_buffer_avail_size(output) == (size_t)-1);

	/* test shrinking sink's max buffer size */
	o_stream_set_max_buffer_size(output, 10);
	test_assert(o_stream_get_buffer_used_size(output) == 0);
	test_assert(o_stream_get_buffer_avail_size(output) == 10);

	/* partial send */
	const char *partial_input = "01234567890123456789";
	ssize_t ret = o_stream_send_str(output, partial_input);
	test_assert(ret == 10);
	test_assert(o_stream_get_buffer_used_size(output) == 10);
	test_assert(o_stream_get_buffer_avail_size(output) == 0);
	
	/* increase max buffer size so that it can hold the whole message */
	o_stream_set_max_buffer_size(output, 100);
	test_assert(o_stream_get_buffer_used_size(output) == 10);
	test_assert(o_stream_get_buffer_avail_size(output) == 90);

	/* send the rest */
	ret += o_stream_send_str(output, partial_input + ret);
	test_assert(ret == (ssize_t)strlen(partial_input));
	test_assert(output->offset == str_len(str));
	test_assert(o_stream_get_buffer_used_size(output) == 20);
	test_assert(o_stream_get_buffer_avail_size(output) == 80);

	/* check buffered data */
	test_assert(strcmp(str_c(str), partial_input) == 0);

	o_stream_unref(&output);

	test_end();
}

void test_ostream_buffer(void)
{
	test_ostream_buffer_random();
	test_ostream_buffer_size();
}
