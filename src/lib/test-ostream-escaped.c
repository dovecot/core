/* Copyright (c) 2016 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "ostream.h"
#include "ostream-escaped.h"
#include "json-parser.h"

static void test_ostream_escaped_json(void)
{
	struct ostream *os_sink;
	struct ostream *os_encode;
	struct const_iovec iov[2];
	string_t *str = t_str_new(64);

	test_begin("test_ostream_escaped_json()");
	os_sink = o_stream_create_buffer(str);
	os_encode = o_stream_create_escaped(os_sink, ostream_escaped_json_format);

	/* test sending iovec */
	iov[0].iov_base = "hello";
	iov[0].iov_len = 5;
	iov[1].iov_base = ", world";
	iov[1].iov_len = 7;
	test_assert(o_stream_sendv(os_encode, iov, 2) == 12);
	test_assert(os_encode->offset == 12);
	test_assert(os_sink->offset == 12);
	test_assert(strcmp(str_c(str), "hello, world") == 0);

	/* reset buffer */
	str_truncate(str, 0); os_sink->offset = 0; os_encode->offset = 0;

	/* test shrinking ostream-escaped's max buffer size */
	o_stream_set_max_buffer_size(os_encode, 10);
	o_stream_set_max_buffer_size(os_sink, 100);
	test_assert(o_stream_send(os_encode, "\x15\x00!\x00\x15\x11" "123456", 12) == 12);
	test_assert(os_encode->offset == 12);
	test_assert(os_sink->offset == 2*6 + 1 + 3*6 + 6);
	test_assert(strcmp(str_c(str), "\\u0015\\u0000!\\u0000\\u0015\\u0011123456") == 0);

	/* reset buffer */
	str_truncate(str, 0); os_sink->offset = 0; os_encode->offset = 0;

	/* test shrinking sink's max buffer size */
	o_stream_set_max_buffer_size(os_encode, 100);
	o_stream_set_max_buffer_size(os_sink, 10);
	const char *partial_input = "\x15!\x01?#&";
	ssize_t ret = o_stream_send_str(os_encode, partial_input);
	test_assert(ret < 6);
	/* send the rest */
	o_stream_set_max_buffer_size(os_sink, 100);
	ret += o_stream_send_str(os_encode, partial_input + ret);
	test_assert(ret == (ssize_t)strlen(partial_input));
	test_assert((ssize_t)os_encode->offset == ret);
	test_assert(os_sink->offset == str_len(str));
	test_assert(strcmp(str_c(str), "\\u0015!\\u0001?#&") == 0);

	o_stream_unref(&os_encode);
	o_stream_unref(&os_sink);

	test_end();
}

static void test_ostream_escaped_hex(void)
{
	struct ostream *os_sink;
	struct ostream *os_encode;
	string_t *str = t_str_new(64);

	os_sink = o_stream_create_buffer(str);
	os_encode = o_stream_create_escaped(os_sink, ostream_escaped_hex_format);

	test_begin("test_ostream_escaped_hex()");
	o_stream_send_str(os_encode, "hello, world");
	o_stream_flush(os_encode);

	test_assert(strcmp(str_c(str), "68656c6c6f2c20776f726c64") == 0);

	o_stream_unref(&os_encode);
	o_stream_unref(&os_sink);

	test_end();
}

void test_ostream_escaped(void) {
	test_ostream_escaped_json();
	test_ostream_escaped_hex();
}
