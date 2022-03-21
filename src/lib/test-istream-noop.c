/* Copyright (c) 2022 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "istream.h"

void test_istream_noop(void)
{
	test_begin("istream_noop");
	struct istream *is = test_istream_create("this is a simple istream");
	struct istream *is_noop = i_stream_create_noop(is);
	i_stream_unref(&is);

	string_t *str = t_str_new(128);

	test_istream_set_max_buffer_size(is_noop, 3);
	while (i_stream_read(is_noop) > 0) {
		size_t size;
		const unsigned char *data = i_stream_get_data(is_noop, &size);
		str_append_data(str, data, size);
		i_stream_skip(is_noop, size);
	}

	test_assert(is_noop->eof);
	test_assert(is_noop->stream_errno == 0);
	test_assert_strcmp("this is a simple istream", str_c(str));

	i_stream_unref(&is_noop);

	test_end();
}
