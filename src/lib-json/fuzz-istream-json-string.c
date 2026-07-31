/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "istream-private.h"
#include "test-common.h"
#include "fuzzer.h"

#include "istream-json-string.h"

/*
 * Feed arbitrary bytes into i_stream_create_json_string() and:
 *   1. Drain the decoded output completely.
 *   2. If the stream is seekable, seek back to 0 and drain again,
 *      verifying both reads produce identical output.
 */
FUZZ_BEGIN_DATA(const unsigned char *data, size_t size)
{
	struct istream *raw, *jstr;
	const unsigned char *buf;
	size_t buf_size;
	string_t *first, *second;
	ssize_t ret;

	raw = i_stream_create_from_data(data, size);
	jstr = i_stream_create_json_string(raw);
	i_stream_unref(&raw);

	/* First pass: decode everything */
	first = str_new(default_pool, 64);
	while ((ret = i_stream_read_more(jstr, &buf, &buf_size)) > 0) {
		str_append_data(first, buf, buf_size);
		i_stream_skip(jstr, buf_size);
	}
	/* ret == -1 on EOF or error; either is acceptable for fuzz input */

	/* Second pass: seek back and verify output is identical.
	   Only meaningful when the first pass completed without error;
	   i_stream_seek() is a no-op when stream_errno != 0. */
	if (jstr->seekable && jstr->stream_errno == 0) {
		i_stream_seek(jstr, 0);

		second = str_new(default_pool, 64);
		while ((ret = i_stream_read_more(jstr, &buf, &buf_size)) > 0) {
			str_append_data(second, buf, buf_size);
			i_stream_skip(jstr, buf_size);
		}

		/* Both reads must produce the same bytes */
		i_assert(str_len(first) == str_len(second) &&
			 memcmp(str_data(first), str_data(second),
				str_len(first)) == 0);
		str_free(&second);
	}

	str_free(&first);
	i_stream_unref(&jstr);
}
FUZZ_END
