/* Copyright (c) 2026 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "istream-private.h"
#include "unichar.h"
#include "test-common.h"

#include "istream-json-string.h"

/*
 * Helpers
 */

static string_t *
read_json_string_stream(const char *raw, size_t raw_len)
{
	struct istream *parent, *stream;
	const unsigned char *data;
	size_t size;
	string_t *out;
	int ret;

	parent = i_stream_create_from_data(raw, raw_len);
	stream = i_stream_create_json_string(parent);
	i_stream_unref(&parent);

	out = str_new(default_pool, raw_len + 4);
	while ((ret = i_stream_read_more(stream, &data, &size)) > 0) {
		str_append_data(out, data, size);
		i_stream_skip(stream, size);
	}
	test_assert(ret < 0);
	test_assert_cmp(stream->stream_errno, ==, 0);
	test_assert_strcmp(i_stream_get_error(stream), "EOF");
	i_stream_unref(&stream);
	return out;
}

static string_t *
read_json_string_stream_trickle(const char *raw, size_t raw_len,
				size_t step)
{
	struct istream *parent, *stream;
	const unsigned char *data;
	size_t size, pos;
	string_t *out;
	int ret;

	parent = test_istream_create_data(raw, raw_len);
	stream = i_stream_create_json_string(parent);

	out = str_new(default_pool, raw_len + 4);
	for (pos = 0; pos <= raw_len; pos += step) {
		test_istream_set_size(parent, pos);
		while ((ret = i_stream_read_more(stream, &data, &size)) > 0) {
			str_append_data(out, data, size);
			i_stream_skip(stream, size);
		}
		if (ret < 0)
			break;
	}
	test_istream_set_size(parent, raw_len);
	test_istream_set_allow_eof(parent, TRUE);
	while ((ret = i_stream_read_more(stream, &data, &size)) > 0) {
		str_append_data(out, data, size);
		i_stream_skip(stream, size);
	}
	test_assert(ret < 0);
	test_assert_cmp(stream->stream_errno, ==, 0);
	test_assert_strcmp(i_stream_get_error(stream), "EOF");
	i_stream_unref(&stream);
	i_stream_unref(&parent);
	return out;
}

static void
read_json_string_stream_expect_invalid(const char *raw, size_t raw_len,
				       int expect_errno)
{
	struct istream *parent, *stream;
	const unsigned char *data;
	size_t size;
	int ret;

	parent = i_stream_create_from_data(raw, raw_len);
	stream = i_stream_create_json_string(parent);
	i_stream_unref(&parent);

	while ((ret = i_stream_read_more(stream, &data, &size)) > 0)
		i_stream_skip(stream, size);
	test_assert(ret < 0);
	test_assert_cmp(stream->stream_errno, ==, expect_errno);
	i_stream_unref(&stream);
}

/*
 * Tests
 */

struct json_string_decode_test {
	const char *input;    /* raw JSON string bytes (no surrounding quotes) */
	const char *output;   /* expected decoded bytes */
};

static const struct json_string_decode_test decode_tests[] = {
	/* Empty */
	{ "", "" },
	/* Plain ASCII pass-through */
	{ "hello world", "hello world" },
	/* All single-char escapes */
	{ "\\\"", "\"" },
	{ "\\\\", "\\" },
	{ "\\/", "/" },
	{ "\\b", "\x08" },
	{ "\\f", "\x0c" },
	{ "\\n", "\n" },
	{ "\\r", "\r" },
	{ "\\t", "\t" },
	/* Escape mixed with plain text */
	{ "hello\\nworld", "hello\nworld" },
	{ "\\\"quoted\\\"", "\"quoted\"" },
	{ "foo\\\\bar", "foo\\bar" },
	/* Multiple escapes in a row */
	{ "\\\"\\\\\\n\\r\\t", "\"\\\n\r\t" },
	/* \uXXXX: U+0041 = A (1-byte UTF-8) */
	{ "\\u0041", "A" },
	/* \uXXXX: U+00C9 = LATIN CAPITAL LETTER E WITH ACUTE (2-byte UTF-8) */
	{ "\\u00C9", "\xc3\x89" },
	/* \uXXXX: U+4E2D = CJK UNIFIED IDEOGRAPH (3-byte UTF-8) */
	{ "\\u4E2D", "\xe4\xb8\xad" },
	/* Surrogate pair: U+1F600 = GRINNING FACE emoji */
	{ "\\uD83D\\uDE00", "\xf0\x9f\x98\x80" },
	/* Surrogate pair: U+10437 = DESERET SMALL LETTER EW */
	{ "\\uD801\\uDC37", "\xf0\x90\x90\xb7" },
	/* Mix of plain text, single escape, and unicode */
	{ "A\\u0042C", "ABC" },
	{ "pre\\u4E2Dpost", "pre\xe4\xb8\xadpost" },
	/* Long plain run (no backslash) */
	{ "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
	/* Escape right at start and end */
	{ "\\nfoo\\n", "\nfoo\n" },
	/* U+FFFF (3-byte UTF-8) */
	{ "\\uFFFF", "\xef\xbf\xbf" },
};

static void test_istream_json_string_decode(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(decode_tests); i++) T_BEGIN {
		const struct json_string_decode_test *test = &decode_tests[i];
		size_t in_len = strlen(test->input);
		size_t out_len = strlen(test->output);
		string_t *got;

		test_begin(t_strdup_printf("istream json string decode [%u]", i));

		/* buffered */
		got = read_json_string_stream(test->input, in_len);
		test_assert_memcmp_idx(str_data(got), str_len(got),
				       test->output, out_len, i);
		str_free(&got);

		test_end();
	} T_END;
}

static void test_istream_json_string_trickle(void)
{
	static const unsigned int steps[] = {1, 2, 3};
	unsigned int i, s;

	for (i = 0; i < N_ELEMENTS(decode_tests); i++) T_BEGIN {
		const struct json_string_decode_test *test = &decode_tests[i];
		size_t in_len = strlen(test->input);
		size_t out_len = strlen(test->output);

		for (s = 0; s < N_ELEMENTS(steps); s++) {
			string_t *got;

			test_begin(t_strdup_printf(
				"istream json string trickle [%u, step=%u]",
				i, steps[s]));

			got = read_json_string_stream_trickle(
				test->input, in_len, steps[s]);
			test_assert_memcmp_idx(str_data(got), str_len(got),
					       test->output, out_len, i);
			str_free(&got);
			test_end();
		}
	} T_END;
}

static void test_istream_json_string_partial_skip(void)
{
	struct istream *parent, *stream;
	const unsigned char *data, *held_data;
	size_t size, pos, held_size, consumed;
	string_t *raw, *expected;
	int ret;
	unsigned int i;

	/* Escaped content long enough to force several buffer growth
	   cycles in the decoding stream's internal buffer (starts at 256
	   bytes, json-parser.c). */
	raw = t_str_new(4096);
	expected = t_str_new(2048);
	for (i = 0; i < 300; i++) {
		str_append(raw, "\\n");
		str_append_c(expected, '\n');
	}

	test_begin("istream json string buffer stays valid across partial skip");

	parent = test_istream_create_data(str_data(raw), str_len(raw));
	stream = i_stream_create_json_string(parent);

	/* On each round, consume all but a small tail of what's newly
	   available, and keep the raw pointer to that unconsumed tail
	   without re-fetching it. The istream framework treats unconsumed
	   data (skip != pos) as still "live" across the next read, so it -
	   and the bytes behind it - must remain valid even though the next
	   round's read forces the decoding stream's buffer to grow (and
	   potentially move). Checked at the start of the following round,
	   right before consuming anything more. */
	held_data = NULL;
	held_size = 0;
	consumed = 0;

	for (pos = 50; pos <= str_len(raw); pos += 50) {
		test_istream_set_size(parent, pos);

		ret = i_stream_read_more(stream, &data, &size);
		test_assert(ret >= 0);
		if (ret <= 0)
			continue;

		if (held_data != NULL) {
			test_assert_memcmp(held_data, held_size,
					   str_data(expected) + consumed,
					   held_size);
		}

		/* Consume all but a small tail. */
		size_t hold_back = I_MIN(3, size);
		size_t skip_now = size - hold_back;

		i_stream_skip(stream, skip_now);
		consumed += skip_now;
		held_data = data + skip_now;
		held_size = hold_back;
	}

	test_istream_set_size(parent, str_len(raw));
	test_istream_set_allow_eof(parent, TRUE);
	while ((ret = i_stream_read_more(stream, &data, &size)) > 0) {
		if (held_data != NULL) {
			test_assert_memcmp(held_data, held_size,
					   str_data(expected) + consumed,
					   held_size);
			held_data = NULL;
		}
		i_stream_skip(stream, size);
		consumed += size;
	}
	test_assert(ret < 0);
	test_assert_cmp(stream->stream_errno, ==, 0);
	test_assert_strcmp(i_stream_get_error(stream), "EOF");
	test_assert_cmp(consumed, ==, str_len(expected));

	i_stream_unref(&stream);
	i_stream_unref(&parent);

	test_end();
}

static void test_istream_json_string_lone_surrogate(void)
{
	/* Lone high surrogate (nothing to pair it with before EOF): rejected
	   with EINVAL rather than silently substituted. */
	const char *input = "\\uD800X";

	test_begin("istream json string lone high surrogate");
	read_json_string_stream_expect_invalid(input, strlen(input), EINVAL);
	test_end();
}

static void test_istream_json_string_lone_surrogate_at_eof(void)
{
	/* Same as the lone-surrogate case above, but with EOF immediately
	   after the escape instead of a following character.  Must fail the
	   same way, not silently succeed with a truncated string. */
	const char *input = "\\uD800";

	test_begin("istream json string lone high surrogate at EOF");
	read_json_string_stream_expect_invalid(input, strlen(input), EINVAL);
	test_end();
}

static void test_istream_json_string_escape_at_boundary(void)
{
	/* Feed input one byte at a time; escape straddles reads */
	static const struct json_string_decode_test boundary_tests[] = {
		{ "ab\\ncd",   "ab\ncd"   },
		{ "\\u0041B",  "AB"       },
		{ "A\\u0042",  "AB"       },
		{ "\\uD83D\\uDE00end", "\xf0\x9f\x98\x80" "end" },
	};
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(boundary_tests); i++) T_BEGIN {
		const struct json_string_decode_test *test =
			&boundary_tests[i];
		size_t in_len = strlen(test->input);
		size_t out_len = strlen(test->output);
		string_t *got;

		test_begin(t_strdup_printf(
			"istream json string escape at boundary [%u]", i));

		got = read_json_string_stream_trickle(test->input, in_len, 1);
		test_assert_memcmp_idx(str_data(got), str_len(got),
				       test->output, out_len, i);
		str_free(&got);
		test_end();
	} T_END;
}

static void test_istream_json_string_truncated_escape(void)
{
	/* Cut off mid-escape at various states; all end at true EOF (not
	   just a syntax error mid-stream), so all must fail with EPIPE -
	   see istream-json-string.c's stream_errno = (at_end ? EPIPE :
	   EINVAL): EINVAL is for a malformed escape encountered with more
	   input still available (see the lone-surrogate tests below). */
	static const char *const truncated_tests[] = {
		"\\",          /* right after backslash */
		"\\u",         /* \u, 0 hex digits read */
		"\\u0",        /* 1 hex digit read */
		"\\u00",       /* 2 hex digits read */
		"\\u000",      /* 3 hex digits read */
		"\\uD800\\",   /* high surrogate, then \, cut before 'u' */
		"\\uD800\\u",  /* high surrogate + \u, cut before hex digits */
		"\\uD800\\u0", /* low surrogate, 1 hex digit read */
	};
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(truncated_tests); i++) T_BEGIN {
		test_begin(t_strdup_printf(
			"istream json string truncated escape [%u]", i));
		read_json_string_stream_expect_invalid(
			truncated_tests[i], strlen(truncated_tests[i]), EPIPE);
		test_end();
	} T_END;
}

static void test_istream_json_string_seek(void)
{
	struct istream *parent, *stream;
	const unsigned char *data;
	size_t size;
	string_t *raw, *expected, *got;
	unsigned int i;
	int ret;

	/* Plain text, no escapes, long enough to seek within. */
	raw = t_str_new(64);
	expected = t_str_new(64);
	for (i = 0; i < 40; i++) {
		str_append_c(raw, 'A' + (i % 26));
		str_append_c(expected, 'A' + (i % 26));
	}

	test_begin("istream json string seek forward past buffered data");

	parent = i_stream_create_from_data(str_data(raw), str_len(raw));
	stream = i_stream_create_json_string(parent);
	i_stream_unref(&parent);

	/* Seek forward without reading anything first: forces the decoder
	   to be bootstrapped and read-and-discarded up to offset 10 (see
	   i_stream_json_string_seek()'s forward path). */
	i_stream_seek(stream, 10);
	test_assert_cmp(stream->v_offset, ==, 10);
	test_assert_cmp(stream->stream_errno, ==, 0);

	ret = i_stream_read_more(stream, &data, &size);
	test_assert(ret > 0);
	if (ret > 0) {
		test_assert_cmp(size, ==, str_len(expected) - 10);
		test_assert_memcmp(data, size, str_data(expected) + 10, size);
	}

	i_stream_unref(&stream);

	test_end();

	test_begin("istream json string seek backwards restarts decoder");

	parent = i_stream_create_from_data(str_data(raw), str_len(raw));
	stream = i_stream_create_json_string(parent);
	i_stream_unref(&parent);

	/* Read forward past the halfway point first. */
	i_stream_seek(stream, 20);
	test_assert_cmp(stream->v_offset, ==, 20);
	test_assert_cmp(stream->stream_errno, ==, 0);

	/* Seek backward to the start: this must go through
	   json_string_istream_restart() (json-parser.c) rather than
	   replaying stale buffered content, which is impossible here since
	   this stream's buffer is a live view into the parser's shared
	   decode buffer. */
	i_stream_seek(stream, 0);
	test_assert_cmp(stream->v_offset, ==, 0);
	test_assert_cmp(stream->stream_errno, ==, 0);

	got = str_new(default_pool, str_len(raw) + 1);
	while ((ret = i_stream_read_more(stream, &data, &size)) > 0) {
		str_append_data(got, data, size);
		i_stream_skip(stream, size);
	}
	test_assert(ret < 0);
	test_assert_cmp(stream->stream_errno, ==, 0);
	test_assert_memcmp(str_data(got), str_len(got),
			   str_data(expected), str_len(expected));
	str_free(&got);

	i_stream_unref(&stream);

	test_end();
}

static void test_istream_json_string_overflow_resume(void)
{
	/* Regression test for 820c7538c0 ("clear context on unicode escape
	   overflow resume"): json_parser_parse_unicode_escape() parks the
	   already-decoded character in state->context when the nested
	   parser's decode buffer doesn't have room for it. Forced here with
	   a 2-byte max_buffer_size: "A" ("A", 1-byte UTF-8) fills the
	   buffer to capacity, so "É" ("\xc3\x89", 2-byte UTF-8) that
	   follows it overflows and gets parked instead of appended. Once
	   the buffer is drained and parsing resumes, the parked character
	   is appended - and if the resume path doesn't clear state->context
	   afterwards, the next json_parser_parse_unicode_escape_close()
	   call (fired here for the plain "X" that follows the escape)
	   asserts on the stale non-surrogate value instead of seeing a
	   clean "no pending surrogate" state. */
	struct istream *parent, *stream;
	const unsigned char *data;
	size_t size;
	string_t *got;
	int ret;
	static const char raw[] = "\\u0041\\u00C9X";

	test_begin("istream json string overflow-resume (820c7538c0)");

	parent = i_stream_create_from_data(raw, strlen(raw));
	stream = i_stream_create_json_string(parent);
	i_stream_unref(&parent);
	i_stream_set_max_buffer_size(stream, 2);

	got = str_new(default_pool, 8);
	while ((ret = i_stream_read_more(stream, &data, &size)) > 0) {
		str_append_data(got, data, size);
		i_stream_skip(stream, size);
	}
	test_assert(ret < 0);
	test_assert_cmp(stream->stream_errno, ==, 0);
	test_assert_strcmp(i_stream_get_error(stream), "EOF");
	test_assert_strcmp(str_c(got), "A\xc3\x89X");
	str_free(&got);
	i_stream_unref(&stream);

	test_end();
}

static void test_istream_json_string_snapshot(void)
{
	struct istream *parent, *stream;
	struct istream_private *_stream;
	struct istream_snapshot *snapshot;
	const unsigned char *data;
	size_t size, snapshot_size;
	string_t *raw, *expected;
	unsigned int i;
	int ret;

	/* Escaped content long enough to force several buffer growth cycles
	   in the decoding stream's buffer. */
	raw = t_str_new(4096);
	expected = t_str_new(2048);
	for (i = 0; i < 300; i++) {
		str_append(raw, "\\n");
		str_append_c(expected, '\n');
	}

	test_begin("istream json string snapshot");

	parent = test_istream_create_data(str_data(raw), str_len(raw));
	test_istream_set_size(parent, 10);
	stream = i_stream_create_json_string(parent);
	_stream = stream->real_stream;

	/* Snapshotting before anything was read must work as well. */
	snapshot = _stream->snapshot(_stream, NULL);
	i_stream_snapshot_free(&snapshot);

	/* Read the beginning of the string and hold on to it. */
	ret = i_stream_read_more(stream, &data, &size);
	test_assert(ret > 0 && size > 0);
	snapshot_size = size;
	snapshot = _stream->snapshot(_stream, NULL);

	/* Decode the remainder of the string without consuming anything,
	   which reallocates the buffer. */
	for (i = 20; i <= str_len(raw); i += 10) {
		test_istream_set_size(parent, i);
		if (i_stream_read(stream) == -2)
			break;
	}
	i_stream_unref(&stream);

	/* The snapshotted data must still be intact. */
	test_assert_memcmp(data, snapshot_size,
			   str_data(expected), snapshot_size);

	i_stream_snapshot_free(&snapshot);
	i_stream_unref(&parent);

	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_istream_json_string_decode,
		test_istream_json_string_trickle,
		test_istream_json_string_partial_skip,
		test_istream_json_string_lone_surrogate,
		test_istream_json_string_lone_surrogate_at_eof,
		test_istream_json_string_escape_at_boundary,
		test_istream_json_string_truncated_escape,
		test_istream_json_string_seek,
		test_istream_json_string_overflow_resume,
		test_istream_json_string_snapshot,
		NULL
	};
	return test_run(test_functions);
}
