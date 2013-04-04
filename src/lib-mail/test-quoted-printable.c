/* Copyright (c) 2007-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "quoted-printable.h"
#include "test-common.h"

struct test_quoted_printable_decode_data {
	const char *input;
	const char *output;
	int end_skip;
	int ret;
};

static void test_quoted_printable_decode(void)
{
	static struct test_quoted_printable_decode_data data[] = {
		{ "foo  \r\nbar=", "foo\r\nbar", 1, 0 },
		{ "foo\t=\nbar", "foo\tbar", 0, 0 },
		{ "foo = \n=01", "foo \001", 0, 0 },
		{ "foo =\t\r\nbar", "foo bar", 0, 0 },
		{ "foo =\r\n=01", "foo \001", 0, 0 },
		{ "foo  \nbar=", "foo\r\nbar", 1, 0 },
		{ "=0A=0D  ", "\n\r", 2, 0 },
		{ "foo_bar", "foo_bar", 0, 0 },
		{ "foo=", "foo", 1, 0 },
		{ "foo=  ", "foo", 3, 0 },
		{ "foo=A", "foo", 2, 0 },
		{ "foo=Ax", "foo=Ax", 0, -1 },
		{ "foo=Ax=xy", "foo=Ax=xy", 0, -1 }
	};
	buffer_t *buf;
	unsigned int i, start, end, len;
	size_t src_pos;
	int ret;

	test_begin("quoted printable decode");
	buf = buffer_create_dynamic(pool_datastack_create(), 128);
	for (i = 0; i < N_ELEMENTS(data); i++) {
		len = strlen(data[i].input);
		ret = quoted_printable_decode((const void *)data[i].input, len,
					      &src_pos, buf);
		test_assert(ret == data[i].ret);
		test_assert(src_pos + data[i].end_skip == len);
		test_assert(strcmp(data[i].output, str_c(buf)) == 0);

		buffer_set_used_size(buf, 0);
		for (start = 0, end = 1; end <= len; ) {
			quoted_printable_decode(CONST_PTR_OFFSET(data[i].input, start),
						end - start, &src_pos, buf);
			src_pos += start;
			start = src_pos;
			if (src_pos <= end)
				end++;
			else
				end = src_pos + 1;
		}
		test_assert(src_pos + data[i].end_skip == len);
		test_assert(strcmp(data[i].output, str_c(buf)) == 0);
		buffer_set_used_size(buf, 0);
	}
	test_end();
}

static void test_quoted_printable_decode_final(void)
{
	static struct test_quoted_printable_decode_data data[] = {
		{ "=0A=0D  ", "\n\r", 2, 0 },
		{ "foo=", "foo", 1, 0 },
		{ "foo  ", "foo", 2, 0 },
		{ "foo=  ", "foo", 3, 0 },
		{ "foo=A", "foo", 2, -1 }
	};
	buffer_t *buf;
	unsigned int i, len;
	size_t src_pos;
	int ret;

	test_begin("quoted printable decode final");
	buf = buffer_create_dynamic(pool_datastack_create(), 128);
	for (i = 0; i < N_ELEMENTS(data); i++) {
		len = strlen(data[i].input);
		ret = quoted_printable_decode_final((const void *)data[i].input,
						    len, &src_pos, buf);
		test_assert(ret == data[i].ret);
		test_assert(src_pos + data[i].end_skip == len);
		test_assert(strcmp(data[i].output, str_c(buf)) == 0);

		buffer_set_used_size(buf, 0);
	}
	test_end();
}

static void test_quoted_printable_q_decode(void)
{
	const char *data[] = {
		"=0A=0D  ", "\n\r  ",
		"__foo__bar__", "  foo  bar  ",
		"foo=", "foo=",
		"foo=A", "foo=A",
		"foo=Ax", "foo=Ax",
		"foo=Ax=xy", "foo=Ax=xy"
	};
	buffer_t *buf;
	unsigned int i;

	test_begin("quoted printable q decode");
	buf = buffer_create_dynamic(pool_datastack_create(), 128);
	for (i = 0; i < N_ELEMENTS(data); i += 2) {
		quoted_printable_q_decode((const void *)data[i], strlen(data[i]),
					  buf);
		test_assert(strcmp(data[i+1], str_c(buf)) == 0);
		buffer_set_used_size(buf, 0);
	}
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_quoted_printable_decode,
		test_quoted_printable_decode_final,
		test_quoted_printable_q_decode,
		NULL
	};
	return test_run(test_functions);
}
