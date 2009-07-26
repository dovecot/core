/* Copyright (c) 2007-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "quoted-printable.h"
#include "test-common.h"

static void test_quoted_printable_decode(void)
{
	const char *data[] = {
		"foo  \r\nbar=", "foo\r\nbar",
		"foo =\nbar", "foo bar",
		"foo =\r\nbar", "foo bar",
		"foo  \nbar=", "foo\r\nbar",
		"=0A=0D  ", "\n\r",
		"foo_bar", "foo_bar",
		"foo=", "foo",
		"foo=A", "foo",
		"foo=Ax", "foo=Ax",
		"foo=Ax=xy", "foo=Ax=xy"
	};
	buffer_t *buf;
	unsigned int i, start, end, len;
	size_t src_pos;

	test_begin("quoted printable decode");
	buf = buffer_create_dynamic(pool_datastack_create(), 128);
	for (i = 0; i < N_ELEMENTS(data); i += 2) {
		len = strlen(data[i]);
		for (start = 0, end = 1; end <= len; ) {
			quoted_printable_decode(CONST_PTR_OFFSET(data[i], start),
						end - start, &src_pos, buf);
			src_pos += start;
			start = src_pos;
			if (src_pos <= end)
				end++;
			else
				end = src_pos + 1;
		}
		test_assert(strcmp(data[i+1], str_c(buf)) == 0);
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
		test_quoted_printable_q_decode,
		NULL
	};
	return test_run(test_functions);
}
