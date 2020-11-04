/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "quoted-printable.h"
#include "test-common.h"

static void test_quoted_printable_q_decode(void)
{
	const char *data[] = {
		"=0A=0D  ", "\n\r  ",
		"__foo__bar__", "  foo  bar  ",
		"foo=", "foo=",
		"foo=A", "foo=A",
		"foo=Ax", "foo=Ax",
		"foo=Ax=xy", "foo=Ax=xy",
		"=C3=9Cberm=C3=A4=C3=9Figer Gebrauch", "\xc3\x9c""berm\xc3\xa4\xc3\x9figer Gebrauch",
		/* Lowercase formally illegal but allowed for robustness */
		"=c3=9cberm=c3=a4=c3=9figer Gebrauch", "\xc3\x9c""berm\xc3\xa4\xc3\x9figer Gebrauch",
		/* Unnecessarily encoded */
		"=66=6f=6f=42=61=72", "fooBar",
		/* Expected to be encoded but not */
		"\xc3\x9c""berm=c3=a4\xc3\x9figer Gebrauch", "\xc3\x9c""berm\xc3\xa4\xc3\x9figer Gebrauch",
		/* Decode control characters */
		"=0C=07", "\x0C\x07",
		"=DE=AD=BE=EF", "\xDE\xAD\xBE\xEF",
		/* Non-Hex data */
		"=FJ=X1", "=FJ=X1",
	};
	buffer_t *buf;
	unsigned int i;

	test_begin("quoted printable q decode");
	buf = t_buffer_create(128);
	for (i = 0; i < N_ELEMENTS(data); i += 2) {
		quoted_printable_q_decode((const void *)data[i], strlen(data[i]),
					  buf);
		test_assert_strcmp_idx(data[i+1], str_c(buf), i/2);
		buffer_set_used_size(buf, 0);
	}
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_quoted_printable_q_decode,
		NULL
	};
	return test_run(test_functions);
}
