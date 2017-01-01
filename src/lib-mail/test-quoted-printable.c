/* Copyright (c) 2007-2017 Dovecot authors, see the included COPYING file */

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
	static void (*const test_functions[])(void) = {
		test_quoted_printable_q_decode,
		NULL
	};
	return test_run(test_functions);
}
