/* Copyright (c) 2008-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "unichar.h"
#include "imap-utf7.h"
#include "test-common.h"

static void test_imap_utf7(void)
{
	static struct test {
		const char *utf8;
		const char *mutf7;
	} tests[] = {
		{ "&&x&&", "&-&-x&-&-" },
		{ "~peter/mail/台北/日本語", "~peter/mail/&U,BTFw-/&ZeVnLIqe-" },
		{ "tietäjä", "tiet&AOQ-j&AOQ-" },
		{ "p\xe4\xe4", NULL },
		{ NULL, "&" },
		{ NULL, "&Jjo" },
		{ NULL, "&Jjo!" },
		{ NULL, "&U,BTFw-&ZeVnLIqe-" }
	};
	string_t *src, *dest;
	const char *orig_src;
	unsigned int i, j;
	unichar_t chr;

	src = t_str_new(256);
	dest = t_str_new(256);

	test_begin("imap mutf7");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		if (tests[i].utf8 != NULL) {
			str_truncate(dest, 0);
			if (imap_utf8_to_utf7(tests[i].utf8, dest) < 0)
				test_assert(tests[i].mutf7 == NULL);
			else
				test_assert(null_strcmp(tests[i].mutf7, str_c(dest)) == 0);
		}
		if (tests[i].mutf7 != NULL) {
			str_truncate(dest, 0);
			if (imap_utf7_to_utf8(tests[i].mutf7, dest) < 0)
				test_assert(tests[i].utf8 == NULL);
			else
				test_assert(null_strcmp(tests[i].utf8, str_c(dest)) == 0);
			test_assert(imap_utf7_is_valid(tests[i].mutf7) != (tests[i].utf8 == NULL));
		}
	}

	for (chr = 0xffff; chr <= 0x10010; chr++) {
		for (i = 1; i <= 10; i++) {
			str_truncate(src, 0);
			str_truncate(dest, 0);
			for (j = 0; j < i; j++) {
				if (j % 3 == 0)
					str_append_c(src, 'x');
				if (j % 5 == 0)
					str_append_c(src, '&');
				uni_ucs4_to_utf8_c(chr, src);
			}

			orig_src = t_strdup(str_c(src));
			str_truncate(src, 0);

			test_assert(imap_utf8_to_utf7(orig_src, dest) == 0);
			test_assert(imap_utf7_to_utf8(str_c(dest), src) == 0);
			test_assert(strcmp(str_c(src), orig_src) == 0);
		}
	}
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_imap_utf7,
		NULL
	};
	return test_run(test_functions);
}
