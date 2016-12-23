/* Copyright (c) 2008-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "unichar.h"
#include "imap-utf7.h"
#include "test-common.h"

static void test_imap_utf7_by_example(void)
{
	static const struct test {
		const char *utf8;
		const char *mutf7;
	} tests[] = {
		{ "&&x&&", "&-&-x&-&-" },
		{ "~peter/mail/\xe5\x8f\xb0\xe5\x8c\x97/\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
		  "~peter/mail/&U,BTFw-/&ZeVnLIqe-" },
		{ "tiet\xc3\xa4j\xc3\xa4", "tiet&AOQ-j&AOQ-" },
		{ "p\xe4\xe4", NULL },
		{ NULL, "&" },
		{ NULL, "&Jjo" },
		{ NULL, "&Jjo!" },
		{ NULL, "&U,BTFw-&ZeVnLIqe-" }
	};
	string_t *dest;
	unsigned int i;

	dest = t_str_new(256);

	test_begin("imap mutf7 examples");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		if (tests[i].utf8 != NULL) {
			str_truncate(dest, 0);
			if (imap_utf8_to_utf7(tests[i].utf8, dest) < 0)
				test_assert_idx(tests[i].mutf7 == NULL, i);
			else
				test_assert_idx(null_strcmp(tests[i].mutf7, str_c(dest)) == 0, i);
		}
		if (tests[i].mutf7 != NULL) {
			str_truncate(dest, 0);
			if (imap_utf7_to_utf8(tests[i].mutf7, dest) < 0)
				test_assert_idx(tests[i].utf8 == NULL, i);
			else
				test_assert_idx(null_strcmp(tests[i].utf8, str_c(dest)) == 0, i);
			test_assert_idx(imap_utf7_is_valid(tests[i].mutf7) != (tests[i].utf8 == NULL), i);
		}
	}
	test_end();
}

static void test_imap_utf7_ucs4_cases(void)
{
	string_t *src, *dest;
	const char *orig_src;
	unsigned int i, j;
	unichar_t chr;

	src = t_str_new(256);
	dest = t_str_new(256);

	test_begin("imap mutf7 ucs4 cases");
	for (chr = 0xffff; chr <= 0x10010; chr++) T_BEGIN {
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

			test_assert_idx(imap_utf8_to_utf7(orig_src, dest) == 0, chr*100+i);
			test_assert_idx(imap_utf7_to_utf8(str_c(dest), src) == 0, chr*100+i);
			test_assert_idx(strcmp(str_c(src), orig_src) == 0, chr+100+i);
		}
	} T_END;
	test_end();
}

static const char mb64[64]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";
static void test_imap_utf7_non_utf16(void)
{
	char csrc[1+4+1+1];
	unsigned int i;

	test_begin("imap mutf7 non-utf16");
	for (i = 0; i <= 255; ++i) {
		/* Invalid, code a single 8-bit octet */
		csrc[2] = '&';
		csrc[3] = mb64[i>>2];
		csrc[4] = mb64[(i&3) << 4];
		csrc[5] = '-';
		csrc[6] = '\0';
		test_assert_idx(!imap_utf7_is_valid(csrc+2), i);
	}
	for (i = 0; i <= 255; ++i) {
		/* Invalid, U+00E4 followed by a single octet */
		csrc[0] = '&';
		csrc[1] = mb64[                       (0x00 >> 2)];
		csrc[2] = mb64[((0x00 & 0x03) << 4) | (0xe4 >> 4)];
		csrc[3] = mb64[((0xe4 & 0x0f) << 2) | (   i >> 6)];
		csrc[4] = mb64[     i & 0x3f                     ];
		test_assert_idx(!imap_utf7_is_valid(csrc), i);
	}
	test_end();
}

static void test_imap_utf7_bad_ascii(void)
{
	string_t *dest;
	char csrc[1+1];
	unsigned int i;

	dest = t_str_new(256);

	test_begin("imap mutf7 bad ascii");
	for (i = 1; i <= 0x7f; ++i) {
		if (i == ' ')
			i = 0x7f;
		csrc[0] = i;
		csrc[1] = '\0';
		test_assert_idx(!imap_utf7_is_valid(csrc), i);
		str_truncate(dest, 0);
		test_assert_idx(imap_utf7_to_utf8(csrc, dest) < 0, i);
	}
	test_end();
}

static void test_imap_utf7_unnecessary(void)
{
	string_t *dest;
	char csrc[1+3+1+1];
	unsigned int i;

	dest = t_str_new(256);

	test_begin("imap mutf7 unnecessary");
	for (i = 0x20; i < 0x7f; ++i) {
		/* Create an invalid escaped encoding of a simple char or '&' */
		csrc[0] = '&';
		csrc[1] = mb64[                       (0x00 >> 2)];
		csrc[2] = mb64[((0x00 & 0x03) << 4) | (   i >> 4)];
		csrc[3] = mb64[((   i & 0x0f) << 2) |     0      ];
		csrc[4] = '-';
		csrc[5] = '\0';
		test_assert_idx(!imap_utf7_is_valid(csrc), i);
		str_truncate(dest, 0);
		test_assert_idx(imap_utf7_to_utf8(csrc, dest) < 0, i);

		/* All self-coding characters must self-code */
		if (i == '&')
			continue;
		csrc[0] = i;
		csrc[1] = '\0';
		str_truncate(dest, 0);
		test_assert_idx(imap_utf8_to_utf7(csrc, dest) >= 0, i);
		test_assert_idx(strcmp(csrc, str_c(dest)) == 0, i);
	}
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_imap_utf7_by_example,
		test_imap_utf7_ucs4_cases,
		test_imap_utf7_non_utf16,
		test_imap_utf7_bad_ascii,
		test_imap_utf7_unnecessary,
		NULL
	};
	return test_run(test_functions);
}
