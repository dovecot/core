/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "strnum.h"
#include "str.h"
#include "unichar.h"
#include "istream.h"

#include <fcntl.h>

#define UCD_NORMALIZATION_TEST_TXT UCD_DIR "/NormalizationTest.txt"

static int test_column_to_utf8(const char *column, const char **out_r)
{
	const char *const *cps = t_strsplit(column, " ");
	string_t *out = t_str_new(256);

	while (*cps != NULL) {
		uint32_t cp;

		if (str_to_uint32_hex(*cps, &cp) < 0)
			return -1;
		if (!uni_is_valid_ucs4(cp))
			return -1;
		uni_ucs4_to_utf8_c(cp, out);
		cps++;
	}
	*out_r = str_c(out);
	return 0;
}

static void
test_columns(const char *c1, const char *c2, const char *c3, const char *c4,
	     const char *c5, unsigned int line_num)
{
	buffer_t *nf_out = t_buffer_create(128);
	int ret;

	/* NFC
	     c2 ==  toNFC(c1) ==  toNFC(c2) ==  toNFC(c3)
	     c4 ==  toNFC(c4) ==  toNFC(c5)
	 */

	/* c2 == toNFC(c1) */
	buffer_set_used_size(nf_out, 0);
	ret = uni_utf8_write_nfc(c1, strlen(c1), nf_out);
	test_assert_idx(ret == 0, line_num);
	test_assert_strcmp_idx(c2, str_c(nf_out), line_num);

	/* c2 == toNFC(c2) */
	buffer_set_used_size(nf_out, 0);
	ret = uni_utf8_write_nfc(c2, strlen(c2), nf_out);
	test_assert_idx(ret == 0, line_num);
	test_assert_strcmp_idx(c2, str_c(nf_out), line_num);

	/* c2 == toNFC(c3) */
	buffer_set_used_size(nf_out, 0);
	ret = uni_utf8_write_nfc(c3, strlen(c3), nf_out);
	test_assert_idx(ret == 0, line_num);
	test_assert_strcmp_idx(c2, str_c(nf_out), line_num);

	/* c4 == toNFC(c4) */
	buffer_set_used_size(nf_out, 0);
	ret = uni_utf8_write_nfc(c4, strlen(c4), nf_out);
	test_assert_idx(ret == 0, line_num);
	test_assert_strcmp_idx(c4, str_c(nf_out), line_num);

	/* c4 == toNFC(c5) */
	buffer_set_used_size(nf_out, 0);
	ret = uni_utf8_write_nfc(c5, strlen(c5), nf_out);
	test_assert_idx(ret == 0, line_num);
	test_assert_strcmp_idx(c4, str_c(nf_out), line_num);

	/* Check isNFC() */
	ret = uni_utf8_is_nfc(c2, strlen(c2));
	test_assert_idx(ret > 0, line_num);
	ret = uni_utf8_is_nfc(c4, strlen(c4));
	test_assert_idx(ret > 0, line_num);
	if (strcmp(c2, c1) != 0) {
		ret = uni_utf8_is_nfc(c1, strlen(c1));
		test_assert_idx(ret == 0, line_num);
	}
	if (strcmp(c2, c3) != 0) {
		ret = uni_utf8_is_nfc(c3, strlen(c3));
		test_assert_idx(ret == 0, line_num);
	}
	if (strcmp(c4, c5) != 0) {
		ret = uni_utf8_is_nfc(c5, strlen(c5));
		test_assert_idx(ret == 0, line_num);
	}

	/* NFD
	     c3 ==  toNFD(c1) ==  toNFD(c2) ==  toNFD(c3)
	     c5 ==  toNFD(c4) ==  toNFD(c5)
	 */

	/* c3 == toNFD(c1) */
	buffer_set_used_size(nf_out, 0);
	ret = uni_utf8_write_nfd(c1, strlen(c1), nf_out);
	test_assert_idx(ret == 0, line_num);
	test_assert_strcmp_idx(c3, str_c(nf_out), line_num);

	/* c3 == toNFD(c2) */
	buffer_set_used_size(nf_out, 0);
	ret = uni_utf8_write_nfd(c2, strlen(c2), nf_out);
	test_assert_idx(ret == 0, line_num);
	test_assert_strcmp_idx(c3, str_c(nf_out), line_num);

	/* c3 == toNFD(c3) */
	buffer_set_used_size(nf_out, 0);
	ret = uni_utf8_write_nfd(c3, strlen(c3), nf_out);
	test_assert_idx(ret == 0, line_num);
	test_assert_strcmp_idx(c3, str_c(nf_out), line_num);

	/* c5 == toNFD(c4) */
	buffer_set_used_size(nf_out, 0);
	ret = uni_utf8_write_nfd(c4, strlen(c4), nf_out);
	test_assert_idx(ret == 0, line_num);
	test_assert_strcmp_idx(c5, str_c(nf_out), line_num);

	/* c5 == toNFD(c5) */
	buffer_set_used_size(nf_out, 0);
	ret = uni_utf8_write_nfd(c5, strlen(c5), nf_out);
	test_assert_idx(ret == 0, line_num);
	test_assert_strcmp_idx(c5, str_c(nf_out), line_num);

	/* Check isNFD() */
	ret = uni_utf8_is_nfd(c3, strlen(c3));
	test_assert_idx(ret > 0, line_num);
	ret = uni_utf8_is_nfd(c5, strlen(c5));
	test_assert_idx(ret > 0, line_num);
	if (strcmp(c1, c3) != 0) {
		ret = uni_utf8_is_nfd(c1, strlen(c1));
		test_assert_idx(ret == 0, line_num);
	}
	if (strcmp(c2, c3) != 0) {
		ret = uni_utf8_is_nfd(c2, strlen(c2));
		test_assert_idx(ret == 0, line_num);
	}
	if (strcmp(c4, c5) != 0) {
		ret = uni_utf8_is_nfd(c4, strlen(c4));
		test_assert_idx(ret == 0, line_num);
	}

	/* NFKC
	     c4 == toNFKC(c1) == toNFKC(c2) == toNFKC(c3) == toNFKC(c4)
	        == toNFKC(c5)
	 */

	/* c4 == toNFKC(c1) */
	buffer_set_used_size(nf_out, 0);
	ret = uni_utf8_write_nfkc(c1, strlen(c1), nf_out);
	test_assert_idx(ret == 0, line_num);
	test_assert_strcmp_idx(c4, str_c(nf_out), line_num);

	/* c4 == toNFKC(c2) */
	buffer_set_used_size(nf_out, 0);
	ret = uni_utf8_write_nfkc(c2, strlen(c2), nf_out);
	test_assert_idx(ret == 0, line_num);
	test_assert_strcmp_idx(c4, str_c(nf_out), line_num);

	/* c4 == toNFKC(c3) */
	buffer_set_used_size(nf_out, 0);
	ret = uni_utf8_write_nfkc(c3, strlen(c3), nf_out);
	test_assert_idx(ret == 0, line_num);
	test_assert_strcmp_idx(c4, str_c(nf_out), line_num);

	/* c4 == toNFKC(c4) */
	buffer_set_used_size(nf_out, 0);
	ret = uni_utf8_write_nfkc(c4, strlen(c4), nf_out);
	test_assert_idx(ret == 0, line_num);
	test_assert_strcmp_idx(c4, str_c(nf_out), line_num);

	/* c4 == toNFKC(c5) */
	buffer_set_used_size(nf_out, 0);
	ret = uni_utf8_write_nfkc(c5, strlen(c5), nf_out);
	test_assert_idx(ret == 0, line_num);
	test_assert_strcmp_idx(c4, str_c(nf_out), line_num);

	/* Check isNFKC() */
	ret = uni_utf8_is_nfkc(c4, strlen(c4));
	test_assert_idx(ret > 0, line_num);
	if (strcmp(c4, c1) != 0) {
		ret = uni_utf8_is_nfkc(c1, strlen(c1));
		test_assert_idx(ret == 0, line_num);
	}
	if (strcmp(c4, c2) != 0) {
		ret = uni_utf8_is_nfkc(c2, strlen(c2));
		test_assert_idx(ret == 0, line_num);
	}
	if (strcmp(c4, c3) != 0) {
		ret = uni_utf8_is_nfkc(c3, strlen(c3));
		test_assert_idx(ret == 0, line_num);
	}
	if (strcmp(c4, c5) != 0) {
		ret = uni_utf8_is_nfkc(c5, strlen(c5));
		test_assert_idx(ret == 0, line_num);
	}

	/* NFKD
	     c5 == toNFKD(c1) == toNFKD(c2) == toNFKD(c3) == toNFKD(c4)
	        == toNFKD(c5)
	 */

	/* c5 == toNFKD(c1) */
	buffer_set_used_size(nf_out, 0);
	ret = uni_utf8_write_nfkd(c1, strlen(c1), nf_out);
	test_assert_idx(ret == 0, line_num);
	test_assert_strcmp_idx(c5, str_c(nf_out), line_num);

	/* c5 == toNFKD(c2) */
	buffer_set_used_size(nf_out, 0);
	ret = uni_utf8_write_nfkd(c2, strlen(c2), nf_out);
	test_assert_idx(ret == 0, line_num);
	test_assert_strcmp_idx(c5, str_c(nf_out), line_num);

	/* c5 == toNFKD(c3) */
	buffer_set_used_size(nf_out, 0);
	ret = uni_utf8_write_nfkd(c3, strlen(c3), nf_out);
	test_assert_idx(ret == 0, line_num);
	test_assert_strcmp_idx(c5, str_c(nf_out), line_num);

	/* c5 == toNFKD(c4) */
	buffer_set_used_size(nf_out, 0);
	ret = uni_utf8_write_nfkd(c4, strlen(c4), nf_out);
	test_assert_idx(ret == 0, line_num);
	test_assert_strcmp_idx(c5, str_c(nf_out), line_num);

	/* c5 == toNFKD(c5) */
	buffer_set_used_size(nf_out, 0);
	ret = uni_utf8_write_nfkd(c5, strlen(c5), nf_out);
	test_assert_idx(ret == 0, line_num);
	test_assert_strcmp_idx(c5, str_c(nf_out), line_num);

	/* Check isNFKD() */
	ret = uni_utf8_is_nfd(c5, strlen(c5));
	test_assert_idx(ret > 0, line_num);
	if (strcmp(c1, c5) != 0) {
		ret = uni_utf8_is_nfkd(c1, strlen(c1));
		test_assert_idx(ret == 0, line_num);
	}
	if (strcmp(c2, c5) != 0) {
		ret = uni_utf8_is_nfkd(c2, strlen(c2));
		test_assert_idx(ret == 0, line_num);
	}
	if (strcmp(c3, c5) != 0) {
		ret = uni_utf8_is_nfkd(c3, strlen(c3));
		test_assert_idx(ret == 0, line_num);
	}
	if (strcmp(c4, c5) != 0) {
		ret = uni_utf8_is_nfkd(c4, strlen(c4));
		test_assert_idx(ret == 0, line_num);
	}
}

static void test_line(const char *line, bool part1, unsigned int line_num)
{
	static uint32_t cp_last = 0;
	uint32_t cp = 0x110000;

	/* CONFORMANCE:

	   1. The following invariants must be true for all conformant
	      implementations

	      NFC
	        c2 ==  toNFC(c1) ==  toNFC(c2) ==  toNFC(c3)
	        c4 ==  toNFC(c4) ==  toNFC(c5)

	      NFD
	        c3 ==  toNFD(c1) ==  toNFD(c2) ==  toNFD(c3)
	        c5 ==  toNFD(c4) ==  toNFD(c5)

	      NFKC
	        c4 == toNFKC(c1) == toNFKC(c2) == toNFKC(c3) == toNFKC(c4)
	           == toNFKC(c5)

	      NFKD
	        c5 == toNFKD(c1) == toNFKD(c2) == toNFKD(c3) == toNFKD(c4)
	           == toNFKD(c5)
	 */
	if (line != NULL) {
		const char *const *columns = t_strsplit(line, ";");
		if (str_array_length(columns) < 5) {
			test_failed(t_strdup_printf(
				"Invalid test at %s:%u",
				UCD_NORMALIZATION_TEST_TXT, line_num));
			return;
		}

		const char *c[5];
		unsigned int i;

		for (i = 0; i < 5; i++) {
			if (test_column_to_utf8(columns[i], &c[i]) < 0) {
				test_failed(t_strdup_printf(
					"Invalid test at %s:%u: "
					"Bad input in column %u: %s",
					UCD_NORMALIZATION_TEST_TXT,
					line_num, i + 1, columns[i]));
				return;
			}
		}

		test_columns(c[0], c[1], c[2], c[3], c[4], line_num);

		if (!part1)
			return;

		if (str_to_uint32_hex(columns[0], &cp) < 0) {
			test_failed(t_strdup_printf(
				"Invalid test at %s:%u: "
				"Bad input in column 1 for part1: %s",
				UCD_NORMALIZATION_TEST_TXT,
				line_num, columns[0]));
			return;
		}
	}

	/* 2. For every code point X assigned in this version of Unicode that is
	      not specifically listed in Part 1, the following invariants must
	      be true for all conformant
	      implementations:

	      X == toNFC(X) == toNFD(X) == toNFKC(X) == toNFKD(X)
	 */

	i_assert(part1);
	string_t *out = t_str_new(256);
	buffer_t *nf_out = t_buffer_create(128);
	uint32_t i;
	int ret;

	for (i = cp_last; i < cp; i++) {
		if (!uni_is_valid_ucs4(i))
			continue;
		str_truncate(out, 0);
		uni_ucs4_to_utf8_c(i, out);

		/* X == toNFC(X) */
		buffer_set_used_size(nf_out, 0);
		ret = uni_utf8_write_nfc(str_data(out), str_len(out), nf_out);
		test_assert_idx(ret == 0, line_num);
		test_assert_strcmp_idx(str_c(out), str_c(nf_out), line_num);

		/* X == toNFD(X) */
		buffer_set_used_size(nf_out, 0);
		ret = uni_utf8_write_nfd(str_data(out), str_len(out), nf_out);
		test_assert_idx(ret == 0, line_num);
		test_assert_strcmp_idx(str_c(out), str_c(nf_out), line_num);

		/* X == toNFKC(X) */
		buffer_set_used_size(nf_out, 0);
		ret = uni_utf8_write_nfkc(str_data(out), str_len(out), nf_out);
		test_assert_idx(ret == 0, line_num);
		test_assert_strcmp_idx(str_c(out), str_c(nf_out), line_num);

		/* X == toNFKD(X) */
		buffer_set_used_size(nf_out, 0);
		ret = uni_utf8_write_nfkd(str_data(out), str_len(out), nf_out);
		test_assert_idx(ret == 0, line_num);
		test_assert_strcmp_idx(str_c(out), str_c(nf_out), line_num);
	}
	cp_last = cp + 1;
}

static void test_long(void)
{
	static const char *nfc_utf32 = "FDFA FDFA FDFA";
	static const char *nfkd_utf32 =
		"0635 0644 0649 0020 0627 0644 0644 0647 0020 "
		"0639 0644 064A 0647 0020 0648 0633 0644 0645 "
		"0635 0644 0649 0020 0627 0644 0644 0647 0020 "
		"0639 0644 064A 0647 0020 0648 0633 0644 0645 "
		"0635 0644 0649 0020 0627 0644 0644 0647 0020 "
		"0639 0644 064A 0647 0020 0648 0633 0644 0645";

	const char *nfc, *nfkd;
	buffer_t *nf_out = t_buffer_create(128);
	int ret;

	ret = test_column_to_utf8(nfc_utf32, &nfc);
	test_assert(ret == 0);
	ret = test_column_to_utf8(nfkd_utf32, &nfkd);
	test_assert(ret == 0);

	buffer_set_used_size(nf_out, 0);
	ret = uni_utf8_write_nfc(nfc, strlen(nfc), nf_out);
	test_assert(ret == 0);
	test_assert_strcmp(nfc, str_c(nf_out));

	buffer_set_used_size(nf_out, 0);
	ret = uni_utf8_write_nfc(nfkd, strlen(nfkd), nf_out);
	test_assert(ret == 0);
	test_assert_strcmp(nfkd, str_c(nf_out));

	buffer_set_used_size(nf_out, 0);
	ret = uni_utf8_write_nfd(nfc, strlen(nfc), nf_out);
	test_assert(ret == 0);
	test_assert_strcmp(nfc, str_c(nf_out));

	buffer_set_used_size(nf_out, 0);
	ret = uni_utf8_write_nfd(nfkd, strlen(nfkd), nf_out);
	test_assert(ret == 0);
	test_assert_strcmp(nfkd, str_c(nf_out));

	buffer_set_used_size(nf_out, 0);
	ret = uni_utf8_write_nfkc(nfc, strlen(nfc), nf_out);
	test_assert(ret == 0);
	test_assert_strcmp(nfkd, str_c(nf_out));

	buffer_set_used_size(nf_out, 0);
	ret = uni_utf8_write_nfkc(nfkd, strlen(nfkd), nf_out);
	test_assert(ret == 0);
	test_assert_strcmp(nfkd, str_c(nf_out));

	buffer_set_used_size(nf_out, 0);
	ret = uni_utf8_write_nfkd(nfc, strlen(nfc), nf_out);
	test_assert(ret == 0);
	test_assert_strcmp(nfkd, str_c(nf_out));

	buffer_set_used_size(nf_out, 0);
	ret = uni_utf8_write_nfkd(nfkd, strlen(nfkd), nf_out);
	test_assert(ret == 0);
	test_assert_strcmp(nfkd, str_c(nf_out));
}

static void test_stream_safe(void)
{
	/* UAX15, Section 13:

	   Consider the extreme case of a string containing a digit 2 followed
	   by 10,000 umlauts followed by one dot-below, then a digit 3. As part
	   of normalization, the dot-below at the end must be reordered to
	   immediately after the digit 2, which means that 10,003 characters
	   need to be considered before the result can be output.

	   Such extremely long sequences of combining marks are not illegal,
	   even though for all practical purposes they are not meaningful.
	   However, the possibility of encountering such sequences forces a
	   conformant, serializing implementation to provide large buffer
	   capacity or to provide a special exception mechanism just for such
	   degenerate cases. The Stream-Safe Text Format specification addresses
	   this situation.
	 */

	/* Construct test string */

	string_t *in = t_str_new(1024);
	buffer_t *nf_out = t_buffer_create(1024);
	unsigned int i = 0;

	/* digit 2 */
	str_append(in, "2");
	/* not quite 10,000 umlauts */
	for  (i = 0; i < 100; i++)
		str_append(in, "\xCC\x88");
	/* dot-below */
	str_append(in, "\xCC\xA3");
	/* digit 3 */
	str_append(in, "3");

	/* Apply NFD normalization */

	int ret;

	ret = uni_utf8_write_nfd(str_data(in), str_len(in), nf_out);
	test_assert(ret == 0);

	/* Check the result */

	const unsigned char *nf_data = nf_out->data;
	size_t nf_size = nf_out->used;

	test_assert(nf_size > 32);

	static const char safe_block[] =
		"\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88"
		"\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88"
		"\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88"
		"\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88"
		"\xCC\x88\xCC\x88";
	static const char last_block[] =
		"\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88"
		"\xCC\x88\xCC\x88\xCC\x88";

	test_assert(nf_data[0] == '2');                    /* digit 2 */
	test_assert_memcmp(&nf_data[1], 60, safe_block, 60);   /* 30 umlauts */
	test_assert_memcmp(&nf_data[61], 2, "\xCD\x8F", 2);   /* CGJ */
	test_assert_memcmp(&nf_data[63], 60, safe_block, 60);  /* 30 umlauts */
	test_assert_memcmp(&nf_data[123], 2, "\xCD\x8F", 2);  /* CGJ */
	test_assert_memcmp(&nf_data[125], 60, safe_block, 60); /* 30 umlauts */
	test_assert_memcmp(&nf_data[185], 2, "\xCD\x8F", 2);  /* CGJ */
	test_assert_memcmp(&nf_data[187], 2, "\xCC\xA3", 2);  /* dot-below */
	test_assert_memcmp(&nf_data[189], 20, last_block, 20); /* 10 umlauts */
	test_assert(nf_data[209] == '3');                  /* digit 3 */
}

void test_unicode_nf(void)
{
	struct istream *input = NULL;
	int fd;

	/* Test using NormalizationTest.txt from UCD */
	test_begin(t_strdup_printf("unicode normalization: open %s",
				   UCD_NORMALIZATION_TEST_TXT));

	fd = open(UCD_NORMALIZATION_TEST_TXT, O_RDONLY);
	if (fd < 0)
		test_failed(t_strdup_printf("Failed to open: %m"));
	else
		input = i_stream_create_fd_autoclose(&fd, 1024);

	unsigned int line_num = 0;
	bool part1 = FALSE;

	while (!test_has_failed()) {
		char *line = i_stream_read_next_line(input);
		if (line == NULL)
			break;
		line_num++;

		char *comment = strchr(line, '#');

		if (comment != NULL)
			*comment = '\0';
		if (*line == '\0')
			continue;

		if (*line == '@') {
			if (part1) {
				T_BEGIN {
					test_line(NULL, part1, line_num);
				} T_END;
			}

			test_end();
			const char *part = t_str_trim(line + 1, " ");;
			test_begin(t_strdup_printf(
				"unicode normalization: %s",
				t_str_lcase(part)));
			part1 = (strcmp(part, "Part1") == 0);
			continue;
		}

		if (test_has_failed())
			break;

		T_BEGIN {
			test_line(line, part1, line_num);
		} T_END;
	}

	i_stream_destroy(&input);
	test_end();

	/* Test long decompositions beyond NormalizationTests.txt */
	test_begin("unicode normalization: long decompositions");
	test_long();
	test_end();

	/* Test Stream Safe algorithm (UAX15-D4) */
	test_begin("unicode normalization: stream safe");
	test_stream_safe();
	test_end();
}
