/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "test-lib.h"
#include "array.h"
#include "strnum.h"
#include "str.h"
#include "unichar.h"
#include "unicode-data.h"
#include "unicode-transform.h"
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

static void test_stream_safe(bool compose)
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

	/*
	 * No decomposition (umlaut, U+0308)
	 */

	/* Construct test string */

	string_t *in = t_str_new(1024);
	buffer_t *nf_out = t_buffer_create(1024);
	unsigned int i;

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

	if (compose)
		ret = uni_utf8_write_nfc(str_data(in), str_len(in), nf_out);
	else
		ret = uni_utf8_write_nfd(str_data(in), str_len(in), nf_out);
	test_assert(ret == 0);

	/* Check the result */

	const unsigned char *nf_data = nf_out->data;
	size_t nf_size = nf_out->used;

	test_assert(nf_size == (1 + (60 + 2) * 3 + 2 + 20 + 1));

	static const char safe_block1[] =
		"\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88"
		"\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88"
		"\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88"
		"\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88"
		"\xCC\x88\xCC\x88";
	static const char last_block1[] =
		"\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88\xCC\x88"
		"\xCC\x88\xCC\x88\xCC\x88";

	test_assert(nf_data[0] == '2');                         /* digit 2 */
	test_assert_memcmp(&nf_data[1], 60, safe_block1, 60);   /* 30 umlauts */
	test_assert_memcmp(&nf_data[61], 2, "\xCD\x8F", 2);     /* CGJ */
	test_assert_memcmp(&nf_data[63], 60, safe_block1, 60);  /* 30 umlauts */
	test_assert_memcmp(&nf_data[123], 2, "\xCD\x8F", 2);    /* CGJ */
	test_assert_memcmp(&nf_data[125], 60, safe_block1, 60); /* 30 umlauts */
	test_assert_memcmp(&nf_data[185], 2, "\xCD\x8F", 2);    /* CGJ */
	test_assert_memcmp(&nf_data[187], 2, "\xCC\xA3", 2);    /* dot-below */
	test_assert_memcmp(&nf_data[189], 20, last_block1, 20); /* 10 umlauts */
	test_assert(nf_data[209] == '3');                       /* digit 3 */

	/*
	 * Decomposing nonstarter (Combining Greek Dialytika Tonos, U+0344)
	 */

	str_truncate(in, 0);
	buffer_clear(nf_out);

	/* digit 2 */
	str_append(in, "2");
	/* not quite 10,000 umlauts (in this case special umlauts) */
	for  (i = 0; i < 100; i++)
		str_append(in, "\xCD\x84");
	/* dot-below */
	str_append(in, "\xCC\xA3");
	/* digit 3 */
	str_append(in, "3");

	/* Apply NFD normalization */

	if (compose)
		ret = uni_utf8_write_nfc(str_data(in), str_len(in), nf_out);
	else
		ret = uni_utf8_write_nfd(str_data(in), str_len(in), nf_out);
	test_assert(ret == 0);

	/* Check the result */

	nf_data = nf_out->data;
	nf_size = nf_out->used;

	test_assert(nf_size == (1 + (60 + 2) * 6 + 2 + 40 + 1));

	static const char safe_block2[] =
		"\xCC\x88\xCC\x81\xCC\x88\xCC\x81\xCC\x88\xCC\x81\xCC\x88"
		"\xCC\x81\xCC\x88\xCC\x81\xCC\x88\xCC\x81\xCC\x88\xCC\x81"
		"\xCC\x88\xCC\x81\xCC\x88\xCC\x81\xCC\x88\xCC\x81\xCC\x88"
		"\xCC\x81\xCC\x88\xCC\x81\xCC\x88\xCC\x81\xCC\x88\xCC\x81"
		"\xCC\x88\xCC\x81";
	static const char last_block2[] =
		"\xCC\x88\xCC\x81\xCC\x88\xCC\x81\xCC\x88\xCC\x81\xCC\x88"
		"\xCC\x81\xCC\x88\xCC\x81\xCC\x88\xCC\x81\xCC\x88\xCC\x81"
		"\xCC\x88\xCC\x81\xCC\x88\xCC\x81\xCC\x88\xCC\x81";

	test_assert(nf_data[0] == '2');                         /* digit 2 */
	test_assert_memcmp(&nf_data[1], 60, safe_block2, 60);   /* 15 umlauts */
	test_assert_memcmp(&nf_data[61], 2, "\xCD\x8F", 2);     /* CGJ */
	test_assert_memcmp(&nf_data[63], 60, safe_block2, 60);  /* 15 umlauts */
	test_assert_memcmp(&nf_data[123], 2, "\xCD\x8F", 2);    /* CGJ */
	test_assert_memcmp(&nf_data[125], 60, safe_block2, 60); /* 15 umlauts */
	test_assert_memcmp(&nf_data[185], 2, "\xCD\x8F", 2);    /* CGJ */
	test_assert_memcmp(&nf_data[187], 60, safe_block2, 60); /* 15 umlauts */
	test_assert_memcmp(&nf_data[247], 2, "\xCD\x8F", 2);    /* CGJ */
	test_assert_memcmp(&nf_data[249], 60, safe_block2, 60); /* 15 umlauts */
	test_assert_memcmp(&nf_data[309], 2, "\xCD\x8F", 2);    /* CGJ */
	test_assert_memcmp(&nf_data[311], 60, safe_block2, 60); /* 15 umlauts */
	test_assert_memcmp(&nf_data[371], 2, "\xCD\x8F", 2);    /* CGJ */
	test_assert_memcmp(&nf_data[373], 2, "\xCC\xA3", 2);    /* dot-below */
	test_assert_memcmp(&nf_data[375], 40, last_block2, 40); /* 10 umlauts */
	test_assert(nf_data[415] == '3');                       /* digit 3 */
}

static void test_full_buffer(bool compose)
{
	static const char input[] =
		"\x20\xeb\x92\x92\xcd\x84\xcd\x84\xcd\x84\xcd\x84\xcd\x84"
		"\xcd\x84\xcd\x84\xcd\x84\xcd\x84\xcc\x9a\xcd\x84\xcd\x84"
		"\xcd\x84\xcd\x84\xcd\x84\xcd\x84";

	buffer_t *nf_out = t_buffer_create(1024);
	int ret;

	if (compose)
		ret = uni_utf8_write_nfc(input, sizeof(input) - 1, nf_out);
	else
		ret = uni_utf8_write_nfd(input, sizeof(input) - 1, nf_out);
	test_assert(ret == 0);
}

/*
 * Long runs and the Stream-Safe Text Format
 */

#define TEST_CGJ 0x034f

static uint8_t test_ccc(uint32_t cp)
{
	return unicode_code_point_get_data(cp)->canonical_combining_class;
}

static void
test_nf_cps_to_utf8(const uint32_t *cps, size_t count, string_t *dest)
{
	str_truncate(dest, 0);
	uni_ucs4_to_utf8(cps, count, dest);
}

static void
test_nf_utf8_to_cps(const buffer_t *str, ARRAY_TYPE(uint32_t) *dest)
{
	const unsigned char *data = str->data;
	size_t size = str->used;
	unichar_t chr;
	int bytes;

	array_clear(dest);
	while (size > 0) {
		bytes = uni_utf8_get_char_n(data, size, &chr);
		i_assert(bytes > 0);
		array_push_back(dest, &chr);
		data += bytes;
		size -= bytes;
	}
}

static int
test_nf_write(const void *input, size_t size, enum unicode_nf_type type,
	      buffer_t *output)
{
	switch (type) {
	case UNICODE_NFD:
		return uni_utf8_write_nfd(input, size, output);
	case UNICODE_NFKD:
		return uni_utf8_write_nfkd(input, size, output);
	case UNICODE_NFC:
		return uni_utf8_write_nfc(input, size, output);
	case UNICODE_NFKC:
		return uni_utf8_write_nfkc(input, size, output);
	}
	i_unreached();
}

static void
test_nf_write_cps(const ARRAY_TYPE(uint32_t) *in, enum unicode_nf_type type,
		  ARRAY_TYPE(uint32_t) *out)
{
	string_t *in_utf8 = t_str_new(256);
	buffer_t *out_utf8 = t_buffer_create(256);
	const uint32_t *cps;
	unsigned int count;

	cps = array_get(in, &count);
	test_nf_cps_to_utf8(cps, count, in_utf8);
	test_assert(test_nf_write(str_data(in_utf8), str_len(in_utf8), type,
				  out_utf8) == 0);
	test_nf_utf8_to_cps(out_utf8, out);
}

static void
test_nf_append_n(ARRAY_TYPE(uint32_t) *arr, uint32_t cp, unsigned int n)
{
	while (n-- > 0)
		array_push_back(arr, &cp);
}

static bool
test_nf_arrays_equal(const ARRAY_TYPE(uint32_t) *arr1,
		     const ARRAY_TYPE(uint32_t) *arr2)
{
	const uint32_t *cps1, *cps2;
	unsigned int count1, count2;

	cps1 = array_get(arr1, &count1);
	cps2 = array_get(arr2, &count2);
	return count1 == count2 &&
		memcmp(cps1, cps2, count1 * sizeof(*cps1)) == 0;
}

static void test_long_runs(void)
{
	ARRAY_TYPE(uint32_t) in, out, expected;
	const uint32_t *cps, *decomp;
	unsigned int i, count;
	size_t len;
	uint32_t cp;

	t_array_init(&in, 128);
	t_array_init(&out, 128);
	t_array_init(&expected, 128);

	/* A starter followed by NFC_QC=Maybe starters, which don't compose
	   with each other */
	test_nf_append_n(&in, 'a', 1);
	test_nf_append_n(&in, 0x1161, 60);
	test_nf_write_cps(&in, UNICODE_NFC, &out);
	test_assert(test_nf_arrays_equal(&out, &in));

	/* 30 non-starters followed by a decomposition that begins with a
	   starter */
	array_clear(&in);
	test_nf_append_n(&in, 'a', 1);
	test_nf_append_n(&in, 0x0301, 30);
	test_nf_append_n(&in, 0x00e9, 1);
	test_nf_append_n(&in, 'b', 1);
	array_clear(&expected);
	test_nf_append_n(&expected, 'a', 1);
	test_nf_append_n(&expected, 0x0301, 30);
	test_nf_append_n(&expected, 'e', 1);
	test_nf_append_n(&expected, 0x0301, 1);
	test_nf_append_n(&expected, 'b', 1);
	test_nf_write_cps(&in, UNICODE_NFD, &out);
	test_assert(test_nf_arrays_equal(&out, &expected));

	array_clear(&expected);
	test_nf_append_n(&expected, 0x00e1, 1);
	test_nf_append_n(&expected, 0x0301, 29);
	test_nf_append_n(&expected, 0x00e9, 1);
	test_nf_append_n(&expected, 'b', 1);
	test_nf_write_cps(&in, UNICODE_NFC, &out);
	test_assert(test_nf_arrays_equal(&out, &expected));

	/* A long run of different non-starters gets a CGJ after every 30
	   non-starters, and each part is in canonical order */
	array_clear(&in);
	for (cp = 0x0301; cp <= 0x0340; cp++)
		array_push_back(&in, &cp);
	test_nf_write_cps(&in, UNICODE_NFD, &out);
	cps = array_get(&out, &count);
	test_assert(count == 66);
	if (count == 66)
		test_assert(cps[30] == TEST_CGJ && cps[61] == TEST_CGJ);
	for (i = 1; i < count; i++) {
		if (cps[i - 1] != TEST_CGJ && cps[i] != TEST_CGJ)
			test_assert_idx(test_ccc(cps[i - 1]) <=
					test_ccc(cps[i]), i);
	}

	/* Long decompositions after non-starters */
	array_clear(&in);
	test_nf_append_n(&in, 'a', 1);
	test_nf_append_n(&in, 0x0301, 25);
	test_nf_append_n(&in, 0xfdfa, 5);
	len = unicode_code_point_get_full_decomposition(0xfdfa, FALSE,
							&decomp);
	array_clear(&expected);
	test_nf_append_n(&expected, 'a', 1);
	test_nf_append_n(&expected, 0x0301, 25);
	for (i = 0; i < 5; i++)
		array_append(&expected, decomp, len);
	test_nf_write_cps(&in, UNICODE_NFKD, &out);
	test_assert(test_nf_arrays_equal(&out, &expected));
}

/*
 * Transform that accepts only a few code points at a time
 */

struct test_throttle_sink {
	struct unicode_transform transform;
	ARRAY_TYPE(uint32_t) *output;
	unsigned int max_count, calls;
};

static ssize_t
test_throttle_sink_input(struct unicode_transform *trans,
			 const struct unicode_transform_buffer *buf,
			 const char **error_r ATTR_UNUSED)
{
	struct test_throttle_sink *sink =
		container_of(trans, struct test_throttle_sink, transform);
	size_t count = I_MIN(buf->cp_count, sink->max_count);

	if (++sink->calls % 4 == 0)
		return 0;
	array_append(sink->output, buf->cp, count);
	return count;
}

static const struct unicode_transform_def test_throttle_sink_def = {
	.input = test_throttle_sink_input,
};

static void
test_nf_throttled(const uint32_t *in, size_t in_count,
		  enum unicode_nf_type type, ARRAY_TYPE(uint32_t) *out)
{
	struct unicode_nf_context nf;
	struct test_throttle_sink sink;
	const char *error;
	unsigned int loops = 0;
	size_t pos = 0;
	ssize_t sret;
	int ret;

	unicode_nf_init(&nf, type);
	i_zero(&sink);
	unicode_transform_init(&sink.transform, &test_throttle_sink_def);
	sink.output = out;
	sink.max_count = i_rand_minmax(1, 3);
	unicode_transform_chain(&nf.transform, &sink.transform);

	array_clear(out);
	while (pos < in_count && ++loops < 100000) {
		size_t count = i_rand_minmax(1, 64);

		count = I_MIN(count, in_count - pos);
		sret = unicode_transform_input(&nf.transform, &in[pos],
					       count, &error);
		test_assert(sret >= 0);
		if (sret < 0)
			return;
		pos += sret;
	}
	do {
		ret = unicode_transform_flush(&nf.transform, &error);
		test_assert(ret >= 0);
	} while (ret == 0 && ++loops < 100000);
	test_assert(pos == in_count);
	test_assert(loops < 100000);
}

static void test_slow_next_transform(void)
{
	ARRAY_TYPE(uint32_t) in, out, expected;
	const uint32_t *cps;
	unsigned int i, count;

	t_array_init(&in, 64);
	t_array_init(&out, 64);
	t_array_init(&expected, 64);
	for (i = 0; i < 20; i++) {
		test_nf_append_n(&in, 'e', 1);
		test_nf_append_n(&in, 0x0301, 1);
		test_nf_append_n(&expected, 0x00e9, 1);
	}
	cps = array_get(&in, &count);
	test_nf_throttled(cps, count, UNICODE_NFC, &out);
	test_assert(test_nf_arrays_equal(&out, &expected));
}

/*
 * Code point data given to the transform
 */

struct test_cpd_sink {
	struct unicode_transform transform;
	ARRAY_TYPE(uint32_t) cps;
	ARRAY(const struct unicode_code_point_data *) cp_data;
};

static ssize_t
test_cpd_sink_input(struct unicode_transform *trans,
		    const struct unicode_transform_buffer *buf,
		    const char **error_r ATTR_UNUSED)
{
	struct test_cpd_sink *sink =
		container_of(trans, struct test_cpd_sink, transform);

	array_append(&sink->cps, buf->cp, buf->cp_count);
	array_append(&sink->cp_data, buf->cp_data, buf->cp_count);
	return buf->cp_count;
}

static const struct unicode_transform_def test_cpd_sink_def = {
	.input = test_cpd_sink_input,
};

static void test_hangul_cp_data(enum unicode_nf_type type)
{
	static const uint32_t in[] = { 0xac00, 0xac01 };
	const struct unicode_code_point_data *in_data[N_ELEMENTS(in)];
	struct unicode_transform_buffer buf = {
		.cp = in,
		.cp_data = in_data,
		.cp_count = N_ELEMENTS(in),
	};
	struct unicode_nf_context nf;
	struct test_cpd_sink sink;
	const struct unicode_code_point_data *const *out_data;
	const uint32_t *out;
	unsigned int i, count;
	const char *error;

	for (i = 0; i < N_ELEMENTS(in); i++)
		in_data[i] = unicode_code_point_get_data(in[i]);

	unicode_nf_init(&nf, type);
	i_zero(&sink);
	unicode_transform_init(&sink.transform, &test_cpd_sink_def);
	t_array_init(&sink.cps, 8);
	t_array_init(&sink.cp_data, 8);
	unicode_transform_chain(&nf.transform, &sink.transform);

	test_assert(unicode_transform_input_buf(&nf.transform, &buf,
						&error) == N_ELEMENTS(in));
	test_assert(unicode_transform_flush(&nf.transform, &error) == 1);

	out = array_get(&sink.cps, &count);
	out_data = array_front(&sink.cp_data);
	test_assert(count > 0);
	for (i = 0; i < count; i++) {
		test_assert_idx(out_data[i] == NULL ||
				out_data[i] ==
				unicode_code_point_get_data(out[i]), i);
	}
}

static void test_stream_safe_nfkd(bool compose)
{
	string_t *input = t_str_new(128), *expected = t_str_new(128);
	buffer_t *nf_out = t_buffer_create(128);
	unsigned int i;

	/* U+FF9E HALFWIDTH KATAKANA VOICED SOUND MARK is a starter, but its
	   NFKD decomposition U+3099 is a non-starter. The Stream-Safe Text
	   Process counts the non-starters in the NFKD decomposition also with
	   NFD and NFC, so a CGJ is inserted before it. */
	str_append_c(input, 'a');
	for (i = 0; i < 30; i++)
		uni_ucs4_to_utf8_c(0x0301, input);
	uni_ucs4_to_utf8_c(0xff9e, input);

	if (compose) {
		uni_ucs4_to_utf8_c(0x00e1, expected);
		for (i = 0; i < 29; i++)
			uni_ucs4_to_utf8_c(0x0301, expected);
		test_assert(uni_utf8_write_nfc(str_data(input), str_len(input),
					       nf_out) == 0);
	} else {
		str_append_c(expected, 'a');
		for (i = 0; i < 30; i++)
			uni_ucs4_to_utf8_c(0x0301, expected);
		test_assert(uni_utf8_write_nfd(str_data(input), str_len(input),
					       nf_out) == 0);
	}
	uni_ucs4_to_utf8_c(0x034f, expected);
	uni_ucs4_to_utf8_c(0xff9e, expected);
	test_assert(buffer_cmp(nf_out, expected));
}

static void test_decomposition_nonstarters(void)
{
	const struct unicode_code_point_data *cpd;
	const uint32_t *decomp, *decomp_k;
	unsigned int lead, trail, lead_k, trail_k, i;
	size_t len, len_k;
	bool starter, starter_k;
	uint32_t cp;

	/* The normalization buffer is sized for the Stream-Safe Text
	   Format, which counts non-starters in the NFKD decomposition. Make
	   sure that the canonical decomposition never has more non-starters
	   at either end. */
	for (cp = 0; cp <= 0x10ffff; cp++) {
		if (!uni_is_valid_ucs4(cp))
			continue;
		cpd = unicode_code_point_get_data(cp);
		len = unicode_code_point_data_get_full_decomposition(
			cpd, TRUE, &decomp);
		len_k = unicode_code_point_data_get_full_decomposition(
			cpd, FALSE, &decomp_k);
		if (len == 0) {
			decomp = &cp;
			len = 1;
		}
		if (len_k == 0) {
			decomp_k = &cp;
			len_k = 1;
		}

		lead = trail = lead_k = trail_k = 0;
		starter = starter_k = FALSE;
		for (i = 0; i < len; i++) {
			if (test_ccc(decomp[i]) == 0) {
				starter = TRUE;
				trail = 0;
			} else if (!starter) {
				lead++;
			} else {
				trail++;
			}
		}
		for (i = 0; i < len_k; i++) {
			if (test_ccc(decomp_k[i]) == 0) {
				starter_k = TRUE;
				trail_k = 0;
			} else if (!starter_k) {
				lead_k++;
			} else {
				trail_k++;
			}
		}
		test_assert_idx(len <= UNICODE_DECOMPOSITION_MAX_LENGTH, cp);
		test_assert_idx(len_k <= UNICODE_DECOMPOSITION_MAX_LENGTH, cp);
		test_assert_idx(lead <= lead_k, cp);
		if (starter_k)
			test_assert_idx(starter && trail <= trail_k, cp);
		else if (!starter)
			test_assert_idx(len <= len_k, cp);
		else
			test_assert_idx(trail <= len_k, cp);
	}
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
	test_begin("unicode normalization: stream safe (nfd)");
	test_stream_safe(FALSE);
	test_end();
	test_begin("unicode normalization: stream safe (nfc)");
	test_stream_safe(TRUE);
	test_end();

	/* Test buffer assertions */
	test_begin("unicode normalization: full buffer (nfd)");
	test_full_buffer(FALSE);
	test_end();
	test_begin("unicode normalization: full buffer (nfc)");
	test_full_buffer(TRUE);
	test_end();

	test_begin("unicode normalization: hangul code point data");
	test_hangul_cp_data(UNICODE_NFD);
	test_hangul_cp_data(UNICODE_NFKD);
	test_hangul_cp_data(UNICODE_NFC);
	test_hangul_cp_data(UNICODE_NFKC);
	test_end();

	test_begin("unicode normalization: stream safe nfkd count (nfd)");
	test_stream_safe_nfkd(FALSE);
	test_end();
	test_begin("unicode normalization: stream safe nfkd count (nfc)");
	test_stream_safe_nfkd(TRUE);
	test_end();

	test_begin("unicode normalization: long runs");
	test_long_runs();
	test_end();
	test_begin("unicode normalization: decomposition non-starters");
	test_decomposition_nonstarters();
	test_end();
	test_begin("unicode normalization: slow next transform");
	test_slow_next_transform();
	test_end();
}

