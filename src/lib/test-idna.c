/* Copyright (c) Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "strnum.h"
#include "str.h"
#include "unichar.h"
#include "istream.h"
#include "idna.h"

#include <fcntl.h>

#define UCD_IDNA_TEST_V2_TXT UCD_DIR "/IdnaTestV2.txt"

/* Copied from unichar.c, but removed assert to that it can process
   surrogates. */
static void utf32_to_utf8_c(uint32_t chr, buffer_t *output)
{
	unsigned char first;
	int bitpos;

	if (chr < 0x80) {
		buffer_append_c(output, chr);
		return;
	}

	if (chr < (1 << (6 + 5))) {
		/* 110xxxxx */
		bitpos = 6;
		first = 0x80 | 0x40;
	} else if (chr < (1 << ((2*6) + 4))) {
		/* 1110xxxx */
		bitpos = 2*6;
		first = 0x80 | 0x40 | 0x20;
	} else if (chr < (1 << ((3*6) + 3))) {
		/* 11110xxx */
		bitpos = 3*6;
		first = 0x80 | 0x40 | 0x20 | 0x10;
	} else if (chr < (1 << ((4*6) + 2))) {
		/* 111110xx */
		bitpos = 4*6;
		first = 0x80 | 0x40 | 0x20 | 0x10 | 0x08;
	} else {
		/* 1111110x */
		bitpos = 5*6;
		first = 0x80 | 0x40 | 0x20 | 0x10 | 0x08 | 0x04;
	}
	buffer_append_c(output, first | (chr >> bitpos));

	do {
		bitpos -= 6;
		buffer_append_c(output, 0x80 | ((chr >> bitpos) & 0x3f));
	} while (bitpos > 0);
}

static const char *resolve_escapes(const char *in)
{
	const unsigned char *p = (const unsigned char *)in;
	const unsigned char *pend = p + strlen(in);
	string_t *out = t_str_new(128);

	while (p < pend) {
		if (*p == '\\' && (p + 1) < pend && *(p + 1) == 'u') {
			const unsigned char *hex_val;

			p += 2;
			if (*p == '{' && (p + 5) < pend && *(p + 5) == '}') {
				hex_val = p + 1;
				p += 6;
			} else {
				hex_val = p;
				p += 4;
			}

			unsigned int i;
			uint16_t cp = 0;
			for (i = 0; i < 4; i++, hex_val++) {
				if (*hex_val >= '0' && *hex_val <= '9')
					cp = (cp << 4) + (*hex_val - '0');
				else if (*hex_val >= 'A' && *hex_val <= 'F')
					cp = (cp << 4) + 0x0a + (*hex_val - 'A');
				else if (*hex_val >= 'a' && *hex_val <= 'f')
					cp = (cp << 4) + 0x0a + (*hex_val - 'a');
			}

			utf32_to_utf8_c(cp, out);
			continue;
		}
		str_append_c(out, *p);
		p++;
	}

	return str_c(out);
}

static void
test_success_status(const char *status, enum idna_process_flags flags)
{
	if (*status == '\0')
		return;

	const char *const *ps = t_strsplit(status, ",");

	while (*ps != NULL && !test_has_failed()) {
		const char *s = t_str_trim(*ps, " \t");

		if (HAS_ALL_BITS(flags, IDNA_PROCESS_FLAG_IGNORE_BIDI) &&
		    *s == 'B') {
			/* BiDi checks disabled. */
		} else if (*s == 'C') {
			/* ContextJ checks not implemented. */
		} else {
			test_failed(t_strdup_printf(
				"Should have failed with: %s", s));
		}
		ps++;
	}
}

static void
test_u_failure_status(const char *u_status, const char *a_status,
		      const char *error, unsigned int line_num)
{
	test_assert_idx(*u_status != '\0' || *a_status != '\0', line_num);
	if (test_has_failed())
		return;

	const char *const *ps = t_strsplit(u_status, ",");
	bool status_found = FALSE;

	while (*ps != NULL && !status_found) {
		const char *s = t_str_trim(*ps, " \t");

		if (*s == 'B' &&
		    str_begins_with(error, "Invalid label in Bidi domain name"))
			status_found = TRUE;
		else if (strcmp(s, "P4") == 0 &&
		    (strcmp(error, "Invalid Punycode in A-label") == 0 ||
		     str_begins_with(error, "Invalid 8bit code point")))
			status_found = TRUE;
		else if (strcmp(s, "V1") == 0 &&
			 strcmp(error,"A-label is not NFC normalized") == 0)
			status_found = TRUE;
		else if (strcmp(s, "V2") == 0 &&
			 strcmp(error,"Label has '-' at both the third and fourth positions") == 0)
			status_found = TRUE;
		else if (strcmp(s, "V3") == 0 &&
			 (strcmp(error, "Label begins with '-'") == 0 ||
			  strcmp(error, "Label ends with '-'") == 0))
			status_found = TRUE;
		else if (strcmp(s, "V6") == 0 &&
			 str_begins_with(error, "Label begins with combining mark"))
			status_found = TRUE;
		else if (strcmp(s, "V7") == 0 &&
			 (str_begins_with(error, "Label contains invalid code point") ||
			  strcmp(error, "Invalid UTF8 encoding") == 0))
			status_found = TRUE;
		else if (strcmp(s, "U1") == 0 &&
			 str_begins_with(error, "Label contains invalid ASCII code point"))
			status_found = TRUE;
		else if (strcmp(s, "X4_2") == 0 &&
			 (strcmp(error, "Empty domain name") == 0 ||
			  strcmp(error, "Empty label") == 0 ||
			  strcmp(error, "Empty A-label") == 0))
			status_found = TRUE;
		ps++;
	}

	ps = t_strsplit(a_status, ",");
	while (*ps != NULL && !status_found) {
		const char *s = t_str_trim(*ps, " \t");

		if (strcmp(s, "A4_1") == 0 &&
		    strcmp(error, "Domain name too long") == 0)
			status_found = TRUE;
		else if (strcmp(s, "A4_2") == 0 &&
		    (strcmp(error, "Empty label") == 0 ||
		     strcmp(error, "Label too long") == 0 ||
		     strcmp(error, "A-label too long") == 0 ||
		     strcmp(error, "U-label too long") == 0))
			status_found = TRUE;
		ps++;
	}

	test_assert_idx(status_found, line_num);
}

static void
test_scenario(const char *source, enum idna_process_flags flags,
	      const char *to_unicode, const char *to_unicode_status,
	      const char *to_ascii_n, const char *to_ascii_n_status,
	      unsigned int line_num)
{
	const char *result_unicode, *result_ascii, *error;
	int ret;

	flags |= IDNA_PROCESS_FLAG_CHECK_HYPHENS;
	ret = idna_process_domain_name(source, flags,
				       &result_unicode, &result_ascii, &error);
	test_assert_idx(*to_unicode_status != '\0' ||
			*to_ascii_n_status != '\0'|| ret >= 0, line_num);
	if (ret >= 0)
		test_success_status(to_unicode_status, flags);
	else {
		test_u_failure_status(to_unicode_status, to_ascii_n_status,
				      error, line_num);
	}
	if (ret >= 0) {
		test_assert_strcmp_idx(to_unicode, result_unicode, line_num);
		test_assert_strcmp_idx(to_ascii_n, result_ascii, line_num);
	}
}

static void test_line(const char *line, unsigned int line_num)
{
	/* Columns (c1, c2,...) are separated by semicolons. Leading and
	   trailing spaces and tabs in each column are ignored. Comments are
	   indicated with hash marks.

	   Column 1: source -          The source string to be tested. "" means
	                               the empty string.
	   Column 2: toUnicode -       The result of applying toUnicode to the
	                               source, with Transitional_Processing=false.
	                               A blank value means the same as the
	                               source value. "" means the empty string.
	   Column 3: toUnicodeStatus - A set of status codes, each corresponding
	                               to a particular test. A blank value means
	                               [] (no errors).
	   Column 4: toAsciiN -        The result of applying toASCII to the
				       source, with Transitional_Processing=false.
	                               A blank value means the same as the
	                               toUnicode value. "" means the empty string.
	   Column 5: toAsciiNStatus -  A set of status codes, each corresponding
	                               to a particular test. A blank value means
	                               the same as the toUnicodeStatus value. An
	                               explicit [] means no errors.
	   Column 6: toAsciiT -        The result of applying toASCII to the
	                               source, with Transitional_Processing=true.
	                               A blank value means the same as the
	                               toAsciiN value. "" means the empty string.
	   Column 7: toAsciiTStatus -  A set of status codes, each corresponding
	                               to a particular test. A blank value means
	                               the same as the toAsciiNStatus value. An
	                               explicit [] means no errors.
	 */
	const char *const *columns = t_strsplit(line, ";");

	if (str_array_length(columns) < 7) {
		test_failed(t_strdup_printf(
			"Invalid test at %s:%u",
			UCD_IDNA_TEST_V2_TXT, line_num));
		return;
	}

	const char *source = resolve_escapes(t_str_trim(columns[0], " \t"));
	const char *to_unicode = resolve_escapes(t_str_trim(columns[1], " \t"));
	const char *to_unicode_status = t_str_trim(columns[2], " \t[]");
	const char *to_ascii_n = t_str_trim(columns[3], " \t");
	const char *to_ascii_n_status = t_str_trim(columns[4], " \t[]");

	if (strcmp(source, "\"\"") == 0)
		source = "";
	if (strlen(to_unicode) == 0)
		to_unicode = source;
	else if (strcmp(source, "\"\"") == 0)
		to_unicode = "";
	if (strlen(to_ascii_n) == 0)
		to_ascii_n = to_unicode;
	else if (strcmp(to_ascii_n, "\"\"") == 0)
		to_ascii_n = "";

	test_scenario(source, 0,
		      to_unicode, to_unicode_status,
		      to_ascii_n, to_ascii_n_status, line_num);
	test_scenario(source, IDNA_PROCESS_FLAG_IGNORE_BIDI,
		      to_unicode, to_unicode_status,
		      to_ascii_n, to_ascii_n_status, line_num);
}

static void test_idna_uts_46(void)
{
	struct istream *input;
	int fd;

	fd = open(UCD_IDNA_TEST_V2_TXT, O_RDONLY);
	if (fd < 0)
		i_fatal("Failed to open: %m");

	input = i_stream_create_fd_autoclose(&fd, 4096);

	unsigned int line_num = 0;

	test_begin("idna - UTS #46");

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

		T_BEGIN {
			test_line(line, line_num);
		} T_END;
	}

	i_stream_destroy(&input);
	test_end();
}

#define DOMAIN_ASCII_240 \
	"fedcba987654321.fedcba987654321.fedcba987654321.fedcba987654321." \
	"fedcba987654321.fedcba987654321.fedcba987654321.fedcba987654321." \
	"fedcba987654321.fedcba987654321.fedcba987654321.fedcba987654321." \
	"fedcba987654321.fedcba987654321.fedcba987654321."
static void test_idna_label_length_limits(void)
{
	const struct {
		const char *input;
		int ret;
	} test_cases[] = {
		/* Maximum ASCII label length of 63 approached (62) */
		{ "Lentokonesuihkuturbiinimoottoria"
		  "pumekaanikkoaliupseerioppilas1.fi", 0 },
		/* Maximum ASCII label length of 63 reached */
		{ "Lentokonesuihkuturbiinimoottoria"
		  "pumekaanikkoaliupseerioppilas11.fi", 0 },
		/* Maximum ASCII label length of 63 exceeded (64) */
		{ "Lentokonesuihkuturbiinimoottoria"
		  "pumekaanikkoaliupseerioppilas666.fi", -1 },
		/* U-label for which equivalent A-label is too long */
		{ "Epäjärjestelmällistyttämättömyydellänsäkäänköhän-"
		  "Äteritsiputeritsipuolilautatsijänkä.fi", -1 },
		/* Maximum ASCII domain name length of 254 reached */
		{ DOMAIN_ASCII_240 "fedcba9876.tld",  // 254
		  0 },
		/* Maximum ASCII domain name length of 254 exceeded */
		{ DOMAIN_ASCII_240 "fedcba98765.tld", // 255
		  -1 },
		/* Maximum ASCII domain name length of 254 reached
		   (A-label TLD) */
		{ DOMAIN_ASCII_240 "fe.xn--42c2d9a",  // 254
		  0 },
		/* Maximum ASCII domain name length of 254 exceeded
		   (A-label TLD) */
		{ DOMAIN_ASCII_240 "fed.xn--42c2d9a", // 255
		  -1 },
		/* Maximum ASCII domain name length of 254 reached
		   (U-label TLD) */
		{ DOMAIN_ASCII_240 "fe.คอม",          // 254
		  0 },
		/* Maximum ASCII domain name length of 254 exceeded
		   (U-label TLD) */
		{ DOMAIN_ASCII_240 "fed.คอม",         // 255
		  -1 },
	};

	test_begin("idna - label length limits");

	for (size_t i = 0; i < N_ELEMENTS(test_cases); i++) {
		const char *unicode, *ascii, *error;
		int ret;

		/* Test with output */
		ret = idna_process_domain_name(
			test_cases[i].input, 0, &unicode, &ascii, &error);
		test_assert_cmp_idx(ret, ==, test_cases[i].ret, i);
		/* Test with validation only */
		ret = idna_process_domain_name(
			test_cases[i].input, 0, NULL, NULL, &error);
		test_assert_cmp_idx(ret, ==, test_cases[i].ret, i);
	}
	test_end();
}

void test_idna(void)
{
	test_idna_uts_46();
	test_idna_label_length_limits();
}
