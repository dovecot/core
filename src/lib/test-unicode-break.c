/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "strnum.h"
#include "str.h"
#include "array.h"
#include "istream.h"
#include "unichar.h"
#include "unicode-break.h"

#include <fcntl.h>

#define UCD_GRAPHEME_BREAK_TEST_TXT "GraphemeBreakTest.txt"

#define BREAK_MARKER "\xc3\xb7"
#define NO_BREAK_MARKER "\xc3\x97"

static void
test_gcb_line(const char *file, const char *line, unsigned int line_num)
{
	struct unicode_gc_break gcbrk;
	const char *const *tokens = t_strsplit(line, " ");

	unicode_gc_break_init(&gcbrk);
	while (tokens[0] != NULL && tokens[1] != NULL && !test_has_failed()) {
		const char *brk = tokens[0];
		const char *cp_hex = tokens[1];
		bool break_m1_test = FALSE;
		uint32_t cp;

		if (strcmp(brk, BREAK_MARKER) == 0)
			break_m1_test = TRUE;
		else if (strcmp(brk, NO_BREAK_MARKER) != 0) {
			test_failed(t_strdup_printf(
				"Invalid data at %s:%u: "
				"Bad break marker", file, line_num));
			return;
		}

		if (str_to_uint32_hex(cp_hex, &cp) < 0) {
			test_failed(t_strdup_printf(
				"Invalid data at %s:%u: "
				"Bad code point", file, line_num));
			return;
		}

		const struct unicode_code_point_data *cp_data = NULL;
		bool break_m1;

		break_m1 = unicode_gc_break_cp(&gcbrk, cp, &cp_data);

		test_assert_idx(break_m1 == break_m1_test, line_num);

		tokens += 2;
	}

	test_assert_strcmp_idx(tokens[0], BREAK_MARKER, line_num);
}

static void
test_ucd_file(const char *file,
	      void (*test_line)(const char *file, const char *line,
				unsigned int line_num))
{
	const char *file_path = t_strconcat(UCD_DIR, "/", file, NULL);

	test_begin(t_strdup_printf("unicode_break - %s", file));

	struct istream *input = i_stream_create_file(file_path, 1024);
	unsigned int line_num = 0;

	while (!test_has_failed()) {
		char *line = i_stream_read_next_line(input);
		if (line == NULL)
			break;
		line_num++;

		/* remove any trailing whitespace and comment */
		if (*line == '\0')
			continue;
		char *end = strchr(line, '#');
		if (end == NULL)
			end = &line[strlen(line) - 1];
		while ((end - 1) >= line && (end[-1] == '\t' || end[-1] == ' '))
			end--;
		*end = '\0';
		if (*line == '\0')
			continue;

		T_BEGIN {
			test_line(file, line, line_num);
		} T_END;
	}

	i_stream_destroy(&input);
	test_end();
}

void test_unicode_break(void)
{
	test_ucd_file(UCD_GRAPHEME_BREAK_TEST_TXT, test_gcb_line);
}
