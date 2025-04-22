/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "strnum.h"
#include "str.h"
#include "unichar.h"
#include "istream.h"
#include "unicode-data.h"

#include <fcntl.h>

#define UCD_UNICODE_DATA_TXT "UnicodeData.txt"

static void test_unicode_data_line(const char *line, unsigned int line_num)
{
	static uint32_t cp_first = 0;

	const char *const *columns = t_strsplit(line, ";");
	if (str_array_length(columns) < 15) {
		test_failed(t_strdup_printf(
			"Invalid data at %s:%u",
			UCD_UNICODE_DATA_TXT, line_num));
		return;
	}

	const char *cp_hex = columns[0];
	uint32_t cp;

	if (str_to_uint32_hex(cp_hex, &cp) < 0) {
		test_failed(t_strdup_printf(
				"Invalid data at %s:%u: "
				"Bad code point",
				UCD_UNICODE_DATA_TXT, line_num));
		return;
	}

	/* Parse Name */

	const char *cp_name = columns[1];
	size_t cp_name_len = strlen(cp_name);
	const char *p;

	if (cp_name[0] == '<' && cp_name[cp_name_len - 1] == '>') {
		p = strchr(cp_name + 1, ',');
		if (p != NULL) {
			if (strcmp(p, ", First>") == 0) {
				cp_first = cp;
				return;
			} else if (strcmp(p, ", Last>") != 0) {
				test_failed(t_strdup_printf(
					"Invalid data at %s:%u: "
					"Bad code point range: %s",
					UCD_UNICODE_DATA_TXT, line_num, cp_name));
				return;
			}
		}
	}

	/* Parse General_Category */

	uint8_t general_category =
		(uint8_t)unicode_general_category_from_string(columns[2]);
	if (general_category == UNICODE_GENERAL_CATEGORY_INVALID) {
		test_failed(t_strdup_printf(
			    "Invalid data at %s:%u: "
			    "Bad General_Category for code point %"PRIu32": %s",
			    UCD_UNICODE_DATA_TXT, line_num, cp, columns[2]));
		return;
	}
	test_assert(!unicode_general_category_is_group(general_category));

	/* Parse Decomposition_* */

	const char *decomp_spec = columns[5];
	enum unicode_decomposition_type decomp_type =
		UNICODE_DECOMPOSITION_TYPE_CANONICAL;

	if (*decomp_spec == '<') {
		const char *p = strchr(decomp_spec + 1, '>');

		if (p == NULL || *(p + 1) != ' ') {
			test_failed(t_strdup_printf(
				"Invalid data at %s:%u: "
				"Bad Decomposition for code point %"PRIu32": %s",
				UCD_UNICODE_DATA_TXT, line_num, cp, columns[5]));
			return;
		}
		decomp_type = unicode_decomposition_type_from_string(
			t_strdup_until(decomp_spec + 1, p));
		decomp_spec = p + 2;
	}

	const char *const *decomp = t_strsplit(decomp_spec, " ");

	/* Parse Simple_*case_Mapping */

	uint32_t simple_uppercase_mapping = 0;
	uint32_t simple_lowercase_mapping = 0;
	uint32_t simple_titlecase_mapping = 0;

	if (*columns[12] != '\0' &&
	    str_to_uint32_hex(columns[12], &simple_uppercase_mapping) < 0) {
		test_failed(t_strdup_printf(
			    "Invalid data at %s:%u: "
			    "Bad Simple_Uppercase_Mapping for code point %"PRIu32": %s",
			    UCD_UNICODE_DATA_TXT, line_num, cp, columns[12]));
		return;
	}
	if (*columns[13] != '\0' &&
	    str_to_uint32_hex(columns[13], &simple_lowercase_mapping) < 0) {
		test_failed(t_strdup_printf(
			    "Invalid data at %s:%u: "
			    "Bad Simple_Lowercase_Mapping for code point %"PRIu32": %s",
			    UCD_UNICODE_DATA_TXT, line_num, cp, columns[13]));
		return;
	}
	if (*columns[14] != '\0' &&
	    str_to_uint32_hex(columns[14], &simple_titlecase_mapping) < 0) {
		test_failed(t_strdup_printf(
			    "Invalid data at %s:%u: "
			    "Bad Simple_Titlecase_Mapping for code point %"PRIu32": %s",
			    UCD_UNICODE_DATA_TXT, line_num, cp, columns[14]));
		return;
	}

	/* Check data */

	uint32_t cp_last = cp;

	if (cp_first == 0)
		cp_first = cp;
	for (cp = cp_first; cp <= cp_last && !test_has_failed(); cp++) {
		const struct unicode_code_point_data *cp_data =
			unicode_code_point_get_data(cp);

		test_assert_idx(
			cp_data->general_category == general_category, cp);

		const uint32_t *cp_decomp;
		size_t cp_decomp_len, cp_decomp_idx;
		uint8_t cp_decomp_type;

		cp_decomp_len =
			unicode_code_point_data_get_first_decomposition(
				cp_data, &cp_decomp_type, &cp_decomp);
		test_assert(str_array_length(decomp) == cp_decomp_len);
		if (test_has_failed())
			break;

		test_assert_idx(
			(cp_decomp_type == decomp_type ||
			 cp_decomp_type == UNICODE_DECOMPOSITION_TYPE_COMPAT),
			cp);
		cp_decomp_idx = 0;
		while (*decomp != NULL && !test_has_failed()) {
			uint32_t dcp;

			test_assert_idx(str_to_uint32_hex(*decomp, &dcp) >= 0, cp);
			if (test_has_failed())
				break;
			test_assert_idx(uni_is_valid_ucs4(dcp), cp);
			test_assert_idx(dcp == cp_decomp[cp_decomp_idx], cp);

			cp_decomp_idx++;
			decomp++;
		}

		test_assert_idx(
			cp_data->simple_titlecase_mapping == simple_titlecase_mapping,
			cp);
	}

	cp_first = 0;
}

static void
test_ucd_file(const char *filename,
	      void (*test_line)(const char *line, unsigned int line_num))
{
	const char *file_path = t_strconcat(UCD_DIR, "/", filename, NULL);
	struct istream *input;
	int fd;

	fd = open(file_path, O_RDONLY);
	if (fd < 0)
		i_fatal("Failed to open '%s': %m", file_path);

	test_begin(t_strdup_printf("unicode_data - %s", filename));

	input = i_stream_create_fd_autoclose(&fd, 1024);

	unsigned int line_num = 0;

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

void test_unicode_data(void)
{
	/* Check that UCD data files match with what is compiled. */
	test_ucd_file(UCD_UNICODE_DATA_TXT, test_unicode_data_line);
}
