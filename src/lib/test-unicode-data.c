/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "strnum.h"
#include "str.h"
#include "unichar.h"
#include "istream.h"
#include "unicode-data.h"

#include <fcntl.h>

#define UCD_COMPOSITION_EXCLUSIONS_TXT "CompositionExclusions.txt"
#define UCD_DERIVED_NORMALIZATION_PROPS_TXT "DerivedNormalizationProps.txt"
#define UCD_PROP_LIST_TXT "PropList.txt"
#define UCD_UNICODE_DATA_TXT "UnicodeData.txt"
#define UCD_WORD_BREAK_PROPERTY_TXT "WordBreakProperty.txt"

static bool
parse_prop_file_line(const char *line, const char *file, unsigned int line_num,
		     uint32_t *cp_first_r, uint32_t *cp_last_r,
		     const char **prop_r, const char **value_r)
{
	unsigned int expected_columns = 1;

	if (prop_r != NULL)
		expected_columns++;

	const char *const *columns = t_strsplit(line, ";");
	if (str_array_length(columns) < expected_columns) {
		test_failed(t_strdup_printf(
			"Invalid data at %s:%u", file, line_num));
		return FALSE;
	}

	const char *p = strstr(columns[0], "..");
	const char *cp_first_hex, *cp_last_hex;

	cp_last_hex = NULL;
	if (p == NULL) {
		cp_first_hex = t_str_trim(columns[0], " \t");
	} else {
		cp_first_hex = t_str_trim(t_strdup_until(columns[0], p), " \t");
		cp_last_hex = t_str_trim(p + 2, " \t");
	}
	if (str_to_uint32_hex(cp_first_hex, cp_first_r) < 0) {
		test_failed(t_strdup_printf(
				"Invalid data at %s:%u: "
				"Bad first code point", file, line_num));
		return FALSE;
	}
	if (cp_last_hex == NULL)
		*cp_last_r = *cp_first_r;
	else if (str_to_uint32_hex(cp_last_hex, cp_last_r) < 0) {
		test_failed(t_strdup_printf(
				"Invalid data at %s:%u: "
				"Bad first code point", file, line_num));
		return FALSE;
	}

	if (prop_r != NULL) {
		*prop_r = t_str_trim(columns[1], " \t");
		if (value_r != NULL) {
			if (columns[2] != NULL)
				*value_r = t_str_trim(columns[2], " \t");
			else
				*value_r = NULL;
		}
	}
	return !test_has_failed();
}

static void
test_composition_exclusions_line(const char *line, unsigned int line_num)
{
	uint32_t cp_first, cp_last, cp;

	if (!parse_prop_file_line(line, UCD_COMPOSITION_EXCLUSIONS_TXT,
				  line_num, &cp_first, &cp_last, NULL, NULL))
		return;

	for (cp = cp_first; cp <= cp_last && !test_has_failed(); cp++) {
		const struct unicode_code_point_data *cp_data =
			unicode_code_point_get_data(cp);

		test_assert_idx(cp_data->composition_count == 0, cp);
	}
}

static void
test_derived_normalization_props_line(const char *line, unsigned int line_num)
{
	uint32_t cp_first, cp_last, cp;
	const char *prop, *value;

	if (!parse_prop_file_line(line, UCD_DERIVED_NORMALIZATION_PROPS_TXT,
				  line_num, &cp_first, &cp_last, &prop, &value))
		return;

	for (cp = cp_first; cp <= cp_last && !test_has_failed(); cp++) {
		const struct unicode_code_point_data *cp_data =
			unicode_code_point_get_data(cp);
		uint8_t qc, qc_no, qc_maybe;

		if (strcmp(prop, "NFD_QC") == 0) {
			qc = (cp_data->nf_quick_check &
			      UNICODE_NFD_QUICK_CHECK_MASK);
			qc_no = UNICODE_NFD_QUICK_CHECK_NO;
			qc_maybe = UNICODE_NFD_QUICK_CHECK_MAYBE;
		} else if (strcmp(prop, "NFKD_QC") == 0) {
			qc = (cp_data->nf_quick_check &
			      UNICODE_NFKD_QUICK_CHECK_MASK);
			qc_no = UNICODE_NFKD_QUICK_CHECK_NO;
			qc_maybe = UNICODE_NFKD_QUICK_CHECK_MAYBE;
		} else if (strcmp(prop, "NFC_QC") == 0) {
			qc = (cp_data->nf_quick_check &
			      UNICODE_NFC_QUICK_CHECK_MASK);
			qc_no = UNICODE_NFC_QUICK_CHECK_NO;
			qc_maybe = UNICODE_NFC_QUICK_CHECK_MAYBE;
		} else if (strcmp(prop, "NFKC_QC") == 0) {
			qc = (cp_data->nf_quick_check &
			      UNICODE_NFKC_QUICK_CHECK_MASK);
			qc_no = UNICODE_NFKC_QUICK_CHECK_NO;
			qc_maybe = UNICODE_NFKC_QUICK_CHECK_MAYBE;
		} else {
			continue;
		}

		i_assert(value != NULL);
		if (strcmp(value, "N") == 0)
			test_assert_idx(qc == qc_no, cp);
		else if (strcmp(value, "M") == 0)
			test_assert_idx(qc == qc_maybe, cp);
	}
}

static void test_prop_list_line(const char *line, unsigned int line_num)
{
	uint32_t cp_first, cp_last, cp;
	const char *prop;

	if (!parse_prop_file_line(line, UCD_PROP_LIST_TXT, line_num,
				  &cp_first, &cp_last, &prop, NULL))
		return;

	for (cp = cp_first; cp <= cp_last && !test_has_failed(); cp++) {
		const struct unicode_code_point_data *cp_data =
			unicode_code_point_get_data(cp);

		if (strcmp(prop, "White_Space") == 0)
			test_assert_idx(cp_data->pb_g_white_space, cp);
		else if (strcmp(prop, "Pattern_White_Space") == 0)
			test_assert_idx(cp_data->pb_i_pattern_white_space, cp);
		else if (strcmp(prop, "Quotation_Mark") == 0)
			test_assert_idx(cp_data->pb_m_quotation_mark, cp);
		else if (strcmp(prop, "Dash") == 0)
			test_assert_idx(cp_data->pb_m_dash, cp);
		else if (strcmp(prop, "Sentence_Terminal") == 0)
			test_assert_idx(cp_data->pb_m_sentence_terminal, cp);
		else if (strcmp(prop, "Terminal_Punctuation") == 0)
			test_assert_idx(cp_data->pb_m_terminal_punctuation, cp);
	}
}

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

	/* Parse Canonical_Combining_Class */

	unsigned int ccc = 0;
	if (*columns[3] != '\0' &&
	    (str_to_uint(columns[3], &ccc) < 0 || ccc > UINT8_MAX)) {
		test_failed(t_strdup_printf(
			    "Invalid data at %s:%u: "
			    "Bad Canonical_Combining_Class for code point %"PRIu32": %s",
			    UCD_UNICODE_DATA_TXT, line_num, cp, columns[3]));
		return;
	}

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
		test_assert_idx(
			cp_data->canonical_combining_class == ccc, cp);

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
test_word_break_property_line(const char *line, unsigned int line_num)
{
	uint32_t cp_first, cp_last, cp;
	const char *prop;

	if (!parse_prop_file_line(line, UCD_WORD_BREAK_PROPERTY_TXT, line_num,
				  &cp_first, &cp_last, &prop, NULL))
		return;

	for (cp = cp_first; cp <= cp_last && !test_has_failed(); cp++) {
		const struct unicode_code_point_data *cp_data =
			unicode_code_point_get_data(cp);

		if (strcmp(prop, "CR") == 0)
			test_assert_idx(cp_data->pb_wb_cr, cp);
		else if (strcmp(prop, "LF") == 0)
			test_assert_idx(cp_data->pb_wb_lf, cp);
		else if (strcmp(prop, "Newline") == 0)
			test_assert_idx(cp_data->pb_wb_newline, cp);
		else if (strcmp(prop, "Extend") == 0)
			test_assert_idx(cp_data->pb_wb_extend, cp);
		else if (strcmp(prop, "ZWJ") == 0)
			test_assert_idx(cp_data->pb_wb_zwj, cp);
		else if (strcmp(prop, "Regional_Indicator") == 0)
			test_assert_idx(cp_data->pb_wb_regional_indicator, cp);
		else if (strcmp(prop, "Format") == 0)
			test_assert_idx(cp_data->pb_wb_format, cp);
		else if (strcmp(prop, "Katakana") == 0)
			test_assert_idx(cp_data->pb_wb_katakana, cp);
		else if (strcmp(prop, "Hebrew_Letter") == 0)
			test_assert_idx(cp_data->pb_wb_hebrew_letter, cp);
		else if (strcmp(prop, "ALetter") == 0)
			test_assert_idx(cp_data->pb_wb_aletter, cp);
		else if (strcmp(prop, "Single_Quote") == 0)
			test_assert_idx(cp_data->pb_wb_single_quote, cp);
		else if (strcmp(prop, "Double_Quote") == 0)
			test_assert_idx(cp_data->pb_wb_double_quote, cp);
		else if (strcmp(prop, "MidNumLet") == 0)
			test_assert_idx(cp_data->pb_wb_midnumlet, cp);
		else if (strcmp(prop, "MidLetter") == 0)
			test_assert_idx(cp_data->pb_wb_midletter, cp);
		else if (strcmp(prop, "MidNum") == 0)
			test_assert_idx(cp_data->pb_wb_midnum, cp);
		else if (strcmp(prop, "Numeric") == 0)
			test_assert_idx(cp_data->pb_wb_numeric, cp);
		else if (strcmp(prop, "ExtendNumLet") == 0)
			test_assert_idx(cp_data->pb_wb_extendnumlet, cp);
	}
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
	/* Check that UCD data files match with what is compiled. For the
	   property files only the positive assignment of properties to the
	   code points mentioned in the files is tested, and notably not their
	   absence for other code points. */
	test_ucd_file(UCD_COMPOSITION_EXCLUSIONS_TXT,
		      test_composition_exclusions_line);
	test_ucd_file(UCD_DERIVED_NORMALIZATION_PROPS_TXT,
		      test_derived_normalization_props_line);
	test_ucd_file(UCD_PROP_LIST_TXT, test_prop_list_line);
	test_ucd_file(UCD_UNICODE_DATA_TXT, test_unicode_data_line);
	test_ucd_file(UCD_WORD_BREAK_PROPERTY_TXT,
		      test_word_break_property_line);
}
