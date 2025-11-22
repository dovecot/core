#ifndef UNICODE_DATA_STATIC_H
#define UNICODE_DATA_STATIC_H

/* UAX #44, Section 5.7.1: General Category Values
 */
enum unicode_general_category {
	UNICODE_GENERAL_CATEGORY_INVALID = 0,

	/* LC - Cased_Letter: Lu | Ll | Lt */
	UNICODE_GENERAL_CATEGORY_LC = (1 << 4),
	/* L - Letter: Lu | Ll | Lt | Lm | Lo */
	UNICODE_GENERAL_CATEGORY_L = (1 << 5) | UNICODE_GENERAL_CATEGORY_LC,
	/* M - Mark: Mn | Mc | Me */
	UNICODE_GENERAL_CATEGORY_M = (2 << 5),
	/* N - Number: Nd | Nl | No */
	UNICODE_GENERAL_CATEGORY_N = (3 << 5),
	/* P - Punctuation: Pc | Pd | Ps | Pe | Pi | Pf | Po */
	UNICODE_GENERAL_CATEGORY_P = (4 << 5),
	/* S - Symbol: Sm | Sc | Sk | So */
	UNICODE_GENERAL_CATEGORY_S = (5 << 5),
	/* Z - Separator: Zs | Zl | Zp */
	UNICODE_GENERAL_CATEGORY_Z = (6 << 5),
	/* C - Other: Cc | Cf | Cs | Co | Cn */
	UNICODE_GENERAL_CATEGORY_C = (7 << 5),

	UNICODE_GENERAL_CATEGORY_GROUP_MASK = (0xf0),

	/* Lu - Uppercase_Letter */
	UNICODE_GENERAL_CATEGORY_LU = UNICODE_GENERAL_CATEGORY_LC | 1,
	/* Ll - Lowercase_Letter */
	UNICODE_GENERAL_CATEGORY_LL = UNICODE_GENERAL_CATEGORY_LC | 2,
	/* Lt - Titlecase_Letter */
	UNICODE_GENERAL_CATEGORY_LT = UNICODE_GENERAL_CATEGORY_LC | 3,
	/* Lm - Modifier_Letter */
	UNICODE_GENERAL_CATEGORY_LM = UNICODE_GENERAL_CATEGORY_L | 4,
	/* Lo - Other_Letter */
	UNICODE_GENERAL_CATEGORY_LO = UNICODE_GENERAL_CATEGORY_L | 5,

	/* Mn - Nonspacing_Mark */
	UNICODE_GENERAL_CATEGORY_MN = UNICODE_GENERAL_CATEGORY_M | 1,
	/* Mc - Spacing_Mark */
	UNICODE_GENERAL_CATEGORY_MC = UNICODE_GENERAL_CATEGORY_M | 2,
	/* Me - Enclosing_Mark */
	UNICODE_GENERAL_CATEGORY_ME = UNICODE_GENERAL_CATEGORY_M | 3,

	/* Nd - Decimal_Number */
	UNICODE_GENERAL_CATEGORY_ND = UNICODE_GENERAL_CATEGORY_N | 1,
	/* Nl - Letter_Number */
	UNICODE_GENERAL_CATEGORY_NL = UNICODE_GENERAL_CATEGORY_N | 2,
	/* No - Other_Number */
	UNICODE_GENERAL_CATEGORY_NO = UNICODE_GENERAL_CATEGORY_N | 3,

	/* Pc -	Connector_Punctuation */
	UNICODE_GENERAL_CATEGORY_PC = UNICODE_GENERAL_CATEGORY_P | 1,
	/* Pd - Dash_Punctuation */
	UNICODE_GENERAL_CATEGORY_PD = UNICODE_GENERAL_CATEGORY_P | 2,
	/* Ps - Open_Punctuation */
	UNICODE_GENERAL_CATEGORY_PS = UNICODE_GENERAL_CATEGORY_P | 3,
	/* Pe - Close_Punctuation */
	UNICODE_GENERAL_CATEGORY_PE = UNICODE_GENERAL_CATEGORY_P | 4,
	/* Pi - Initial_Punctuation */
	UNICODE_GENERAL_CATEGORY_PI = UNICODE_GENERAL_CATEGORY_P | 5,
	/* Pf - Final_Punctuation */
	UNICODE_GENERAL_CATEGORY_PF = UNICODE_GENERAL_CATEGORY_P | 6,
	/* Po - Other_Punctuation */
	UNICODE_GENERAL_CATEGORY_PO = UNICODE_GENERAL_CATEGORY_P | 7,

	/* Sm - Math_Symbol */
	UNICODE_GENERAL_CATEGORY_SM = UNICODE_GENERAL_CATEGORY_S | 1,
	/* Sc - Currency_Symbol */
	UNICODE_GENERAL_CATEGORY_SC = UNICODE_GENERAL_CATEGORY_S | 2,
	/* Sk - Modifier_Symbol */
	UNICODE_GENERAL_CATEGORY_SK = UNICODE_GENERAL_CATEGORY_S | 3,
	/* So -	Other_Symbol */
	UNICODE_GENERAL_CATEGORY_SO = UNICODE_GENERAL_CATEGORY_S | 4,

	/* Zs - Space_Separator */
	UNICODE_GENERAL_CATEGORY_ZS = UNICODE_GENERAL_CATEGORY_Z | 1,
	/* Zl - Line_Separator */
	UNICODE_GENERAL_CATEGORY_ZL = UNICODE_GENERAL_CATEGORY_Z | 2,
	/* Zp - Paragraph_Separator */
	UNICODE_GENERAL_CATEGORY_ZP = UNICODE_GENERAL_CATEGORY_Z | 3,

	/* Cc - Control */
	UNICODE_GENERAL_CATEGORY_CC = UNICODE_GENERAL_CATEGORY_C | 1,
	/* Cf - Format */
	UNICODE_GENERAL_CATEGORY_CF = UNICODE_GENERAL_CATEGORY_C | 2,
	/* Cs - Surrogate */
	UNICODE_GENERAL_CATEGORY_CS = UNICODE_GENERAL_CATEGORY_C | 3,
	/* Co - Private_Use */
	UNICODE_GENERAL_CATEGORY_CO = UNICODE_GENERAL_CATEGORY_C | 4,
	/* Cn - Unassigned */
	UNICODE_GENERAL_CATEGORY_CN = UNICODE_GENERAL_CATEGORY_C | 5,
};

/* UAX #44, Section 5.7.5: Decompositions and Normalization
 */
enum unicode_nf_quick_check {
	UNICODE_NFKC_QUICK_CHECK_YES   = (0x00 << 6),
	UNICODE_NFKC_QUICK_CHECK_NO    = (0x01 << 6),
	UNICODE_NFKC_QUICK_CHECK_MAYBE = (0x02 << 6),
	UNICODE_NFC_QUICK_CHECK_YES    = (0x00 << 4),
	UNICODE_NFC_QUICK_CHECK_NO     = (0x01 << 4),
	UNICODE_NFC_QUICK_CHECK_MAYBE  = (0x02 << 4),
	UNICODE_NFKD_QUICK_CHECK_YES   = (0x00 << 2),
	UNICODE_NFKD_QUICK_CHECK_NO    = (0x01 << 2),
	UNICODE_NFKD_QUICK_CHECK_MAYBE = (0x02 << 2),
	UNICODE_NFD_QUICK_CHECK_YES    = (0x00 << 0),
	UNICODE_NFD_QUICK_CHECK_NO     = (0x01 << 0),
	UNICODE_NFD_QUICK_CHECK_MAYBE  = (0x02 << 0),

	UNICODE_NFKC_QUICK_CHECK_MASK  = (0x03 << 6),
	UNICODE_NFC_QUICK_CHECK_MASK   = (0x03 << 4),
	UNICODE_NFKD_QUICK_CHECK_MASK  = (0x03 << 2),
	UNICODE_NFD_QUICK_CHECK_MASK   = (0x03 << 0),
};

struct unicode_code_point_data {
	uint8_t general_category; // Not yet used
	uint8_t canonical_combining_class;
	uint8_t nf_quick_check;

	uint8_t decomposition_type; // Not yet used
	uint8_t decomposition_first_length;
	uint8_t decomposition_full_length;
	uint8_t decomposition_full_k_length;

	uint8_t composition_count;

	uint8_t uppercase_mapping_length;
	uint8_t lowercase_mapping_length;
	uint8_t casefold_mapping_length;

	uint16_t decomposition_first_offset;
	uint16_t decomposition_full_offset;
	uint16_t decomposition_full_k_offset;
	uint16_t composition_offset;

	uint16_t uppercase_mapping_offset;
	uint16_t lowercase_mapping_offset;
	uint16_t casefold_mapping_offset;

	uint32_t simple_titlecase_mapping;

	/* Property bits (UAX #44, Section 5.1) */

	/* General */
	bool pb_g_white_space:1;

	/* Identifiers */
	bool pb_i_pattern_white_space:1;

	/* Miscellaneous */
	bool pb_m_quotation_mark:1;
	bool pb_m_dash:1;
	bool pb_m_sentence_terminal:1;
	bool pb_m_terminal_punctuation:1;

	/* Common Break */
	bool pb_b_cr:1;
	bool pb_b_lf:1;
	bool pb_b_zwj:1; // Not currently used
	bool pb_b_regional_indicator:1;

	/* Word_Break (UAX #29, Section 4.1) */
	bool pb_wb_newline:1;
	bool pb_wb_extend:1;
	bool pb_wb_format:1;
	bool pb_wb_katakana:1;
	bool pb_wb_hebrew_letter:1;
	bool pb_wb_aletter:1;
	bool pb_wb_single_quote:1;
	bool pb_wb_double_quote:1;
	bool pb_wb_midnumlet:1;
	bool pb_wb_midletter:1;
	bool pb_wb_midnum:1;
	bool pb_wb_numeric:1;
	bool pb_wb_extendnumlet:1;
};

#endif
