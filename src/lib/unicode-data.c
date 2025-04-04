/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "unicode-data.h"

uint8_t unicode_general_category_from_string(const char *str)
{
	if (str == NULL || strlen(str) != 2)
		return UNICODE_GENERAL_CATEGORY_INVALID;

	switch (str[0]) {
	case 'L':
		switch (str[1]) {
		/* Lu - Uppercase_Letter */
		case 'u':
			return UNICODE_GENERAL_CATEGORY_LU;
		/* Ll - Lowercase_Letter */
		case 'l':
			return UNICODE_GENERAL_CATEGORY_LL;
		/* Lt - Titlecase_Letter */
		case 't':
			return UNICODE_GENERAL_CATEGORY_LT;
		/* LC - Cased_Letter: Lu | Ll | Lt */
		case 'C':
			return UNICODE_GENERAL_CATEGORY_LC;
		/* Lm - Modifier_Letter */
		case 'm':
			return UNICODE_GENERAL_CATEGORY_LM;
		/* Lo - Other_Letter */
		case 'o':
			return UNICODE_GENERAL_CATEGORY_LO;
		/* L - Letter: Lu | Ll | Lt | Lm | Lo */
		case '\0':
			return UNICODE_GENERAL_CATEGORY_L;
		default:
			break;
		}
		break;
	case 'M':
		switch (str[1]) {
		/* Mn - Nonspacing_Mark */
		case 'n':
			return UNICODE_GENERAL_CATEGORY_MN;
		/* Mc - Spacing_Mark */
		case 'c':
			return UNICODE_GENERAL_CATEGORY_MC;
		/* Me - Enclosing_Mark */
		case 'e':
			return UNICODE_GENERAL_CATEGORY_ME;
		/* M - Mark: Mn | Mc | Me */
		case '\0':
			return UNICODE_GENERAL_CATEGORY_M;
		default:
			break;
		}
		break;
	case 'N':
		switch (str[1]) {
		/* Nd - Decimal_Number */
		case 'd':
			return UNICODE_GENERAL_CATEGORY_ND;
		/* Nl - Letter_Number */
		case 'l':
			return UNICODE_GENERAL_CATEGORY_NL;
		/* No - Other_Number */
		case 'o':
			return UNICODE_GENERAL_CATEGORY_NO;
		/* N - Number: Nd | Nl | No */
		case '\0':
			return UNICODE_GENERAL_CATEGORY_N;
		default:
			break;
		}
		break;
	case 'P':
		switch (str[1]) {
		/* Pc -	Connector_Punctuation */
		case 'c':
			return UNICODE_GENERAL_CATEGORY_PC;
		/* Pd - Dash_Punctuation */
		case 'd':
			return UNICODE_GENERAL_CATEGORY_PD;
		/* Ps - Open_Punctuation */
		case 's':
			return UNICODE_GENERAL_CATEGORY_PS;
		/* Pe - Close_Punctuation */
		case 'e':
			return UNICODE_GENERAL_CATEGORY_PE;
		/* Pi - Initial_Punctuation */
		case 'i':
			return UNICODE_GENERAL_CATEGORY_PI;
		/* Pf - Final_Punctuation */
		case 'f':
			return UNICODE_GENERAL_CATEGORY_PF;
		/* Po - Other_Punctuation */
		case 'o':
			return UNICODE_GENERAL_CATEGORY_PO;
		/* P - Punctuation: Pc | Pd | Ps | Pe | Pi | Pf | Po */
		case '\0':
			return UNICODE_GENERAL_CATEGORY_P;
		default:
			break;
		}
		break;
	case 'S':
		switch (str[1]) {
		/* Sm - Math_Symbol */
		case 'm':
			return UNICODE_GENERAL_CATEGORY_SM;
		/* Sc - Currency_Symbol */
		case 'c':
			return UNICODE_GENERAL_CATEGORY_SC;
		/* Sk - Modifier_Symbol */
		case 'k':
			return UNICODE_GENERAL_CATEGORY_SK;
		/* So -	Other_Symbol */
		case 'o':
			return UNICODE_GENERAL_CATEGORY_SO;
		/* S - Symbol: Sm | Sc | Sk | So */
		case '\0':
			return UNICODE_GENERAL_CATEGORY_S;
		default:
			break;
		}
		break;
	case 'Z':
		switch (str[1]) {
		/* Zs - Space_Separator */
		case 's':
			return UNICODE_GENERAL_CATEGORY_ZS;
		/* Zl - Line_Separator */
		case 'l':
			return UNICODE_GENERAL_CATEGORY_ZL;
		/* Zp - Paragraph_Separator */
		case 'p':
			return UNICODE_GENERAL_CATEGORY_ZP;
		/* Z - Separator: Zs | Zl | Zp */
		case '\0':
			return UNICODE_GENERAL_CATEGORY_Z;
		default:
			break;
		}
		break;
	case 'C':
		switch (str[1]) {
		/* Cc - Control */
		case 'c':
			return UNICODE_GENERAL_CATEGORY_CC;
		/* Cf - Format */
		case 'f':
			return UNICODE_GENERAL_CATEGORY_CF;
		/* Cs - Surrogate */
		case 's':
			return UNICODE_GENERAL_CATEGORY_CS;
		/* Co - Private_Use */
		case 'o':
			return UNICODE_GENERAL_CATEGORY_CO;
		/* Cn - Unassigned */
		case 'n':
			return UNICODE_GENERAL_CATEGORY_CN;
		/* C - Other: Cc | Cf | Cs | Co | Cn */
		case '\0':
			return UNICODE_GENERAL_CATEGORY_C;
		default:
			break;
		}
		break;
	default:
		break;
	}
	return UNICODE_GENERAL_CATEGORY_INVALID;
}

static const char *unicode_bidi_class_labels[] = {
	/* Left_To_Right */
	[UNICODE_BIDI_CLASS_L] = "L",
	/* Right_To_Left */
	[UNICODE_BIDI_CLASS_R] =  "R",
	/* Arabic_Letter */
	[UNICODE_BIDI_CLASS_AL] = "AL",
	/* European_Number */
	[UNICODE_BIDI_CLASS_EN] = "EN",
	/* European_Separator */
	[UNICODE_BIDI_CLASS_ES] = "ES",
	/* European_Terminator */
	[UNICODE_BIDI_CLASS_ET] = "ET",
	/* Arabic_Number */
	[UNICODE_BIDI_CLASS_AN] = "AN",
	/* Common_Separator */
	[UNICODE_BIDI_CLASS_CS] = "CS",
	/* Nonspacing_Mark */
	[UNICODE_BIDI_CLASS_NSM] = "NSM",
	/* Boundary_Neutral */
	[UNICODE_BIDI_CLASS_BN] = "BN",
	/* Paragraph_Separator */
	[UNICODE_BIDI_CLASS_B] = "B",
	/* Segment_Separator */
	[UNICODE_BIDI_CLASS_S] = "S",
	/* White_Space */
	[UNICODE_BIDI_CLASS_WS] = "WS",
	/* Other_Neutral */
	[UNICODE_BIDI_CLASS_ON] = "ON",
	/* Left_To_Right_Embedding */
	[UNICODE_BIDI_CLASS_LRE] = "LRE",
	/* Left_To_Right_Override */
	[UNICODE_BIDI_CLASS_LRO] = "LRO",
	/* Right_To_Left_Embedding */
	[UNICODE_BIDI_CLASS_RLE] = "RLE",
	/* Right_To_Left_Override */
	[UNICODE_BIDI_CLASS_RLO] = "RLO",
	/* Pop_Directional_Format */
	[UNICODE_BIDI_CLASS_PDF] = "PDF",
	/* Left_To_Right_Isolate */
	[UNICODE_BIDI_CLASS_LRI] = "LRI",
	/* Right_To_Left_Isolate */
	[UNICODE_BIDI_CLASS_RLI] = "RLI",
	/* First_Strong_Isolate */
	[UNICODE_BIDI_CLASS_FSI] = "FSI",
	/* Pop_Directional_Isolate */
	[UNICODE_BIDI_CLASS_PDI] = "PDI",
};
static_assert_array_size(unicode_bidi_class_labels, UNICODE_BIDI_CLASS_PDI + 1);

enum unicode_bidi_class unicode_bidi_class_from_string(const char *str)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(unicode_bidi_class_labels); i++) {
		if (strcmp(str, unicode_bidi_class_labels[i]) == 0)
			return (enum unicode_bidi_class)i;
	}
	return UNICODE_BIDI_CLASS_ON;
}

static const char *unicode_bidi_class_long_labels[] = {
	/* Left_To_Right */
	[UNICODE_BIDI_CLASS_L] = "Left_To_Right",
	/* Right_To_Left */
	[UNICODE_BIDI_CLASS_R] =  "Right_To_Left",
	/* Arabic_Letter */
	[UNICODE_BIDI_CLASS_AL] = "Arabic_Letter",
	/* European_Number */
	[UNICODE_BIDI_CLASS_EN] = "European_Number",
	/* European_Separator */
	[UNICODE_BIDI_CLASS_ES] = "European_Separator",
	/* European_Terminator */
	[UNICODE_BIDI_CLASS_ET] = "European_Terminator",
	/* Arabic_Number */
	[UNICODE_BIDI_CLASS_AN] = "Arabic_Number",
	/* Common_Separator */
	[UNICODE_BIDI_CLASS_CS] = "Common_Separator",
	/* Nonspacing_Mark */
	[UNICODE_BIDI_CLASS_NSM] = "Nonspacing_Mark",
	/* Boundary_Neutral */
	[UNICODE_BIDI_CLASS_BN] = "Boundary_Neutral",
	/* Paragraph_Separator */
	[UNICODE_BIDI_CLASS_B] = "Paragraph_Separator",
	/* Segment_Separator */
	[UNICODE_BIDI_CLASS_S] = "Segment_Separator",
	/* White_Space */
	[UNICODE_BIDI_CLASS_WS] = "White_Space",
	/* Other_Neutral */
	[UNICODE_BIDI_CLASS_ON] = "Other_Neutral",
	/* Left_To_Right_Embedding */
	[UNICODE_BIDI_CLASS_LRE] = "Left_To_Right_Embedding",
	/* Left_To_Right_Override */
	[UNICODE_BIDI_CLASS_LRO] = "Left_To_Right_Override",
	/* Right_To_Left_Embedding */
	[UNICODE_BIDI_CLASS_RLE] = "Right_To_Left_Embedding",
	/* Right_To_Left_Override */
	[UNICODE_BIDI_CLASS_RLO] = "Right_To_Left_Override",
	/* Pop_Directional_Format */
	[UNICODE_BIDI_CLASS_PDF] = "Pop_Directional_Format",
	/* Left_To_Right_Isolate */
	[UNICODE_BIDI_CLASS_LRI] = "Left_To_Right_Isolate",
	/* Right_To_Left_Isolate */
	[UNICODE_BIDI_CLASS_RLI] = "Right_To_Left_Isolate",
	/* First_Strong_Isolate */
	[UNICODE_BIDI_CLASS_FSI] = "First_Strong_Isolate",
	/* Pop_Directional_Isolate */
	[UNICODE_BIDI_CLASS_PDI] = "Pop_Directional_Isolate",
};
static_assert_array_size(unicode_bidi_class_long_labels,
			 UNICODE_BIDI_CLASS_PDI + 1);

enum unicode_bidi_class unicode_bidi_class_from_string_long(const char *str)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(unicode_bidi_class_long_labels); i++) {
		if (strcmp(str, unicode_bidi_class_long_labels[i]) == 0)
			return (enum unicode_bidi_class)i;
	}
	return UNICODE_BIDI_CLASS_ON;
}
