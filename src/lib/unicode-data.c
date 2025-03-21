/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

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
