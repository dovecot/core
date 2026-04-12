/* Copyright (c) Dovecot authors, see the included COPYING file */

#include "lib.h"

#include "sasl-common.h"

/*
 * Mechanism names
 */

bool sasl_mechanism_name_is_valid(const char *mech_name)
{
	size_t mech_name_len;
	const char *p, *pend;

	/* SASL mechanisms are named by character strings, from 1 to 20
	   characters in length, consisting of ASCII [ASCII] uppercase letters,
	   digits, hyphens, and/or underscores.  In the following Augmented
	   Backus-Naur Form (ABNF) [RFC4234] grammar, the <sasl-mech> production
	   defines the syntax of a SASL mechanism name.

	      sasl-mech    = 1*20mech-char
	      mech-char    = UPPER-ALPHA / DIGIT / HYPHEN / UNDERSCORE
	      ; mech-char is restricted to A-Z (uppercase only), 0-9, -, and _
	      ; from ASCII character set.

	      UPPER-ALPHA  = %x41-5A  ; A-Z (uppercase only)
	      DIGIT        = %x30-39  ; 0-9
	      HYPHEN       = %x2D ; hyphen (-)
	      UNDERSCORE   = %x5F ; underscore (_)
	 */

	/* sasl-mech    = 1*20mech-char */
	mech_name_len = strlen(mech_name);
	if (mech_name_len == 0 || mech_name_len > 20)
		return FALSE;

	p = mech_name;
	pend = mech_name + mech_name_len;
	while (p < pend) {
		switch (*p) {
		/* UPPER-ALPHA  = %x41-5A  ; A-Z (uppercase only) */
		case 'A': case 'B': case 'C': case 'D': case 'E':
		case 'F': case 'G': case 'H': case 'I': case 'J':
		case 'K': case 'L': case 'M': case 'N': case 'O':
		case 'P': case 'Q': case 'R': case 'S': case 'T':
		case 'U': case 'V': case 'W': case 'X':	case 'Y': case 'Z':
			break;
		/* DIGIT        = %x30-39  ; 0-9 */
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			break;
		/* HYPHEN       = %x2D ; hyphen (-) */
		case '-':
			break;
		/* UNDERSCORE   = %x5F ; underscore (_) */
		case '_':
			break;
		default:
			return FALSE;
		}
		p++;
	}
	return TRUE;
}
