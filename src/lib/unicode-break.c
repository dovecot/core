/* Copyright (c) 2024 Dovecot authors, see the included COPYING file */

/* This file implements the Unicode Grapheme Cluster Breaking algorithm as
   specified in Unicode Standard Annex #29.

   The code in this file contains some deviations from the Unicode
   specification for grapheme cluster breaking. It is recommended that this
   code be verified against the latest Unicode standard and be rewritten to
   correctly implement the specification.
 */

#include "lib.h"
#include "unicode-data.h"
#include "unicode-break.h"

/*
 * Grapheme cluster break
 */

void unicode_gc_break_init(struct unicode_gc_break *ubrk)
{
	i_zero(ubrk);
}

bool unicode_gc_break_cp(struct unicode_gc_break *ubrk, uint32_t cp,
			 const struct unicode_code_point_data **_cp_data)
{
	if (*_cp_data == NULL)
		*_cp_data = unicode_code_point_get_data(cp);

	const struct unicode_code_point_data *cp_data = *_cp_data;
	int bstatus = -1;

	/* GB1: Break at the start and end of text.
	   (sot ÷ Any) and (Any ÷ eot)
	 */
	if (!ubrk->gb1) {
		ubrk->gb1 = TRUE;
		bstatus = 1;
	}

	/* GB3: Do not break between a CR and LF.
	   (CR × LF)
	 */
	if (ubrk->gb3) {
		if (cp_data->pb_b_lf) {
			if (bstatus < 0)
				bstatus = 0;
		}
		if (!cp_data->pb_b_cr)
			ubrk->gb3 = FALSE;
	} else if (cp_data->pb_b_cr) {
		ubrk->gb3 = TRUE;
	}

	/* GB4: Break before and after controls.
	   (Control | CR | LF ÷)
	 */
	if (ubrk->gb4) {
		/* GB4 */
		if (bstatus < 0)
			bstatus = 1;
		if (!cp_data->pb_b_cr && !cp_data->pb_b_lf &&
		    !cp_data->pb_gcb_control)
			ubrk->gb4 = FALSE;
	} else if (cp_data->pb_b_cr || cp_data->pb_b_lf ||
		   cp_data->pb_gcb_control) {
		ubrk->gb4 = TRUE;
		/* GB5: (÷ Control | CR | LF) */
		if (bstatus < 0)
			bstatus = 1;
	}

	/* GB6: Do not break Hangul syllable sequences.
	   (L × (L | V | LV | LVT))
	 */
	if (ubrk->gb6) {
		if (cp_data->pb_gcb_v || cp_data->pb_gcb_lv ||
		    cp_data->pb_gcb_lvt) {
			if (bstatus < 0)
				bstatus = 0;
			ubrk->gb6 = FALSE;
		} else if (cp_data->pb_gcb_l) {
			if (bstatus < 0)
				bstatus = 0;
		} else {
			ubrk->gb6 = FALSE;
		}
	} else if (cp_data->pb_gcb_l) {
		ubrk->gb6 = TRUE;
	}

	/* GB7: Do not break Hangul syllable sequences.
	   ((LV | V) × (V | T))
	 */
	if (ubrk->gb7) {
		if (cp_data->pb_gcb_t) {
			if (bstatus < 0)
				bstatus = 0;
			ubrk->gb7 = FALSE;
		} else if (cp_data->pb_gcb_v) {
			if (bstatus < 0)
				bstatus = 0;
		} else {
			ubrk->gb7 = FALSE;
		}
	} else if (cp_data->pb_gcb_lv || cp_data->pb_gcb_v) {
		ubrk->gb7 = TRUE;
	}

	/* GB8: Do not break Hangul syllable sequences.
	   ((LVT | T) × T)
	 */
	if (ubrk->gb8) {
		if (!cp_data->pb_gcb_t)
			ubrk->gb8 = FALSE;
		else {
			if (bstatus < 0)
				bstatus = 0;
		}
	} else if (cp_data->pb_gcb_lvt || cp_data->pb_gcb_t) {
		ubrk->gb8 = TRUE;
	}

	/* GB9: Do not break before extending characters.
	   (× Extend)
	   This is not fully compliant, as it does not handle ZWJ correctly.
	 */
	if (cp_data->pb_gcb_extend || cp_data->pb_b_zwj) {
		if (bstatus < 0)
			bstatus = 0;
	}

	/* GB9a: Do not break after a ZWJ.
	   (ZWJ ×)
	   This is not implemented. It is handled by GB9 incorrectly.
	 */
	if (cp_data->pb_gcb_spacingmark) {
		if (bstatus < 0)
			bstatus = 0;
	}

	/* GB9b: Do not break after prepend characters.
	   (× Prepend)
	 */
	if (ubrk->gb9b) {
		if (bstatus < 0)
			bstatus = 0;
		if (!cp_data->pb_gcb_prepend)
			ubrk->gb9b = FALSE;
	} else if (cp_data->pb_gcb_prepend) {
		ubrk->gb9b = TRUE;
	}

	/* GB9c: Do not break within Indic conjuncts.
	 */
	enum {
		GB9C_STATE_NONE = 0,
		GB9C_STATE_CONSONANT,
		GB9C_STATE_LINKER,
	};
	switch (ubrk->gb9c) {
	case GB9C_STATE_NONE:
		switch (cp_data->indic_conjunct_break) {
		case UNICODE_INDIC_CONJUNCT_BREAK_CONSONANT:
			ubrk->gb9c = GB9C_STATE_CONSONANT;
			break;
		default:
			break;
		}
		break;
	case GB9C_STATE_CONSONANT:
		switch (cp_data->indic_conjunct_break) {
		case UNICODE_INDIC_CONJUNCT_BREAK_LINKER:
			ubrk->gb9c = GB9C_STATE_LINKER;
		case UNICODE_INDIC_CONJUNCT_BREAK_CONSONANT:
		case UNICODE_INDIC_CONJUNCT_BREAK_EXTEND:
			break;
		default:
			ubrk->gb9c = GB9C_STATE_NONE;
			break;
		}
		break;
	case GB9C_STATE_LINKER:
		switch (cp_data->indic_conjunct_break) {
		case UNICODE_INDIC_CONJUNCT_BREAK_LINKER:
		case UNICODE_INDIC_CONJUNCT_BREAK_EXTEND:
			break;
		case UNICODE_INDIC_CONJUNCT_BREAK_CONSONANT:
			if (bstatus < 0)
				bstatus = 0;
			ubrk->gb9c = GB9C_STATE_CONSONANT;
			break;
		default:
			ubrk->gb9c = GB9C_STATE_NONE;
			break;
		}
		break;
	default:
		i_unreached();
	}

	/* GB11: Do not break within emoji ZWJ sequences.
	   (Extended_Pictographic Extend* ZWJ × Extended_Pictographic)
	   This state machine is buggy and does not correctly handle all cases.
	   It is missing the Extend* part of the rule.
	 */
	enum {
		GB11_STATE_NONE = 0,
		GB11_STATE_EP,
		GB11_STATE_ZWJ,
	};
	switch (ubrk->gb11) {
	case GB11_STATE_NONE:
		if (cp_data->pb_e_extended_pictographic)
			ubrk->gb11 = GB11_STATE_EP;
		break;
	case GB11_STATE_EP:
		if (cp_data->pb_e_extended_pictographic)
			break;
		if (cp_data->pb_gcb_extend)
			break;
		if (cp_data->pb_b_zwj) {
			ubrk->gb11 = GB11_STATE_ZWJ;
			break;
		}
		ubrk->gb11 = GB11_STATE_NONE;
		break;
	case GB11_STATE_ZWJ:
		if (cp_data->pb_e_extended_pictographic) {
			if (bstatus < 0)
				bstatus = 0;
			ubrk->gb11 = GB11_STATE_EP;
			break;
		}
		ubrk->gb11 = GB11_STATE_NONE;
		break;
	default:
		i_unreached();
	}

	/* GB12/13: Do not break within emoji flag sequences.
	   (Regional_Indicator × Regional_Indicator)
	 */
	if (ubrk->gb12) {
		if (cp_data->pb_b_regional_indicator) {
			if (bstatus < 0)
				bstatus = 0;
		}
		ubrk->gb12 = FALSE;
	} else if (cp_data->pb_b_regional_indicator) {
		ubrk->gb12 = TRUE;
	}

	/* GB999: Otherwise, break everywhere.
	   (Any ÷ Any)
	 */
	if (bstatus == 0)
		return FALSE;
	return TRUE;
}
