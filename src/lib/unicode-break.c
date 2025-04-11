/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "unicode-data.h"
#include "unicode-break.h"

/* This file implements the Unicode Text Segmemtation algorithms as specified in
   Unicode Standard Annex #29.
 */

/*
 * Grapheme Cluster Boundaries (Unicode Standard Annex #29, Section 3)
 */

void unicode_gc_break_init(struct unicode_gc_break *gcbrk)
{
	i_zero(gcbrk);
}

bool unicode_gc_break_cp(struct unicode_gc_break *gcbrk, uint32_t cp,
			 const struct unicode_code_point_data **_cp_data)
{
	if (*_cp_data == NULL)
		*_cp_data = unicode_code_point_get_data(cp);

	const struct unicode_code_point_data *cp_data = *_cp_data;
	int bstatus = -1;

	/* GB1: Break at the start and end of text.
	   sot + Any
	   Any + eot
	 */
	if (!gcbrk->gb1) {
		gcbrk->gb1 = TRUE;
		bstatus = 1;
	}

	/* GB3: Do not break between a CR and LF.
	   CR x LF
	 */
	if (gcbrk->gb3) {
		if (cp_data->pb_b_lf) {
			if (bstatus < 0)
				bstatus = 0;
		}
		if (!cp_data->pb_b_cr)
			gcbrk->gb3 = FALSE;
	} else if (cp_data->pb_b_cr) {
		gcbrk->gb3 = TRUE;
	}

	/* GB4, GB5: Break before and after controls.
	   (Control | CR | LF) +
	   + (Control | CR | LF)
	 */
	if (gcbrk->gb4) {
		/* GB4: (Control | CR | LF) / */
		if (bstatus < 0)
			bstatus = 1;
		if (!cp_data->pb_b_cr && !cp_data->pb_b_lf &&
		    !cp_data->pb_gcb_control)
			gcbrk->gb4 = FALSE;
	} else if (cp_data->pb_b_cr || cp_data->pb_b_lf ||
		   cp_data->pb_gcb_control) {
		gcbrk->gb4 = TRUE;
		/* GB5: / (Control | CR | LF) */
		if (bstatus < 0)
			bstatus = 1;
	}

	/* GB6: Do not break Hangul syllable or other conjoining sequences.
	   L x (L | V | LV | LVT)
	 */
	if (gcbrk->gb6) {
		if (cp_data->pb_gcb_v || cp_data->pb_gcb_lv ||
		    cp_data->pb_gcb_lvt) {
			if (bstatus < 0)
				bstatus = 0;
			gcbrk->gb6 = FALSE;
		} else if (cp_data->pb_gcb_l) {
			if (bstatus < 0)
				bstatus = 0;
		} else {
			gcbrk->gb6 = FALSE;
		}
	} else if (cp_data->pb_gcb_l) {
		gcbrk->gb6 = TRUE;
	}

	/* GB7: Do not break Hangul syllable or other conjoining sequences.
	   (LV | V) x (V | T)
	 */
	if (gcbrk->gb7) {
		if (cp_data->pb_gcb_t) {
			if (bstatus < 0)
				bstatus = 0;
			gcbrk->gb7 = FALSE;
		} else if (cp_data->pb_gcb_v) {
			if (bstatus < 0)
				bstatus = 0;
		} else {
			gcbrk->gb7 = FALSE;
		}
	} else if (cp_data->pb_gcb_lv || cp_data->pb_gcb_v) {
		gcbrk->gb7 = TRUE;
	}

	/* GB8: Do not break Hangul syllable or other conjoining sequences.
	   (LVT | T) x T
	 */
	if (gcbrk->gb8) {
		if (!cp_data->pb_gcb_t)
			gcbrk->gb8 = FALSE;
		else {
			if (bstatus < 0)
				bstatus = 0;
		}
	} else if (cp_data->pb_gcb_lvt || cp_data->pb_gcb_t) {
		gcbrk->gb8 = TRUE;
	}

	/* GB9: Do not break before extending characters or ZWJ.
	   x (Extend | ZWJ)
	 */
	if (cp_data->pb_gcb_extend || cp_data->pb_b_zwj) {
		if (bstatus < 0)
			bstatus = 0;
	}

	/* GB9a: Do not break before SpacingMarks.
	   x SpacingMark
	 */
	if (cp_data->pb_gcb_spacingmark) {
		if (bstatus < 0)
			bstatus = 0;
	}

	/* GB9b: Do not break after Prepend characters.
	   Prepend x
	 */
	if (gcbrk->gb9b) {
		if (bstatus < 0)
			bstatus = 0;
		if (!cp_data->pb_gcb_prepend)
			gcbrk->gb9b = FALSE;
	} else if (cp_data->pb_gcb_prepend) {
		gcbrk->gb9b = TRUE;
	}

	/* GB9c: Do not break within Indic conjuncts.
	 */
	enum {
		GB9C_STATE_NONE = 0,
		GB9C_STATE_CONSONANT,
		GB9C_STATE_LINKER,
	};
	switch (gcbrk->gb9c) {
	case GB9C_STATE_NONE:
		switch (cp_data->indic_conjunct_break) {
		case UNICODE_INDIC_CONJUNCT_BREAK_CONSONANT:
			gcbrk->gb9c = GB9C_STATE_CONSONANT;
			break;
		default:
			break;
		}
		break;
	case GB9C_STATE_CONSONANT:
		switch (cp_data->indic_conjunct_break) {
		case UNICODE_INDIC_CONJUNCT_BREAK_LINKER:
			gcbrk->gb9c = GB9C_STATE_LINKER;
		case UNICODE_INDIC_CONJUNCT_BREAK_CONSONANT:
		case UNICODE_INDIC_CONJUNCT_BREAK_EXTEND:
			break;
		default:
			gcbrk->gb9c = GB9C_STATE_NONE;
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
			gcbrk->gb9c = GB9C_STATE_CONSONANT;
			break;
		default:
			gcbrk->gb9c = GB9C_STATE_NONE;
			break;
		}
		break;
	default:
		i_unreached();
	}

	/* GB11: Do not break within emoji ZWJ sequences.
	   \p{Extended_Pictographic} Extend* ZWJ x \p{Extended_Pictographic}
	 */
	enum {
		GB11_STATE_NONE = 0,
		GB11_STATE_EP,
		GB11_STATE_ZWJ,
	};
	switch (gcbrk->gb11) {
	case GB11_STATE_NONE:
		if (cp_data->pb_e_extended_pictographic)
			gcbrk->gb11 = GB11_STATE_EP;
		break;
	case GB11_STATE_EP:
		if (cp_data->pb_e_extended_pictographic)
			break;
		if (cp_data->pb_gcb_extend)
			break;
		if (cp_data->pb_b_zwj) {
			gcbrk->gb11 = GB11_STATE_ZWJ;
			break;
		}
		gcbrk->gb11 = GB11_STATE_NONE;
		break;
	case GB11_STATE_ZWJ:
		if (cp_data->pb_e_extended_pictographic) {
			if (bstatus < 0)
				bstatus = 0;
			gcbrk->gb11 = GB11_STATE_EP;
			break;
		}
		gcbrk->gb11 = GB11_STATE_NONE;
		break;
	default:
		i_unreached();
	}

	/* GB12, GB13: Do not break within emoji flag sequences. That is, do not
		       break between regional indicator (RI) symbols if there is
		       an odd number of RI characters before the break point.
	   sot   (RI RI)* RI x RI
	   [^RI] (RI RI)* RI x RI
	 */
	if (gcbrk->gb12) {
		if (cp_data->pb_b_regional_indicator) {
			if (bstatus < 0)
				bstatus = 0;
		}
		gcbrk->gb12 = FALSE;
	} else if (cp_data->pb_b_regional_indicator) {
		gcbrk->gb12 = TRUE;
	}

	/* GB999: Otherwise, break everywhere.
	   (Any + Any)
	 */
	if (bstatus == 0)
		return FALSE;
	return TRUE;
}
