/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

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

	/* GB1 */
	if (!ubrk->gb1) {
		ubrk->gb1 = TRUE;
		bstatus = 1;
	}

	/* GB3 */
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

	/* GB4, GB5 */
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
		/* GB5 */
		if (bstatus < 0)
			bstatus = 1;
	}

	/* GB6 */
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

	/* GB7 */
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

	/* GB8 */
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

	/* GB9 */
	if (cp_data->pb_gcb_extend || cp_data->pb_b_zwj) {
		if (bstatus < 0)
			bstatus = 0;
	}

	/* GB9a */
	if (cp_data->pb_gcb_spacingmark) {
		if (bstatus < 0)
			bstatus = 0;
	}

	/* GB9b */
	if (ubrk->gb9b) {
		if (bstatus < 0)
			bstatus = 0;
		if (!cp_data->pb_gcb_prepend)
			ubrk->gb9b = FALSE;
	} else if (cp_data->pb_gcb_prepend) {
		ubrk->gb9b = TRUE;
	}

	/* GB9c */
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

	/* GB11 */
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

	/* GB12, GB13 */
	if (ubrk->gb12) {
		if (cp_data->pb_b_regional_indicator) {
			if (bstatus < 0)
				bstatus = 0;
		}
		ubrk->gb12 = FALSE;
	} else if (cp_data->pb_b_regional_indicator) {
		ubrk->gb12 = TRUE;
	}

	/* GB999 */
	if (bstatus == 0)
		return FALSE;
	return TRUE;
}
