/* Copyright (c) Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "buffer.h"
#include "unichar.h"
#include "unicode-data.h"
#include "unicode-transform.h"
#include "idna.h"
#include "idna-punycode.h"

/*
 * Bidi Checking
 */

void idna_bidi_checker_init(struct idna_bidi_checker *ibc_r,
			    struct idna_bidi_check_context *ctx)
{
	i_zero(ibc_r);
	ibc_r->ctx = ctx;
}

void idna_bidi_checker_reset(struct idna_bidi_checker *ibc)
{
	struct idna_bidi_check_context *ctx = ibc->ctx;

	idna_bidi_checker_init(ibc, ctx);
}

void idna_bidi_checker_input(struct idna_bidi_checker *ibc,  uint32_t cp,
			     const struct unicode_code_point_data **cp_data)
{
	struct idna_bidi_check_context *ctx = ibc->ctx;

	if (*cp_data == NULL)
		*cp_data = unicode_code_point_get_data(cp);

	/* RFC 5893, Section 2: The Bidi Rule

	   The following rule, consisting of six conditions, applies to labels
	   in Bidi domain names. The requirements that this rule satisfies are
	   described in Section 3. All of the conditions must be satisfied for
	   the rule to be satisfied.

	   1.  The first character must be a character with Bidi property L, R,
	       or AL.  If it has the R or AL property, it is an RTL label; if it
	       has the L property, it is an LTR label.

	   2.  In an RTL label, only characters with the Bidi properties R, AL,
	       AN, EN, ES, CS, ET, ON, BN, or NSM are allowed.

	   3.  In an RTL label, the end of the label must be a character with
	       Bidi property R, AL, EN, or AN, followed by zero or more
	       characters with Bidi property NSM.

	   4.  In an RTL label, if an EN is present, no AN may be present, and
	       vice versa.

	   5.  In an LTR label, only characters with the Bidi properties L, EN,
	       ES, CS, ET, ON, BN, or NSM are allowed.

	   6.  In an LTR label, the end of the label must be a character with
	       Bidi property L or EN, followed by zero or more characters with
	       Bidi property NSM.
	 */

	switch (ibc->state) {
	case IDNA_BIDI_CHECK_STATE_START:
		switch ((*cp_data)->bidi_class) {
		case UNICODE_BIDI_CLASS_R:
		case UNICODE_BIDI_CLASS_AL:
			ctx->rtl_label = TRUE;
			ibc->label_can_end = TRUE;
			ibc->state = IDNA_BIDI_CHECK_STATE_RTL;
			break;
		case UNICODE_BIDI_CLASS_AN:
			ctx->rtl_label = TRUE;
			ctx->valid = FALSE;
			break;
		case UNICODE_BIDI_CLASS_L:
			ibc->label_can_end = TRUE;
			ibc->state = IDNA_BIDI_CHECK_STATE_LTR;
			break;
		default:
			ctx->valid = FALSE;
			break;
		}
		break;
	case IDNA_BIDI_CHECK_STATE_RTL:
		switch ((*cp_data)->bidi_class) {
		case UNICODE_BIDI_CLASS_R:
		case UNICODE_BIDI_CLASS_AL:
			ibc->label_can_end = TRUE;
			break;
		case UNICODE_BIDI_CLASS_ES:
		case UNICODE_BIDI_CLASS_CS:
		case UNICODE_BIDI_CLASS_ET:
		case UNICODE_BIDI_CLASS_ON:
		case UNICODE_BIDI_CLASS_BN:
			ibc->label_can_end = FALSE;
			break;
		case UNICODE_BIDI_CLASS_NSM:
			break;
		case UNICODE_BIDI_CLASS_EN:
			if (ibc->an_present) {
				ctx->valid = FALSE;
				break;
			}
			ibc->en_present = TRUE;
			ibc->label_can_end = TRUE;;
			break;
		case UNICODE_BIDI_CLASS_AN:
			if (ibc->en_present) {
				ctx->valid = FALSE;
				break;
			}
			ibc->an_present = TRUE;
			ibc->label_can_end = TRUE;;
			break;
		default:
			ctx->valid = FALSE;
			break;
		}
		break;
	case IDNA_BIDI_CHECK_STATE_LTR:
		switch ((*cp_data)->bidi_class) {
		case UNICODE_BIDI_CLASS_L:
		case UNICODE_BIDI_CLASS_EN:
			ibc->label_can_end = TRUE;
			break;
		case UNICODE_BIDI_CLASS_ES:
		case UNICODE_BIDI_CLASS_CS:
		case UNICODE_BIDI_CLASS_ET:
		case UNICODE_BIDI_CLASS_ON:
		case UNICODE_BIDI_CLASS_BN:
			ibc->label_can_end = FALSE;
			break;
		case UNICODE_BIDI_CLASS_NSM:
			break;
		case UNICODE_BIDI_CLASS_R:
		case UNICODE_BIDI_CLASS_AL:
		case UNICODE_BIDI_CLASS_AN:
			ctx->rtl_label = TRUE;
			ctx->valid = FALSE;
			break;
		default:
			ctx->valid = FALSE;
			break;
		}
		break;
	default:
		i_unreached();
	}
}

int idna_bidi_checker_finish(struct idna_bidi_checker *ibc)
{
	struct idna_bidi_check_context *ctx = ibc->ctx;

	switch (ibc->state) {
	case IDNA_BIDI_CHECK_STATE_START:
		break;
	case IDNA_BIDI_CHECK_STATE_RTL:
		if (!ibc->label_can_end)
			ctx->valid = FALSE;
		break;
	case IDNA_BIDI_CHECK_STATE_LTR:
		if (!ibc->label_can_end)
			ctx->valid = FALSE;
		break;
	}

	if (!ctx->valid && ctx->rtl_label)
		return -1;
	return 0;
}

/*
 * IDNA Processing
 */

/* IDNA Processing Step 1: Map */

struct idna_map {
	struct unicode_transform transform;

	uint32_t cp;
	const struct unicode_code_point_data *cp_data;
	unsigned int cp_map_pos;

	bool cp_buffered:1;
};

static ssize_t
idna_map_input(struct unicode_transform *trans,
	       const struct unicode_transform_buffer *buf,
	       const char **error_r);
static int
idna_map_flush(struct unicode_transform *trans, bool finished,
	       const char **error_r);

static const struct unicode_transform_def idna_map_def = {
	.input = idna_map_input,
	.flush = idna_map_flush,
};

static void idna_map_init(struct idna_map *map_r)
{
	i_zero(map_r);
	unicode_transform_init(&map_r->transform, &idna_map_def);
}

static ssize_t
idna_map_input_cp(struct idna_map *map, uint32_t cp,
		  const struct unicode_code_point_data *cp_data,
		  const char **error_r)
{
	bool was_buffered = map->cp_buffered;
	ssize_t sret;

	if (cp_data == NULL)
		cp_data = unicode_code_point_get_data(cp);

	/* 1. Map:

	   For each code point in the domain_name string, look up the Status
	   value in the IDNA Mapping Table, and take the following actions:

	     disallowed: Leave the code point unchanged in the string.
	                 Note: The Convert/Validate step below checks for
	                       disallowed characters, after mapping and
	                       normalization.
             ignored:    Remove the code point from the string. This is
	                 equivalent to mapping the code point to an empty
	                 string.
             mapped:     If Transitional_Processing (deprecated) and the code
	                 point is U+1E9E capital sharp s (ẞ), then replace the
	                 code point in the string by “ss”. Otherwise: Replace
	                 the code point in the string by the value for the
	                 mapping the IDNA Mapping Table.
             deviation:  If Transitional_Processing (deprecated), replace the
	                 code point in the string by the value for the mapping
	                 in the IDNA Mapping Table. Otherwise, leave the code
	                 point unchanged in the string.
	     valid:      Leave the code point unchanged in the string.
	 */

	switch (cp_data->idna_status) {
	case UNICODE_IDNA_STATUS_DISALLOWED:
	case UNICODE_IDNA_STATUS_VALID:
	case UNICODE_IDNA_STATUS_DEVIATION:
		i_assert(map->cp_map_pos == 0);
		sret = uniform_transform_forward(&map->transform,
						 &cp, &cp_data, 1, error_r);
		if (sret < 0) {
			i_assert(*error_r != NULL);
			return -1;
		}
		if (sret == 0) {
			map->cp_buffered = TRUE;
			map->cp = cp;
			map->cp_data = cp_data;
			return (was_buffered ? 0 : 1);
		}
		break;
	case UNICODE_IDNA_STATUS_IGNORED:
		break;
	case UNICODE_IDNA_STATUS_MAPPED:
		i_assert(cp_data->idna_mapping_length > 0);

		const uint32_t *map_cps =
			&unicode_idna_mappings[cp_data->idna_mapping_offset];
		size_t map_cps_len = cp_data->idna_mapping_length;

		map_cps += map->cp_map_pos;
		map_cps_len -= map->cp_map_pos;
		sret = uniform_transform_forward(&map->transform,
						 map_cps, NULL, map_cps_len,
						 error_r);
		if (sret < 0) {
			i_assert(*error_r != NULL);
			return -1;
		}
		if ((size_t)sret < map_cps_len) {
			map->cp_buffered = TRUE;
			map->cp = cp;
			map->cp_data = cp_data;
			map->cp_map_pos += sret;
			return (was_buffered ? 0 : 1);
		}
		break;
	}
	map->cp_buffered = FALSE;
	map->cp_data = NULL;
	map->cp_map_pos = 0;
	return 1;
}

static ssize_t
idna_map_input(struct unicode_transform *trans,
	       const struct unicode_transform_buffer *buf,
	       const char **error_r)
{
	struct idna_map *map = container_of(trans, struct idna_map, transform);
	int ret;

	ret = idna_map_flush(trans, TRUE, error_r);
	if (ret < 0) {
		i_assert(*error_r != NULL);
		return -1;
	}
	if (map->cp_buffered)
		return 0;

	size_t n;
	for (n = 0; n < buf->cp_count; n++) {
		if (map->cp_buffered)
			break;
		ret = idna_map_input_cp(map, buf->cp[n],
					(buf->cp_data != NULL ?
					 buf->cp_data[n] : NULL), error_r);
		if (ret < 0) {
			i_assert(*error_r != NULL);
			return -1;
		}
		if (ret == 0)
			break;
	}
	return n;
}

static int
idna_map_flush(struct unicode_transform *trans, bool finished ATTR_UNUSED,
	       const char **error_r)
{
	struct idna_map *map = container_of(trans, struct idna_map, transform);
	int ret;

	if (!map->cp_buffered)
		return 1;

	ret = idna_map_input_cp(map, map->cp, map->cp_data, error_r);
	i_assert(ret >= 0 || *error_r != NULL);
	return ret;
}

/* IDNA Processing Step 3: Validate */

enum idna_validate_state {
	IDNA_VALIDATE_STATE_START = 0,
	IDNA_VALIDATE_STATE_X,
	IDNA_VALIDATE_STATE_P2,
	IDNA_VALIDATE_STATE_XN,
	IDNA_VALIDATE_STATE_P3,
	IDNA_VALIDATE_STATE_XN_,
	IDNA_VALIDATE_STATE_DASH4,
	IDNA_VALIDATE_STATE_P4,
	IDNA_VALIDATE_STATE_ALABEL,
	IDNA_VALIDATE_STATE_ULABEL,
};

struct idna_validate {
	struct unicode_transform transform;
	enum idna_process_flags flags;

	enum idna_validate_state state;
	struct idna_bidi_checker bidicheck;

	uint32_t cp, last_cp;
	const struct unicode_code_point_data *cp_data;

	struct unicode_nf_checker nfccheck;

	bool cp_buffered:1;
	bool decoded_a_label:1;
	bool seen_non_ascii:1;
};

static ssize_t
idna_validate_input(struct unicode_transform *trans,
		    const struct unicode_transform_buffer *buf,
		    const char **error_r);
static int
idna_validate_flush(struct unicode_transform *trans,
		    bool finished ATTR_UNUSED, const char **error_r);

static const struct unicode_transform_def idna_validate_def = {
	.input = idna_validate_input,
	.flush = idna_validate_flush,
};

static void
idna_validate_init(struct idna_validate *valdt_r,
		   struct idna_bidi_check_context *bidictx,
		   enum idna_process_flags flags,
		   bool decoded_a_label)
{
	i_zero(valdt_r);
	unicode_transform_init(&valdt_r->transform, &idna_validate_def);
	valdt_r->flags = flags;
	valdt_r->decoded_a_label = decoded_a_label;
	if (decoded_a_label)
		unicode_nf_checker_init(&valdt_r->nfccheck, UNICODE_NFC);
	idna_bidi_checker_init(&valdt_r->bidicheck, bidictx);
}

static int
idna_validate_label_end(struct idna_validate *valdt, const char **error_r)
{
	int ret;

	/* 1. The label must be in Unicode Normalization Form NFC.
	 */
	if (valdt->decoded_a_label) {
		ret = unicode_nf_checker_finish(&valdt->nfccheck);
		i_assert(ret >= 0);
		if (ret == 0) {
			*error_r = "A-label is not NFC normalized";
			return -1;
		}
	}

	/* 3. If CheckHyphens, the label must neither begin nor end with
	      a U+002D HYPHEN-MINUS character.
	 */
	if (HAS_ALL_BITS(valdt->flags, IDNA_PROCESS_FLAG_CHECK_HYPHENS) &&
	    valdt->state != IDNA_VALIDATE_STATE_ALABEL &&
	    valdt->last_cp == '-') {
		*error_r = "Label ends with '-'";
		return -1;
	}

	/* 9. If CheckBidi, and if the domain name is a Bidi domain name, then
	   the label must satisfy all six of the numbered conditions in
	   RFC 5893, Section 2.
	 */
	if (HAS_NO_BITS(valdt->flags, IDNA_PROCESS_FLAG_IGNORE_BIDI) &&
	    valdt->state != IDNA_VALIDATE_STATE_ALABEL &&
	    idna_bidi_checker_finish(&valdt->bidicheck) < 0) {
		*error_r = "Invalid label in Bidi domain name";
		return -1;
	}
	idna_bidi_checker_reset(&valdt->bidicheck);

	return 0;
}

static int
idna_validate_cp(struct idna_validate *valdt, uint32_t cp,
		 const struct unicode_code_point_data **cp_data,
		 const char **error_r)
{
	int ret;

	switch (valdt->state) {
	case IDNA_VALIDATE_STATE_START:
		/* We explicitly don't allow empty labels */
		if (cp == '.') {
			*error_r = "Empty label";
			return -1;
		}
		/* Check for 'xn--' for A-label */
		if (cp == 'x' && !valdt->decoded_a_label) {
			valdt->state = IDNA_VALIDATE_STATE_X;
			break;
		}
		/* 3. If CheckHyphens, the label must neither begin nor end with
		      a U+002D HYPHEN-MINUS character. */
		if (HAS_ALL_BITS(valdt->flags,
				 IDNA_PROCESS_FLAG_CHECK_HYPHENS) &&
		    cp == '-') {
			*error_r = "Label begins with '-'";
			return -1;
		}
		/* 6. The label must not begin with a combining mark, that is:
		      General_Category=Mark.
		 */
		if (*cp_data == NULL)
			*cp_data = unicode_code_point_get_data(cp);
		if (unicode_code_point_data_general_category_in(
			*cp_data, UNICODE_GENERAL_CATEGORY_M)) {
			*error_r = t_strdup_printf(
				"Label begins with combining mark U+%04X", cp);
			return -1;
		}
		valdt->state = IDNA_VALIDATE_STATE_P2;
		break;
	case IDNA_VALIDATE_STATE_X:
		/* Check for 'xn--' for A-label */
		i_assert(!valdt->decoded_a_label);
		if (cp == 'n') {
			valdt->state = IDNA_VALIDATE_STATE_XN;
			break;
		}
		/* Fall through */
	case IDNA_VALIDATE_STATE_P2:
		valdt->state = IDNA_VALIDATE_STATE_P3;
		break;
	case IDNA_VALIDATE_STATE_XN:
		/* Check for 'xn--' for A-label */
		i_assert(!valdt->decoded_a_label);
		if (cp == '-') {
			valdt->state = IDNA_VALIDATE_STATE_XN_;
			break;
		}
		valdt->state = IDNA_VALIDATE_STATE_P4;
		break;
	case IDNA_VALIDATE_STATE_P3:
		/* 2. If CheckHyphens, the label must not contain a U+002D
		      HYPHEN-MINUS character in both the third and fourth
		      positions. */
		if (HAS_ALL_BITS(valdt->flags,
				 IDNA_PROCESS_FLAG_CHECK_HYPHENS) &&
		    cp == '-') {
			valdt->state = IDNA_VALIDATE_STATE_DASH4;
			break;
		}
		valdt->state = IDNA_VALIDATE_STATE_P4;
		break;
	case IDNA_VALIDATE_STATE_XN_:
		/* Check for 'xn--' for A-label */
		i_assert(!valdt->decoded_a_label);
		if (cp == '-') {
			idna_bidi_checker_reset(&valdt->bidicheck);
			valdt->state = IDNA_VALIDATE_STATE_ALABEL;
			return 0;
		}
		valdt->state = IDNA_VALIDATE_STATE_ULABEL;
		return 0;
	case IDNA_VALIDATE_STATE_DASH4:
		/* 2. If CheckHyphens, the label must not contain a U+002D
		      HYPHEN-MINUS character in both the third and fourth
		      positions. */
		if (HAS_ALL_BITS(valdt->flags,
				 IDNA_PROCESS_FLAG_CHECK_HYPHENS) &&
		    cp == '-') {
			*error_r = "Label has '-' at both the third and fourth positions";
			return -1;
		}
		/* Fall through */
	case IDNA_VALIDATE_STATE_P4:
		valdt->state = IDNA_VALIDATE_STATE_ULABEL;
		break;
	case IDNA_VALIDATE_STATE_ALABEL:
		if (cp > 0x7f) {
			*error_r = "Invalid 8bit code point in A-label";
			return -1;
		}
		if (cp == '.')
			valdt->state = IDNA_VALIDATE_STATE_START;
		return 0;
	case IDNA_VALIDATE_STATE_ULABEL:
		break;
	default:
		i_unreached();
	}

	if (cp == '.') {
		/* 5. The label must not contain a U+002E ( . ) FULL STOP. */
		if (valdt->decoded_a_label) {
			*error_r = "A-label contains '.'";
			return -1;
		}
		if (idna_validate_label_end(valdt, error_r) < 0)
			return -1;
		valdt->state = IDNA_VALIDATE_STATE_START;
		return 0;
	}

	/* 7. Each code point in the label must only have certain Status values
	      according to the IDNA Mapping Table:

	      1. For Transitional Processing (deprecated), each value must be
	         valid.
	      2. For Nontransitional Processing, each value must be either valid
	         or deviation.
	      3. In addition, if UseSTD3ASCIIRules=true and the code point is an
	         ASCII code point (U+0000..U+007F), then it must be a lowercase
		 letter (a-z), a digit (0-9), or a hyphen-minus (U+002D).
		 (Note: This excludes uppercase ASCII A-Z which are mapped in
	          UTS #46 and disallowed in IDNA2008.)
	 */

	/* Disallow control characters no matter what. */
	if (cp < 0x020 || cp == 0x7f) {
		*error_r = t_strdup_printf(
			"Label contains ASCII control code point U+%04X", cp);
		return -1;
	}

	if (HAS_ALL_BITS(valdt->flags,
			 IDNA_PROCESS_FLAG_IGNORE_STD3_ASCII_RULES) ||
	    cp >= 0x80) {
		if (cp >= 0x80)
			valdt->seen_non_ascii = TRUE;

		if (*cp_data == NULL)
			*cp_data = unicode_code_point_get_data(cp);

		switch ((*cp_data)->idna_status) {
		case UNICODE_IDNA_STATUS_VALID:
		case UNICODE_IDNA_STATUS_DEVIATION:
			break;
		default:
			*error_r = t_strdup_printf(
				"Label contains invalid code point U+%04X", cp);
			return -1;
		}
	} else if ((cp >= 'a' && cp <= 'z') || (cp >= '0' && cp <= '9') ||
		   cp == '-' || cp == '_') {
		if (*cp_data == NULL)
			*cp_data = unicode_code_point_get_data(cp);
	} else {
		*error_r = t_strdup_printf(
			"Label contains invalid ASCII code point U+%04X", cp);
		return -1;
	}

	/* 1. The label must be in Unicode Normalization Form NFC.
	 */
	if (valdt->decoded_a_label) {
		ret = unicode_nf_checker_input(&valdt->nfccheck, cp, cp_data);
		i_assert(ret >= 0);
		if (ret == 0) {
			*error_r = "A-label is not NFC normalized";
			return -1;
		}
	}

	/* 8. If CheckJoiners, the label must satisify the ContextJ rules from
	   Appendix A, in RFC 5892.
	 */

	/* - NOT IMPLEMENTED - */

	/* 9. If CheckBidi, and if the domain name is a Bidi domain name, then
	   the label must satisfy all six of the numbered conditions in
	   RFC 5893, Section 2.
	 */
	if (HAS_NO_BITS(valdt->flags, IDNA_PROCESS_FLAG_IGNORE_BIDI))
		idna_bidi_checker_input(&valdt->bidicheck, cp, cp_data);

	return 0;
}

static ssize_t
idna_validate_input_cp(struct idna_validate *valdt, uint32_t cp,
		       const struct unicode_code_point_data *cp_data,
		       const char **error_r)
{
	bool was_buffered = valdt->cp_buffered;
	ssize_t sret;

	if (!was_buffered &&
	    idna_validate_cp(valdt, cp, &cp_data, error_r) < 0)
		return -1;
	valdt->last_cp = cp;

	if (valdt->transform.next == NULL)
		return 1;

	sret = uniform_transform_forward(&valdt->transform,
					 &cp, &cp_data, 1, error_r);
	if (sret < 0) {
		i_assert(*error_r != NULL);
		return -1;
	}
	if (sret == 0) {
		valdt->cp_buffered = TRUE;
		valdt->cp = cp;
		valdt->cp_data = cp_data;
		return (was_buffered ? 0 : 1);
	}

	valdt->cp_buffered = FALSE;
	valdt->cp_data = NULL;
	return 1;
}

static ssize_t
idna_validate_input(struct unicode_transform *trans,
		    const struct unicode_transform_buffer *buf,
		    const char **error_r)
{
	struct idna_validate *valdt =
		container_of(trans, struct idna_validate, transform);
	int ret;

	if (valdt->cp_buffered) {
		ret = idna_validate_input_cp(valdt, valdt->cp, valdt->cp_data,
					     error_r);
		i_assert(ret >= 0 || *error_r != NULL);
		if (valdt->cp_buffered)
			return 0;
	}

	size_t n;
	for (n = 0; n < buf->cp_count; n++) {
		if (valdt->cp_buffered)
			break;
		ret = idna_validate_input_cp(valdt, buf->cp[n],
					     (buf->cp_data != NULL ?
					      buf->cp_data[n] : NULL), error_r);
		if (ret < 0) {
			i_assert(*error_r != NULL);
			return -1;
		}
		if (ret == 0)
			break;
	}
	return n;
}

static int
idna_validate_flush(struct unicode_transform *trans,
		    bool finished, const char **error_r)
{
	struct idna_validate *valdt =
		container_of(trans, struct idna_validate, transform);
	int ret;

	if (finished) {
		if (idna_validate_label_end(valdt, error_r) < 0)
			return -1;
		if (valdt->decoded_a_label && !valdt->seen_non_ascii) {
			*error_r = "A-label contains only ASCII code points";
			return -1;
		}
	}

	if (!valdt->cp_buffered)
		return 1;

	ret = idna_validate_input_cp(valdt, valdt->cp, valdt->cp_data, error_r);
	i_assert(ret >= 0 || *error_r != NULL);
	return ret;
}

/* Domain name processing */

#define LABEL_BUF_SIZE (IDNA_DNS_MAX_NAME_LENGTH + 1)

struct idna_process_sink {
	struct unicode_transform transform;
	struct idna_bidi_check_context *bidictx;
	enum idna_process_flags flags;

	uint32_t label_buf[LABEL_BUF_SIZE];
	size_t label_buf_size;

	buffer_t *unicode_buffer;
	buffer_t *ascii_buffer;
	size_t ascii_size;
};

static int
idna_check_a_label(struct idna_process_sink *sink,
		   const uint32_t *label, size_t label_len,
		   const char **error_r)
{
	struct idna_validate valdt;

	idna_validate_init(&valdt, sink->bidictx, sink->flags, TRUE);

	struct unicode_transform *trans = &valdt.transform;
	size_t pos;
	ssize_t sret;

	pos = 0;
	while (pos < label_len) {
		sret = unicode_transform_input(trans, &label[pos],
					       label_len - pos, error_r);
		if (sret < 0)
			return -1;
		i_assert(pos <= (label_len - sret));
		pos += sret;
	}

	int ret = unicode_transform_flush(trans, error_r);
	i_assert(ret != 0);
	if (ret < 0)
		return -1;
	return 0;
}

static int
idna_process_label(struct idna_process_sink *sink, bool last,
		   const char **error_r)
{
	uint32_t punycode_buf[LABEL_BUF_SIZE];

	if (sink->label_buf_size < 4 ||
	    sink->label_buf[0] != 'x' || sink->label_buf[1] != 'n' ||
	    sink->label_buf[2] != '-' || sink->label_buf[3] != '-') {
		if (sink->label_buf_size == 0) {
			*error_r = "Empty label";
			return -1;
		}

		ssize_t sret;
		size_t n;
		bool is_8bit = FALSE;

		for (n = 0; n < sink->label_buf_size; n++) {
			if (sink->label_buf[n] >= 0x80) {
				is_8bit = TRUE;
				break;
			}
		}
		if (sink->unicode_buffer != NULL) {
			uni_ucs4_to_utf8(sink->label_buf, sink->label_buf_size,
					 sink->unicode_buffer);
		}
		if (is_8bit) {
			sret = idna_punycode_encode(
				sink->label_buf, sink->label_buf_size,
				punycode_buf + 4,
				IDNA_DNS_MAX_LABEL_LENGTH - 4);
			if (sret < 0) {
				*error_r = "U-label too long";
				return -1;
			}
			if (((sink->ascii_buffer != NULL ?
			      sink->ascii_buffer->used : sink->ascii_size) +
			     sret + 4) > IDNA_DNS_MAX_NAME_LENGTH) {
				*error_r = "Domain name too long";
				return -1;
			}
			if (sink->ascii_buffer == NULL)
				sink->ascii_size += sret + 4;
			else {
				punycode_buf[0] = 'x';
				punycode_buf[1] = 'n';
				punycode_buf[2] = '-';
				punycode_buf[3] = '-';
				uni_ucs4_to_utf8(punycode_buf, sret + 4,
						 sink->ascii_buffer);
			}
		} else {
			if (sink->label_buf_size > IDNA_DNS_MAX_LABEL_LENGTH) {
				*error_r = "Label too long";
				return -1;
			}
			if (((sink->ascii_buffer != NULL ?
			      sink->ascii_buffer->used : sink->ascii_size) +
			     sink->label_buf_size) >
			    IDNA_DNS_MAX_NAME_LENGTH) {
				*error_r = "Domain name too long";
				return -1;
			}
			if (sink->ascii_buffer == NULL)
				sink->ascii_size += sink->label_buf_size;
			else {
				uni_ucs4_to_utf8(sink->label_buf,
						 sink->label_buf_size,
						 sink->ascii_buffer);
			}
		}
	} else if (sink->label_buf_size == 4) {
		*error_r = "Empty A-label";
		return -1;
	} else {
		ssize_t sret;

		if (sink->label_buf_size > IDNA_DNS_MAX_LABEL_LENGTH) {
			*error_r = "A-label too long";
			return -1;
		}
		if (((sink->ascii_buffer != NULL ?
		      sink->ascii_buffer->used : sink->ascii_size) +
		     sink->label_buf_size) > IDNA_DNS_MAX_NAME_LENGTH) {
			*error_r = "Domain name too long";
			return -1;
		}
		sret = idna_punycode_decode(sink->label_buf + 4,
					    sink->label_buf_size - 4,
					    punycode_buf, LABEL_BUF_SIZE);
		if (sret < 0) {
			*error_r = "Invalid Punycode in A-label";
			return -1;
		}
		if (idna_check_a_label(sink, punycode_buf,
				       (size_t)sret, error_r) < 0)
			return -1;
		if (sink->unicode_buffer != NULL) {
			uni_ucs4_to_utf8(punycode_buf, (size_t)sret,
					 sink->unicode_buffer);
		}
		if (sink->ascii_buffer == NULL)
			sink->ascii_size += sink->label_buf_size;
		else {
			uni_ucs4_to_utf8(sink->label_buf, sink->label_buf_size,
					 sink->ascii_buffer);
		}
	}
	if (!last) {
		if (sink->unicode_buffer != NULL)
			buffer_append_c(sink->unicode_buffer, '.');
		if (sink->ascii_buffer == NULL)
			sink->ascii_size++;
		else
			buffer_append_c(sink->ascii_buffer, '.');
	}
	return 0;
}

static ssize_t
idna_process_sink_input(struct unicode_transform *trans,
			const struct unicode_transform_buffer *buf,
			const char **error_r)
{
	struct idna_process_sink *sink =
		container_of(trans, struct idna_process_sink, transform);
	unsigned int n;

	for (n = 0; n < buf->cp_count; n++) {
		if (sink->label_buf_size >= LABEL_BUF_SIZE) {
			*error_r = "Label too long";
			return -1;
		}
		if (buf->cp[n] == '.') {
			if (idna_process_label(sink, FALSE, error_r) < 0) {
				i_assert(*error_r != NULL);
				return -1;
			}
			sink->label_buf_size = 0;
			continue;
		}
		sink->label_buf[sink->label_buf_size++] = buf->cp[n];
	}
	return n;
}

static int
idna_process_sink_flush(struct unicode_transform *trans, bool finished,
			const char **error_r)
{
	struct idna_process_sink *sink =
		container_of(trans, struct idna_process_sink, transform);

	if (!finished)
		return 0;
	if (idna_process_label(sink, TRUE, error_r) < 0)
		return -1;
	return 1;
}

struct unicode_transform_def idna_process_sink_def = {
	.input = idna_process_sink_input,
	.flush = idna_process_sink_flush,
};

static void
idna_process_sink_init(struct idna_process_sink *sink_r,
		       struct idna_bidi_check_context *bidictx,
		       enum idna_process_flags flags,
		       buffer_t *unicode_buffer,
		       buffer_t *ascii_buffer)
{
	i_zero(sink_r);
	unicode_transform_init(&sink_r->transform, &idna_process_sink_def);
	sink_r->bidictx = bidictx;
	sink_r->flags = flags;
	sink_r->unicode_buffer = unicode_buffer;
	sink_r->ascii_buffer = ascii_buffer;
}

int idna_process_domain_name(const char *domain_name,
			     enum idna_process_flags flags,
			     const char **to_unicode_r, const char **to_ascii_r,
			     const char **error_r)
{
	const unsigned char *input = (const unsigned char *)domain_name;
	size_t size = strlen(domain_name);

	if (to_unicode_r != NULL)
		*to_unicode_r = NULL;
	if (to_ascii_r != NULL)
		*to_ascii_r = NULL;
	*error_r = NULL;

	if (size == 0) {
		*error_r = "Empty domain name";
		return -1;
	}

	/* UTS #46 - Unicode IDNA Compatibility Processing,
	     Section 4 - Processing:

	   This is executed as a Unicode transform chain. So each of the steps
	   outlined hereafter is not executed immediately, but rather at the
	   end of this function.
	 */

	struct idna_bidi_check_context bidictx;

	idna_bidi_checker_context_init(&bidictx);

	/* 1. Map: */

	struct idna_map map;

	idna_map_init(&map);

	/* 2. Normalize:

	   Normalize the domain_name string to Unicode Normalization Form C.
	 */

	struct unicode_nf_context nfc;

	unicode_nf_init(&nfc, UNICODE_NFC);
	unicode_transform_chain(&map.transform, &nfc.transform);

	/* 3. Break, 4. Validate:

	   Perform most of the label validation before actually breaking the
	   domain name into labels, by just recognizing the U+002E ( . ) FULL
	   STOP boundaries and checking each code points in its context.
	 */

	struct idna_validate valdt;

	idna_validate_init(&valdt, &bidictx, flags, FALSE);
	unicode_transform_chain(&nfc.transform, &valdt.transform);

	/* Actually break the string into labels at U+002E ( . ) FULL STOP and
	   perform the rest of the label validation.
	 */

	struct idna_process_sink sink;
	buffer_t *out_unicode = NULL, *out_ascii = NULL;

	if (to_unicode_r != NULL)
		out_unicode = t_buffer_create(256);
	if (to_ascii_r != NULL)
		out_ascii = t_buffer_create(256);

	idna_process_sink_init(&sink, &bidictx, flags, out_unicode, out_ascii);
	unicode_transform_chain(&valdt.transform, &sink.transform);

	/* Run the Unicode transform chain */

	struct unicode_transform *trans = &map.transform;
	unichar_t chr;
	ssize_t sret;
	bool got_chr = FALSE;

	while (size > 0 || got_chr) {
		int bytes = uni_utf8_get_char_n(input, size, &chr);
		if (bytes <= 0) {
			*error_r = "Invalid UTF8 encoding";
			return -1;

		}
		input += bytes;
		size -= bytes;

		sret = unicode_transform_input(trans, &chr, 1, error_r);
		if (sret < 0)
			return -1;
		if (sret > 0)
			got_chr = FALSE;
	}

	int fret = unicode_transform_flush(trans, error_r);
	i_assert(fret != 0);
	if (fret < 0)
		return -1;

	if (to_unicode_r != NULL)
		*to_unicode_r = str_c(out_unicode);
	if (to_ascii_r != NULL)
		*to_ascii_r = str_c(out_ascii);
	return 0;
}
