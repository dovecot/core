/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "unichar.h"
#include "unicode-data.h"
#include "unicode-transform.h"

#define HANGUL_FIRST 0xac00
#define HANGUL_LAST 0xd7a3

/*
 * Transform
 */

ssize_t uniform_transform_forward(
	struct unicode_transform *trans, const uint32_t *out,
	const struct unicode_code_point_data *const *out_data, size_t out_len,
	const char **error_r)
{
	struct unicode_transform_buffer buf_next;
	ssize_t sret;

	i_zero(&buf_next);
	buf_next.cp = out;
	buf_next.cp_data = out_data;
	buf_next.cp_count = out_len;

	i_assert(trans->next != NULL);
	i_assert(trans->next->def != NULL);
	i_assert(trans->next->def->input != NULL);
	sret = trans->next->def->input(trans->next, &buf_next, error_r);

	i_assert(sret >= 0 || *error_r != NULL);
	i_assert(sret <= (ssize_t)out_len);
	return sret;
}

ssize_t unicode_transform_input_buf(struct unicode_transform *trans,
				    const struct unicode_transform_buffer *buf,
				    const char **error_r)
{
	struct unicode_transform_buffer in_buf;
	size_t input_total = 0;
	ssize_t sret;
	bool flushed = FALSE;
	int ret;

	*error_r = NULL;

	in_buf = *buf;

	while (in_buf.cp_count > 0) {
		if (in_buf.cp_count > 0) {
			i_assert(trans->def->input != NULL);
			sret = trans->def->input(trans, &in_buf, error_r);
			if (sret < 0) {
				i_assert(*error_r != NULL);
				return -1;
			}
			if (sret > 0) {
				i_assert((size_t)sret <= in_buf.cp_count);
				in_buf.cp += sret;
				in_buf.cp_count -= sret;
				input_total += sret;
				flushed = FALSE;
				continue;
			}
			if (sret == 0 && flushed)
				break;
		}

		struct unicode_transform *tp = trans;

		while (tp->next != NULL) {
			if (tp->def->flush != NULL) {
				ret = tp->def->flush(tp, FALSE, error_r);
				if (ret < 0) {
					i_assert(*error_r != NULL);
					return -1;
				}
			}
			tp = tp->next;
		}

		flushed = TRUE;
	}

	return input_total;
}

int unicode_transform_flush(struct unicode_transform *trans,
			    const char **error_r)
{
	int ret;

	*error_r = NULL;

	while (trans != NULL) {
		struct unicode_transform *tp = trans;
		bool progress = FALSE;

		while (tp != NULL) {
			if (tp->def->flush == NULL) {
				progress = TRUE;
				if (tp == trans)
					trans = trans->next;
			} else {
				ret = tp->def->flush(tp, (tp == trans), error_r);
				if (ret < 0) {
					i_assert(*error_r != NULL);
					return -1;
				}
				if (ret > 0) {
					progress = TRUE;
					if (tp == trans)
						trans = trans->next;
				}
			}
			tp = tp->next;
		}
		if (!progress)
			return 0;
	}
	return 1;
}

/* Buffer Sink */

static ssize_t
unicode_buffer_sink_input(struct unicode_transform *trans,
			  const struct unicode_transform_buffer *buf,
			  const char **error_r);

static const struct unicode_transform_def unicode_buffer_sink_def = {
	.input = unicode_buffer_sink_input,
};

void unicode_buffer_sink_init(struct unicode_buffer_sink *sink,
			      buffer_t *buffer)
{
	i_zero(sink);
	unicode_transform_init(&sink->transform, &unicode_buffer_sink_def);
	sink->buffer = buffer;
}

static ssize_t
unicode_buffer_sink_input(struct unicode_transform *trans,
			  const struct unicode_transform_buffer *buf,
			  const char **error_r ATTR_UNUSED)
{
	struct unicode_buffer_sink *sink =
		container_of(trans, struct unicode_buffer_sink, transform);

	uni_ucs4_to_utf8(buf->cp, buf->cp_count, sink->buffer);
	return buf->cp_count;
}

/* Static Array Sink */

static ssize_t
unicode_static_array_sink_input(struct unicode_transform *trans,
				const struct unicode_transform_buffer *buf,
				const char **error_r);

static const struct unicode_transform_def unicode_static_array_sink_def = {
	.input = unicode_static_array_sink_input,
};

void unicode_static_array_sink_init(struct unicode_static_array_sink *sink,
				    uint32_t *array, size_t array_size,
				    size_t *array_pos)
{
	i_zero(sink);
	unicode_transform_init(&sink->transform,
			       &unicode_static_array_sink_def);
	sink->array = array;
	sink->array_size = array_size;
	sink->array_pos = array_pos;
}

static ssize_t
unicode_static_array_sink_input(struct unicode_transform *trans,
				const struct unicode_transform_buffer *buf,
				const char **error_r)
{
	struct unicode_static_array_sink *sink =
		container_of(trans, struct unicode_static_array_sink,
			     transform);

	if (*sink->array_pos + buf->cp_count > sink->array_size) {
		*error_r = "Output overflow";
		return -1;
	}
	memcpy(sink->array + *sink->array_pos, buf->cp,
	       buf->cp_count * sizeof(*buf->cp));
	*sink->array_pos += buf->cp_count;
	return buf->cp_count;
}

/*
 * Hangul syllable (de)composition
 */

#define UNI_HANGUL_S_BASE 0xac00
#define UNI_HANGUL_L_BASE 0x1100
#define UNI_HANGUL_V_BASE 0x1161
#define UNI_HANGUL_T_BASE 0x11a7
#define UNI_HANGUL_L_COUNT 19
#define UNI_HANGUL_V_COUNT 21
#define UNI_HANGUL_T_COUNT 28
#define UNI_HANGUL_N_COUNT (UNI_HANGUL_V_COUNT * UNI_HANGUL_T_COUNT)
#define UNI_HANGUL_L_END (UNI_HANGUL_L_BASE + UNI_HANGUL_L_COUNT)
#define UNI_HANGUL_V_END (UNI_HANGUL_V_BASE + UNI_HANGUL_V_COUNT)
#define UNI_HANGUL_T_END (UNI_HANGUL_T_BASE + UNI_HANGUL_T_COUNT)
#define UNI_HANGUL_S_END 0xD7A4

static size_t unicode_hangul_decompose(uint32_t cp, uint32_t buf[3])
{
	/* The Unicode Standard, Section 3.12.2:
	   Hangul Syllable Decomposition
	 */

	size_t s_index = cp - UNI_HANGUL_S_BASE;
	size_t l_index = s_index / UNI_HANGUL_N_COUNT;
	size_t v_index = ((s_index % UNI_HANGUL_N_COUNT) / UNI_HANGUL_T_COUNT);
	size_t t_index = s_index % UNI_HANGUL_T_COUNT;
	uint32_t l_part = UNI_HANGUL_L_BASE + l_index;
	uint32_t v_part = UNI_HANGUL_V_BASE + v_index;

	if (t_index == 0) {
		buf[0] = l_part;
		buf[1] = v_part;
		return 2;
	}

	uint32_t t_part = UNI_HANGUL_T_BASE + t_index;

	buf[0] = l_part;
	buf[1] = v_part;
	buf[2] = t_part;
	return 3;
}

static uint32_t unicode_hangul_compose_pair(uint32_t l, uint32_t r)
{
	/* The Unicode Standard, Section 3.12.3:
	   Hangul Syllable Composition
	 */

	/* <LPart, VPart> */
	if (l >= UNI_HANGUL_L_BASE && l < UNI_HANGUL_L_END &&
	    r >= UNI_HANGUL_V_BASE && r < UNI_HANGUL_V_END) {
		uint32_t l_part = l, v_part = r;

		size_t l_index = l_part - UNI_HANGUL_L_BASE;
		size_t v_index = v_part - UNI_HANGUL_V_BASE;
		size_t lv_index = l_index * UNI_HANGUL_N_COUNT +
				  v_index * UNI_HANGUL_T_COUNT;
		return UNI_HANGUL_S_BASE + lv_index;
	}
	/* A sequence <LVPart, TPart> */
	if (l >= UNI_HANGUL_S_BASE && l < UNI_HANGUL_S_END &&
	    r >= (UNI_HANGUL_T_BASE + 1u) && r < UNI_HANGUL_T_END &&
	    ((l - UNI_HANGUL_S_BASE) % UNI_HANGUL_T_COUNT) == 0) {
		uint32_t lv_part = l, t_part = r;

		size_t t_index = t_part - UNI_HANGUL_T_BASE;
		return lv_part + t_index;
	}
	return 0x0000;
}

/*
 * Normalization transform: NFD, NFKD, NFC, NFKC
 */

#define UNICODE_COMBINING_GRAPHEME_JOINER 0x034f

static ssize_t
unicode_nf_input(struct unicode_transform *trans,
		 const struct unicode_transform_buffer *buf,
		 const char **error_r);
static int
unicode_nf_flush(struct unicode_transform *trans, bool finished,
		 const char **error_r);

static const struct unicode_transform_def unicode_nf_def = {
	.input = unicode_nf_input,
	.flush = unicode_nf_flush,
};

void unicode_nf_init(struct unicode_nf_context *ctx_r,
		     enum unicode_nf_type type)
{
	i_zero(ctx_r);
	unicode_transform_init(&ctx_r->transform, &unicode_nf_def);

	switch (type) {
	case UNICODE_NFD:
		ctx_r->canonical = TRUE;
		ctx_r->nf_qc_mask = UNICODE_NFD_QUICK_CHECK_MASK;
		break;
	case UNICODE_NFKD:
		ctx_r->nf_qc_mask = UNICODE_NFKD_QUICK_CHECK_MASK;
		break;
	case UNICODE_NFC:
		ctx_r->compose = TRUE;
		ctx_r->canonical = TRUE;
		ctx_r->nf_qc_mask = UNICODE_NFC_QUICK_CHECK_MASK;
		break;
	case UNICODE_NFKC:
		ctx_r->compose = TRUE;
		ctx_r->nf_qc_mask = UNICODE_NFKC_QUICK_CHECK_MASK;
		break;
	}
}

void unicode_nf_reset(struct unicode_nf_context *ctx)
{
	enum unicode_nf_type type =
		(ctx->compose ? (ctx->canonical ? UNICODE_NFC : UNICODE_NFKC) :
				(ctx->canonical ? UNICODE_NFD : UNICODE_NFKD));
	struct unicode_transform *next = ctx->transform.next;

	unicode_nf_init(ctx, type);
	unicode_transform_chain(&ctx->transform, next);
}

static void
unicode_nf_buffer_delete(struct unicode_nf_context *ctx, size_t offset,
			 size_t count)
{
	if (count == 0)
		return;

	i_assert(offset < ctx->buffer_len);
	i_assert(count <= ctx->buffer_len);
	i_assert(offset <= (ctx->buffer_len - count));

	if (count == ctx->buffer_len) {
		ctx->buffer_len = 0;
		return;
	}

	size_t trailer = ctx->buffer_len - (offset + count);
	if (trailer > 0) {
		memmove(&ctx->cp_buffer[offset],
			&ctx->cp_buffer[offset + count],
			trailer * sizeof(ctx->cp_buffer[0]));
		memmove(&ctx->cpd_buffer[offset],
			&ctx->cpd_buffer[offset + count],
			trailer * sizeof(ctx->cpd_buffer[0]));
	}
	ctx->buffer_len -= count;
}

static void
unicode_nf_buffer_append(struct unicode_nf_context *ctx, uint32_t cp,
			 const struct unicode_code_point_data *cpd)
{
	uint8_t ccc = cpd->canonical_combining_class;
	size_t pos = ctx->buffer_len;

	i_assert(ctx->buffer_len < UNICODE_NF_BUFFER_SIZE);
	if (ccc != 0) {
		/* Apply the Canonical Ordering Algorithm (COA): Insert the
		   non-starter after the preceding code points that have the
		   same or a lower combining class. Starters have combining
		   class 0, so a non-starter is never moved before a
		   starter. */
		while (pos > 0 &&
		       ctx->cpd_buffer[pos - 1]->canonical_combining_class > ccc) {
			ctx->cp_buffer[pos] = ctx->cp_buffer[pos - 1];
			ctx->cpd_buffer[pos] = ctx->cpd_buffer[pos - 1];
			pos--;
		}
	}
	ctx->cp_buffer[pos] = cp;
	ctx->cpd_buffer[pos] = cpd;
	ctx->buffer_len++;
}

static void
unicode_nf_get_ccc_counts(const uint32_t *decomp, size_t len,
			  const struct unicode_code_point_data *const *decomp_cpd,
			  size_t *lead_r, size_t *trail_r, bool *seen_starter_r)
{
	const struct unicode_code_point_data *cpd;
	size_t i;

	*lead_r = *trail_r = 0;
	*seen_starter_r = FALSE;
	for (i = 0; i < len; i++) {
		cpd = (decomp_cpd != NULL ? decomp_cpd[i] :
		       unicode_code_point_get_data(decomp[i]));
		if (cpd->canonical_combining_class == 0)
			*seen_starter_r = TRUE;
		else if (!*seen_starter_r)
			(*lead_r)++;
		else
			(*trail_r)++;
	}
}

static bool
unicode_nf_cp(struct unicode_nf_context *ctx, uint32_t cp,
	      const struct unicode_code_point_data *cpd)
{
	static const size_t buffer_size = UNICODE_NF_BUFFER_SIZE;
	uint8_t nf_qc_mask = ctx->nf_qc_mask;
	size_t i;

	i_assert(ctx->buffer_len <= buffer_size);
	if (ctx->buffer_len == buffer_size) {
		/* Buffer already full */
		return FALSE;
	}

	/*
	 * Decompose the code point
	 */

	const struct unicode_code_point_data *
		decomp_cpd[UNICODE_DECOMPOSITION_MAX_LENGTH];
	const uint32_t *decomp, *decomp_k;
	uint32_t decomp_hangul[3];
	size_t len, len_k;

	if (cp >= HANGUL_FIRST && cp <= HANGUL_LAST) {
		len = len_k = unicode_hangul_decompose(cp, decomp_hangul);
		decomp = decomp_k = decomp_hangul;
		for (i = 0; i < len; i++)
			decomp_cpd[i] = unicode_code_point_get_data(decomp[i]);
	} else {
		if (cpd == NULL)
			cpd = unicode_code_point_get_data(cp);
		len = unicode_code_point_data_get_full_decomposition(
			cpd, ctx->canonical, &decomp);
		if (len == 0) {
			decomp = &cp;
			len = 1;
			decomp_cpd[0] = cpd;
		} else {
			for (i = 0; i < len; i++) {
				decomp_cpd[i] =
					unicode_code_point_get_data(decomp[i]);
			}
		}
		len_k = len;
		decomp_k = decomp;
		if (ctx->canonical) {
			len_k = unicode_code_point_data_get_full_decomposition(
				cpd, FALSE, &decomp_k);
			if (len_k == 0) {
				decomp_k = decomp;
				len_k = len;
			}
		}
	}

	i_assert(len <= UNICODE_DECOMPOSITION_MAX_LENGTH);
	i_assert(len_k <= UNICODE_DECOMPOSITION_MAX_LENGTH);

	if ((ctx->buffer_len + len) > buffer_size &&
	    (ctx->nonstarter_count + len) <=
		UNICODE_NF_STREAM_SAFE_NON_STARTER_LEN) {
		/* Decomposition overflows the buffer. Record and mark it as
		   pending and come back to it once the buffer is sufficiently
		   drained. */
		i_assert(ctx->pending_decomp == 0 || ctx->pending_cp == cp);
		ctx->pending_decomp = len;
		ctx->pending_cp = cp;
		ctx->pending_cpd = cpd;
		return FALSE;
	}

	/* UAX15-D4: Stream-Safe Text Process is the process of producing a
	   Unicode string in Stream-Safe Text Format by processing that string
	   from start to finish, inserting U+034F COMBINING GRAPHEME JOINER
	   (CGJ) within long sequences of non-starters. The exact position of
	   the inserted CGJs are determined according to the following
	   algorithm, which describes the generation of an output string from an
	   input string:

	   1. If the input string is empty, return an empty output string.
	   2. Set nonStarterCount to zero.
	   3. For each code point C in the input string:
		a. Produce the NFKD decomposition S.
		b. If nonStarterCount plus the number of initial non-starters in
		   S is greater than 30, append a CGJ to the output string and
		   set the nonStarterCount to zero.
		c. Append C to the output string.
		d. If there are no starters in S, increment nonStarterCount by
		   the number of code points in S; otherwise, set
		   nonStarterCount to the number of trailing non-starters in S
		   (which may be zero).
	   4. Return the output string.
	 */
	size_t ns_lead, ns_trail;
	bool seen_starter;

	unicode_nf_get_ccc_counts(decomp_k, len_k,
				  (decomp_k == decomp ? decomp_cpd : NULL),
				  &ns_lead, &ns_trail, &seen_starter);
	ctx->nonstarter_count += ns_lead;
	if (ctx->nonstarter_count > UNICODE_NF_STREAM_SAFE_NON_STARTER_LEN) {
		ctx->nonstarter_count = 0;
		unicode_nf_buffer_append(ctx, UNICODE_COMBINING_GRAPHEME_JOINER,
			unicode_code_point_get_data(
				UNICODE_COMBINING_GRAPHEME_JOINER));
	} else if (seen_starter) {
		ctx->nonstarter_count = ns_trail;
	}

	/*
	 * Buffer the requested decomposition in canonical order
	 */

	bool pending_decomp = FALSE;

	i_assert(ctx->buffer_len <= buffer_size);
	if ((ctx->buffer_len + len) > buffer_size) {
		/* Decomposition now overflows the buffer. Record and mark it as
		   pending and come back to it once the buffer is sufficiently
		   drained. */
		i_assert(ctx->pending_decomp == 0 || ctx->pending_cp == cp);
		ctx->pending_decomp = len;
		ctx->pending_cp = cp;
		ctx->pending_cpd = cpd;
		pending_decomp = TRUE;
	} else {
		for (i = 0; i < len; i++)
			unicode_nf_buffer_append(ctx, decomp[i], decomp_cpd[i]);
	}

	/*
	 * Everything before the last starter with quick check Yes is final
	 */

	size_t last_qc_y = 0;

	for (i = I_MAX(1, ctx->buffer_output_max); i < ctx->buffer_len; i++) {
		const struct unicode_code_point_data *cpd_i =
			ctx->cpd_buffer[i];

		if (cpd_i->canonical_combining_class == 0 &&
		    (cpd_i->nf_quick_check & nf_qc_mask) == 0)
			last_qc_y = i;
	}
	ctx->buffer_output_max = last_qc_y;
	return !pending_decomp;
}

static bool
unicode_nf_input_cp(struct unicode_nf_context *ctx, uint32_t cp,
		    const struct unicode_code_point_data *cpd)
{
	static const size_t buffer_size = UNICODE_NF_BUFFER_SIZE;

	i_assert(ctx->buffer_len <= buffer_size);
	if (ctx->buffer_len == buffer_size ||
	    (ctx->pending_decomp > 0 &&
	     ctx->buffer_len > (buffer_size - ctx->pending_decomp))) {
		/* Buffer is (still too) full. */
		return FALSE;
	}

	if (ctx->pending_decomp > 0) {
		/* Earlier, the buffer was too full for the next decomposition
		   and it was recorded and marked as pending. Now, we have the
		   opportunity to continue. */
		if (!unicode_nf_cp(ctx, ctx->pending_cp, ctx->pending_cpd))
			return FALSE;
		ctx->pending_decomp = 0;

		i_assert(ctx->buffer_len <= buffer_size);
		if (ctx->buffer_output_max > 0 &&
		    ctx->buffer_len == buffer_size) {
			/* Pending decomposition filled the buffer completely.
			 */
			return FALSE;
		}
	}

	/* Normal input of next code point */
	(void)unicode_nf_cp(ctx, cp, cpd);
	return TRUE;
}

static ssize_t
unicode_nf_input(struct unicode_transform *trans,
		 const struct unicode_transform_buffer *buf,
		 const char **error_r ATTR_UNUSED)
{
	struct unicode_nf_context *ctx =
		container_of(trans, struct unicode_nf_context, transform);
	size_t n;

	for (n = 0; n < buf->cp_count; n++) {
		if (!unicode_nf_input_cp(ctx, buf->cp[n],
					 (buf->cp_data == NULL ?
					  NULL : buf->cp_data[n])))
			break;
	}
	return n;
}

static uint32_t
unicode_nf_compose_pair(uint32_t l, uint32_t r,
			const struct unicode_code_point_data **l_data)
{
	uint32_t comp = unicode_hangul_compose_pair(l, r);

	if (comp > 0x0000)
		return comp;

	if (*l_data == NULL)
		*l_data = unicode_code_point_get_data(l);
	return unicode_code_point_data_find_composition(*l_data, r);
}

static int
unicode_nf_flush_more(struct unicode_nf_context *ctx, bool finished,
		      const char **error_r)
{
	struct unicode_transform *trans = &ctx->transform;

	ctx->finished = finished;

	if (ctx->buffer_len == 0)
		return 1;
	if (!finished && ctx->buffer_output_max == 0)
		return 0;

	/*
	 * Apply the Canonical Composition Algorithm
	 */

	if (ctx->finished)
		ctx->buffer_output_max = ctx->buffer_len;
	i_assert(ctx->buffer_processed <= ctx->buffer_output_max);
	if (ctx->compose && ctx->buffer_len > 1) {
		size_t in_pos, out_pos, starter;
		int last_ccc;

		out_pos = 1;
		last_ccc = -1;
		starter = 0;
		for (in_pos = I_MAX(1, ctx->buffer_processed);
		     in_pos < ctx->buffer_output_max; in_pos++) {
			uint32_t cp = ctx->cp_buffer[in_pos];
			const struct unicode_code_point_data *cpd =
				ctx->cpd_buffer[in_pos];

			if (cpd == NULL) {
				ctx->cpd_buffer[in_pos] = cpd =
					unicode_code_point_get_data(cp);
			}

			uint8_t ccc = cpd->canonical_combining_class;
			uint32_t comp = 0x0000;
			if (last_ccc < (int)ccc) {
				comp = unicode_nf_compose_pair(
					ctx->cp_buffer[starter], cp,
					&ctx->cpd_buffer[starter]);
			}
			if (comp > 0x0000) {
				ctx->cp_buffer[starter] = comp;
				ctx->cpd_buffer[starter] = NULL;
			} else if (ccc == 0) {
				starter = out_pos;
				last_ccc = -1;
				ctx->cp_buffer[out_pos] = cp;
				ctx->cpd_buffer[out_pos] = cpd;
				out_pos++;
			} else {
				last_ccc = ccc;
				ctx->cp_buffer[out_pos] = cp;
				ctx->cpd_buffer[out_pos] = cpd;
				out_pos++;
			}
		}
		if (finished) {
			ctx->buffer_len = ctx->buffer_output_max = out_pos;
		} else if (in_pos > out_pos) {
			unicode_nf_buffer_delete(ctx, out_pos,
						 (in_pos - out_pos));
			ctx->buffer_output_max = out_pos;
		}
	}
	ctx->buffer_processed = ctx->buffer_output_max;

	/*
	 * Forward output
	 */

	size_t output_len = ctx->buffer_processed;
	ssize_t sret;

	sret = uniform_transform_forward(trans, ctx->cp_buffer, ctx->cpd_buffer,
					 output_len, error_r);
	if (sret < 0)
		return -1;

	i_assert((size_t)sret <= ctx->buffer_processed);
	unicode_nf_buffer_delete(ctx, 0, sret);
	ctx->buffer_processed -= sret;
	ctx->buffer_output_max -= sret;
	if ((size_t)sret < output_len)
		return 0;
	return 1;
}

static int
unicode_nf_flush(struct unicode_transform *trans, bool finished,
		 const char **error_r)
{
	struct unicode_nf_context *ctx =
		container_of(trans, struct unicode_nf_context, transform);
	int ret;

	ret = unicode_nf_flush_more(ctx, finished, error_r);
	if (ret <= 0)
		return ret;

	if (finished && ctx->pending_decomp > 0) {
		if (unicode_nf_cp(ctx, ctx->pending_cp, ctx->pending_cpd))
			ctx->pending_decomp = 0;
	}

	return unicode_nf_flush_more(ctx, finished, error_r);
}

/*
 * Normalization check
 */

static ssize_t
unicode_nf_check_sink_input(struct unicode_transform *trans,
			    const struct unicode_transform_buffer *buf,
			    const char **error_r);

static const struct unicode_transform_def unicode_nf_check_sink_def = {
	.input = unicode_nf_check_sink_input,
};

void unicode_nf_checker_init(struct unicode_nf_checker *unc_r,
			     enum unicode_nf_type type)
{
	i_zero(unc_r);

	switch (type) {
	case UNICODE_NFD:
		unc_r->canonical = TRUE;
		unc_r->nf_qc_mask = UNICODE_NFD_QUICK_CHECK_MASK;
		unc_r->nf_qc_yes = UNICODE_NFD_QUICK_CHECK_YES;
		unc_r->nf_qc_no = UNICODE_NFD_QUICK_CHECK_NO;
		break;
	case UNICODE_NFKD:
		unc_r->nf_qc_mask = UNICODE_NFKD_QUICK_CHECK_MASK;
		unc_r->nf_qc_yes = UNICODE_NFKD_QUICK_CHECK_YES;
		unc_r->nf_qc_no = UNICODE_NFKD_QUICK_CHECK_NO;
		break;
	case UNICODE_NFC:
		unc_r->compose = TRUE;
		unc_r->canonical = TRUE;
		unc_r->nf_qc_mask = UNICODE_NFC_QUICK_CHECK_MASK;
		unc_r->nf_qc_yes = UNICODE_NFC_QUICK_CHECK_YES;
		unc_r->nf_qc_no = UNICODE_NFC_QUICK_CHECK_NO;
		break;
	case UNICODE_NFKC:
		unc_r->compose = TRUE;
		unc_r->nf_qc_mask = UNICODE_NFKC_QUICK_CHECK_MASK;
		unc_r->nf_qc_yes = UNICODE_NFKC_QUICK_CHECK_YES;
		unc_r->nf_qc_no = UNICODE_NFKC_QUICK_CHECK_NO;
		break;
	}

	unicode_nf_init(&unc_r->nf, type);
	unicode_transform_init(&unc_r->sink, &unicode_nf_check_sink_def);
	unicode_transform_chain(&unc_r->nf.transform, &unc_r->sink);
}

void unicode_nf_checker_reset(struct unicode_nf_checker *unc)
{
	enum unicode_nf_type type =
		(unc->compose ? (unc->canonical ? UNICODE_NFC : UNICODE_NFKC) :
				(unc->canonical ? UNICODE_NFD : UNICODE_NFKD));

	unicode_nf_checker_init(unc, type);
}

static ssize_t
unicode_nf_check_sink_input(struct unicode_transform *trans,
			    const struct unicode_transform_buffer *buf,
			    const char **error_r)
{
	struct unicode_nf_checker *unc =
		container_of(trans, struct unicode_nf_checker, sink);
	size_t n;

	if (buf->cp_count > unc->buffer_len) {
		*error_r = "Not normalized";
		return -1;
	}
	for (n = 0; n < buf->cp_count; n++) {
		if (buf->cp[n] != unc->cp_buffer[n]) {
			*error_r = "Not normalized";
			return -1;
		}
	}
	unc->buffer_len -= buf->cp_count;
	memmove(&unc->cp_buffer[0], &unc->cp_buffer[buf->cp_count],
		unc->buffer_len * sizeof(unc->cp_buffer[0]));
	return buf->cp_count;
}

static int
unicode_nf_checker_nf_input(struct unicode_nf_checker *unc, uint32_t cp,
			    const struct unicode_code_point_data *cp_data)
{
	struct unicode_transform_buffer buf;
	const char *error;
	ssize_t sret;

	/* Add the code point to the buffer first, since the normalization
	   transform may output it immediately. */
	i_assert(unc->buffer_len < N_ELEMENTS(unc->cp_buffer));
	unc->cp_buffer[unc->buffer_len++] = cp;
	unc->nf_used = TRUE;

	i_zero(&buf);
	buf.cp = &cp;
	buf.cp_data = &cp_data;
	buf.cp_count = 1;
	sret = unicode_transform_input_buf(&unc->nf.transform, &buf, &error);
	if (sret < 0)
		return -1;
	i_assert(sret == 1);
	return 0;
}

static int unicode_nf_checker_nf_finish(struct unicode_nf_checker *unc)
{
	const char *error;
	int ret;

	if (!unc->nf_used)
		return 1;

	ret = unicode_transform_flush(&unc->nf.transform, &error);
	i_assert(ret != 0);
	if (ret < 0 || unc->buffer_len > 0)
		return 0;
	unicode_nf_reset(&unc->nf);
	unc->nf_used = FALSE;
	return 1;
}

int unicode_nf_checker_input(struct unicode_nf_checker *unc, uint32_t cp,
			     const struct unicode_code_point_data **_cp_data)
{
	const struct unicode_code_point_data *cpd_last = unc->cpd_last;

	if (*_cp_data == NULL)
		*_cp_data = unicode_code_point_get_data(cp);

	const struct unicode_code_point_data *cp_data = *_cp_data;
	bool last_starter = unc->last_starter;

	unc->cpd_last = cp_data;
	unc->last_starter = FALSE;

	if (cp_data->general_category == UNICODE_GENERAL_CATEGORY_INVALID)
		return -1;
	if ((cp_data->nf_quick_check & unc->nf_qc_mask) == unc->nf_qc_no)
		return 0;
	if (cpd_last != NULL && cp_data->canonical_combining_class != 0 &&
	    cpd_last->canonical_combining_class >
		cp_data->canonical_combining_class)
		return 0;
	if ((cp_data->nf_quick_check & unc->nf_qc_mask) == unc->nf_qc_yes &&
	    cp_data->canonical_combining_class == 0) {
		/* Nothing after this starter interacts with anything before
		   it. Finish checking the previous code points, and remember
		   this one in case the next code point needs to be checked
		   with the normalization transform. */
		if (unicode_nf_checker_nf_finish(unc) == 0)
			return 0;
		unc->last_cp = cp;
		unc->last_starter = TRUE;
		return 1;
	}

	if (last_starter &&
	    unicode_nf_checker_nf_input(unc, unc->last_cp, cpd_last) < 0)
		return 0;
	if (unicode_nf_checker_nf_input(unc, cp, cp_data) < 0)
		return 0;
	return 1;
}

int unicode_nf_checker_finish(struct unicode_nf_checker *unc)
{
	return unicode_nf_checker_nf_finish(unc);
}

/*
 * Casemap Transform
 */

static size_t
unicode_casemap_uppercase_cp(const struct unicode_code_point_data *cp_data,
			     const uint32_t **map_r);
static size_t
unicode_casemap_lowercase_cp(const struct unicode_code_point_data *cp_data,
			     const uint32_t **map_r);
static size_t
unicode_casemap_casefold_cp(const struct unicode_code_point_data *cp_data,
			    const uint32_t **map_r);

static ssize_t
unicode_casemap_input(struct unicode_transform *trans,
		      const struct unicode_transform_buffer *buf,
		      const char **error_r);
static int
unicode_casemap_flush(struct unicode_transform *trans, bool finished,
		      const char **error_r);

static const struct unicode_transform_def unicode_casemap_def = {
	.input = unicode_casemap_input,
	.flush = unicode_casemap_flush,
};

void unicode_casemap_init_uppercase(struct unicode_casemap *map_r)
{
	i_zero(map_r);
	unicode_transform_init(&map_r->transform, &unicode_casemap_def);
	map_r->map = unicode_casemap_uppercase_cp;
}

void unicode_casemap_init_lowercase(struct unicode_casemap *map_r)
{
	i_zero(map_r);
	unicode_transform_init(&map_r->transform, &unicode_casemap_def);
	map_r->map = unicode_casemap_lowercase_cp;
}

void unicode_casemap_init_casefold(struct unicode_casemap *map_r)
{
	i_zero(map_r);
	unicode_transform_init(&map_r->transform, &unicode_casemap_def);
	map_r->map = unicode_casemap_casefold_cp;
}

static size_t
unicode_casemap_uppercase_cp(const struct unicode_code_point_data *cp_data,
			     const uint32_t **map_r)
{
	return unicode_code_point_data_get_uppercase_mapping(cp_data, map_r);
}

static size_t
unicode_casemap_lowercase_cp(const struct unicode_code_point_data *cp_data,
			     const uint32_t **map_r)
{
	return unicode_code_point_data_get_lowercase_mapping(cp_data, map_r);
}

static size_t
unicode_casemap_casefold_cp(const struct unicode_code_point_data *cp_data,
			    const uint32_t **map_r)
{
	return unicode_code_point_data_get_casefold_mapping(cp_data, map_r);
}

static ssize_t
unicode_casemap_input_cp(struct unicode_casemap *map, uint32_t cp,
			 const struct unicode_code_point_data *cp_data,
			 const char **error_r)
{
	bool was_buffered = map->cp_buffered;
	ssize_t sret;

	if (cp_data == NULL)
		cp_data = unicode_code_point_get_data(cp);

	const uint32_t *map_cps;
	const struct unicode_code_point_data *const *map_cps_data = NULL;
	size_t map_cps_len;

	map_cps_len = map->map(cp_data, &map_cps);
	if (map_cps_len == 0) {
		map_cps = &cp;
		map_cps_data = &cp_data;
		map_cps_len = 1;
	}
	i_assert(map_cps_len > map->cp_map_pos);

	map_cps += map->cp_map_pos;
	map_cps_len -= map->cp_map_pos;
	sret = uniform_transform_forward(&map->transform,
					 map_cps, map_cps_data, map_cps_len,
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

	map->cp_buffered = FALSE;
	map->cp_data = NULL;
	map->cp_map_pos = 0;
	return 1;
}

static ssize_t
unicode_casemap_input(struct unicode_transform *trans,
		      const struct unicode_transform_buffer *buf,
		      const char **error_r)
{
	struct unicode_casemap *map =
		container_of(trans, struct unicode_casemap, transform);
	int ret;

	ret = unicode_casemap_flush(trans, TRUE, error_r);
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
		ret = unicode_casemap_input_cp(map, buf->cp[n],
					       (buf->cp_data != NULL ?
					        buf->cp_data[n] : NULL),
					       error_r);
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
unicode_casemap_flush(struct unicode_transform *trans,
		      bool finished ATTR_UNUSED, const char **error_r)
{
	struct unicode_casemap *map =
		container_of(trans, struct unicode_casemap, transform);
	int ret;

	if (!map->cp_buffered)
		return 1;

	ret = unicode_casemap_input_cp(map, map->cp, map->cp_data, error_r);
	i_assert(ret >= 0 || *error_r != NULL);
	return ret;
}

/*
 * RFC 5051 - Simple Unicode Collation Algorithm
 */

void unicode_rfc5051_init(struct unicode_rfc5051_context *ctx)
{
	i_zero(ctx);
}

size_t unicode_rfc5051_normalize(struct unicode_rfc5051_context *ctx,
				 uint32_t cp, const uint32_t **norm_r)
{
	const struct unicode_code_point_data *cpd;
	size_t len;

	cpd = unicode_code_point_get_data(cp);
	if (cpd->simple_titlecase_mapping != 0x0000)
		cp = cpd->simple_titlecase_mapping;

	if (cp >= HANGUL_FIRST && cp <= HANGUL_LAST) {
		*norm_r = ctx->buffer;
		return unicode_hangul_decompose(cp, ctx->buffer);
	}

	len = unicode_code_point_get_full_decomposition(cp, FALSE, norm_r);
	if (len == 0) {
		ctx->buffer[0] = cp;
		*norm_r = ctx->buffer;
		return 1;
	}
	return len;
}
