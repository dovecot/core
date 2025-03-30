/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

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

ssize_t unicode_transform_input(struct unicode_transform *trans,
				const uint32_t *in, size_t in_len,
				const char **error_r)
{
	struct unicode_transform_buffer in_buf;
	size_t input_total = 0;
	ssize_t sret;
	bool flushed = FALSE;
	int ret;

	*error_r = NULL;

	i_zero(&in_buf);
	in_buf.cp = in;
	in_buf.cp_count = in_len;

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

static const uint16_t uni_hangul_s_base = 0xac00;
static const uint16_t uni_hangul_l_base = 0x1100;
static const uint16_t uni_hangul_v_base = 0x1161;
static const uint16_t uni_hangul_t_base = 0x11a7;
static const unsigned int uni_hangul_v_count = 21;
static const unsigned int uni_hangul_t_count = 28;
static const unsigned int uni_hangul_n_count =
	uni_hangul_v_count * uni_hangul_t_count;

static size_t unicode_hangul_decompose(uint32_t cp, uint32_t buf[3])
{
	/* The Unicode Standard, Section 3.12.2:
	   Hangul Syllable Decomposition
	 */

	unsigned int s_index = cp - uni_hangul_s_base;
	unsigned int l_index = s_index / uni_hangul_n_count;
	unsigned int v_index = ((s_index % uni_hangul_n_count) /
				uni_hangul_t_count);
	unsigned int t_index = s_index % uni_hangul_t_count;
	uint32_t l_part = uni_hangul_l_base + l_index;
	uint32_t v_part = uni_hangul_v_base + v_index;

	if (t_index == 0) {
		buf[0] = l_part;
		buf[1] = v_part;
		return 2;
	}

	uint32_t t_part = uni_hangul_t_base + t_index;

	buf[0] = l_part;
	buf[1] = v_part;
	buf[2] = t_part;
	return 3;
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
