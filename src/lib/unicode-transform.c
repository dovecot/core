/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "unicode-data.h"
#include "unicode-transform.h"

#define HANGUL_FIRST 0xac00
#define HANGUL_LAST 0xd7a3

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
