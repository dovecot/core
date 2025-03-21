/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#define HANGUL_FIRST 0xac00
#define HANGUL_LAST 0xd7a3

/*
 * Hangul syllable (de)composition
 */

static size_t uni_ucs4_decompose_hangul(uint32_t chr, uint32_t buf[3])
{
	/* The Unicode Standard, Section 3.12.2:
	   Hangul Syllable Decomposition
	 */

	static const uint16_t s_base = 0xac00;
	static const uint16_t l_base = 0x1100;
	static const uint16_t v_base = 0x1161;
	static const uint16_t t_base = 0x11a7;
	static const unsigned int v_count = 21;
	static const unsigned int t_count = 28;
	static const unsigned int n_count = (v_count * t_count);

	unsigned int s_index = chr - s_base;
	unsigned int l_index = s_index / n_count;
	unsigned int v_index = (s_index % n_count) / t_count;
	unsigned int t_index = s_index % t_count;
	uint32_t l_part = l_base + l_index;
	uint32_t v_part = v_base + v_index;

	if (t_index == 0) {
		buf[0] = l_part;
		buf[1] = v_part;
		return 2;
	}

	uint32_t t_part = t_base + t_index;

	buf[0] = l_part;
	buf[1] = v_part;
	buf[2] = t_part;
	return 3;
}

static void uni_ucs4_decompose_hangul_utf8(uint32_t chr, buffer_t *output)
{
	uint32_t buf[3];
	size_t len, i;

	len = uni_ucs4_decompose_hangul(chr, buf);

	for (i = 0; i < len; i++)
		uni_ucs4_to_utf8_c(buf[i], output);
}

static void
uni_ucs4_decompose_one_utf8(uint32_t chr, bool canonical, buffer_t *output)
{
	const uint32_t *decomp;
	size_t len, i;

	if (chr >= HANGUL_FIRST && chr <= HANGUL_LAST) {
		uni_ucs4_decompose_hangul_utf8(chr, output);
		return;
	}

	len = unicode_code_point_get_full_decomposition(chr, canonical,
							&decomp);
	if (len == 0) {
		uni_ucs4_to_utf8_c(chr, output);
		return;
	}

	for (i = 0; i < len; i++)
		uni_ucs4_to_utf8_c(decomp[i], output);
}
