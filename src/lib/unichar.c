/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "bsearch-insert-pos.h"
#include "unicode-data.h"
#include "unicode-transform.h"
#include "unichar.h"

const unsigned char utf8_replacement_char[UTF8_REPLACEMENT_CHAR_LEN] =
	{ 0xef, 0xbf, 0xbd }; /* 0xfffd */

static const uint8_t utf8_non1_bytes[256 - 192 - 2] = {
	2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
	3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,6,6,1,1
};

const uint8_t *const uni_utf8_non1_bytes = utf8_non1_bytes;

unsigned int uni_strlen(const unichar_t *str)
{
	unsigned int len = 0;

	for (len = 0; str[len] != 0; len++) ;

	return len;
}

static int
uni_utf8_parse_char(const void *_buffer, size_t size, bool cstr,
		    unichar_t *chr_r)
{
	static unichar_t lowest_valid_chr_table[] =
		{ 0, 0, 0x80, 0x800, 0x10000, 0x200000, 0x4000000 };
	const unsigned char *input = _buffer;
	unichar_t chr, lowest_valid_chr;
	unsigned int i, len;
	int ret;

	i_assert(size > 0);

	if (*input < 0x80) {
		*chr_r = *input;
		return 1;
	}

	/* first byte has len highest bits set, followed by zero bit.
	   the rest of the bits are used as the highest bits of the value. */
	chr = *input;
	len = uni_utf8_char_bytes(*input);
	switch (len) {
	case 2:
		chr &= 0x1f;
		break;
	case 3:
		chr &= 0x0f;
		break;
	case 4:
		chr &= 0x07;
		break;
	case 5:
		chr &= 0x03;
		break;
	case 6:
		chr &= 0x01;
		break;
	default:
		/* only 7bit chars should have len==1 */
		i_assert(len == 1);
		return -1;
	}

	if (len <= size) {
		lowest_valid_chr = lowest_valid_chr_table[len];
		ret = len;
	} else {
		/* check first if the input is invalid before returning 0 */
		lowest_valid_chr = 0;
		ret = 0;
		len = size;
	}

	/* the following bytes must all be 10xxxxxx */
	for (i = 1; i < len; i++) {
		if ((input[i] & 0xc0) != 0x80) {
			return (cstr && size == SIZE_MAX && input[i] == '\0' ?
				0 : -1);
		}

		chr <<= 6;
		chr |= input[i] & 0x3f;
	}
	/* these are specified as invalid encodings by standards
	   see RFC3629 */
	if (!uni_is_valid_ucs4(chr))
		return -1;
	if (chr < lowest_valid_chr) {
		/* overlong encoding */
		return -1;
	}

	*chr_r = chr;
	return ret;
}

int uni_utf8_get_char(const char *input, unichar_t *chr_r)
{
	return uni_utf8_parse_char(input, SIZE_MAX, TRUE, chr_r);
}

int uni_utf8_get_char_n(const void *input, size_t max_len, unichar_t *chr_r)
{
	return uni_utf8_parse_char(input, max_len, TRUE, chr_r);
}

int uni_utf8_get_char_buf(const void *buffer, size_t size, unichar_t *chr_r)
{
	return uni_utf8_parse_char(buffer, size, FALSE, chr_r);
}

int uni_utf8_to_ucs4(const char *input, ARRAY_TYPE(unichars) *output)
{
	unichar_t chr;

	while (*input != '\0') {
		int len = uni_utf8_get_char(input, &chr);
		if (len <= 0) {
			/* invalid input */
			return -1;
		}
                input += len;

		array_push_back(output, &chr);
	}
	return 0;
}

int uni_utf8_to_ucs4_n(const unsigned char *input, size_t size,
		       ARRAY_TYPE(unichars) *output)
{
	unichar_t chr;

	while (size > 0) {
		int len = uni_utf8_get_char_n(input, size, &chr);
		if (len <= 0)
			return -1; /* invalid input */
		input += len; size -= len;

		array_push_back(output, &chr);
	}
	return 0;
}

void uni_ucs4_to_utf8(const unichar_t *input, size_t len, buffer_t *output)
{
	for (; len > 0 && *input != '\0'; input++, len--)
		uni_ucs4_to_utf8_c(*input, output);
}

void uni_ucs4_to_utf8_c(unichar_t chr, buffer_t *output)
{
	unsigned char first;
	int bitpos;

	if (chr < 0x80) {
		buffer_append_c(output, chr);
		return;
	}

	i_assert(uni_is_valid_ucs4(chr));

	if (chr < (1 << (6 + 5))) {
		/* 110xxxxx */
		bitpos = 6;
		first = 0x80 | 0x40;
	} else if (chr < (1 << ((2*6) + 4))) {
		/* 1110xxxx */
		bitpos = 2*6;
		first = 0x80 | 0x40 | 0x20;
	} else if (chr < (1 << ((3*6) + 3))) {
		/* 11110xxx */
		bitpos = 3*6;
		first = 0x80 | 0x40 | 0x20 | 0x10;
	} else if (chr < (1 << ((4*6) + 2))) {
		/* 111110xx */
		bitpos = 4*6;
		first = 0x80 | 0x40 | 0x20 | 0x10 | 0x08;
	} else {
		/* 1111110x */
		bitpos = 5*6;
		first = 0x80 | 0x40 | 0x20 | 0x10 | 0x08 | 0x04;
	}
	buffer_append_c(output, first | (chr >> bitpos));

	do {
		bitpos -= 6;
		buffer_append_c(output, 0x80 | ((chr >> bitpos) & 0x3f));
	} while (bitpos > 0);
}

unsigned int uni_utf8_strlen(const char *input)
{
	return uni_utf8_strlen_n(input, strlen(input));
}

unsigned int uni_utf8_strlen_n(const void *input, size_t size)
{
	size_t partial_pos;

	return uni_utf8_partial_strlen_n(input, size, &partial_pos);
}

unsigned int uni_utf8_partial_strlen_n(const void *_input, size_t size,
				       size_t *partial_pos_r)
{
	const unsigned char *input = _input;
	unsigned int count, len = 0;
	size_t i;

	for (i = 0; i < size; ) {
		count = uni_utf8_char_bytes(input[i]);
		if (i + count > size)
			break;
		i += count;
		len++;
	}
	*partial_pos_r = i;
	return len;
}

unichar_t uni_ucs4_to_titlecase(unichar_t chr)
{
	const struct unicode_code_point_data *cp_data =
		unicode_code_point_get_data(chr);

	if (cp_data->simple_titlecase_mapping != 0x0000)
		return cp_data->simple_titlecase_mapping;
	return chr;
}

static void output_add_replacement_char(buffer_t *output)
{
	if (output->used >= UTF8_REPLACEMENT_CHAR_LEN &&
	    memcmp(CONST_PTR_OFFSET(output->data,
				    output->used - UTF8_REPLACEMENT_CHAR_LEN),
		   utf8_replacement_char, UTF8_REPLACEMENT_CHAR_LEN) == 0) {
		/* don't add the replacement char multiple times */
		return;
	}
	buffer_append(output, utf8_replacement_char, UTF8_REPLACEMENT_CHAR_LEN);
}

int uni_utf8_run_transform(const void *_input, size_t size,
			   struct unicode_transform *trans, buffer_t *output,
			   const char **error_r)
{
	struct unicode_transform *trans_last =
		unicode_transform_get_last(trans);
	struct unicode_buffer_sink sink;
	const unsigned char *input = _input;
	unichar_t chr;
	ssize_t sret;
	bool got_chr = FALSE, bad_cp = FALSE;
	int ret = 0;

	unicode_buffer_sink_init(&sink, output);
	unicode_transform_chain(trans_last, &sink.transform);

	while (size > 0 || got_chr) {
		if (!got_chr) {
			int bytes = uni_utf8_get_char_n(input, size, &chr);
			if (bytes <= 0) {
				/* Invalid input. try the next byte. */
				ret = -1;
				input++; size--;
				if (!bad_cp) {
				       chr = UNICODE_REPLACEMENT_CHAR;
				       bad_cp = TRUE;
				}
			} else {
				input += bytes;
				size -= bytes;
				bad_cp = FALSE;
			}
		}

		sret = unicode_transform_input(trans, &chr, 1, error_r);
		if (sret < 0)
			return -1;
		if (sret > 0)
			got_chr = FALSE;
	}

	int fret = unicode_transform_flush(trans, error_r);
	if (fret < 0)
		i_panic("unicode_transform_flush(): %s", *error_r);
	i_assert(fret == 1);
	return ret;
}

static inline int
uni_utf8_write_nf_common(const void *_input, size_t size,
			 enum unicode_nf_type nf_type, buffer_t *output)
{
	static struct unicode_nf_context ctx;
	const char *error;

	unicode_nf_init(&ctx, nf_type);

	return uni_utf8_run_transform(_input, size, &ctx.transform, output,
				      &error);
}

int uni_utf8_write_nfd(const void *input, size_t size, buffer_t *output)
{
	return uni_utf8_write_nf_common(input, size, UNICODE_NFD, output);
}

int uni_utf8_write_nfkd(const void *input, size_t size, buffer_t *output)
{
	return uni_utf8_write_nf_common(input, size, UNICODE_NFKD, output);
}

int uni_utf8_write_nfc(const void *input, size_t size, buffer_t *output)
{
	return uni_utf8_write_nf_common(input, size, UNICODE_NFC, output);
}

int uni_utf8_write_nfkc(const void *input, size_t size, buffer_t *output)
{
	return uni_utf8_write_nf_common(input, size, UNICODE_NFKC, output);
}

int uni_utf8_to_nfd(const void *input, size_t size, const char **output_r)
{
	buffer_t *output = t_buffer_create(size);

	if (uni_utf8_write_nf_common(input, size, UNICODE_NFD, output) < 0)
		return -1;
	*output_r = str_c(output);
	return 0;
}

int uni_utf8_to_nfkd(const void *input, size_t size, const char **output_r)
{
	buffer_t *output = t_buffer_create(size);

	if (uni_utf8_write_nf_common(input, size, UNICODE_NFKD, output) < 0)
		return -1;
	*output_r = str_c(output);
	return 0;
}

int uni_utf8_to_nfc(const void *input, size_t size, const char **output_r)
{
	buffer_t *output = t_buffer_create(size);

	if (uni_utf8_write_nf_common(input, size, UNICODE_NFC, output) < 0)
		return -1;
	*output_r = str_c(output);
	return 0;
}

int uni_utf8_to_nfkc(const void *input, size_t size, const char **output_r)
{
	buffer_t *output = t_buffer_create(size);

	if (uni_utf8_write_nf_common(input, size, UNICODE_NFKC, output) < 0)
		return -1;
	*output_r = str_c(output);
	return 0;
}

static int
uni_utf8_is_nf(const void *_input, size_t size, enum unicode_nf_type type)
{
	static struct unicode_nf_checker unc;
	const unsigned char *input = _input;
	unichar_t chr;
	int ret;

	unicode_nf_checker_init(&unc, type);

	while (size > 0) {
		const struct unicode_code_point_data *cp_data = NULL;
		int bytes = uni_utf8_get_char_n(input, size, &chr);
		if (bytes <= 0)
			return -1;
		input += bytes;
		size -= bytes;

		ret = unicode_nf_checker_input(&unc, chr, &cp_data);
		if (ret <= 0)
			return ret;
	}

	return unicode_nf_checker_finish(&unc);
}

int uni_utf8_is_nfd(const void *input, size_t size)
{
	return uni_utf8_is_nf(input, size, UNICODE_NFD);
}

int uni_utf8_is_nfkd(const void *input, size_t size)
{
	return uni_utf8_is_nf(input, size, UNICODE_NFKD);
}

int uni_utf8_is_nfc(const void *input, size_t size)
{
	return uni_utf8_is_nf(input, size, UNICODE_NFC);
}

int uni_utf8_is_nfkc(const void *input, size_t size)
{
	return uni_utf8_is_nf(input, size, UNICODE_NFKC);
}

int uni_utf8_write_uppercase(const void *_input, size_t size, buffer_t *output)
{
	static struct unicode_casemap map;
	const char *error;

	unicode_casemap_init_uppercase(&map);

	return uni_utf8_run_transform(_input, size, &map.transform, output,
				      &error);
}

int uni_utf8_write_lowercase(const void *_input, size_t size, buffer_t *output)
{
	static struct unicode_casemap map;
	const char *error;

	unicode_casemap_init_lowercase(&map);

	return uni_utf8_run_transform(_input, size, &map.transform, output,
				      &error);
}

int uni_utf8_write_casefold(const void *_input, size_t size, buffer_t *output)
{
	static struct unicode_casemap map;
	const char *error;

	unicode_casemap_init_casefold(&map);

	return uni_utf8_run_transform(_input, size, &map.transform, output,
				      &error);
}

int uni_utf8_to_uppercase(const void *input, size_t size, const char **output_r)
{
	buffer_t *output = t_buffer_create(size);
	int ret;

	ret = uni_utf8_write_uppercase(input, size, output);
	*output_r = str_c(output);
	return ret;
}

int uni_utf8_to_lowercase(const void *input, size_t size, const char **output_r)
{
	buffer_t *output = t_buffer_create(size);
	int ret;

	ret = uni_utf8_write_lowercase(input, size, output);
	*output_r = str_c(output);
	return ret;
}

int uni_utf8_to_casefold(const void *input, size_t size, const char **output_r)
{
	buffer_t *output = t_buffer_create(size);
	int ret;

	ret = uni_utf8_write_casefold(input, size, output);
	*output_r = str_c(output);
	return ret;
}

int uni_utf8_to_decomposed_titlecase(const void *_input, size_t size,
				     buffer_t *output)
{
	struct unicode_rfc5051_context ctx;
	const unsigned char *input = _input;
	unichar_t chr;
	int ret = 0;

	unicode_rfc5051_init(&ctx);

	while (size > 0) {
		int bytes = uni_utf8_get_char_n(input, size, &chr);
		if (bytes <= 0) {
			/* invalid input. try the next byte. */
			ret = -1;
			input++; size--;
			output_add_replacement_char(output);
			continue;
		}
		input += bytes;
		size -= bytes;

		const unichar_t *norm;
		size_t norm_len;

		norm_len = unicode_rfc5051_normalize(&ctx, chr, &norm);
		uni_ucs4_to_utf8(norm, norm_len, output);
	}
	return ret;
}

static inline unsigned int
is_valid_utf8_seq(const unsigned char *input, unsigned int size)
{
	unichar_t chr;
	int len = uni_utf8_get_char_n(input, size, &chr);
	return len <= 0 ? 0 : len;
}

static int uni_utf8_find_invalid_pos(const unsigned char *input, size_t size,
				     size_t *pos_r)
{
	size_t i, len;

	/* find the first invalid utf8 sequence */
	for (i = 0; i < size;) {
		if (input[i] < 0x80)
			i++;
		else {
			len = is_valid_utf8_seq(input + i, size-i);
			if (unlikely(len == 0)) {
				*pos_r = i;
				return -1;
			}
			i += len;
		}
	}
	return 0;
}

bool uni_utf8_get_valid_data(const unsigned char *input, size_t size,
			     buffer_t *buf)
{
	size_t i, len;

	if (uni_utf8_find_invalid_pos(input, size, &i) == 0)
		return TRUE;

	/* broken utf-8 input - skip the broken characters */
	buffer_append(buf, input, i++);

	output_add_replacement_char(buf);
	while (i < size) {
		if (input[i] < 0x80) {
			buffer_append_c(buf, input[i++]);
			continue;
		}

		len = is_valid_utf8_seq(input + i, size-i);
		if (len == 0) {
			i++;
			output_add_replacement_char(buf);
			continue;
		}
		buffer_append(buf, input + i, len);
		i += len;
	}
	return FALSE;
}

bool uni_utf8_str_is_valid(const char *str)
{
	size_t i;

	return uni_utf8_find_invalid_pos((const unsigned char *)str,
					 strlen(str), &i) == 0;
}

bool uni_utf8_data_is_valid(const unsigned char *data, size_t size)
{
	size_t i;

	return uni_utf8_find_invalid_pos(data, size, &i) == 0;
}

size_t uni_utf8_data_truncate(const unsigned char *data, size_t old_size,
			      size_t max_new_size)
{
	if (max_new_size >= old_size)
		return old_size;
	if (max_new_size == 0)
		return 0;

	if ((data[max_new_size] & 0x80) == 0)
		return max_new_size;
	while (max_new_size > 0 && (data[max_new_size-1] & 0xc0) == 0x80)
		max_new_size--;
	if (max_new_size > 0 && (data[max_new_size-1] & 0xc0) == 0xc0)
		max_new_size--;
	return max_new_size;
}

/*
 * Grapheme clusters
 */

void uni_gc_scanner_init(struct uni_gc_scanner *gcsc,
			 const void *input, size_t size)
{
	i_zero(gcsc);
	unicode_gc_break_init(&gcsc->gcbrk);
	gcsc->p = input;
	gcsc->pend = gcsc->p + size;
}

bool uni_gc_scan_shift(struct uni_gc_scanner *gcsc)
{
	bool first = (gcsc->poffset == NULL);

	/* Reset offset to last grapheme boundary (after the last grapheme
	   cluster we indicated). */
	gcsc->poffset = gcsc->p;
	/* Shift pointer past last code point; starts the next grapheme cluster
	   we shall compose in this call. */
	gcsc->p += gcsc->cp_size;
	gcsc->cp_size = 0;
	while (gcsc->p < gcsc->pend) {
		/* Decode next UTF-8 code point */
		gcsc->cp_size = uni_utf8_get_char_n(
			gcsc->p, gcsc->pend - gcsc->p, &gcsc->cp);
		/* We expect valid and complete UTF-8 input */
		i_assert(gcsc->cp_size > 0);

		/* Determine whether there exists a grapheme cluster boundary
		   before this code point. */
		const struct unicode_code_point_data *cp_data = NULL;
		if (unicode_gc_break_cp(&gcsc->gcbrk, gcsc->cp, &cp_data)) {
			/* Yes, but ignore the very first grapheme boundary that
			   occurs at the start of input. */
			if (!first) {
				/* Grapheme cluster detected, but it does *NOT*
				   include the last code point we decoded just
				   now. */
				i_assert(gcsc->p > gcsc->poffset);
				return TRUE;
			}
			first = FALSE;
		}

		/* Shift pointer past last code point; include this in the next
		   grapheme cluster we shall compose in this call. */
		gcsc->p += gcsc->cp_size;
		gcsc->cp_size = 0;
	}
	/* Return whether there is any last remaining grapheme cluster. */
	return (gcsc->p > gcsc->poffset);
}
