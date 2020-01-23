/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "base64.h"
#include "message-header-encode.h"

#define MIME_WRAPPER_LEN (strlen("=?utf-8?q?""?="))
#define MIME_MAX_LINE_LEN 76

#define IS_LWSP(c) \
	((c) == ' ' || (c) == '\t' || (c) == '\n')

static bool input_idx_need_encoding(const unsigned char *input,
				    unsigned int i, unsigned int len)
{
	switch (input[i]) {
	case '\r':
		if (i+1 == len || input[i+1] != '\n')
			return TRUE;
		i++;
		/* fall through - verify the LF as well */
	case '\n':
		if (i+1 == len) {
			/* trailing LF - we need to drop it */
			return TRUE;
		}
		i_assert(i+1 < len);
		if (input[i+1] != '\t' && input[i+1] != ' ') {
			/* LF not followed by whitespace - we need to
			   add the whitespace */
			return TRUE;
		}
		break;
	case '\t':
		/* TAB doesn't need to be encoded */
		break;
	case '=':
		/* <LWSP>=? - we need to check backwards a bit to see if
		   there is LWSP (note that we don't want to return TRUE for
		   the LWSP itself yet, so we need to do this backwards
		   check) */
		if ((i == 0 || IS_LWSP(input[i-1])) && i+2 <= len &&
		    memcmp(input + i, "=?", 2) == 0)
			return TRUE;
		break;
	default:
		/* 8bit chars */
		if ((input[i] & 0x80) != 0)
			return TRUE;
		/* control chars */
		if (input[i] < 32)
			return TRUE;
		break;
	}
	return FALSE;
}

void message_header_encode_q(const unsigned char *input, unsigned int len,
			     string_t *output, unsigned int first_line_len)
{
	unsigned int i, line_len_left;

	line_len_left = MIME_MAX_LINE_LEN - MIME_WRAPPER_LEN;

	if (first_line_len >= MIME_MAX_LINE_LEN - MIME_WRAPPER_LEN - 3) {
		str_append(output, "\n\t");
		line_len_left--;
	} else {
		line_len_left -= first_line_len;
	}

	str_append(output, "=?utf-8?q?");
	for (i = 0; i < len; i++) {
		if (line_len_left < 3) {
			/* if we're not at the beginning of an UTF8 character,
			   go backwards until we are */
			while (i > 0 && (input[i] & 0xc0) == 0x80) {
				str_truncate(output, str_len(output)-3);
				i--;
			}
			str_append(output, "?=\n\t=?utf-8?q?");
			line_len_left = MIME_MAX_LINE_LEN -
				MIME_WRAPPER_LEN - 1;
		}
		switch (input[i]) {
		case ' ':
			str_append_c(output, '_');
			break;
		case '=':
		case '?':
		case '_':
			line_len_left -= 2;
			str_printfa(output, "=%02X", input[i]);
			break;
		default:
			if (input[i] < 32 || (input[i] & 0x80) != 0) {
				line_len_left -= 2;
				str_printfa(output, "=%02X", input[i]);
			} else {
				str_append_c(output, input[i]);
			}
			break;
		}
		line_len_left--;
	}
	str_append(output, "?=");
}

void message_header_encode_b(const unsigned char *input, unsigned int len,
			     string_t *output, unsigned int first_line_len)
{
	unsigned int line_len, line_len_left, max;

	line_len = first_line_len;
	if (line_len >= MIME_MAX_LINE_LEN - MIME_WRAPPER_LEN) {
		str_append(output, "\n\t");
		line_len = 1;
	}

	for (;;) {
		line_len_left = MIME_MAX_LINE_LEN - MIME_WRAPPER_LEN - line_len;
		max = MAX_BASE64_DECODED_SIZE(line_len_left);
		do {
			max--;
			if (max > len)
				max = len;
			else {
				/* all of it doesn't fit. find a character where we
				   can split it from. */
				while (max > 0 && (input[max] & 0xc0) == 0x80)
					max--;
			}
		} while (MAX_BASE64_ENCODED_SIZE(max) > line_len_left &&
			 max > 0);

		if (max > 0) {
			str_append(output, "=?utf-8?b?");
			base64_encode(input, max, output);
			str_append(output, "?=");
		}

		input += max;
		len -= max;

		if (len == 0)
			break;

		str_append(output, "\n\t");
		line_len = 1;
	}
}

void message_header_encode(const char *input, string_t *output)
{
	message_header_encode_data((const void *)input, strlen(input), output);
}

void message_header_encode_data(const unsigned char *input, unsigned int len,
				string_t *output)
{
	unsigned int i, j, first_line_len, cur_line_len, last_idx;
	unsigned int enc_chars, enc_len, base64_len, q_len;
	const unsigned char *next_line_input;
	unsigned int next_line_len = 0;
	bool use_q, cr;

	/* find the first word that needs encoding */
	for (i = 0; i < len; i++) {
		if (input_idx_need_encoding(input, i, len))
			break;
	}
	if (i == len) {
		/* no encoding necessary */
		str_append_data(output, input, len);
		return;
	}
	/* go back to the beginning of the word so it is fully encoded */
	if (input[i] != '\r' && input[i] != '\n') {
		while (i > 0 && !IS_LWSP(input[i-1]))
			i--;
	}

	/* write the prefix */
	str_append_data(output, input, i);
	first_line_len = j = i;
	while (j > 0 && input[j-1] != '\n') j--;
	if (j != 0)
		first_line_len = j;

	input += i;
	len -= i;

	/* we'll encode data only up to the next LF, the rest is handled
	   recursively. */
	next_line_input = memchr(input, '\n', len);
	if (next_line_input != NULL) {
		cur_line_len = next_line_input - input;
		if (cur_line_len > 0 && input[cur_line_len-1] == '\r') {
			cur_line_len--;
			next_line_input = input + cur_line_len;
		}
		next_line_len = len - cur_line_len;
		len = cur_line_len;
	}

	/* find the last word that needs encoding */
	last_idx = 0; enc_chars = 0;
	for (i = 0; i < len; i++) {
		if (input_idx_need_encoding(input, i, len)) {
			last_idx = i + 1;
			enc_chars++;
		}
	}
	while (last_idx < len && !IS_LWSP(input[last_idx]))
		last_idx++;

	/* figure out if we should use Q or B encoding. Prefer Q if it's not
	   too much larger. */
	enc_len = last_idx;
	base64_len = MAX_BASE64_ENCODED_SIZE(enc_len);
	q_len = enc_len + enc_chars*3;
	use_q = q_len*2/3 <= base64_len;

	/* and do it */
	if (enc_len == 0)
		;
	else if (use_q)
		message_header_encode_q(input, enc_len, output, first_line_len);
	else
		message_header_encode_b(input, enc_len, output, first_line_len);
	str_append_data(output, input + last_idx, len - last_idx);

	if (next_line_input != NULL) {
		/* we're at [CR]LF */
		i = 0;
		if (next_line_input[0] == '\r') {
			cr = TRUE;
			i++;
		} else {
			cr = FALSE;
		}
		i_assert(next_line_input[i] == '\n');
		if (++i == next_line_len)
			return; /* drop trailing [CR]LF */

		if (cr)
			str_append_c(output, '\r');
		str_append_c(output, '\n');

		if (next_line_input[i] == ' ' || next_line_input[i] == '\t') {
			str_append_c(output, next_line_input[i]);
			i++;
		} else {
			/* make it valid folding whitespace by adding a TAB */
			str_append_c(output, '\t');
		}
		message_header_encode_data(next_line_input+i, next_line_len-i,
					   output);
	}
}
