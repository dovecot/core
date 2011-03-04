/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "base64.h"
#include "message-header-encode.h"

#define MIME_WRAPPER_LEN (strlen("=?utf-8?q?""?="))
#define MIME_MAX_LINE_LEN 76

#define IS_LWSP(c) \
	((c) == ' ' || (c) == '\t' || (c) == '\n')

static bool input_idx_need_encoding(const unsigned char *input, unsigned int i)
{
	if ((input[i] & 0x80) != 0)
		return TRUE;

	if (input[i] == '=' && input[i+1] == '?' &&
	    (i == 0 || IS_LWSP(input[i-1])))
		return TRUE;
	return FALSE;
}

static unsigned int str_last_line_len(string_t *str)
{
	const unsigned char *data = str_data(str);
	unsigned int i = str_len(str);

	while (i > 0 && data[i-1] != '\n')
		i--;
	return str_len(str) - i;
}

void message_header_encode_q(const unsigned char *input, unsigned int len,
			     string_t *output)
{
	unsigned int i, line_len, line_len_left;

	line_len = str_last_line_len(output);
	if (line_len >= MIME_MAX_LINE_LEN - MIME_WRAPPER_LEN - 3) {
		str_append(output, "\n\t");
		line_len = 1;
	}

	str_append(output, "=?utf-8?q?");
	line_len_left = MIME_MAX_LINE_LEN - MIME_WRAPPER_LEN - line_len;
	for (i = 0; i < len; i++) {
		if (line_len_left < 3) {
			/* if we're not at the beginning of a character,
			   go backwards until we are */
			while ((input[i] & 0xc0) == 0x80) {
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
			str_printfa(output, "=%2X", input[i]);
			break;
		default:
			if (input[i] < 32 || (input[i] & 0x80) != 0) {
				line_len_left -= 2;
				str_printfa(output, "=%2X", input[i]);
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
			     string_t *output)
{
	unsigned int line_len, line_len_left, max;

	line_len = str_last_line_len(output);
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

void message_header_encode(const char *_input, string_t *output)
{
	const unsigned char *input = (const unsigned char *)_input;
	unsigned int i, first_idx, last_idx;
	unsigned int enc_chars, enc_len, base64_len, q_len;
	bool use_q;

	/* find the first word that needs encoding */
	for (i = 0; input[i] != '\0'; i++) {
		if (input_idx_need_encoding(input, i))
			break;
	}
	if (input[i] == '\0') {
		/* no encoding necessary */
		str_append(output, _input);
		return;
	}
	first_idx = i;
	while (first_idx > 0 && !IS_LWSP(input[first_idx-1]))
		first_idx--;

	/* find the last word that needs encoding */
	last_idx = ++i; enc_chars = 1;
	for (; input[i] != '\0'; i++) {
		if (input_idx_need_encoding(input, i)) {
			last_idx = i + 1;
			enc_chars++;
		}
	}
	while (input[last_idx] != '\0' && !IS_LWSP(input[last_idx]))
		last_idx++;

	/* figure out if we should use Q or B encoding. Prefer Q if it's not
	   too much larger. */
	enc_len = last_idx - first_idx;
	base64_len = MAX_BASE64_ENCODED_SIZE(enc_len);
	q_len = enc_len + enc_chars*3;
	use_q = q_len*2/3 <= base64_len;

	/* and do it */
	str_append_n(output, input, first_idx);
	if (use_q)
		message_header_encode_q(input + first_idx, enc_len, output);
	else
		message_header_encode_b(input + first_idx, enc_len, output);
	str_append(output, _input + last_idx);
}
