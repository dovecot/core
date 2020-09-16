/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "unichar.h"
#include "base64.h"
#include "message-header-encode.h"

#define MIME_WRAPPER_LEN (strlen("=?utf-8?q?""?="))
#define MIME_MAX_LINE_LEN 76

#define IS_LWSP(c) \
	((c) == ' ' || (c) == '\t' || (c) == '\n')

static bool
input_idx_need_encoding(const unsigned char *input, size_t i, size_t len)
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

void message_header_encode_q(const unsigned char *input, size_t len,
			     string_t *output, size_t first_line_len)
{
	static const unsigned char *rep_char =
		(const unsigned char *)UNICODE_REPLACEMENT_CHAR_UTF8;
	static const unsigned int rep_char_len =
		UNICODE_REPLACEMENT_CHAR_UTF8_LEN;
	size_t line_len_left;
	bool invalid_char = FALSE;

	if (len == 0)
		return;

	line_len_left = MIME_MAX_LINE_LEN - MIME_WRAPPER_LEN;

	if (first_line_len >= MIME_MAX_LINE_LEN - MIME_WRAPPER_LEN - 3) {
		str_append(output, "\n\t");
		line_len_left--;
	} else {
		line_len_left -= first_line_len;
	}

	str_append(output, "=?utf-8?q?");
	for (;;) {
		unichar_t ch;
		int nch = 1;
		size_t n_in, n_out = 0, j;

		/* Determine how many bytes are to be consumed from input and
		   written to output. */
		switch (input[0]) {
		case ' ':
			/* Space is translated to a single '_'. */
			n_out = 1;
			n_in = 1;
			break;
		case '=':
		case '?':
		case '_':
			/* Special characters are escaped. */
			n_in = 1;
			n_out = 3;
			break;
		default:
			nch = uni_utf8_get_char_n(input, len, &ch);
			if (nch <= 0) {
				/* Invalid UTF-8 character */
				n_in = 1;
				if (!invalid_char) {
					/* First octet of bad stuff; will emit
					   replacement character. */
					n_out = rep_char_len * 3;
				} else {
					/* Emit only one replacement char for
					   a burst of bad stuff. */
					n_out = 0;
				}
			} else if (nch > 1) {
				/* Unicode characters are escaped as several
				   escape sequences for each octet. */
				n_in = nch;
				n_out = nch * 3;
			} else if (ch < 0x20 || ch > 0x7e) {
				/* Control characters are escaped. */
				i_assert(ch < 0x80);
				n_in = 1;
				n_out = 3;
			} else {
				/* Other ASCII characters are written to output
				   directly. */
				n_in = 1;
				n_out = 1;
			}
		}
		invalid_char = (nch <= 0);

		/* Start a new line once unsufficient space is available to
		   write more to the current line. */
		if (line_len_left < n_out) {
			str_append(output, "?=\n\t=?utf-8?q?");
			line_len_left = MIME_MAX_LINE_LEN -
				MIME_WRAPPER_LEN - 1;
		}

		/* Encode the character */
		if (input[0] == ' ') {
			/* Write special escape sequence for space character */
			str_append_c(output, '_');
		} else if (invalid_char) {
			/* Write replacement character for invalid UTF-8 code
			   point. */
			for (j = 0; n_out > 0 && j < rep_char_len; j++)
				str_printfa(output, "=%02X", rep_char[j]);
		} else if (n_out > 1) {
			/* Write one or more escape sequences for a special
			   character, a control character, or a valid UTF-8
			   code point. */
			for (j = 0; j < n_in; j++)
				str_printfa(output, "=%02X", input[j]);
		} else {
			/* Write other ASCII characters directly to output. */
			str_append_c(output, input[0]);
		}

		/* Update sizes and pointers */
		i_assert(len >= n_in);
		line_len_left -= n_out;
		input += n_in;
		len -= n_in;

		if (len == 0)
			break;
	}
	str_append(output, "?=");
}

void message_header_encode_b(const unsigned char *input, size_t len,
			     string_t *output, size_t first_line_len)
{
	size_t line_len, line_len_left, max;

	if (len == 0)
		return;

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

void message_header_encode_data(const unsigned char *input, size_t len,
				string_t *output)
{
	size_t i, j, first_line_len, cur_line_len, last_idx;
	size_t enc_chars, enc_len, base64_len, q_len;
	const unsigned char *next_line_input;
	size_t next_line_len = 0;
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
