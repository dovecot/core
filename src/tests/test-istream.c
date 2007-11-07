/* Copyright (c) 2007 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "istream-internal.h"
#include "istream-crlf.h"

static void test_istream_crlf_input(const char *input, unsigned int num)
{
	string_t *output;
	const unsigned char *data;
	size_t size;
	ssize_t ret;
	unsigned int i, j, pos, input_len = strlen(input);
	struct istream *istream, *crlf_istream;
	bool success;

	output = t_str_new(256);

	for (j = 0; j < 2; j++) {
		istream = i_stream_create_from_data(input, input_len);
		success = TRUE;
		str_truncate(output, 0);
		if (j == 0) {
			/* drop CRs */
			crlf_istream = i_stream_create_lf(istream);
			for (i = 0; i < input_len; i++) {
				if (input[i] == '\r' &&
				    (i == input_len || input[i+1] == '\n'))
					;
				else
					str_append_c(output, input[i]);
			}
		} else {
			/* add missing CRs */
			crlf_istream = i_stream_create_crlf(istream);
			for (i = 0; i < input_len; i++) {
				if (input[i] == '\n' &&
				    (i == 0 || input[i-1] != '\r'))
					str_append_c(output, '\r');
				str_append_c(output, input[i]);
			}
		}

		pos = 0;
		for (i = 1; i <= input_len; i++) {
			istream->real_stream->pos = i;
			if (crlf_istream->real_stream->buffer_size != 0) {
				/* this is pretty evil */
				crlf_istream->real_stream->buffer_size =
					I_MAX(crlf_istream->real_stream->pos, i);
			}
			ret = i_stream_read(crlf_istream);
			data = i_stream_get_data(crlf_istream, &size);
			if (ret > 0) {
				if (pos + (unsigned int)ret != size) {
					success = FALSE;
					break;
				}
				pos += ret;
			}
			if (memcmp(data, str_data(output), size) != 0) {
				success = FALSE;
				break;
			}
		}
		if (size != str_len(output))
			success = FALSE;
		i_stream_unref(&crlf_istream);
		i_stream_unref(&istream);

		test_out(t_strdup_printf("test_istream_crlf(%d)", num*2+j),
			 success);
	}
}

static void test_istream_crlf(void)
{
	const char *input[] = {
		"foo\nbar\r\nbaz\r\r\n",
		"\rfoo",
		"\r\nfoo",
		"\r\r\n",
		"\nfoo"
	};
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(input); i++)
		test_istream_crlf_input(input[i], i);
}

void test_istreams(void)
{
	test_istream_crlf();
}
