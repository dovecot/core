/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "istream-internal.h"
#include "istream-crlf.h"

static void test_istream_crlf_input(const char *input)
{
	string_t *output;
	const unsigned char *data;
	size_t size = 0;
	ssize_t ret1, ret2;
	unsigned int i, j, pos, input_len = strlen(input);
	struct istream *istream, *crlf_istream;

	output = t_str_new(256);

	for (j = 0; j < 4; j++) {
		istream = i_stream_create_from_data(input, input_len);
		str_truncate(output, 0);
		if (j%2 == 0) {
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
			if (j >= 2) {
				i_stream_unref(&istream);
				i_stream_unref(&crlf_istream);
				istream = i_stream_create_from_data(input,
								    input_len);
				crlf_istream = j%2 == 0 ?
					i_stream_create_lf(istream) :
					i_stream_create_crlf(istream);
				pos = 0;
			}
			istream->real_stream->pos = i;
			ret1 = i_stream_read(crlf_istream);
			if (crlf_istream->real_stream->buffer_size != 0) {
				/* this is pretty evil */
				crlf_istream->real_stream->buffer_size =
					I_MAX(crlf_istream->real_stream->pos, i);
			}
			ret2 = i_stream_read(crlf_istream);
			data = i_stream_get_data(crlf_istream, &size);
			if (ret1 > 0 || ret2 > 0) {
				ret1 = I_MAX(ret1, 0) + I_MAX(ret2, 0);
				test_assert(pos + (unsigned int)ret1 == size);
				pos += ret1;
			}
			test_assert(memcmp(data, str_data(output), size) == 0);
		}
		test_assert(size == str_len(output));
		i_stream_unref(&crlf_istream);
		i_stream_unref(&istream);
	}
}

void test_istream_crlf(void)
{
	const char *input[] = {
		"\rfoo",
		"foo\nbar\r\nbaz\r\r\n",
		"\r\nfoo",
		"\r\r\n",
		"\nfoo"
	};
	unsigned int i;

	test_begin("istream crlf");
	for (i = 0; i < N_ELEMENTS(input); i++)
		test_istream_crlf_input(input[i]);
	test_end();
}
