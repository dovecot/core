/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "istream-private.h"
#include "istream-qp.h"

static const struct {
	const char *input;
	const char *output;
	int stream_errno;
	int eof;
} tests[] = {
	{ "p=C3=A4=C3=A4t=C3=B6s", "p\xC3\xA4\xC3\xA4t\xC3\xB6s", 0 , 0 },
	{ "p=c3=a4=c3=a4t=c3=b6s=  \n", "p\xC3\xA4\xC3\xA4t\xC3\xB6s", 0, 0 },
	{ "p=c3=a4= \t \n=c3=\r\n=a4t=  \r\n=c3=b6s", "p\xC3\xA4\xC3\xA4t\xC3\xB6s", 0, 1 },
	{ "p=c3=a4= \t \n=c3=\r\n=a4t=  \r\n=c3=b6s", "p\xC3\xA4\xC3\xA4t\xC3\xB6s", 0, 2 },
	{ "p=c3=a4= \t \n=c3=\r\n=a4t=  \r\n=c3=b6s", "p\xC3\xA4\xC3\xA4t\xC3\xB6s", 0, 3 },
	{ "p=c3=a4= \t \n=c3=\r\n=a4t=  \r\n=c3=b6s", "p\xC3\xA4\xC3\xA4t\xC3\xB6s", 0, 4 },
	{ "p=c3=a4= \t \n=c3=\r\n=a4t=  \r\n=c3=b6s", "p\xC3\xA4\xC3\xA4t\xC3\xB6s", 0, 5 },
	{ "p=c3=a4= \t \n=c3=\r\n=a4t=  \r\n=c3=b6s", "p\xC3\xA4\xC3\xA4t\xC3\xB6s", 0, 7 },
	{ "p=c3", "p\xC3", 0, 2 },
	{ "=0A=0D  ", "\n\r", 0, 4 },
	{ "foo_bar", "foo_bar", 0, 0 },
	{ "\n\n", "\r\n\r\n", 0, 0 },
	{ "\r\n\n\n\r\n", "\r\n\r\n\r\n\r\n", 0, 0 },
	/* Unnecessarily encoded */
	{ "=66=6f=6f=42=61=72", "fooBar", 0, 4 },
	/* Expected to be encoded but not */
	{ "\xc3\x9c""berm=c3=a4\xc3\x9figer Gebrauch", "\xc3\x9c""berm\xc3\xa4\xc3\x9figer Gebrauch", 0, 9 },
	/* Decode control characters */
	{ "=0C=07", "\x0C\x07", 0, 0 },
	/* Data */
	{ "=DE=AD=BE=EF", "\xDE\xAD\xBE\xEF", 0, 0 },
	/* Non hex data */
	{ "=FJ=X1", "", EINVAL, 0 },
	/* No content allowed after Soft Line Break */
	{ "=C3=9C = ","\xc3\x9c ", EPIPE, 0 },
	/* Boundary delimiter */
	{ "=C3=9C=\r\n-------","\xc3\x9c-------", 0, 0 },
	{ "=----------- =C3=9C","", EINVAL, 0 },
	{ "=___________ =C3=9C","", EINVAL, 0 },
	{ "___________ =C3=9C","___________ \xc3\x9c", 0, 0 },
	{ "=2D=2D=2D=2D=2D=2D =C3=9C","------ \xc3\x9c", 0, 0 },
	{ "=FC=83=BF=BF=BF=BF", "\xFC\x83\xBF\xBF\xBF\xBF", 0, 0 },
	{ "=FE=FE=FF=FF", "\xFE\xFE\xFF\xFF", 0, 0 },
	{ "\xFF=C3=9C\xFE\xFF""foobar", "\xFF\xc3\x9c\xFE\xFF""foobar", 0, 0 },

	{ "p=c3=a4\rasdf", "p\xC3\xA4", EINVAL, 0 },
	{ "=___________ \xc3\x9c","", EINVAL, 0 },
	{ "p=c", "p", EPIPE, 0 },
	{ "p=A", "p", EPIPE, 0 },
	{ "p=Ax", "p", EINVAL, 0 },
	{ "___________ \xc3\x9c=C3=9","___________ \xc3\x9c\xC3", EPIPE, 0},
	{ "p=c3=a4=c3=a4t=c3=b6s=  ", "p\xC3\xA4\xC3\xA4t\xC3\xB6s", EPIPE, 0 },
	/* Soft Line Break example from the RFC */
	{
		"Now's the time =\r\nfor all folk to come=\r\n to the aid of "
		"their country.", "Now's the time for all folk to come to the"
		" aid of their country.", 0, 41
	},
};

static bool is_hex(char c) {
	return ((c >= 48 && c <= 57) || (c >= 65 && c <= 70)
		|| (c >= 97 && c <= 102));

}

static unsigned int
get_encoding_size_diff(const char *qp_input, unsigned int limit)
{
	unsigned int encoded_chars = 0;
	unsigned int soft_line_breaks = 0;
	for (unsigned int i = 0; i < limit; i++) {
		char c = qp_input[i];
		if (c == '=' && i+2 < limit) {
			if (qp_input[i+1] == '\r' && qp_input[i+2] == '\n') {
				soft_line_breaks++;
				i += 2;
				limit += 3;
			} else if (is_hex(qp_input[i+1]) && is_hex(qp_input[i+2])) {
				encoded_chars++;
				i += 2;
				limit += 2;
			}
		}
	}
	return encoded_chars*2 + soft_line_breaks*3;
}

static void
decode_test(const char *qp_input, const char *output, int stream_errno,
	    unsigned int buffer_size, unsigned int eof)
{
	size_t qp_input_len = strlen(qp_input);
	struct istream *input_data, *input_data_limited, *input;
	const unsigned char *data;
	size_t i, size;
	string_t *str = t_str_new(32);
	int ret = 0;

	input_data = test_istream_create_data(qp_input, qp_input_len);
	test_istream_set_max_buffer_size(input_data, buffer_size);
	test_istream_set_allow_eof(input_data, FALSE);
	input = i_stream_create_qp_decoder(input_data);

	for (i = 1; i <= qp_input_len; i++) {
		test_istream_set_size(input_data, i);
		while ((ret = i_stream_read_more(input, &data, &size)) > 0) {
			str_append_data(str, data, size);
			i_stream_skip(input, size);
		}
		if (ret == -1 && stream_errno != 0)
			break;
		test_assert(ret == 0);
	}
	if (ret == 0) {
		test_istream_set_allow_eof(input_data, TRUE);
		while ((ret = i_stream_read_more(input, &data, &size)) > 0) {
			str_append_data(str, data, size);
			i_stream_skip(input, size);
		}
	}
	test_assert(ret == -1);
	test_assert(input->stream_errno == stream_errno);

	if (stream_errno == 0) {
		/* Test seeking on streams where the testcases do not
		 * expect a specific errno already */
		uoff_t v_off = input->v_offset;
		/* Seeking backwards */
		i_stream_seek(input, 0);
		test_assert(input->v_offset == 0);

		/* Seeking forward */
		i_stream_seek(input, v_off+1);
		test_assert(input->stream_errno == ESPIPE);
	}
	/* Compare outputs */
	test_assert_strcmp(str_c(str), output);

	if (eof > 0) {
		/* Insert early EOF into input_data */
		i_stream_seek(input_data, 0);
		str_truncate(str, 0);
		input_data_limited = i_stream_create_limit(input_data, eof);
		test_istream_set_allow_eof(input_data_limited, TRUE);
		i_stream_unref(&input);
		input = i_stream_create_qp_decoder(input_data_limited);
		while ((ret = i_stream_read_more(input, &data, &size)) > 0) {
			str_append_data(str, data, size);
			i_stream_skip(input, size);
		}
		test_assert(ret == -1);
		/* If there is no error still assume that the result is valid
		 * till artifical eof. */
		if (input->stream_errno == 0) {
			unsigned int encoding_margin =
				get_encoding_size_diff(qp_input, eof);

			/* Cut the expected output at eof of input*/
			const char *expected_output =
				t_strdup_printf("%.*s", eof-encoding_margin,
						output);
			test_assert_strcmp(str_c(str), expected_output);
		}
		test_assert(input->eof);
		i_stream_unref(&input_data_limited);
	}

	i_stream_unref(&input);
	i_stream_unref(&input_data);
}

static void test_istream_qp_decoder(void)
{
	unsigned int i, j;

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		test_begin(t_strdup_printf("istream qp decoder %u", i+1));
		for (j = 1; j < 10; j++) T_BEGIN {
			decode_test(tests[i].input, tests[i].output,
				    tests[i].stream_errno, j, tests[i].eof);
		} T_END;
		test_end();
	}
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_istream_qp_decoder,
		NULL
	};
	return test_run(test_functions);
}
