/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "istream-private.h"
#include "istream-qp.h"

static const struct {
	const char *input;
	const char *output;
	int stream_errno;
} tests[] = {
	{ "p=C3=A4=C3=A4t=C3=B6s", "p\xC3\xA4\xC3\xA4t\xC3\xB6s", 0 },
	{ "p=c3=a4=c3=a4t=c3=b6s=  \n", "p\xC3\xA4\xC3\xA4t\xC3\xB6s", 0 },
	{ "p=c3=a4= \t \n=c3=\r\n=a4t=  \r\n=c3=b6s", "p\xC3\xA4\xC3\xA4t\xC3\xB6s", 0 },

	{ "p=c3=a4\rasdf", "p\xC3\xA4", EINVAL },
	{ "p=c", "p", EPIPE },
	{ "p=A", "p", EPIPE },
	{ "p=Ax", "p", EINVAL },
	{ "p=c3=a4=c3=a4t=c3=b6s=  ", "p\xC3\xA4\xC3\xA4t\xC3\xB6s", EPIPE }
};

static void
decode_test(const char *qp_input, const char *output, int stream_errno,
	    unsigned int buffer_size)
{
	size_t qp_input_len = strlen(qp_input);
	struct istream *input_data, *input;
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

	test_assert(strcmp(str_c(str), output) == 0);
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
				    tests[i].stream_errno, j);
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
