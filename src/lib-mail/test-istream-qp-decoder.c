/* Copyright (c) 2010-2013 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "istream-private.h"
#include "istream-qp.h"

struct {
	const char *input;
	const char *output;
} tests[] = {
	{ "p=C3=A4=C3=A4t=C3=B6s", "päätös" },
	{ "p=c3=a4=c3=a4t=c3=b6s=  ", "päätös" },
	{ "p=c3=a4=c3=a4t=c3=b6s=  \n", "päätös" },
	{ "p=c3=a4= \t \n=c3=\r\n=a4t=  \r\n=c3=b6s", "päätös" },
};

static void
decode_test(const char *qp_input, const char *output, bool broken_input)
{
	unsigned int qp_input_len = strlen(qp_input);
	struct istream *input_data, *input;
	const unsigned char *data;
	size_t i, size;
	int ret = 0;

	input_data = test_istream_create_data(qp_input, qp_input_len);
	test_istream_set_allow_eof(input_data, FALSE);
	input = i_stream_create_qp_decoder(input_data);

	for (i = 1; i <= qp_input_len; i++) {
		test_istream_set_size(input_data, i);
		while ((ret = i_stream_read(input)) > 0) ;
		if (ret == -1 && broken_input)
			break;
		test_assert(ret == 0);
	}
	if (ret == 0) {
		test_istream_set_allow_eof(input_data, TRUE);
		while ((ret = i_stream_read(input)) > 0) ;
	}
	test_assert(ret == -1);
	test_assert((input->stream_errno == 0 && !broken_input) ||
		    (input->stream_errno == EINVAL && broken_input));

	data = i_stream_get_data(input, &size);
	test_assert(size == strlen(output) && memcmp(data, output, size) == 0);
	i_stream_unref(&input);
	i_stream_unref(&input_data);
}

static void test_istream_qp_decoder(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		test_begin(t_strdup_printf("istream qp decoder %u", i+1));
		decode_test(tests[i].input, tests[i].output, FALSE);
		test_end();
	}
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_istream_qp_decoder,
		NULL
	};
	return test_run(test_functions);
}
