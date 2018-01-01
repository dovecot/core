/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "qp-encoder.h"
#include "test-common.h"

struct test_quoted_printable_encode_data {
	const void *input;
	size_t input_len;
	const char *output;
};

static void test_qp_encoder(void)
{
	static struct test_quoted_printable_encode_data tests[] = {
		{ "", 0, "" },
		{ "a", 1, "a" },
		{ "a b \r c d", 9, "a b =0D c d" },
		{ "a b \n c d", 9, "a b \r\n c d" },
		{
		  "test wrap at max 20 characters tab\ttoo", 38,
		  "test wrap at max=20=\r\n20 characters tab=09=\r\ntoo"
		},
		{ "Invalid UTF-8 sequence in \x99", 27, "Invalid UTF-8 sequ=\r\nence in =99" },
		{ "keep CRLF\r\non two lines", 23, "keep CRLF\r\non two lines" },
	};
	string_t *str;
	unsigned int i, j;

	test_begin("qp-encoder");
	str = t_str_new(128);
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		const unsigned char *input = tests[i].input;
		struct qp_encoder *qp = qp_encoder_init(str, 20, 0);

		/* try all at once */
		qp_encoder_more(qp, input, tests[i].input_len);
		qp_encoder_finish(qp);

		test_assert_idx(strcmp(str_c(str), tests[i].output) == 0, i);

		/* try in small pieces */
		str_truncate(str, 0);
		for (j = 0; j < tests[i].input_len; j++) {
			unsigned char c = input[j];
			qp_encoder_more(qp, &c, 1);
		}
		qp_encoder_finish(qp);
		test_assert_idx(strcmp(str_c(str), tests[i].output) == 0, i);

		qp_encoder_deinit(&qp);
		str_truncate(str, 0);
	}
	test_end();
}

static void test_qp_encoder_binary(void)
{
	static struct test_quoted_printable_encode_data tests[] = {
		{ "\0nil\0delimited\0string\0", 22, "=00nil=00delimited=\r\n=00string=00" },
		{
		  "\xef\x4e\xc5\xe0\x31\x66\xd7\xef\xae\x12\x7d\x45\x1e\x05\xc7\x2a",
		  16,
		  "=EFN=C5=E01f=D7=EF=\r\n=AE=12}E=1E=05=C7*"
		},
	};

	string_t *str;
	unsigned int i, j;

	test_begin("qp-encoder (binary safe)");
	str = t_str_new(128);
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		const unsigned char *input = tests[i].input;
		struct qp_encoder *qp = qp_encoder_init(str, 20, QP_ENCODER_FLAG_BINARY_DATA);

		/* try all at once */
		qp_encoder_more(qp, input, tests[i].input_len);
		qp_encoder_finish(qp);

		test_assert_idx(strcmp(str_c(str), tests[i].output) == 0, i);

		/* try in small pieces */
		str_truncate(str, 0);
		for (j = 0; j < tests[i].input_len; j++) {
			unsigned char c = input[j];
			qp_encoder_more(qp, &c, 1);
		}
		qp_encoder_finish(qp);
		test_assert_idx(strcmp(str_c(str), tests[i].output) == 0, i);

		qp_encoder_deinit(&qp);
		str_truncate(str, 0);
	}
	test_end();
}

static void test_qp_encoder_header(void)
{
        static struct test_quoted_printable_encode_data tests[] = {
		{ "simple", 6, "=?utf-8?Q?simple?=" },
		{ "J'esuis de paris caf\xc3\xa9", 22, "=?utf-8?Q?J'esuis_de_paris_caf=C3=A9?=" },
		{ "hello_world", 11, "=?utf-8?Q?hello=5Fworld?=" },
		{
		  "make sure this wraps and that the actual lines are not longer than maximum length including preamble",
		  100,
		  "=?utf-8?Q?make_sure_this_wraps_and_that_the_actual_lines_are_not_longer_t?=\r\n"
		  " =?utf-8?Q?han_maximum_length_including_preamble?="
		},
        };

        string_t *str;
        unsigned int i, j;

        test_begin("qp-encoder (header format)");
        str = t_str_new(128);
        for (i = 0; i < N_ELEMENTS(tests); i++) {
                const unsigned char *input = tests[i].input;
                struct qp_encoder *qp = qp_encoder_init(str, 75, QP_ENCODER_FLAG_HEADER_FORMAT);

                /* try all at once */
                qp_encoder_more(qp, input, tests[i].input_len);
                qp_encoder_finish(qp);

                test_assert_idx(strcmp(str_c(str), tests[i].output) == 0, i);

                /* try in small pieces */
                str_truncate(str, 0);
                for (j = 0; j < tests[i].input_len; j++) {
                        unsigned char c = input[j];
                        qp_encoder_more(qp, &c, 1);
                }
                qp_encoder_finish(qp);
                test_assert_idx(strcmp(str_c(str), tests[i].output) == 0, i);

                qp_encoder_deinit(&qp);
                str_truncate(str, 0);
        }
        test_end();
}


int main(void)
{
	static void (*const test_functions[])(void) = {
		test_qp_encoder,
		test_qp_encoder_binary,
		test_qp_encoder_header,
		NULL
	};
	return test_run(test_functions);
}
