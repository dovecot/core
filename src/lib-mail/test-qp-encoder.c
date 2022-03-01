/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "qp-encoder.h"
#include "test-common.h"

struct test_quoted_printable_encode_data {
	const void *input;
	size_t input_len;
	const char *output;
	size_t max_line_len;
};

static void test_qp_encoder(void)
{
#define WHITESPACE10 "   \t   \t \t"
#define WHITESPACE70 WHITESPACE10 WHITESPACE10 WHITESPACE10 WHITESPACE10 WHITESPACE10 WHITESPACE10 WHITESPACE10
	static struct test_quoted_printable_encode_data tests[] = {
		{ "", 0, "", 20 },
		{ "a", 1, "a", 20 },
		{ "a b \r c d", 9, "a b =0D c d", 20 },
		{ "a b c d\r", 8, "a b c d=0D", 20 },
		{ "a b \n c d", 9, "a b \r\n c d", 20 },
		{
		  "test wrap at max 20 characters tab\ttoo", 38,
		  "test wrap at max=20=\r\n20 characters tab=09=\r\ntoo",
		   20
		},
		{ "Invalid UTF-8 sequence in \x99", 27, "Invalid UTF-8 sequ=\r\nence in =99", 20 },
		{ "keep CRLF\r\non two lines", 23, "keep CRLF\r\non two lines", 20 },
		/* Trailing whitespace should be followed by encoded char. */
		{ "Keep trailing whitesp\xC3\xA4""ce ", 26, "Keep trailing whit=\r\nesp=C3=A4ce =", 20 },
		{ "Keep trailing whitesp\xC3\xA4""ce\t", 26, "Keep trailing whitesp=C3=A4ce\t=", 67 },
		{ "Keep trailing whitesp\xC3\xA4""ce ", 26, "Keep trailing whitesp=C3=A4ce =", 67 },
		{ "Keep trailing whitesp\xC3\xA4""ce   ", 28, "Keep trailing whitesp=C3=A4ce   =", 67 },
		{ "Keep trailing whitesp\xC3\xA4""ce \t ", 28, "Keep trailing whitesp=C3=A4ce \t =", 67 },
		{ "Keep trailing whitesp\xC3\xA4""ce    ", 29, "Keep trailing whitesp=C3=A4ce    =", 67 },
		{ "Keep trailing whitesp\xC3\xA4""ce     ", 30, "Keep trailing whitesp=C3=A4ce     =", 67 },
		{ "Keep trailing whitesp\xC3\xA4""ce      ", 31, "Keep trailing whitesp=C3=A4ce      =", 67 },
		/* Test line breaking */
		{ WHITESPACE70"1234567", 77, WHITESPACE70"1234=\r\n567", 76 },
		{ WHITESPACE70"      7", 77, WHITESPACE70"  =20=\r\n   7", 76 },
		{ WHITESPACE70""WHITESPACE10"1", 81, WHITESPACE70"  =20=\r\n\t   \t \t1", 76 },
		/* Control characters */
		{ "\x0C\x07", 2, "=0C=07", 20},
		/* Data */
		{ "\xDE\xAD\xBE\xEF""deadbeef", 12 ,"=DE=AD=BE=EFdeadbe=\r\nef", 20 },
		{ "\xDE""de""\xAD""ad""\xBE""be""\xEF""ef", 12 ,"=DEde=ADad=BEbe=EF=\r\nef", 20 },
		/* boundary delimiter */
		{ "___________ \xc3\x9c", 14, "___________ =C3=9C", 20 },
		{ "----------- \xc3\x9c", 14, "----------- =C3=9C", 20 },
		{ "=---------- \xc3\x9c", 14, "=3D---------- =C3=\r\n=9C", 20 },
		{ "=__________ \xc3\x9c", 14, "=3D__________ =C3=\r\n=9C", 20 },
		/* mixed inputs */
		{ "\xed\xae\x80\xed\xbf\xbf", 6, "=ED=AE=80=ED=BF=BF", 20 },
		{ "f\x6f\x6f""bar\xae\x80\xed\xbf\xbf", 11, "foobar=AE=80=ED=BF=\r\n=BF", 20 },
		{
			"\xc3\x9c""ber\x6d\xc3\xa4\xc3\x9f\x69\x67\x0a\xe0\x80\x80 \xf0\x9d\x84\x9e", 21,
			"=C3=9Cberm=C3=A4=C3=9Fig\r\n=E0=80=80 =F0=9D=84=9E",
			76
		},
		{
			"\xc3\x9c""ber\x6d\xc3\xa4\xc3\x9f\x69\x67\x0a\xe0\x80\x80 \xf0\x9d\x84\x9e", 21,
			"=C3=9Cberm=C3=A4=\r\n=C3=9Fig\r\n=E0=80=80 =F0=9D=\r\n=84=9E",
			20
		},
		{
			"\xc3\x9c""ber\x6dä\xc3\x9fi\x0a\xe0g\x80\x80 \xf0\x9d\x84\x9e", 21,
			"=C3=9Cberm=C3=A4=C3=9Fi\r\n=E0g=80=80 =F0=9D=84=9E",
			76
		},
		{
			"\xc3\x9c""ber\x6dä\xc3\xff\x9fi\x0a\xe0g\x80\x80\xfe\xf0\x9d\x84\x9e", 22,
			"=C3=9Cberm=C3=A4=C3=FF=9Fi\r\n=E0g=80=80=FE=F0=9D=84=9E",
			76
		},
	};
	string_t *str;
	unsigned int i, j;

	test_begin("qp-encoder");
	str = t_str_new(128);
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		const unsigned char *input = tests[i].input;
		struct qp_encoder *qp = qp_encoder_init(str, tests[i].max_line_len, 0);

		/* try all at once */
		qp_encoder_more(qp, input, tests[i].input_len);
		qp_encoder_finish(qp);

		test_assert_strcmp_idx(str_c(str), tests[i].output, i);

		/* try in small pieces */
		str_truncate(str, 0);
		for (j = 0; j < tests[i].input_len; j++) {
			unsigned char c = input[j];
			qp_encoder_more(qp, &c, 1);
		}
		qp_encoder_finish(qp);
		test_assert_strcmp_idx(str_c(str), tests[i].output, i);

		qp_encoder_deinit(&qp);
		str_truncate(str, 0);
	}
	test_end();
}

static void test_qp_encoder_binary(void)
{
	static struct test_quoted_printable_encode_data tests[] = {
		{ "\0nil\0delimited\0string\0", 22, "=00nil=00delimited=\r\n=00string=00" ,20 },
		{
		  "\xef\x4e\xc5\xe0\x31\x66\xd7\xef\xae\x12\x7d\x45\x1e\x05\xc7\x2a",
		  16,
		  "=EFN=C5=E01f=D7=EF=\r\n=AE=12}E=1E=05=C7*",
		  20
		},
	};

	string_t *str;
	unsigned int i, j;

	test_begin("qp-encoder (binary safe)");
	str = t_str_new(128);
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		const unsigned char *input = tests[i].input;
		struct qp_encoder *qp = qp_encoder_init(str, tests[i].max_line_len, QP_ENCODER_FLAG_BINARY_DATA);

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
		{ "simple", 6, "=?utf-8?Q?simple?=", 75 },
		{ "J'esuis de paris caf\xc3\xa9", 22, "=?utf-8?Q?J'esuis_de_paris_caf=C3=A9?=", 75 },
		{ "hello_world", 11, "=?utf-8?Q?hello=5Fworld?=", 75 },
		{
		  "make sure this wraps and that the actual lines are not longer than maximum length including preamble",
		  100,
		  "=?utf-8?Q?make_sure_this_wraps_and_that_the_actual_lines_are_not_longer_t?=\r\n"
		  " =?utf-8?Q?han_maximum_length_including_preamble?=",
		  75
		},
        };

        string_t *str;
        unsigned int i, j;

        test_begin("qp-encoder (header format)");
        str = t_str_new(128);
        for (i = 0; i < N_ELEMENTS(tests); i++) {
                const unsigned char *input = tests[i].input;
                struct qp_encoder *qp = qp_encoder_init(str, tests[i].max_line_len, QP_ENCODER_FLAG_HEADER_FORMAT);

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
