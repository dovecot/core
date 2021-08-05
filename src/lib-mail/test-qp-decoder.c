/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "qp-decoder.h"
#include "test-common.h"

struct test_quoted_printable_decode_data {
	const char *input;
	const char *output;
	size_t error_pos;
	int ret;
};

static void test_qp_decoder(void)
{
#define WHITESPACE10 "   \t   \t \t"
#define WHITESPACE70 WHITESPACE10 WHITESPACE10 WHITESPACE10 WHITESPACE10 WHITESPACE10 WHITESPACE10 WHITESPACE10
	static struct test_quoted_printable_decode_data tests[] = {
		{ "foo  \r\nbar=\n", "foo\r\nbar", 0, 0 },
		{ "foo\t=\nbar", "foo\tbar", 0, 0 },
		{ "foo = \n=01", "foo \001", 0, 0 },
		{ "foo =\t\r\nbar", "foo bar", 0, 0 },
		{ "foo =\r\n=01", "foo \001", 0, 0 },
		{ "foo  \nbar=\r\n", "foo\r\nbar", 0, 0 },
		{ "=0A=0D  ", "\n\r", 0, 0 },
		{ "foo_bar", "foo_bar", 0, 0 },
		{ "\n\n", "\r\n\r\n", 0, 0 },
		{ "\r\n\n\n\r\n", "\r\n\r\n\r\n\r\n", 0, 0 },

		{ "foo=", "foo=", 4, -1 },
		{ "foo= =66", "foo= f", 5, -1 },
		{ "foo= \t", "foo= \t", 6, -1 },
		{ "foo= \r", "foo= \r", 6, -1 },
		{ "foo= \r bar", "foo= \r bar", 6, -1 },
		{ "foo=A", "foo=A", 5, -1 },
		{ "foo=Ax", "foo=Ax", 5, -1 },
		{ "foo=Ax=xy", "foo=Ax=xy", 5, -1 },

		/* above 76 whitespaces is invalid and gets truncated
		   (at 77th whitespace because of the current implementation) */
		{ WHITESPACE70"      7\n", WHITESPACE70"      7\r\n", 0, 0 },
		{ WHITESPACE70"       8\n", WHITESPACE70"       8\r\n", 77, -1 },
		{ WHITESPACE70"        9\n", WHITESPACE70"       9\r\n", 78, -1 },
		{ WHITESPACE70"         0\n", WHITESPACE70"       0\r\n", 79, -1 },
		/* Expect extra whitespace to be truncated */
		{ WHITESPACE70"      7\n"WHITESPACE10"", WHITESPACE70"      7\r\n", 0, 0 },
		{ WHITESPACE70"      7=\r\n"WHITESPACE10, WHITESPACE70"      7", 0, 0 },
		/* Unnecessarily encoded */
		{ "=66=6f=6f=42=61=72", "fooBar", 0, 0 },
		/* Expected to be encoded but not */
		{ "\xc3\x9c""berm=c3=a4\xc3\x9figer Gebrauch", "\xc3\x9c""berm\xc3\xa4\xc3\x9figer Gebrauch", 0, 0 },
		/* Decode control characters */
		{ "=0C=07", "\x0C\x07", 0, 0 },
		/* Data */
		{ "=DE=AD=BE=EF", "\xDE\xAD\xBE\xEF", 0, 0 },
		/* Non hex data */
		{ "=FJ=X1", "=FJ=X1", 2, -1 },
		/* No content allowed after Soft Line Break */
		{ "=C3=9C = ","\xc3\x9c"" = ", 9, -1 },
		/* Boundary delimiter */
		{ "=C3=9C=\r\n-------","\xc3\x9c""-------", 0, 0 },
		{ "=----------- =C3=9C","=----------- \xc3\x9c""", 1, -1 },
		{ "=___________ =C3=9C","=___________ \xc3\x9c""", 1, -1 },
		{ "___________ =C3=9C","___________ \xc3\x9c""", 0, 0 },
		{ "=2D=2D=2D=2D=2D=2D =C3=9C","------ \xc3\x9c""", 0, 0 },
		{ "=FC=83=BF=BF=BF=BF", "\xFC\x83\xBF\xBF\xBF\xBF", 0, 0 },
		{ "=FE=FE=FF=FF", "\xFE\xFE\xFF\xFF", 0, 0 },
		{ "\xFF=C3=9C\xFE\xFF""foobar", "\xFF\xc3\x9c""\xFE\xFF""foobar", 0, 0 },
		/* Unnecessarily encoded and trailing whitespace */
		{
			"=66=6f=6f=42=61=72                         ",
			"fooBar", 0, 0
		},
		/* Indicate error if encoded line is longer then 76 */
		{
			WHITESPACE70"       =C3=9C\n",
			WHITESPACE70"       \xc3\x9c""\r\n", 77, -1
		},
		/* Soft Line Break example from the RFC */
		{
			"Now's the time =\r\nfor all folk to come=\r\n to the"
			" aid of their country.",
			"Now's the time for all folk to come to the aid of "
			"their country.", 0, 0
		},
		{
			"=C3=9Cberm=C3=A4=C3=9Figer Gebrauch",
			"\xc3\x9c""berm\xc3\xa4\xc3\x9figer Gebrauch", 0, 0
		},
		/* Softlinebreak without following content */
		{
			"=C3=9Cberm=C3=A4=C3=9Figer Gebrauch=",
			"\xc3\x9c""berm\xc3\xa4\xc3\x9figer Gebrauch=", 36, -1
		},
		/* Lowercase formally illegal but allowed for robustness */
		{
			"=c3=9cberm=c3=a4=c3=9figer Gebrauch",
			"\xc3\x9c""berm\xc3\xa4\xc3\x9figer Gebrauch", 0, 0
		},
		/* Control characters in input */
		{
			"=c3=9c=10berm=c3=a4=c3=9figer Geb=0Frauch",
			"\xc3\x9c\x10""berm\xc3\xa4\xc3\x9figer Geb\x0Frauch", 0, 0
		},
		/* Trailing whitespace */
		{
			"Trailing Whitesp=C3=A4ce =\r\n        ",
			"Trailing Whitesp\xc3\xa4""ce ", 0 ,0
		},
		{
			"Trailing Whitesp=C3=A4ce         ",
			"Trailing Whitesp\xc3\xa4""ce", 0 ,0
		},
		{
			"=54=65=73=74=20=6D=65=73=73=61=67=65",
			"Test message", 0 , 0
		},
		{
			"=E3=81=93=E3=82=8C=E3=81=AF=E5=A2\r\n=83=E7=95=8C=E3"
			"=81=AE=E3=81=82=E3=82=8B=E3=83=A1=E3=83=83=E3=82=BB="
			"E3=83=BC=E3=82=B8=E3=81=A7=E3=81=99",
			"\xE3\x81\x93\xE3\x82\x8C\xE3\x81\xAF\xE5\xA2\r\n\x83"
			"\xE7\x95\x8C\xE3\x81\xAE\xE3\x81\x82\xE3\x82\x8B\xE3"
			"\x83\xA1\xE3\x83\x83\xE3\x82\xBB\xE3\x83\xBC\xE3\x82"
			"\xB8\xE3\x81\xA7\xE3\x81\x99", 0, 0
		},
		{
			"=E3=81\xc3\xf1=93=E3=82=8\xff""C=E3=81=AF=E5=A2",
			"\xE3\x81\xc3\xf1\x93\xE3\x82=8\xff""C\xE3\x81\xAF\xE5\xA2",
			19, -1
		},
		{
			"\x77Hello\x76=20 \x20 =E3=81\xc3\xf1=93=E3=82",
			"wHellov    \xE3\x81\xc3\xf1\x93\xE3\x82",
			0, 0
		},
	};
	string_t *str;
	unsigned int i, j;

	test_begin("qp-decoder");
	str = t_str_new(128);
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		const char *input = tests[i].input;
		struct qp_decoder *qp = qp_decoder_init(str);
		size_t error_pos;
		const char *error;
		int ret;

		/* try all at once */
		ret = qp_decoder_more(qp, (const void *)input, strlen(input),
				      &error_pos, &error);
		if (qp_decoder_finish(qp, &error) < 0 && ret == 0) {
			error_pos = strlen(input);
			ret = -1;
		}
		test_assert_idx(ret == tests[i].ret, i);
		test_assert_idx(ret == 0 || error_pos == tests[i].error_pos, i);
		test_assert_strcmp_idx(str_c(str), tests[i].output, i);

		/* try in small pieces */
		str_truncate(str, 0);
		ret = 0;
		for (j = 0; input[j] != '\0'; j++) {
			unsigned char c = (unsigned char)input[j];
			if (qp_decoder_more(qp, &c, 1, &error_pos, &error) < 0)
				ret = -1;
		}
		if (qp_decoder_finish(qp, &error) < 0)
			ret = -1;
		test_assert_idx(ret == tests[i].ret, i);
		test_assert_strcmp_idx(str_c(str), tests[i].output, i);

		qp_decoder_deinit(&qp);
		str_truncate(str, 0);
	}
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_qp_decoder,
		NULL
	};
	return test_run(test_functions);
}
