/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "istream-private.h"
#include "istream-qp.h"

static const struct {
	const void *input;
	const char *output;
	int stream_errno;
} tests[] = {
	{ "", "", 0 },
	{ "short test", "short test", 0 },
	{ "C'est une cha\xc3\xaene de test simple", "C'est une cha=C3=AEne de test simple", 0 },
	{
	  "wrap after 76 characters wrap after 76 characters wrap after 76 characters wrap after 76 characters",
	  "wrap after 76 characters wrap after 76 characters wrap after 76 character=\r\ns wrap after 76 characters",
	  0
	},
	{
	  /* the string is split up to avoid C compilers thinking \x99ed as escape */
	  "P\xc5\x99" "edstavitel\xc3\xa9 francouzsk\xc3\xa9ho lidu, ustanoveni v "
	  "N\xc3\xa1rodn\xc3\xadm shrom\xc3\xa1\xc5\xbe" "d\xc4\x9bn\xc3\xad, domn"
	  "\xc3\xadvaj\xc3\xad" "ce se, \xc5\xbe" "e nev\xc4\x9b" "domost, zapomenut\xc3"
	  "\xad nebo pohrd\xc3\xa1n\xc3\xad lidsk\xc3\xbdmi pr\xc3\xa1vy jsou j"
	  "edin\xc3\xbdmi p\xc5\x99\xc3\xad\xc4\x8dinami ve\xc5\x99" "ejn\xc3\xb"
	  "dch ne\xc5\xa1t\xc4\x9bst\xc3\xad a zkorumpov\xc3\xa1n\xc3\xad vl"
	  "\xc3\xa1" "d, rozhodli se vylo\xc5\xbeit v slavnostn\xc3\xad Deklara"
	  "ci p\xc5\x99irozen\xc3\xa1, nezciziteln\xc3\xa1 a posv\xc3\xa1tn\xc3"
	  "\xa1 pr\xc3\xa1va \xc4\x8dlov\xc4\x9bka za t\xc3\xadm \xc3\xba\xc4"
	  "\x8d" "elem, aby tato Deklarace, neust\xc3\xa1le jsouc p\xc5\x99" "ed o"
	  "\xc4\x8" "dima v\xc5\xa1" "em \xc4\x8dlen\xc5\xafm lidsk\xc3\xa9 spo"
	  "le\xc4\x8dnosti, uv\xc3\xa1" "d\xc4\x9bla jim st\xc3\xa1le na pam\xc4"
	  "\x9b\xc5\xa5 jejich pr\xc3\xa1va a jejich povinnosti; aby \xc4\x8din"
	  "y z\xc3\xa1konod\xc3\xa1rn\xc3\xa9 moci a \xc4\x8diny v\xc3\xbdkonn"
	  "\xc3\xa9 moci mohly b\xc3\xbdt v ka\xc5\xbe" "d\xc3\xa9 chv\xc3\xadli p"
	  "orovn\xc3\xa1v\xc3\xa1ny s \xc3\xba\xc4\x8d" "elem ka\xc5\xbe" "d\xc3"
	  "\xa9 politick\xc3\xa9 instituce a byly v d\xc5\xafsledku toho chov"
	  "\xc3\xa1ny je\xc5\xa1t\xc4\x9b v\xc3\xad" "ce v \xc3\xba" "ct\xc4"
	  "\x9b; aby po\xc5\xbe" "adavky ob\xc4\x8d" "an\xc5\xaf, kdy\xc5\xbe s"
	  "e budou nap\xc5\x99\xc3\xad\xc5\xa1t\xc4\x9b zakl\xc3\xa1" "dat na j"
	  "ednoduch\xc3\xb" "dch a nepop\xc3\xadrateln\xc3\xbd" "ch z\xc3\xa1sa"
	  "d\xc3\xa1" "ch, sm\xc4\x9b\xc5\x99ovaly v\xc5\xb" "edy k zachov\xc3"
	  "\xa1n\xc3\xad \xc3\xbastavy a ku blahu v\xc5\xa1" "ech.",
	  "P=C5=99edstavitel=C3=A9 francouzsk=C3=A9ho lidu, ustanoveni v N=C3=A1rodn=\r\n"
	  "=C3=ADm shrom=C3=A1=C5=BEd=C4=9Bn=C3=AD, domn=C3=ADvaj=C3=ADce se, =C5=BE=\r\n"
	  "e nev=C4=9Bdomost, zapomenut=C3=AD nebo pohrd=C3=A1n=C3=AD lidsk=C3=BDmi=20=\r\n"
	  "pr=C3=A1vy jsou jedin=C3=BDmi p=C5=99=C3=AD=C4=8Dinami ve=C5=99ejn=C3=0Bd=\r\n"
	  "ch ne=C5=A1t=C4=9Bst=C3=AD a zkorumpov=C3=A1n=C3=AD vl=C3=A1d, rozhodli=20=\r\n"
	  "se vylo=C5=BEit v slavnostn=C3=AD Deklaraci p=C5=99irozen=C3=A1, nezcizit=\r\n"
	  "eln=C3=A1 a posv=C3=A1tn=C3=A1 pr=C3=A1va =C4=8Dlov=C4=9Bka za t=C3=ADm=20=\r\n"
	  "=C3=BA=C4=8Delem, aby tato Deklarace, neust=C3=A1le jsouc p=C5=99ed o=C4=\r\n"
	  "=08dima v=C5=A1em =C4=8Dlen=C5=AFm lidsk=C3=A9 spole=C4=8Dnosti, uv=C3=A1=\r\n"
	  "d=C4=9Bla jim st=C3=A1le na pam=C4=9B=C5=A5 jejich pr=C3=A1va a jejich po=\r\n"
	  "vinnosti; aby =C4=8Diny z=C3=A1konod=C3=A1rn=C3=A9 moci a =C4=8Diny v=C3=\r\n"
	  "=BDkonn=C3=A9 moci mohly b=C3=BDt v ka=C5=BEd=C3=A9 chv=C3=ADli porovn=C3=\r\n"
	  "=A1v=C3=A1ny s =C3=BA=C4=8Delem ka=C5=BEd=C3=A9 politick=C3=A9 instituce=20=\r\n"
	  "a byly v d=C5=AFsledku toho chov=C3=A1ny je=C5=A1t=C4=9B v=C3=ADce v =C3=\r\n"
	  "=BAct=C4=9B; aby po=C5=BEadavky ob=C4=8Dan=C5=AF, kdy=C5=BE se budou nap=\r\n"
	  "=C5=99=C3=AD=C5=A1t=C4=9B zakl=C3=A1dat na jednoduch=C3=0Bdch a nepop=C3=\r\n"
	  "=ADrateln=C3=BDch z=C3=A1sad=C3=A1ch, sm=C4=9B=C5=99ovaly v=C5=0Bedy k za=\r\n"
	  "chov=C3=A1n=C3=AD =C3=BAstavy a ku blahu v=C5=A1ech.",
	  0
	},
};

static void
encode_test(const char *qp_input, const char *output, int stream_errno,
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
	input = i_stream_create_qp_encoder(input_data, 0);

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

static void test_istream_qp_encoder(void)
{
	unsigned int i, j;

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		test_begin(t_strdup_printf("istream qp encoder %u", i+1));
		for (j = 1; j < 10; j++) T_BEGIN {
			encode_test(tests[i].input, tests[i].output,
				    tests[i].stream_errno, j);
		} T_END;
		test_end();
	}
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_istream_qp_encoder,
		NULL
	};
	return test_run(test_functions);
}
