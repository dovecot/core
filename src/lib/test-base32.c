/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "test-lib.h"
#include "str.h"
#include "base32.h"


static void test_base32_encode(void)
{
	static const char *input[] = {
		"toedeledokie!!",
		"bye bye world",
		"hoeveel onzin kun je testen?????",
		"c'est pas vrai! ",
		"dit is het einde van deze test"
	};
	static const char *output[] = {
		"ORXWKZDFNRSWI33LNFSSCII=",
		"MJ4WKIDCPFSSA53POJWGI===",
		"NBXWK5TFMVWCA33OPJUW4IDLOVXCA2TFEB2GK43UMVXD6PZ7H47Q====",
		"MMTWK43UEBYGC4ZAOZZGC2JBEA======",
		"MRUXIIDJOMQGQZLUEBSWS3TEMUQHMYLOEBSGK6TFEB2GK43U"
	};
	string_t *str;
	unsigned int i;

	test_begin("base32_encode() with padding");
	str = t_str_new(256);
	for (i = 0; i < N_ELEMENTS(input); i++) {
		str_truncate(str, 0);
		base32_encode(TRUE, input[i], strlen(input[i]), str);
		test_assert(strcmp(output[i], str_c(str)) == 0);
	}
	test_end();

	test_begin("base32_encode() no padding");
	str = t_str_new(256);
	for (i = 0; i < N_ELEMENTS(input); i++) {
		const char *p = strchr(output[i], '=');
		size_t len;

		if (p == NULL)
			len = strlen(output[i]);
		else
			len = (size_t)(p - output[i]);
		str_truncate(str, 0);
		base32_encode(FALSE, input[i], strlen(input[i]), str);
		test_assert(strncmp(output[i], str_c(str), len) == 0);
	}
	test_end();
}

static void test_base32hex_encode(void)
{
	static const char *input[] = {
		"toedeledokie!!",
		"bye bye world",
		"hoeveel onzin kun je testen?????",
		"c'est pas vrai! ",
		"dit is het einde van deze test"
	};
	static const char *output[] = {
		"EHNMAP35DHIM8RRBD5II288=",
		"C9SMA832F5II0TRFE9M68===",
		"D1NMATJ5CLM20RREF9KMS83BELN20QJ541Q6ASRKCLN3UFPV7SVG====",
		"CCJMASRK41O62SP0EPP62Q9140======",
		"CHKN8839ECG6GPBK41IMIRJ4CKG7COBE41I6AUJ541Q6ASRK"
	};
	string_t *str;
	unsigned int i;

	test_begin("base32hex_encode() with padding");
	str = t_str_new(256);
	for (i = 0; i < N_ELEMENTS(input); i++) {
		str_truncate(str, 0);
		base32hex_encode(TRUE, input[i], strlen(input[i]), str);
		test_assert(strcmp(output[i], str_c(str)) == 0);
	}
	test_end();

	test_begin("base32hex_encode() no padding");
	str = t_str_new(256);
	for (i = 0; i < N_ELEMENTS(input); i++) {
		const char *p = strchr(output[i], '=');
		size_t len;

		if (p == NULL)
			len = strlen(output[i]);
		else
			len = (size_t)(p - output[i]);
		str_truncate(str, 0);
		base32hex_encode(FALSE, input[i], strlen(input[i]), str);
		test_assert(strncmp(output[i], str_c(str), len) == 0);
	}
	test_end();

}

struct test_base32_decode_output {
	const char *text;
	int ret;
	unsigned int src_pos;
};

static void test_base32_decode(void)
{
	static const char *input[] = {
		"ORXWKZDFNRSWI33LNFSSCII=",
		"MJ4WKIDCPFSSA53POJWGI===",
		"NBXWK5TFMVWCA33OPJUW4IDLOVXCA2TFEB2GK43UMVXD6PZ7H47Q====",
		"MMTWK43UEBYGC4ZAOZZGC2JBEA======",
		"MRUXIIDJOMQGQZLUEBSWS3TEMUQHMYLOEBSGK6TFEB2GK43U"
	};
	static const struct test_base32_decode_output output[] = {
		{ "toedeledokie!!", 0, 24 },
		{ "bye bye world", 0, 24 },
		{ "hoeveel onzin kun je testen?????", 0, 56 },
		{ "c'est pas vrai! ", 0, 32 },
		{ "dit is het einde van deze test", 1, 48 },
	};
	string_t *str;
	unsigned int i;
	size_t src_pos;
	int ret;

	test_begin("base32_decode()");
	str = t_str_new(256);
	for (i = 0; i < N_ELEMENTS(input); i++) {
		str_truncate(str, 0);

		src_pos = 0;
		ret = base32_decode(input[i], strlen(input[i]), &src_pos, str);

		test_assert(output[i].ret == ret &&
			    strcmp(output[i].text, str_c(str)) == 0 &&
			    (src_pos == output[i].src_pos ||
			     (output[i].src_pos == UINT_MAX &&
			      src_pos == strlen(input[i]))));
	}
	test_end();
}

static void test_base32crockford_encode(void)
{
	static const char *input[] = {
		"toedeledokie!!",
		"bye bye world",
		"hoeveel onzin kun je testen?????",
		"c'est pas vrai! ",
		"dit is het einde van deze test",
		"",
		"f",
		"fo",
		"foo",
		"foob",
		"fooba",
		"foobar",
	};
	static const char *output[] = {
		"EHQPAS35DHJP8VVBD5JJ288",
		"C9WPA832F5JJ0XVFE9P68",
		"D1QPAXK5CNP20VVEF9MPW83BENQ20TK541T6AWVMCNQ3YFSZ7WZG",
		"CCKPAWVM41R62WS0ESS62T9140",
		"CHMQ8839ECG6GSBM41JPJVK4CMG7CRBE41J6AYK541T6AWVM",
		"",
		"CR",
		"CSQG",
		"CSQPY",
		"CSQPYRG",
		"CSQPYRK1",
		"CSQPYRK1E8",
	};
	string_t *str;
	unsigned int i;

	test_begin("base32crockford_encode()");
	str = t_str_new(256);
	for (i = 0; i < N_ELEMENTS(input); i++) {
		str_truncate(str, 0);
		base32crockford_encode(input[i], strlen(input[i]), str);
		test_assert_strcmp_idx(output[i], str_c(str), i);
	}
	test_end();
}

static void test_base32crockford_decode(void)
{
	static const struct {
		const char *input;
		const char *output;
	} tests[] = {
		{ "", "" },
		{ "CSQPYRK1E8", "foobar" },
		/* case-insensitive */
		{ "csqpyrk1e8", "foobar" },
		{ "CsQpYrK1e8", "foobar" },
		/* hyphens are ignored */
		{ "CSQP-YRK1-E8", "foobar" },
		{ "-CSQPY--RK1E8-", "foobar" },
		{ "---", "" },
		/* O is read as 0, I and L as 1 */
		{ "CSQPYRKIE8", "foobar" },
		{ "CSQPYRKiE8", "foobar" },
		{ "CSQPYRKLE8", "foobar" },
		{ "CSQPYRKlE8", "foobar" },
		{ "CCKPAWVM41R62WSOESS62T914o", "c'est pas vrai! " },
		{ "CCKPAWVM41R62WS0ESS62T9140", "c'est pas vrai! " },
	};
	static const char *invalid[] = {
		/* U is not in the alphabet */
		"CSQPYRKUE8", "CSQPYRKuE8",
		/* padding, whitespace and other characters */
		"CR======", "CSQP YRK1E8", "CSQPYRK1E8\n", "CSQPYRK1E8*",
		"CSQPYRK1E8=", "CSQPYRK1E8\x80",
		/* lengths no encoder produces */
		"C", "CSQ", "CSQPYR", "CSQPYRK1E",
		"0", "000", "000000", "000000000",
		/* non-zero bits after the last full byte */
		"CS", "CSQH", "CSQPZ", "CSQPYRH",
	};
	string_t *str;
	unsigned int i;

	test_begin("base32crockford_decode()");
	str = t_str_new(256);
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		test_assert_idx(base32crockford_decode(
			tests[i].input, strlen(tests[i].input), str) == 0, i);
		test_assert_strcmp_idx(str_c(str), tests[i].output, i);
	}
	for (i = 0; i < N_ELEMENTS(invalid); i++) {
		str_truncate(str, 0);
		test_assert_idx(base32crockford_decode(
			invalid[i], strlen(invalid[i]), str) == -1, i);
	}
	test_end();
}

static void test_base32crockford_canonical(void)
{
	/* Decoding and encoding again gives the canonical form: upper case,
	   no hyphens, no aliases. 16 characters are exactly 10 bytes. */
	static const struct {
		const char *input;
		const char *output;
	} tests[] = {
		{ "0123456789abcdef", "0123456789ABCDEF" },
		{ "0123-4567-89ab-cdef", "0123456789ABCDEF" },
		{ "ABCD-EFGH-JKMN-PQRS", "ABCDEFGHJKMNPQRS" },
		{ "tvwx-yz01-2345-6789", "TVWXYZ0123456789" },
		{ "oooo-iiii-llll-0000", "0000111111110000" },
	};
	string_t *bin, *str;
	unsigned int i;

	test_begin("base32crockford_decode() + base32crockford_encode()");
	bin = t_str_new(16);
	str = t_str_new(32);
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(bin, 0);
		str_truncate(str, 0);
		test_assert_idx(base32crockford_decode(
			tests[i].input, strlen(tests[i].input), bin) == 0, i);
		test_assert_idx(str_len(bin) == 10, i);
		base32crockford_encode(str_data(bin), str_len(bin), str);
		test_assert_strcmp_idx(str_c(str), tests[i].output, i);
	}
	test_end();
}

static void test_base32crockford_is_valid_char(void)
{
	static const char valid[] =
		"0123456789ABCDEFGHJKMNPQRSTVWXYZabcdefghjkmnpqrstvwxyzOoIiLl";
	unsigned int c;

	test_begin("base32crockford_is_valid_char()");
	for (c = 0; c < 256; c++) {
		bool expected = c != '\0' && strchr(valid, c) != NULL;
		test_assert_idx(base32crockford_is_valid_char(c) == expected,
				c);
	}
	test_end();
}

static void test_base32_random(void)
{
	string_t *str, *dest;
	unsigned char buf[10];
	unsigned int i, j, max;

	str = t_str_new(256);
	dest = t_str_new(256);

	test_begin("padded base32 encode/decode with random input");
	for (i = 0; i < 1000; i++) {
		max = i_rand_limit(sizeof(buf));
		for (j = 0; j < max; j++)
			buf[j] = i_rand_uchar();

		str_truncate(str, 0);
		str_truncate(dest, 0);
		base32_encode(TRUE, buf, max, str);
		test_assert(base32_decode(str_data(str), str_len(str), NULL, dest) >= 0);
		test_assert(str_len(dest) == max &&
			    memcmp(buf, str_data(dest), max) == 0);
	}
	test_end();

	test_begin("padded base32hex encode/decode with random input");
	for (i = 0; i < 1000; i++) {
		max = i_rand_limit(sizeof(buf));
		for (j = 0; j < max; j++)
			buf[j] = i_rand_uchar();

		str_truncate(str, 0);
		str_truncate(dest, 0);
		base32hex_encode(TRUE, buf, max, str);
		test_assert(base32hex_decode(str_data(str), str_len(str), NULL, dest) >= 0);
		test_assert(str_len(dest) == max &&
			    memcmp(buf, str_data(dest), max) == 0);
	}
	test_end();

	test_begin("base32crockford encode/decode with random input");
	for (i = 0; i < 1000; i++) {
		max = i_rand_limit(sizeof(buf));
		for (j = 0; j < max; j++)
			buf[j] = i_rand_uchar();

		str_truncate(str, 0);
		str_truncate(dest, 0);
		base32crockford_encode(buf, max, str);
		test_assert(base32crockford_decode(str_data(str), str_len(str),
						   dest) == 0);
		test_assert(str_len(dest) == max &&
			    memcmp(buf, str_data(dest), max) == 0);
	}
	test_end();
}

void test_base32(void)
{
	test_base32_encode();
	test_base32hex_encode();
	test_base32_decode();
	test_base32crockford_encode();
	test_base32crockford_decode();
	test_base32crockford_canonical();
	test_base32crockford_is_valid_char();
	test_base32_random();
}
