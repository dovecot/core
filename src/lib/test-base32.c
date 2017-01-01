/* Copyright (c) 2007-2017 Dovecot authors, see the included COPYING file */

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

static void test_base32_random(void)
{
	string_t *str, *dest;
	char buf[10];
	unsigned int i, j, max;

	str = t_str_new(256);
	dest = t_str_new(256);

	test_begin("padded base32 encode/decode with random input");
	for (i = 0; i < 1000; i++) {
		max = rand() % sizeof(buf);
		for (j = 0; j < max; j++)
			buf[j] = rand();

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
		max = rand() % sizeof(buf);
		for (j = 0; j < max; j++)
			buf[j] = rand();

		str_truncate(str, 0);
		str_truncate(dest, 0);
		base32hex_encode(TRUE, buf, max, str);
		test_assert(base32hex_decode(str_data(str), str_len(str), NULL, dest) >= 0);
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
	test_base32_random();
}
