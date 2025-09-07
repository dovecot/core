/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "sasl-oauth2.h"

struct test_kvpair {
	const char *key;
	const char *value;
};

struct test_kvpair_valid {
	const char *in;

	const struct test_kvpair *pairs;
};

static const struct test_kvpair_valid kvpair_valid_tests[] = {
	{
		.in = "key=value\x01",
		.pairs = (const struct test_kvpair []){
			{
				.key = "key",
				.value = "value",
			},
			{
				.key = NULL,
			},
		},
	},
	{
		.in = "key=value=frop\x01",
		.pairs = (const struct test_kvpair []){
			{
				.key = "key",
				.value = "value=frop",
			},
			{
				.key = NULL,
			},
		},
	},
	{
		.in = "key=value\x01keytwo=value2\x01",
		.pairs = (const struct test_kvpair []){
			{
				.key = "key",
				.value = "value",
			},
			{
				.key = "keytwo",
				.value = "value2",
			},
			{
				.key = NULL,
			},
		},
	},
	{
		.in = 	"host=server.example.com\x01"
			"port=143\x01"
			"auth=Bearer vF9dft4qmTc2Nvb3RlckBhbHRhdmlzdGEuY29tCg==\x01",
		.pairs = (const struct test_kvpair []){
			{
				.key = "host",
				.value = "server.example.com",
			},
			{
				.key = "port",
				.value = "143",
			},
			{
				.key = "auth",
				.value = "Bearer vF9dft4qmTc2Nvb3RlckBhbHRhdmlzdGEuY29tCg==",
			},
			{
				.key = NULL,
			},
		},
	},
	{
		.in =	"abcdefghijklmnopqrstuvwxyz=value1\x01"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ=value2\x01",
		.pairs = (const struct test_kvpair []){
			{
				.key = "abcdefghijklmnopqrstuvwxyz",
				.value = "value1",
			},
			{
				.key = "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
				.value = "value2",
			},
			{
				.key = NULL,
			},
		},
	},
	{
		.in =	"a=abcdefghijklmnopqrstuvwxyz\x01"
			"b=ABCDEFGHIJKLMNOPQRSTUVWXYZ\x01"
			"c=0123456789\x01"
			"d=!\"#$%&'()*+,-./\x01"
			"e=:;<=>@\x01"
			"f=[/]^`{|}~\x01"
			"g= \t\r\n\x01",
		.pairs = (const struct test_kvpair []){
			{
				.key = "a",
				.value = "abcdefghijklmnopqrstuvwxyz",
			},
			{
				.key = "b",
				.value = "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			},
			{
				.key = "c",
				.value = "0123456789",
			},
			{
				.key = "d",
				.value = "!\"#$%&'()*+,-./",
			},
			{
				.key = "e",
				.value = ":;<=>@",
			},
			{
				.key = "f",
				.value = "[/]^`{|}~",
			},
			{
				.key = "g",
				.value = " \t\r\n",
			},
			{
				.key = NULL,
			},
		},
	},
};

static void
test_kvpair_valid_next(const unsigned char **in, const unsigned char *in_end,
		       const struct test_kvpair *test)
{
	const char *key, *value;
	const char *error;
	int ret;

	ret = sasl_oauth2_kvpair_parse(*in, in_end - *in, &key, &value,
				       in, &error);
	test_out_reason_quiet("decode success", ret >= 0, error);
	if (ret < 0)
		return;

	test_assert_strcmp(key, test->key);
	test_assert_strcmp(value, test->value);

	test_assert(sasl_oauth2_kvpair_check_value(value));
}

static void test_kvpair_valid(void)
{
	unsigned int i;
	buffer_t *buf;

	buf = t_buffer_create(128);
	for (i = 0; i < N_ELEMENTS(kvpair_valid_tests); i++) {
		const struct test_kvpair_valid *test = &kvpair_valid_tests[i];
		const unsigned char *in = (const unsigned char *)test->in;
		const unsigned char *in_end = in + strlen(test->in);
		const struct test_kvpair *pairs = test->pairs;

		test_begin(t_strdup_printf("sasl oauth2 kvpair valid [%u]",
					   i + 1));

		while (!test_has_failed() &&
		       in < in_end && pairs->key != NULL) {
			test_kvpair_valid_next(&in, in_end, pairs);
			pairs++;
		}

		test_assert(test_has_failed() || in == in_end);
		test_assert(test_has_failed() || pairs->key == NULL);

		test_end();
		buffer_clear(buf);
	}

}

struct test_kvpair_invalid {
	const char *in;
	size_t nul_at;

	bool expect_nonstd;
};

static const struct test_kvpair_invalid kvpair_invalid_tests[] = {
	{
		.in = "=",
	},
	{
		.in = "a",
	},
	{
		.in = "key1=a",
	},
{
		.in = "key=a\x01key2=b\x01",
	},
	{
		.in = "k e y=a",
	},
	{
		.in = "key=a\x02",
	},
	{
		.in = "key=a\x02\x01",
	},
	{
		.in = "key=value",
	},
	{
		.in = "key=value\x01keytwo=value2",
	},
};

static void test_kvpair_invalid(void)
{
	unsigned int i;
	int ret;

	for (i = 0; i < N_ELEMENTS(kvpair_invalid_tests); i++) {
		const struct test_kvpair_invalid *test =
			&kvpair_invalid_tests[i];
		const unsigned char *in = (unsigned char *)test->in;
		size_t in_len = strlen(test->in);
		const unsigned char *in_end = in + in_len;
		const char *key, *value;
		const char *error;

		test_begin(t_strdup_printf("sasl oauth2 kvpair invalid [%u]",
					   i + 1));

		if (test->nul_at > 0) {
			unsigned char *in_nul;

			i_assert((test->nul_at - 1) < in_len);
			in_nul = (unsigned char *)t_strdup_noconst(test->in);
			in_nul[test->nul_at - 1] = '\0';
			in = in_nul;
		}

		ret = 0;
		while (ret == 0 && in < in_end) {
			ret = sasl_oauth2_kvpair_parse(in, in_end - in,
						       &key, &value, &in,
						       &error);
		}
		test_out_reason("decode failure", ret < 0, error);

		test_end();
	}
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_kvpair_valid,
		test_kvpair_invalid,
		NULL
	};
	return test_run(test_functions);
}
