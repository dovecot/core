/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "base64.h"

static void test_base64_encode(void)
{
	const struct {
		const char *input;
		const char *output;
	} tests[] = {
		{ "hello world", "aGVsbG8gd29ybGQ=" },
		{ "foo barits", "Zm9vIGJhcml0cw==" },
		{ "just niin", "anVzdCBuaWlu" },
		{ "\xe7\x8c\xbf\xe3\x82\x82\xe6\x9c\xa8\xe3\x81\x8b"
		  "\xe3\x82\x89\xe8\x90\xbd\xe3\x81\xa1\xe3\x82\x8b",
		  "54y/44KC5pyo44GL44KJ6JC944Gh44KL" },
		{ "\xe8\xa7\x92\xe3\x82\x92\xe7\x9f\xaf\xe3\x82\x81\xe3\x81"
		  "\xa6\xe7\x89\x9b\xe3\x82\x92\xe6\xae\xba\xe3\x81\x99",
		  "6KeS44KS55+v44KB44Gm54mb44KS5q6644GZ" },
	};
	string_t *str;
	unsigned int i;

	test_begin("base64_encode()");
	str = t_str_new(256);
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		base64_encode(tests[i].input, strlen(tests[i].input), str);
		test_assert_idx(strcmp(tests[i].output, str_c(str)) == 0, i);
		test_assert_idx(
			str_len(str) ==	MAX_BASE64_ENCODED_SIZE(
				strlen(tests[i].input)), i);
	}
	test_end();
}

struct test_base64_decode {
	const char *input;
	const char *output;
	int ret;
};

static void test_base64_decode(void)
{
	static const struct test_base64_decode tests[] = {
		{ "\taGVsbG8gd29ybGQ=",
		  "hello world", 0 },
		{ "\nZm9v\n \tIGJh  \t\ncml0cw==",
		  "foo barits", 0 },
		{ "  anVzdCBuaWlu  \n",
		  "just niin", 0 },
		{ "aGVsb",
		  "hel", -1 },
		{ "aGVsb!!!!!",
		  "hel", -1 },
		{ "aGVs!!!!!",
		  "hel", -1 },
		{ "0JPQvtCy0L7RgNGPzIHRgiwg0YfRgt"
		  "C+INC60YPRgCDQtNC+0Y/MgdGCLg==",
		  "\xd0\x93\xd0\xbe\xd0\xb2\xd0\xbe\xd1\x80\xd1\x8f\xcc"
		  "\x81\xd1\x82\x2c\x20\xd1\x87\xd1\x82\xd0\xbe\x20\xd0"
		  "\xba\xd1\x83\xd1\x80\x20\xd0\xb4\xd0\xbe\xd1\x8f\xcc"
		  "\x81\xd1\x82\x2e", 0 },
	};
	string_t *str;
	buffer_t buf;
	unsigned int i;
	int ret;

	test_begin("base64_decode()");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		/* Some of the base64_decode() callers use fixed size buffers.
		   Use a fixed size buffer here as well to test that
		   base64_decode() can't allocate any extra space even
		   temporarily. */
		size_t max_decoded_size =
			MAX_BASE64_DECODED_SIZE(strlen(tests[i].input));

		buffer_create_from_data(&buf, t_malloc0(max_decoded_size),
					max_decoded_size);
		str = &buf;
		ret = base64_decode(tests[i].input, strlen(tests[i].input),
				    NULL, str);

		test_assert_idx(tests[i].ret == ret, i);
		test_assert_idx(strlen(tests[i].output) == str_len(str) &&
				memcmp(tests[i].output, str_data(str),
				       str_len(str)) == 0, i);
		if (ret >= 0) {
			test_assert_idx(
				str_len(str) <= MAX_BASE64_DECODED_SIZE(
					strlen(tests[i].input)), i);
		}
	}
	test_end();
}

static void test_base64_random(void)
{
	string_t *str, *dest;
	char buf[10];
	unsigned int i, j, max;

	str = t_str_new(256);
	dest = t_str_new(256);

	test_begin("base64 encode/decode with random input");
	for (i = 0; i < 1000; i++) {
		max = i_rand_limit(sizeof(buf));
		for (j = 0; j < max; j++)
			buf[j] = i_rand();

		str_truncate(str, 0);
		str_truncate(dest, 0);
		base64_encode(buf, max, str);
		test_assert_idx(base64_decode(str_data(str), str_len(str),
					      NULL, dest) >= 0, i);
		test_assert_idx(str_len(dest) == max &&
				memcmp(buf, str_data(dest), max) == 0, i);
	}
	test_end();
}

static void test_base64url_encode(void)
{
	const struct {
		const char *input;
		const char *output;
	} tests[] = {
		{ "hello world", "aGVsbG8gd29ybGQ=" },
		{ "foo barits", "Zm9vIGJhcml0cw==" },
		{ "just niin", "anVzdCBuaWlu" },
		{ "\xe7\x8c\xbf\xe3\x82\x82\xe6\x9c\xa8\xe3\x81\x8b"
		  "\xe3\x82\x89\xe8\x90\xbd\xe3\x81\xa1\xe3\x82\x8b",
		  "54y_44KC5pyo44GL44KJ6JC944Gh44KL" },
		{ "\xe8\xa7\x92\xe3\x82\x92\xe7\x9f\xaf\xe3\x82\x81\xe3\x81"
		  "\xa6\xe7\x89\x9b\xe3\x82\x92\xe6\xae\xba\xe3\x81\x99",
		  "6KeS44KS55-v44KB44Gm54mb44KS5q6644GZ" },
	};
	string_t *str;
	unsigned int i;

	test_begin("base64url_encode()");
	str = t_str_new(256);
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		base64url_encode(tests[i].input, strlen(tests[i].input), str);
		test_assert_idx(strcmp(tests[i].output, str_c(str)) == 0, i);
		test_assert_idx(
			str_len(str) ==	MAX_BASE64_ENCODED_SIZE(
				strlen(tests[i].input)), i);
	}
	test_end();
}

struct test_base64url_decode {
	const char *input;
	const char *output;
	int ret;
};

static void test_base64url_decode(void)
{
	static const struct test_base64url_decode tests[] = {
		{ "\taGVsbG8gd29ybGQ=",
		  "hello world", 0 },
		{ "\nZm9v\n \tIGJh  \t\ncml0cw==",
		  "foo barits", 0 },
		{ "  anVzdCBuaWlu  \n",
		  "just niin", 0 },
		{ "aGVsb",
		  "hel", -1 },
		{ "aGVsb!!!!!",
		  "hel", -1 },
		{ "aGVs!!!!!",
		  "hel", -1 },
		{ "0JPQvtCy0L7RgNGPzIHRgiwg0YfRgt"
		  "C-INC60YPRgCDQtNC-0Y_MgdGCLg==",
		  "\xd0\x93\xd0\xbe\xd0\xb2\xd0\xbe\xd1\x80\xd1\x8f\xcc"
		  "\x81\xd1\x82\x2c\x20\xd1\x87\xd1\x82\xd0\xbe\x20\xd0"
		  "\xba\xd1\x83\xd1\x80\x20\xd0\xb4\xd0\xbe\xd1\x8f\xcc"
		  "\x81\xd1\x82\x2e", 0 },
	};
	string_t *str;
	buffer_t buf;
	unsigned int i;
	int ret;

	test_begin("base64url_decode()");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		/* Some of the base64_decode() callers use fixed size buffers.
		   Use a fixed size buffer here as well to test that
		   base64_decode() can't allocate any extra space even
		   temporarily. */
		size_t max_decoded_size =
			MAX_BASE64_DECODED_SIZE(strlen(tests[i].input));

		buffer_create_from_data(&buf, t_malloc0(max_decoded_size),
					max_decoded_size);
		str = &buf;
		ret = base64url_decode(tests[i].input, strlen(tests[i].input),
				       str);

		test_assert_idx(tests[i].ret == ret, i);
		test_assert_idx(strlen(tests[i].output) == str_len(str) &&
				memcmp(tests[i].output, str_data(str),
				       str_len(str)) == 0, i);
		if (ret >= 0) {
			test_assert_idx(
				str_len(str) <= MAX_BASE64_DECODED_SIZE(
					strlen(tests[i].input)), i);
		}
	}
	test_end();
}

static void test_base64url_random(void)
{
	string_t *str, *dest;
	char buf[10];
	unsigned int i, j, max;

	str = t_str_new(256);
	dest = t_str_new(256);

	test_begin("base64url encode/decode with random input");
	for (i = 0; i < 1000; i++) {
		max = i_rand_limit(sizeof(buf));
		for (j = 0; j < max; j++)
			buf[j] = i_rand();

		str_truncate(str, 0);
		str_truncate(dest, 0);
		base64url_encode(buf, max, str);
		test_assert_idx(base64url_decode(str_data(str), str_len(str),
						 dest) >= 0, i);
		test_assert_idx(str_len(dest) == max &&
				memcmp(buf, str_data(dest), max) == 0, i);
	}
	test_end();
}

struct test_base64_encode_lowlevel {
	const struct base64_scheme *scheme;
	enum base64_encode_flags flags;
	size_t max_line_len;

	const char *input;
	const char *output;
};

static const struct test_base64_encode_lowlevel
tests_base64_encode_lowlevel[] = {
	{
		.scheme = &base64_scheme,
		.input = "hello world",
		.output = "aGVsbG8gd29ybGQ=",
	},
	{
		.scheme = &base64url_scheme,
		.input = "hello world",
		.output = "aGVsbG8gd29ybGQ=",
	},
	{
		.scheme = &base64_scheme,
		.flags = BASE64_ENCODE_FLAG_NO_PADDING,
		.input = "hello world",
		.output = "aGVsbG8gd29ybGQ",
	},
	{
		.scheme = &base64_scheme,
		.input = "foo barits",
		.output = "Zm9vIGJhcml0cw==",
	},
	{
		.scheme = &base64url_scheme,
		.input = "foo barits",
		.output = "Zm9vIGJhcml0cw==",
	},
	{
		.scheme = &base64_scheme,
		.flags = BASE64_ENCODE_FLAG_NO_PADDING,
		.input = "foo barits",
		.output = "Zm9vIGJhcml0cw",
	},
	{
		.scheme = &base64_scheme,
		.input = "just niin",
		.output = "anVzdCBuaWlu",
	},
	{
		.scheme = &base64url_scheme,
		.input = "just niin",
		.output = "anVzdCBuaWlu",
	},
	{
		.scheme = &base64_scheme,
		.flags = BASE64_ENCODE_FLAG_NO_PADDING,
		.input = "just niin",
		.output = "anVzdCBuaWlu",
	},
	{
		.scheme = &base64_scheme,
		.input =
			"\xe7\x8c\xbf\xe3\x82\x82\xe6\x9c\xa8\xe3\x81\x8b"
			"\xe3\x82\x89\xe8\x90\xbd\xe3\x81\xa1\xe3\x82\x8b",
		.output = "54y/44KC5pyo44GL44KJ6JC944Gh44KL",
	},
	{
		.scheme = &base64url_scheme,
		.input =
			"\xe7\x8c\xbf\xe3\x82\x82\xe6\x9c\xa8\xe3\x81\x8b"
			"\xe3\x82\x89\xe8\x90\xbd\xe3\x81\xa1\xe3\x82\x8b",
		.output = "54y_44KC5pyo44GL44KJ6JC944Gh44KL",
	},
	{
		.scheme = &base64_scheme,
		.input =
			"\xe8\xa7\x92\xe3\x82\x92\xe7\x9f\xaf\xe3\x82\x81\xe3"
			"\x81\xa6\xe7\x89\x9b\xe3\x82\x92\xe6\xae\xba\xe3\x81"
			"\x99",
		.output = "6KeS44KS55+v44KB44Gm54mb44KS5q6644GZ",
	},
	{
		.scheme = &base64url_scheme,
		.input =
			"\xe8\xa7\x92\xe3\x82\x92\xe7\x9f\xaf\xe3\x82\x81\xe3"
			"\x81\xa6\xe7\x89\x9b\xe3\x82\x92\xe6\xae\xba\xe3\x81"
			"\x99",
		.output = "6KeS44KS55-v44KB44Gm54mb44KS5q6644GZ",
	},
	{
		.scheme = &base64_scheme,
		.flags = BASE64_ENCODE_FLAG_CRLF,
		.input = "just niin",
		.output = "anVzdCBuaWlu",
	},
	{
		.scheme = &base64_scheme,
		.flags = BASE64_ENCODE_FLAG_CRLF,
		.max_line_len = 80,
		.input = "just niin",
		.output = "anVzdCBuaWlu",
	},
	{
		.scheme = &base64_scheme,
		.flags = BASE64_ENCODE_FLAG_CRLF,
		.max_line_len = 48,
		.input =
			"Passer, deliciae meae puellae,\n"
			"quicum ludere, quem in sinu tenere,\n"
			"cui primum digitum dare appetenti\n"
			"et acris solet incitare morsus,\n"
			"cum desiderio meo nitenti\n"
			"carum nescio quid lubet iocari,\n"
			"credo ut, cum gravis acquiescet ardor,\n"
			"sit solaciolum sui doloris,\n"
			"tecum ludere sicut ipsa possem\n"
			"et tristis animi levare curas!\n",
		.output =
			"UGFzc2VyLCBkZWxpY2lhZSBtZWFlIHB1ZWxsYWUsCnF1aWN1\r\n"
			"bSBsdWRlcmUsIHF1ZW0gaW4gc2ludSB0ZW5lcmUsCmN1aSBw\r\n"
			"cmltdW0gZGlnaXR1bSBkYXJlIGFwcGV0ZW50aQpldCBhY3Jp\r\n"
			"cyBzb2xldCBpbmNpdGFyZSBtb3JzdXMsCmN1bSBkZXNpZGVy\r\n"
			"aW8gbWVvIG5pdGVudGkKY2FydW0gbmVzY2lvIHF1aWQgbHVi\r\n"
			"ZXQgaW9jYXJpLApjcmVkbyB1dCwgY3VtIGdyYXZpcyBhY3F1\r\n"
			"aWVzY2V0IGFyZG9yLApzaXQgc29sYWNpb2x1bSBzdWkgZG9s\r\n"
			"b3JpcywKdGVjdW0gbHVkZXJlIHNpY3V0IGlwc2EgcG9zc2Vt\r\n"
			"CmV0IHRyaXN0aXMgYW5pbWkgbGV2YXJlIGN1cmFzIQo=",
	},
	{
		.scheme = &base64_scheme,
		.max_line_len = 48,
		.input =
			"Lugete, o Veneres Cupidinesque,\n"
			"et quantum est hominum venustiorum:\n"
			"passer mortuus est meae puellae, \n"
			"passer, deliciae meae puellae\n"
			"quem plus amat illa oculis suis amabat.\n"
			"Nam mellitus erat suamque norat\n"
			"ipsam tam bene quam puella matrem,\n"
			"nec sese a gremio illius movebat,\n"
			"sed circumsiliens modo huc modo illuc\n"
			"ad solam dominam usque pipiabat;\n"
			"qui nunc it per iter tenebricosum\n"
			"illuc, unde negant redire quemquam.\n"
			"At vobis male sint, malae tenebrae\n"
			"Orci, quae omnia bella devoratis:\n"
			"tam bellum mihi passerem abstulistis.\n"
			"O factum male! O miselle passer!\n"
			"Tua nunc opera meae puellae\n"
			"flendo turgiduli rubent ocelli.\n",
		.output =
			"THVnZXRlLCBvIFZlbmVyZXMgQ3VwaWRpbmVzcXVlLApldCBx\n"
			"dWFudHVtIGVzdCBob21pbnVtIHZlbnVzdGlvcnVtOgpwYXNz\n"
			"ZXIgbW9ydHV1cyBlc3QgbWVhZSBwdWVsbGFlLCAKcGFzc2Vy\n"
			"LCBkZWxpY2lhZSBtZWFlIHB1ZWxsYWUKcXVlbSBwbHVzIGFt\n"
			"YXQgaWxsYSBvY3VsaXMgc3VpcyBhbWFiYXQuCk5hbSBtZWxs\n"
			"aXR1cyBlcmF0IHN1YW1xdWUgbm9yYXQKaXBzYW0gdGFtIGJl\n"
			"bmUgcXVhbSBwdWVsbGEgbWF0cmVtLApuZWMgc2VzZSBhIGdy\n"
			"ZW1pbyBpbGxpdXMgbW92ZWJhdCwKc2VkIGNpcmN1bXNpbGll\n"
			"bnMgbW9kbyBodWMgbW9kbyBpbGx1YwphZCBzb2xhbSBkb21p\n"
			"bmFtIHVzcXVlIHBpcGlhYmF0OwpxdWkgbnVuYyBpdCBwZXIg\n"
			"aXRlciB0ZW5lYnJpY29zdW0KaWxsdWMsIHVuZGUgbmVnYW50\n"
			"IHJlZGlyZSBxdWVtcXVhbS4KQXQgdm9iaXMgbWFsZSBzaW50\n"
			"LCBtYWxhZSB0ZW5lYnJhZQpPcmNpLCBxdWFlIG9tbmlhIGJl\n"
			"bGxhIGRldm9yYXRpczoKdGFtIGJlbGx1bSBtaWhpIHBhc3Nl\n"
			"cmVtIGFic3R1bGlzdGlzLgpPIGZhY3R1bSBtYWxlISBPIG1p\n"
			"c2VsbGUgcGFzc2VyIQpUdWEgbnVuYyBvcGVyYSBtZWFlIHB1\n"
			"ZWxsYWUKZmxlbmRvIHR1cmdpZHVsaSBydWJlbnQgb2NlbGxp\n"
			"Lgo=",
	},
};

static void test_base64_encode_lowlevel(void)
{
	string_t *str;
	unsigned int i;

	test_begin("base64 encode low-level");
	str = t_str_new(256);
	for (i = 0; i < N_ELEMENTS(tests_base64_encode_lowlevel); i++) {
		const struct test_base64_encode_lowlevel *test =
			&tests_base64_encode_lowlevel[i];
		struct base64_encoder enc;
		uoff_t out_size;

		str_truncate(str, 0);

		base64_encode_init(&enc, test->scheme, test->flags,
				   test->max_line_len);
		out_size = base64_get_full_encoded_size(
			&enc, strlen(test->input));
		base64_encode_more(&enc, test->input, strlen(test->input),
				   NULL, str);
		base64_encode_finish(&enc, str);

		test_assert_idx(strcmp(test->output, str_c(str)) == 0, i);
		test_assert_idx(test->flags != 0 || test->max_line_len != 0 ||
			str_len(str) == MAX_BASE64_ENCODED_SIZE(
				strlen(test->input)), i);
		test_assert_idx(str_len(str) == out_size, i);
	}
	test_end();
}

struct test_base64_decode_lowlevel {
	const struct base64_scheme *scheme;
	enum base64_decode_flags flags;

	const char *input;
	const char *output;
	int ret;
	unsigned int src_pos;
};

static const struct test_base64_decode_lowlevel
tests_base64_decode_lowlevel[] = {
	{
		.scheme = &base64_scheme,
		.input = "\taGVsbG8gd29ybGQ=",
		.output = "hello world",
		.ret = 0,
		.src_pos = UINT_MAX,
	},
	{
		.scheme = &base64url_scheme,
		.input = "\taGVsbG8gd29ybGQ=",
		.output = "hello world",
		.ret = 0,
		.src_pos = UINT_MAX,
	},
	{
		.scheme = &base64_scheme,
		.input = "aGVsbG8gd29ybGQ=\t",
		.output = "hello world",
		.ret = 0,
		.src_pos = UINT_MAX,
	},
	{
		.scheme = &base64_scheme,
		.input = "\taGVsbG8gd29ybGQ=\t",
		.output = "hello world",
		.ret = 0,
		.src_pos = UINT_MAX,
	},
	{
		.scheme = &base64_scheme,
		.input = "aGVsbG8gd29ybGQ=:frop",
		.output = "hello world",
		.ret = 0,
		.src_pos = 16,
		.flags = BASE64_DECODE_FLAG_EXPECT_BOUNDARY,
	},
	{
		.scheme = &base64_scheme,
		.input = "\taGVsbG8gd29ybGQ=\t:frop",
		.output = "hello world",
		.ret = 0,
		.src_pos = 18,
		.flags = BASE64_DECODE_FLAG_EXPECT_BOUNDARY,
	},
	{
		.scheme = &base64_scheme,
		.input = "aGVsbG8gd29ybGQ=\t",
		.output = "hello world",
		.ret = -1,
		.src_pos = 16,
		.flags = BASE64_DECODE_FLAG_NO_WHITESPACE,
	},
	{
		.scheme = &base64_scheme,
		.input = "\taGVsbG8gd29ybGQ=\t",
		.output = "",
		.ret = -1,
		.src_pos = 0,
		.flags = BASE64_DECODE_FLAG_NO_WHITESPACE,
	},
	{
		.scheme = &base64_scheme,
		.input = "\nZm9v\n \tIGJh  \t\ncml0cw==",
		.output = "foo barits",
		.ret = 0,
		.src_pos = UINT_MAX,
	},
	{
		.scheme = &base64url_scheme,
		.input = "\nZm9v\n \tIGJh  \t\ncml0cw==",
		.output = "foo barits",
		.ret = 0,
		.src_pos = UINT_MAX,
	},
	{
		.scheme = &base64_scheme,
		.input = "\nZm9v\n \tIGJh  \t\ncml0cw==\n  ",
		.output = "foo barits",
		.ret = 0,
		.src_pos = UINT_MAX,
	},
	{
		.scheme = &base64_scheme,
		.input = "\nZm9v\n \tIGJh  \t\ncml0cw= =\n  ",
		.output = "foo barits",
		.ret = 0,
		.src_pos = UINT_MAX,
	},
	{
		.scheme = &base64_scheme,
		.input = "\nZm9v\n \tIGJh  \t\ncml0cw\n= =\n  ",
		.output = "foo barits",
		.ret = 0,
		.src_pos = UINT_MAX,
	},
	{
		.scheme = &base64_scheme,
		.input = "  anVzdCBuaWlu  \n",
		.output = "just niin",
		.ret = 0,
		.src_pos = UINT_MAX,
	},
	{
		.scheme = &base64url_scheme,
		.input = "  anVzdCBuaWlu  \n",
		.output = "just niin",
		.ret = 0,
		.src_pos = UINT_MAX,
	},
	{
		.scheme = &base64_scheme,
		.input = "aGVsb",
		.output = "hel",
		.ret = -1,
		.src_pos = 5,
	},
	{
		.scheme = &base64url_scheme,
		.input = "aGVsb",
		.output = "hel",
		.ret = -1,
		.src_pos = 5,
	},
	{
		.scheme = &base64_scheme,
		.input = "aGVsb!!!!!",
		.output = "hel",
		.ret = -1,
		.src_pos = 5,
	},
	{
		.scheme = &base64url_scheme,
		.input = "aGVsb!!!!!",
		.output = "hel",
		.ret = -1,
		.src_pos = 5,
	},
	{
		.scheme = &base64_scheme,
		.input = "aGVs!!!!!",
		.output = "hel",
		.ret = -1,
		.src_pos = 4,
	},
	{
		.scheme = &base64url_scheme,
		.input = "aGVs!!!!!",
		.output = "hel",
		.ret = -1,
		.src_pos = 4,
	},
	{
		.scheme = &base64_scheme,
		.input =
			"0JPQvtCy0L7RgNGPzIHRgiwg0YfRgt"
			"C+INC60YPRgCDQtNC+0Y/MgdGCLg==",
		.output =
			"\xd0\x93\xd0\xbe\xd0\xb2\xd0\xbe\xd1\x80\xd1\x8f\xcc"
			"\x81\xd1\x82\x2c\x20\xd1\x87\xd1\x82\xd0\xbe\x20\xd0"
			"\xba\xd1\x83\xd1\x80\x20\xd0\xb4\xd0\xbe\xd1\x8f\xcc"
			"\x81\xd1\x82\x2e",
		.ret = 0,
		.src_pos = UINT_MAX,
	},
	{
		.scheme = &base64url_scheme,
		.input =
			"0JPQvtCy0L7RgNGPzIHRgiwg0YfRgt"
			"C-INC60YPRgCDQtNC-0Y_MgdGCLg==",
		.output =
			"\xd0\x93\xd0\xbe\xd0\xb2\xd0\xbe\xd1\x80\xd1\x8f\xcc"
			"\x81\xd1\x82\x2c\x20\xd1\x87\xd1\x82\xd0\xbe\x20\xd0"
			"\xba\xd1\x83\xd1\x80\x20\xd0\xb4\xd0\xbe\xd1\x8f\xcc"
			"\x81\xd1\x82\x2e",
		.ret = 0,
		.src_pos = UINT_MAX,
	},
};

static void test_base64_decode_lowlevel(void)
{
	string_t *str;
	buffer_t buf;
	unsigned int i;

	test_begin("base64 decode low-level");
	for (i = 0; i < N_ELEMENTS(tests_base64_decode_lowlevel); i++) {
		const struct test_base64_decode_lowlevel *test =
			&tests_base64_decode_lowlevel[i];
		struct base64_decoder dec;
		size_t src_pos;
		int ret;

		/* Some of the base64_decode() callers use fixed size buffers.
		   Use a fixed size buffer here as well to test that
		   base64_decode() can't allocate any extra space even
		   temporarily. */
		size_t max_decoded_size =
			MAX_BASE64_DECODED_SIZE(strlen(test->input));

		buffer_create_from_data(&buf, t_malloc0(max_decoded_size),
					max_decoded_size);
		str = &buf;
		base64_decode_init(&dec, test->scheme, test->flags);
		ret = base64_decode_more(&dec, test->input, strlen(test->input),
					 &src_pos, str);
		if (ret >= 0)
			ret = base64_decode_finish(&dec);

		test_assert_idx(ret == test->ret, i);
		test_assert_idx(strlen(test->output) == str_len(str) &&
				memcmp(test->output, str_data(str),
				       str_len(str)) == 0, i);
		test_assert_idx(src_pos == test->src_pos ||
				(test->src_pos == UINT_MAX &&
				src_pos == strlen(test->input)), i);
		if (ret >= 0) {
			test_assert_idx(
				str_len(str) <= MAX_BASE64_DECODED_SIZE(
					strlen(test->input)), i);
		}
	}
	test_end();
}

static void
test_base64_random_lowlevel_one_block(const struct base64_scheme *b64,
				      enum base64_encode_flags enc_flags,
				      enum base64_decode_flags dec_flags,
				      size_t max_line_len,
				      unsigned int test_idx,
				      const unsigned char *in_buf,
				      size_t in_buf_size,
				      buffer_t *buf1, buffer_t *buf2)
{
	struct base64_encoder enc;
	struct base64_decoder dec;
	int ret;

	buffer_set_used_size(buf1, 0);
	buffer_set_used_size(buf2, 0);

	base64_encode_init(&enc, b64, enc_flags, max_line_len);
	base64_encode_more(&enc, in_buf, in_buf_size, NULL, buf1);
	base64_encode_finish(&enc, buf1);

	base64_decode_init(&dec, b64, dec_flags);
	ret = base64_decode_more(&dec, buf1->data, buf1->used,
				 NULL, buf2);
	if (ret >= 0)
		ret = base64_decode_finish(&dec);

	test_assert_idx(ret >= 0, test_idx);
	test_assert_idx(buf2->used == in_buf_size &&
			memcmp(in_buf, buf2->data, in_buf_size) == 0, test_idx);
}

static void
test_base64_random_lowlevel_stream(const struct base64_scheme *b64,
				   enum base64_encode_flags enc_flags,
				   enum base64_decode_flags dec_flags,
				   size_t max_line_len, unsigned int test_idx,
				   const unsigned char *in_buf,
				   size_t in_buf_size,
				   buffer_t *buf1, buffer_t *buf2,
				   size_t chunk_size)
{
	struct base64_encoder enc;
	struct base64_decoder dec;
	const unsigned char *buf_p, *buf_begin, *buf_end;
	int ret;
	size_t out_space;
	void *out_data;
	buffer_t out;

	buf_begin = in_buf;
	buf_end = buf_begin + in_buf_size;

	buffer_set_used_size(buf1, 0);
	buffer_set_used_size(buf2, 0);

	base64_encode_init(&enc, b64, enc_flags, max_line_len);
	out_space = 0;
	for (buf_p = buf_begin; buf_p < buf_end; ) {
		size_t buf_ch, out_ch;
		size_t left = (buf_end - buf_p);
		size_t used = buf1->used;
		size_t src_pos;

		if (chunk_size == 0) {
			buf_ch = i_rand_limit(32);
			out_ch = i_rand_limit(32);
		} else {
			buf_ch = chunk_size;
			out_ch = chunk_size;
		}

		out_space += out_ch;
		out_data = buffer_append_space_unsafe(buf1, out_space);
		buffer_create_from_data(&out, out_data, out_space);

		if (buf_ch > left)
			buf_ch = left;

		base64_encode_more(&enc, buf_p, buf_ch, &src_pos, &out);
		buf_p += src_pos;
		i_assert(out_space >= out.used);
		out_space -= out.used;
		buffer_set_used_size(buf1, used + out.used);
	}
	base64_encode_finish(&enc, buf1);

	buf_begin = buf1->data;
	buf_end = buf_begin + buf1->used;

	base64_decode_init(&dec, b64, dec_flags);
	ret = 1;
	out_space = 0;
	for (buf_p = buf_begin; buf_p < buf_end; ) {
		size_t buf_ch, out_ch;
		size_t left = (buf_end - buf_p);
		size_t used = buf2->used;
		size_t src_pos;

		if (chunk_size == 0) {
			buf_ch = i_rand_limit(32);
			out_ch = i_rand_limit(32);
		} else {
			buf_ch = chunk_size;
			out_ch = chunk_size;
		}

		out_space += out_ch;
		out_data = buffer_append_space_unsafe(buf2, out_space);
		buffer_create_from_data(&out, out_data, out_space);

		if (buf_ch > left)
			buf_ch = left;
		ret = base64_decode_more(&dec, buf_p, buf_ch,
					 &src_pos, &out);
		test_assert_idx(ret >= 0, test_idx);
		if (ret < 0) {
			break;
		}
		buf_p += src_pos;
		i_assert(out_space >= out.used);
		out_space -= out.used;
		buffer_set_used_size(buf2, used + out.used);
	}
	test_assert_idx(ret >= 0, test_idx);

	if (ret > 0) {
		ret = base64_decode_finish(&dec);
		test_assert_idx(ret == 0, test_idx);
		test_assert_idx(buf2->used == in_buf_size &&
				memcmp(in_buf, buf2->data, in_buf_size) == 0,
				test_idx);
	}
}

static void
test_base64_random_lowlevel_case(const struct base64_scheme *b64,
				 enum base64_encode_flags enc_flags,
				 enum base64_decode_flags dec_flags,
				 size_t max_line_len)
{
	unsigned char in_buf[512];
	size_t in_buf_size;
	buffer_t *buf1, *buf2;
	unsigned int i, j;

	buf1 = t_buffer_create(MAX_BASE64_ENCODED_SIZE(sizeof(in_buf)));
	buf2 = t_buffer_create(sizeof(in_buf));

	/* one block */
	for (i = 0; i < 1000; i++) {
		in_buf_size = i_rand_limit(sizeof(in_buf));
		for (j = 0; j < in_buf_size; j++)
			in_buf[j] = i_rand();

		test_base64_random_lowlevel_one_block(b64, enc_flags, dec_flags,
						      max_line_len, i,
						      in_buf, in_buf_size,
						      buf1, buf2);
	}

	/* streaming; single-byte trickle */
	for (i = 0; i < 1000; i++) {
		in_buf_size = i_rand_limit(sizeof(in_buf));
		for (j = 0; j < in_buf_size; j++)
			in_buf[j] = i_rand();

		test_base64_random_lowlevel_stream(b64, enc_flags, dec_flags,
						   max_line_len, i,
						   in_buf, in_buf_size,
						   buf1, buf2, 1);
	}

	/* streaming; random chunks */
	for (i = 0; i < 1000; i++) {
		in_buf_size = i_rand_limit(sizeof(in_buf));
		for (j = 0; j < in_buf_size; j++)
			in_buf[j] = i_rand();

		test_base64_random_lowlevel_stream(b64, enc_flags, dec_flags,
						   max_line_len, i,
						   in_buf, in_buf_size,
						   buf1, buf2, 0);
	}
}

static void
test_base64_random_lowlevel(void)
{
	test_begin("base64 encode/decode low-level with random input");
	test_base64_random_lowlevel_case(&base64_scheme, 0, 0, 0);
	test_base64_random_lowlevel_case(&base64url_scheme, 0, 0, 0);
	test_base64_random_lowlevel_case(&base64_scheme, 0,
					 BASE64_DECODE_FLAG_EXPECT_BOUNDARY, 0);
	test_base64_random_lowlevel_case(&base64url_scheme, 0,
					 BASE64_DECODE_FLAG_EXPECT_BOUNDARY, 0);
	test_base64_random_lowlevel_case(&base64_scheme, 0,
					 BASE64_DECODE_FLAG_NO_WHITESPACE, 0);
	test_base64_random_lowlevel_case(&base64url_scheme, 0,
					 BASE64_DECODE_FLAG_NO_WHITESPACE, 0);
	test_base64_random_lowlevel_case(&base64_scheme, 0, 0, 10);
	test_base64_random_lowlevel_case(&base64url_scheme, 0, 0, 10);
	test_base64_random_lowlevel_case(&base64_scheme,
					 BASE64_ENCODE_FLAG_CRLF, 0, 10);
	test_base64_random_lowlevel_case(&base64url_scheme,
					 BASE64_ENCODE_FLAG_CRLF, 0, 10);
	test_end();
}

static void
_add_lines(const char *in, size_t max_line_len, bool crlf, string_t *out)
{
	size_t in_len = strlen(in);

	while (max_line_len > 0 && in_len > max_line_len) {
		str_append_data(out, in, max_line_len);
		if (crlf)
			str_append(out, "\r\n");
		else
			str_append_c(out, '\n');
		in += max_line_len;
		in_len -= max_line_len;
	}

	str_append_data(out, in, in_len);
}

static void test_base64_encode_lines(void)
{
	static const char *input[] = {
		"Passer, deliciae meae puellae,\n"
		"quicum ludere, quem in sinu tenere,\n"
		"cui primum digitum dare appetenti\n"
		"et acris solet incitare morsus,\n"
		"cum desiderio meo nitenti\n"
		"carum nescio quid lubet iocari,\n"
		"credo ut, cum gravis acquiescet ardor,\n"
		"sit solaciolum sui doloris,\n"
		"tecum ludere sicut ipsa possem\n"
		"et tristis animi levare curas!\n"
	};
	static const char *output[] = {
		"UGFzc2VyLCBkZWxpY2lhZSBtZWFlIHB1ZWxsYWUsCnF1aWN1"
		"bSBsdWRlcmUsIHF1ZW0gaW4gc2ludSB0ZW5lcmUsCmN1aSBw"
		"cmltdW0gZGlnaXR1bSBkYXJlIGFwcGV0ZW50aQpldCBhY3Jp"
		"cyBzb2xldCBpbmNpdGFyZSBtb3JzdXMsCmN1bSBkZXNpZGVy"
		"aW8gbWVvIG5pdGVudGkKY2FydW0gbmVzY2lvIHF1aWQgbHVi"
		"ZXQgaW9jYXJpLApjcmVkbyB1dCwgY3VtIGdyYXZpcyBhY3F1"
		"aWVzY2V0IGFyZG9yLApzaXQgc29sYWNpb2x1bSBzdWkgZG9s"
		"b3JpcywKdGVjdW0gbHVkZXJlIHNpY3V0IGlwc2EgcG9zc2Vt"
		"CmV0IHRyaXN0aXMgYW5pbWkgbGV2YXJlIGN1cmFzIQo=",
	};
	string_t *out_test, *out_ref;
	unsigned int i, n;

	out_test = t_str_new(256);
	out_ref = t_str_new(256);

	test_begin("base64 encode lines (LF)");
	for (i = 0; i < N_ELEMENTS(input); i++) {
		struct base64_encoder b64enc;

		for (n = 0; n <= 80; n++) {
			str_truncate(out_test, 0);
			base64_encode_init(&b64enc, &base64_scheme, 0, n);
			base64_encode_more(&b64enc, input[i], strlen(input[i]),
					   NULL, out_test);
			base64_encode_finish(&b64enc, out_test);

			str_truncate(out_ref, 0);
			_add_lines(output[i], n, FALSE, out_ref);

			test_assert(strcmp(str_c(out_ref),
					   str_c(out_test)) == 0);

		}
	}
	test_end();

	test_begin("base64 encode lines (CRLF)");
	for (i = 0; i < N_ELEMENTS(input); i++) {
		struct base64_encoder b64enc;

		for (n = 0; n <= 80; n++) {
			str_truncate(out_test, 0);
			base64_encode_init(&b64enc, &base64_scheme,
					   BASE64_ENCODE_FLAG_CRLF, n);
			base64_encode_more(&b64enc, input[i], strlen(input[i]),
					   NULL, out_test);
			base64_encode_finish(&b64enc, out_test);

			str_truncate(out_ref, 0);
			_add_lines(output[i], n, TRUE, out_ref);

			test_assert(strcmp(str_c(out_ref),
					   str_c(out_test)) == 0);

		}
	}
	test_end();
}

void test_base64(void)
{
	test_base64_encode();
	test_base64_decode();
	test_base64_random();
	test_base64url_encode();
	test_base64url_decode();
	test_base64url_random();
	test_base64_encode_lowlevel();
	test_base64_decode_lowlevel();
	test_base64_random_lowlevel();
	test_base64_encode_lines();
}
