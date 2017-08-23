/* Copyright (c) 2016-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "md5.h"
#include "message-header-hash.h"

static const char test_input_with_nuls[] = {
	"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
	"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
	"\x20!?x??yz\x7f\x80\x90\xff-plop\xff"
};

static const struct {
	const char *input;
	unsigned int version;
	const char *output;
} tests[] = {
	{ "???hi???", 1, "???hi???" },

	{ test_input_with_nuls, 2, "?\t\n? !?x?yz?-plop?" },
	{ "?hi?", 2, "?hi?" },
	{ "\x01hi\x01", 2, "?hi?" },
	{ "???hi???", 2, "?hi?" },
	{ "\x01?hi??\x01", 2, "?hi?" },
	{ "?\t?hi?\t?", 2, "?\t?hi?\t?" },
	{ "\n\nhi\n\n", 2, "\n\nhi\n\n" },
	{ "", 2, "" },
	{ " ", 2, " " },
	{ "   ", 2, "   " },
	{ "? ? ? hi \x01\x02   \x03   ", 2, "? ? ? hi ?   ?   " },

	{ test_input_with_nuls, 3, "?\t\n?!?x?yz?-plop?" },
	{ "\n\nhi\n\n", 3, "\n\nhi\n\n" },
	{ "", 3, "" },
	{ " ", 3, "" },
	{ "   ", 3, "" },
	{ " ? ", 3, "?" },
	{ "? ? ? hi \x01\x02   \x03   ", 3, "???hi??" },
	{ " \t \t", 3, "\t\t" },

	{ test_input_with_nuls, 4, "?\n?!?x?yz?-plop?" },
	{ "\n\nhi\n\n", 4, "\n\nhi\n\n" },
	{ "", 4, "" },
	{ " ", 4, "" },
	{ " \t \t", 4, "" },
	{ "foo\t\t", 4, "foo" },
};

static void test_message_header_hash_more(void)
{
	struct message_header_hash_context ctx;
	struct md5_context md5_ctx;
	unsigned char md5_input[MD5_RESULTLEN], md5_output[MD5_RESULTLEN];

	test_begin("message_header_hash_more");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		size_t input_len = tests[i].input == test_input_with_nuls ?
			sizeof(test_input_with_nuls)-1 : strlen(tests[i].input);
		md5_init(&md5_ctx);
		i_zero(&ctx);
		message_header_hash_more(&ctx, &hash_method_md5, &md5_ctx,
					 tests[i].version,
					 (const unsigned char *)tests[i].input,
					 input_len);
		md5_final(&md5_ctx, md5_input);

		md5_init(&md5_ctx);
		md5_update(&md5_ctx, tests[i].output, strlen(tests[i].output));
		md5_final(&md5_ctx, md5_output);

		test_assert_idx(memcmp(md5_input, md5_output, MD5_RESULTLEN) == 0, i);

		/* single byte at a time */
		md5_init(&md5_ctx);
		i_zero(&ctx);
		for (unsigned int j = 0; j < input_len; j++) {
			unsigned char chr = tests[i].input[j];
			message_header_hash_more(&ctx, &hash_method_md5,
						 &md5_ctx, tests[i].version,
						 &chr, 1);
		}
		md5_final(&md5_ctx, md5_input);
		test_assert_idx(memcmp(md5_input, md5_output, MD5_RESULTLEN) == 0, i);

		/* random number of chars at a time */
		md5_init(&md5_ctx);
		i_zero(&ctx);
		for (unsigned int j = 0; j < input_len; ) {
			const unsigned char *input_part =
				(const unsigned char *)tests[i].input + j;
			unsigned int len = i_rand() % (input_len - j) + 1;
			message_header_hash_more(&ctx, &hash_method_md5,
						 &md5_ctx, tests[i].version,
						 input_part, len);
			j += len;
		}
		md5_final(&md5_ctx, md5_input);
		test_assert_idx(memcmp(md5_input, md5_output, MD5_RESULTLEN) == 0, i);
	}
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_message_header_hash_more,
		NULL
	};
	return test_run(test_functions);
}
