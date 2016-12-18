/* Copyright (c) 2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "md5.h"
#include "message-header-hash.h"

static const unsigned char test_input[] =
	"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
	"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
	"\x20!?x??yz\x7f\x80\x90\xff-plop\xff";
static const unsigned char test_output[] =
	"?\t\n? !?x?yz?-plop?";

static void test_dsync_mail_hash_more(void)
{
	struct message_header_hash_context ctx;
	struct md5_context md5_ctx;
	unsigned char md5_input[MD5_RESULTLEN], md5_output[MD5_RESULTLEN];

	test_begin("dsync_mail_hash_more v2");
	md5_init(&md5_ctx);
	i_zero(&ctx);
	message_header_hash_more(&ctx, &hash_method_md5, &md5_ctx, 2,
				 test_input, sizeof(test_input)-1);
	md5_final(&md5_ctx, md5_input);

	md5_init(&md5_ctx);
	md5_update(&md5_ctx, test_output, sizeof(test_output)-1);
	md5_final(&md5_ctx, md5_output);

	test_assert(memcmp(md5_input, md5_output, MD5_RESULTLEN) == 0);

	/* single byte at a time */
	md5_init(&md5_ctx);
	i_zero(&ctx);
	for (unsigned int i = 0; i < sizeof(test_input)-1; i++) {
		message_header_hash_more(&ctx, &hash_method_md5, &md5_ctx, 2,
					 test_input + i, 1);
	}
	md5_final(&md5_ctx, md5_input);
	test_assert(memcmp(md5_input, md5_output, MD5_RESULTLEN) == 0);

	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_dsync_mail_hash_more,
		NULL
	};
	return test_run(test_functions);
}
