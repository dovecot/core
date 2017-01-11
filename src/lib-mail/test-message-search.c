/* Copyright (c) 2016-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "unichar.h"
#include "message-parser.h"
#include "message-search.h"
#include "test-common.h"

static void test_message_search_more_get_decoded(void)
{
	const char input[] = "p\xC3\xB6\xC3\xB6";
	const unsigned char text_plain[] = "text/plain; charset=utf-8";
	struct message_search_context *ctx1, *ctx2;
	struct message_block raw_block, decoded_block;
	struct message_header_line hdr;
	struct message_part part;
	unsigned int i;

	test_begin("message_search_more_get_decoded()");

	ctx1 = message_search_init("p\xC3\xA4\xC3\xA4", NULL, 0);
	ctx2 = message_search_init("p\xC3\xB6\xC3\xB6", NULL, 0);

	i_zero(&raw_block);
	raw_block.part = &part;

	/* feed the Content-Type header */
	i_zero(&hdr);
	hdr.name = "Content-Type"; hdr.name_len = strlen(hdr.name);
	hdr.value = hdr.full_value = text_plain;
	hdr.value_len = hdr.full_value_len = sizeof(text_plain)-1;
	raw_block.hdr = &hdr;
	test_assert(!message_search_more_get_decoded(ctx1, &raw_block, &decoded_block));
	test_assert(!message_search_more_decoded(ctx2, &decoded_block));

	/* EOH */
	raw_block.hdr = NULL;
	test_assert(!message_search_more_get_decoded(ctx1, &raw_block, &decoded_block));
	test_assert(!message_search_more_decoded(ctx2, &decoded_block));

	/* body */
	raw_block.size = 1;
	for (i = 0; input[i] != '\0'; i++) {
		raw_block.data = (const void *)&input[i];
		test_assert(!message_search_more_get_decoded(ctx1, &raw_block, &decoded_block));
		test_assert(message_search_more_decoded(ctx2, &decoded_block) == (input[i+1] == '\0'));
	}
	message_search_deinit(&ctx1);
	message_search_deinit(&ctx2);
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_message_search_more_get_decoded,
		NULL
	};
	return test_run(test_functions);
}
