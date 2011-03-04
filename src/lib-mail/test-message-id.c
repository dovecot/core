/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "message-id.h"
#include "test-common.h"

static void test_message_id_get_next(void)
{
	const char *input[] = {
		"<foo@bar>",
		"<foo@bar>,skipped,<foo2@bar2>",
		"(c) < (c) foo (c) @ (c) bar (c) > (c)",
	};
	const char *output[] = {
		"foo@bar", NULL,
		"foo@bar", "foo2@bar2", NULL,
		"foo@bar", NULL
	};
	const char *msgid, *next_msgid;
	unsigned int i, j;

	test_begin("message id parser");
	for (i = 0, j = 0; i < N_ELEMENTS(input); i++) {
		msgid = input[i];
		while ((next_msgid = message_id_get_next(&msgid)) != NULL) {
			if (output[j] == NULL)
				break;
			test_assert(strcmp(output[j++], next_msgid) == 0);
		}
		test_assert(output[j++] == NULL && next_msgid == NULL);
	}
	test_assert(j == N_ELEMENTS(output));
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_message_id_get_next,
		NULL
	};
	return test_run(test_functions);
}
