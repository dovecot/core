/* Copyright (c) 2026 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "mail-storage.h"
#include "imap-msgpart.h"

static void test_imap_msgpart_parse(void)
{
	const struct {
		const char *section;
		bool success;
		bool contains_body;
	} tests[] = {
		{ "", TRUE, TRUE },
		{ "1", TRUE, TRUE },
		{ "1.2", TRUE, TRUE },
		{ "MIME", FALSE, FALSE },
		{ "1.MIME", TRUE, TRUE },
		{ "HEADER", TRUE, FALSE },
		{ "1.HEADER", TRUE, FALSE },
		{ "TEXT", TRUE, TRUE },
		{ "1.TEXT", TRUE, TRUE },
		{ "HEADER.FIELDS (Subject Date)", TRUE, FALSE },
		{ "HEADER.FIELDS.NOT (From)", TRUE, FALSE },
		{ "1.HEADER.FIELDS (Subject)", TRUE, FALSE },
		{ "1.2.3.4", TRUE, TRUE },
		{ "1.2.MIME", TRUE, TRUE },
		{ "1.2.TEXT", TRUE, TRUE },
		{ "1.2.HEADER", TRUE, FALSE },
		{ "1.", FALSE, FALSE },
		{ ".1", FALSE, FALSE },
		{ "1.2..3", FALSE, FALSE },
		{ "HEADER.FIELDS", FALSE, FALSE },
		{ "HEADER.FIELDS ()", FALSE, FALSE },
		{ "INVALID", FALSE, FALSE },
	};
	unsigned int i;

	test_begin("imap_msgpart_parse()");

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		struct imap_msgpart *part = NULL;
		int ret = imap_msgpart_parse(tests[i].section, &part);

		test_assert_idx((ret == 0) == tests[i].success, i);
		if (ret == 0) {
			test_assert_idx(imap_msgpart_contains_body(part) == tests[i].contains_body, i);
			imap_msgpart_free(&part);
		}
	}

	test_end();
}

int main(void)
{
	void (*const test_functions[])(void) = {
		test_imap_msgpart_parse,
		NULL
	};
	return test_run(test_functions);
}
