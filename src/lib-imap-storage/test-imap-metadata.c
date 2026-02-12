/* Copyright (c) 2026 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "mail-storage.h"
#include "mail-namespace.h"
#include "imap-metadata.h"

static void test_imap_metadata_verify_entry_name(void)
{
	const struct {
		const char *name;
		bool valid;
	} tests[] = {
		{ "/private/comment", TRUE },
		{ "/shared/comment", TRUE },
		{ "/private/foo/bar", TRUE },
		{ "/shared/a/b/c", TRUE },
		{ "/PRIVATE/UPPER", TRUE },
		{ "/Shared/Mixed", TRUE },
		{ "private/foo", FALSE },
		{ "/private", TRUE },
		{ "/shared", TRUE },
		{ "/private/", FALSE },
		{ "/shared//foo", FALSE },
		{ "/private/foo*", FALSE },
		{ "/shared/foo%", FALSE },
		{ "/other/foo", FALSE },
		{ "", FALSE },
		{ "/", FALSE },
		{ "/private/ctrl\x01", FALSE },
		{ "//private/foo", FALSE },
		{ "/private/foo//bar", FALSE },
	};
	unsigned int i;

	test_begin("imap_metadata_verify_entry_name()");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		const char *error = NULL;
		bool result = imap_metadata_verify_entry_name(tests[i].name, &error);
		test_assert_idx(result == tests[i].valid, i);
	}
	test_end();
}

int main(void)
{
	void (*const test_functions[])(void) = {
		test_imap_metadata_verify_entry_name,
		NULL
	};
	return test_run(test_functions);
}
