/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "test-index.h"

int main(void)
{
	static void (*test_functions[])(void) = {
		test_transaction_log_view,
		NULL
	};
	return test_run(test_functions);
}
