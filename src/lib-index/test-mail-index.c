/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "test-common.h"
#include "test-mail-index.h"
#include "mail-transaction-log-private.h"

static void test_mail_index_rotate(void)
{
	struct mail_index *index;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;

	test_begin("mail index rotate");
	index = test_mail_index_init();
	view = mail_index_view_open(index);

	/* First rotation of the index. The view will point to the old index. */
	trans = mail_index_transaction_begin(view, 0);
	mail_index_reset(trans);
	test_assert(mail_index_transaction_commit(&trans) == 0);

	/* Second rotation of the index. The log head doesn't have any extra
	   references. */
	trans = mail_index_transaction_begin(view, 0);
	mail_index_reset(trans);
	test_assert(mail_index_transaction_commit(&trans) == 0);

	mail_index_view_close(&view);
	test_mail_index_deinit(&index);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_mail_index_rotate,
		NULL
	};
	return test_run(test_functions);
}
