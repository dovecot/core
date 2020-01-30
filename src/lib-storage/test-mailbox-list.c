/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "test-common.h"
#include "mailbox-list-private.h"

static void test_init_list(struct mailbox_list *list_r)
{
	i_zero(list_r);
}

static void test_deinit_list(struct mailbox_list *list)
{
	mailbox_list_clear_error(list);
	if (array_is_created(&list->error_stack)) {
		mailbox_list_clear_error(list);
		i_assert(array_count(&list->error_stack) == 0);
		array_free(&list->error_stack);
	}
}

static void test_mailbox_list_errors(void)
{
	/* NOTE: keep in sync with test-mail-storage.c */
	struct mailbox_list list;
	enum mail_error mail_error;
	const char *errstr;

	test_begin("mail list errors");
	test_init_list(&list);

	/* try a regular error */
	mailbox_list_set_error(&list, MAIL_ERROR_PERM, "error1");
	test_assert(strcmp(mailbox_list_get_last_error(&list, &mail_error),
			   "error1") == 0);
	test_assert(mail_error == MAIL_ERROR_PERM);
	test_assert(strcmp(mailbox_list_get_last_internal_error(&list, &mail_error),
			   "error1") == 0);
	test_assert(mail_error == MAIL_ERROR_PERM);
	test_assert(!list.last_error_is_internal);

	/* set the error to itself */
	mailbox_list_set_error(&list, MAIL_ERROR_PARAMS,
		mailbox_list_get_last_error(&list, &mail_error));
	test_assert(strcmp(mailbox_list_get_last_error(&list, &mail_error),
			   "error1") == 0);
	test_assert(mail_error == MAIL_ERROR_PARAMS);
	test_assert(strcmp(mailbox_list_get_last_internal_error(&list, &mail_error),
			   "error1") == 0);
	test_assert(mail_error == MAIL_ERROR_PARAMS);
	test_assert(!list.last_error_is_internal);

	/* clear the error - asking for it afterwards is a bug */
	mailbox_list_clear_error(&list);
	test_assert(strcmp(mailbox_list_get_last_error(&list, &mail_error),
			   "BUG: Unknown internal list error") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strcmp(mailbox_list_get_last_internal_error(&list, &mail_error),
			   "BUG: Unknown internal list error") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(!list.last_error_is_internal);

	/* set internal error in preparation for the next test */
	test_expect_error_string("critical0");
	mailbox_list_set_critical(&list, "critical0");
	test_expect_no_more_errors();
	test_assert(strstr(mailbox_list_get_last_error(&list, &mail_error),
			   MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strcmp(mailbox_list_get_last_internal_error(&list, &mail_error),
			   "critical0") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(list.last_error_is_internal);

	/* internal error without specifying what it is. this needs to clear
	   the previous internal error. */
	mailbox_list_set_internal_error(&list);
	test_assert(strstr(mailbox_list_get_last_error(&list, &mail_error),
			   MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strstr(mailbox_list_get_last_internal_error(&list, &mail_error),
			   MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(!list.last_error_is_internal);

	/* proper internal error */
	test_expect_error_string("critical1");
	mailbox_list_set_critical(&list, "critical1");
	test_expect_no_more_errors();
	test_assert(strstr(mailbox_list_get_last_error(&list, &mail_error),
			   MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strcmp(mailbox_list_get_last_internal_error(&list, &mail_error),
			   "critical1") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(list.last_error_is_internal);

	/* use it in the following internal error */
	test_expect_error_string("critical2: critical1");
	mailbox_list_set_critical(&list, "critical2: %s",
		mailbox_list_get_last_internal_error(&list, &mail_error));
	test_expect_no_more_errors();
	test_assert(strstr(mailbox_list_get_last_error(&list, &mail_error),
			   MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strcmp(mailbox_list_get_last_internal_error(&list, &mail_error),
			   "critical2: critical1") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(list.last_error_is_internal);

	/* use the previous non-internal error as part of the internal error */
	test_expect_error_string("critical3: "MAIL_ERRSTR_CRITICAL_MSG);
	mailbox_list_set_critical(&list, "critical3: %s",
		mailbox_list_get_last_error(&list, &mail_error));
	test_expect_no_more_errors();
	test_assert(strstr(mailbox_list_get_last_error(&list, &mail_error),
			   MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	errstr = mailbox_list_get_last_internal_error(&list, &mail_error);
	test_assert(str_begins(errstr, "critical3: "));
	test_assert(strstr(errstr+11, MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(list.last_error_is_internal);

	/* clear the error again and check that all is as expected */
	mailbox_list_clear_error(&list);
	test_assert(strcmp(mailbox_list_get_last_error(&list, &mail_error),
			   "BUG: Unknown internal list error") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strcmp(mailbox_list_get_last_internal_error(&list, &mail_error),
			   "BUG: Unknown internal list error") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(!list.last_error_is_internal);

	/* use internal error as a regular error (although that really
	   shouldn't be done) */
	test_expect_error_string("critical4");
	mailbox_list_set_critical(&list, "critical4");
	mailbox_list_set_error(&list, MAIL_ERROR_PARAMS,
		mailbox_list_get_last_internal_error(&list, &mail_error));
	test_expect_no_more_errors();
	test_assert(strcmp(mailbox_list_get_last_error(&list, &mail_error),
			   "critical4") == 0);
	test_assert(mail_error == MAIL_ERROR_PARAMS);
	test_assert(strcmp(mailbox_list_get_last_internal_error(&list, &mail_error),
			   "critical4") == 0);
	test_assert(mail_error == MAIL_ERROR_PARAMS);
	test_assert(!list.last_error_is_internal);

	test_deinit_list(&list);
	test_end();
}

static void test_mailbox_list_last_error_push_pop(void)
{
	/* NOTE: keep in sync with test-mail-storage.c */
	struct mailbox_list list;
	enum mail_error mail_error;

	test_begin("mailbox_list_last_error_push/pop()");
	test_init_list(&list);

	/* regular error 1 */
	mailbox_list_set_error(&list, MAIL_ERROR_PERM, "regular error 1");
	mailbox_list_last_error_push(&list);

	/* critical error 1 */
	test_expect_error_string("critical error 1");
	mailbox_list_set_critical(&list, "critical error 1");
	test_expect_no_more_errors();
	mailbox_list_last_error_push(&list);

	/* regular error 2 */
	mailbox_list_set_error(&list, MAIL_ERROR_PARAMS, "regular error 2");
	mailbox_list_last_error_push(&list);

	/* critical error 2 */
	test_expect_error_string("critical error 2");
	mailbox_list_set_critical(&list, "critical error 2");
	test_expect_no_more_errors();
	mailbox_list_last_error_push(&list);

	/* -- clear all errors -- */
	mailbox_list_clear_error(&list);

	/* critical error 2 pop */
	mailbox_list_last_error_pop(&list);
	test_assert(strstr(mailbox_list_get_last_error(&list, &mail_error),
			   MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strcmp(mailbox_list_get_last_internal_error(&list, &mail_error),
			   "critical error 2") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(list.last_error_is_internal);

	/* regular error 2 pop */
	mailbox_list_last_error_pop(&list);
	test_assert(strcmp(mailbox_list_get_last_error(&list, &mail_error),
			   "regular error 2") == 0);
	test_assert(mail_error == MAIL_ERROR_PARAMS);
	test_assert(strcmp(mailbox_list_get_last_internal_error(&list, &mail_error),
			   "regular error 2") == 0);
	test_assert(mail_error == MAIL_ERROR_PARAMS);
	test_assert(!list.last_error_is_internal);

	/* critical error 1 pop */
	mailbox_list_last_error_pop(&list);
	test_assert(strstr(mailbox_list_get_last_error(&list, &mail_error),
			   MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strcmp(mailbox_list_get_last_internal_error(&list, &mail_error),
			   "critical error 1") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(list.last_error_is_internal);

	/* regular error 1 pop */
	mailbox_list_last_error_pop(&list);
	test_assert(strcmp(mailbox_list_get_last_error(&list, &mail_error),
			   "regular error 1") == 0);
	test_assert(mail_error == MAIL_ERROR_PERM);
	test_assert(strcmp(mailbox_list_get_last_internal_error(&list, &mail_error),
			   "regular error 1") == 0);
	test_assert(mail_error == MAIL_ERROR_PERM);
	test_assert(!list.last_error_is_internal);

	test_deinit_list(&list);
	test_end();
}

int main(void)
{
	void (*const tests[])(void) = {
		test_mailbox_list_errors,
		test_mailbox_list_last_error_push_pop,
		NULL
	};
	return test_run(tests);
}
