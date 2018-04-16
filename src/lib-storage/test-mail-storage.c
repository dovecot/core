/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "mail-storage-private.h"

static void test_init_storage(struct mail_storage *storage_r)
{
	i_zero(storage_r);
	storage_r->user = t_new(struct mail_user, 1);
	storage_r->user->event = event_create(NULL);
	storage_r->event = event_create(storage_r->user->event);
}

static void test_deinit_storage(struct mail_storage *storage)
{
	mail_storage_clear_error(storage);
	if (array_is_created(&storage->error_stack)) {
		mail_storage_clear_error(storage);
		i_assert(array_count(&storage->error_stack) == 0);
		array_free(&storage->error_stack);
	}
	event_unref(&storage->event);
	event_unref(&storage->user->event);
}

static void test_mail_storage_errors(void)
{
	struct mail_storage storage;
	enum mail_error mail_error;
	const char *errstr;

	test_begin("mail storage errors");
	test_init_storage(&storage);

	/* try a regular error */
	mail_storage_set_error(&storage, MAIL_ERROR_PERM, "error1");
	test_assert(strcmp(mail_storage_get_last_error(&storage, &mail_error), "error1") == 0);
	test_assert(mail_error == MAIL_ERROR_PERM);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error), "error1") == 0);
	test_assert(mail_error == MAIL_ERROR_PERM);
	test_assert(!storage.last_error_is_internal);

	/* set the error to itself */
	mail_storage_set_error(&storage, MAIL_ERROR_PARAMS,
		mail_storage_get_last_error(&storage, &mail_error));
	test_assert(strcmp(mail_storage_get_last_error(&storage, &mail_error), "error1") == 0);
	test_assert(mail_error == MAIL_ERROR_PARAMS);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error), "error1") == 0);
	test_assert(mail_error == MAIL_ERROR_PARAMS);
	test_assert(!storage.last_error_is_internal);

	/* clear the error - asking for it afterwards is a bug */
	mail_storage_clear_error(&storage);
	test_assert(strcmp(mail_storage_get_last_error(&storage, &mail_error), "BUG: Unknown internal error") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error), "BUG: Unknown internal error") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(!storage.last_error_is_internal);

	/* set internal error in preparation for the next test */
	test_expect_error_string("critical0");
	mail_storage_set_critical(&storage, "critical0");
	test_expect_no_more_errors();
	test_assert(strstr(mail_storage_get_last_error(&storage, &mail_error), MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error), "critical0") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(storage.last_error_is_internal);

	/* internal error without specifying what it is. this needs to clear
	   the previous internal error. */
	mail_storage_set_internal_error(&storage);
	test_assert(strstr(mail_storage_get_last_error(&storage, &mail_error), MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strstr(mail_storage_get_last_internal_error(&storage, &mail_error), MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(!storage.last_error_is_internal);

	/* proper internal error */
	test_expect_error_string("critical1");
	mail_storage_set_critical(&storage, "critical1");
	test_expect_no_more_errors();
	test_assert(strstr(mail_storage_get_last_error(&storage, &mail_error), MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error), "critical1") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(storage.last_error_is_internal);

	/* use it in the following internal error */
	test_expect_error_string("critical2: critical1");
	mail_storage_set_critical(&storage, "critical2: %s",
		mail_storage_get_last_internal_error(&storage, &mail_error));
	test_expect_no_more_errors();
	test_assert(strstr(mail_storage_get_last_error(&storage, &mail_error), MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error), "critical2: critical1") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(storage.last_error_is_internal);

	/* use the previous non-internal error as part of the internal error */
	test_expect_error_string("critical3: "MAIL_ERRSTR_CRITICAL_MSG);
	mail_storage_set_critical(&storage, "critical3: %s",
		mail_storage_get_last_error(&storage, &mail_error));
	test_expect_no_more_errors();
	test_assert(strstr(mail_storage_get_last_error(&storage, &mail_error), MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	errstr = mail_storage_get_last_internal_error(&storage, &mail_error);
	test_assert(str_begins(errstr, "critical3: "));
	test_assert(strstr(errstr+11, MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(storage.last_error_is_internal);

	/* clear the error again and check that all is as expected */
	mail_storage_clear_error(&storage);
	test_assert(strcmp(mail_storage_get_last_error(&storage, &mail_error), "BUG: Unknown internal error") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error), "BUG: Unknown internal error") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(!storage.last_error_is_internal);

	/* use internal error as a regular error (although that really
	   shouldn't be done) */
	test_expect_error_string("critical4");
	mail_storage_set_critical(&storage, "critical4");
	mail_storage_set_error(&storage, MAIL_ERROR_PARAMS,
		mail_storage_get_last_internal_error(&storage, &mail_error));
	test_expect_no_more_errors();
	test_assert(strcmp(mail_storage_get_last_error(&storage, &mail_error), "critical4") == 0);
	test_assert(mail_error == MAIL_ERROR_PARAMS);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error), "critical4") == 0);
	test_assert(mail_error == MAIL_ERROR_PARAMS);
	test_assert(!storage.last_error_is_internal);

	test_deinit_storage(&storage);
	test_end();
}

static void test_mail_storage_last_error_push_pop(void)
{
	struct mail_storage storage;
	enum mail_error mail_error;

	test_begin("mail_storage_last_error_push/pop()");
	test_init_storage(&storage);

	/* regular error 1 */
	mail_storage_set_error(&storage, MAIL_ERROR_PERM, "regular error 1");
	mail_storage_last_error_push(&storage);

	/* critical error 1 */
	test_expect_error_string("critical error 1");
	mail_storage_set_critical(&storage, "critical error 1");
	test_expect_no_more_errors();
	mail_storage_last_error_push(&storage);

	/* regular error 2 */
	mail_storage_set_error(&storage, MAIL_ERROR_PARAMS, "regular error 2");
	mail_storage_last_error_push(&storage);

	/* critical error 2 */
	test_expect_error_string("critical error 2");
	mail_storage_set_critical(&storage, "critical error 2");
	test_expect_no_more_errors();
	mail_storage_last_error_push(&storage);

	/* -- clear all errors -- */
	mail_storage_clear_error(&storage);

	/* critical error 2 pop */
	mail_storage_last_error_pop(&storage);
	test_assert(strstr(mail_storage_get_last_error(&storage, &mail_error), MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error), "critical error 2") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(storage.last_error_is_internal);

	/* regular error 2 pop */
	mail_storage_last_error_pop(&storage);
	test_assert(strcmp(mail_storage_get_last_error(&storage, &mail_error), "regular error 2") == 0);
	test_assert(mail_error == MAIL_ERROR_PARAMS);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error), "regular error 2") == 0);
	test_assert(mail_error == MAIL_ERROR_PARAMS);
	test_assert(!storage.last_error_is_internal);

	/* critical error 1 pop */
	mail_storage_last_error_pop(&storage);
	test_assert(strstr(mail_storage_get_last_error(&storage, &mail_error), MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error), "critical error 1") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(storage.last_error_is_internal);

	/* regular error 1 pop */
	mail_storage_last_error_pop(&storage);
	test_assert(strcmp(mail_storage_get_last_error(&storage, &mail_error), "regular error 1") == 0);
	test_assert(mail_error == MAIL_ERROR_PERM);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error), "regular error 1") == 0);
	test_assert(mail_error == MAIL_ERROR_PERM);
	test_assert(!storage.last_error_is_internal);

	test_deinit_storage(&storage);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_mail_storage_errors,
		test_mail_storage_last_error_push_pop,
		NULL
	};

	return test_run(test_functions);
}
