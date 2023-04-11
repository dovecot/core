/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "test-common.h"
#include "master-service.h"
#include "test-mail-storage-common.h"

static const struct test_globals {
	const char *str;
	time_t timestamp;
	bool utc;
} human_timestamp_tests[] = {
	/* ISO */
	{ "2022-01-21", 1642723200, TRUE },
	/* IMAP date */
	{ "21-Jan-2022", 1642723200, FALSE },
	/* IMAP datetime */
	{ "21-Jan-2022 10:00:00 +0300", 1642723200 + 7*3600, TRUE },
	/* UNIX timestamp */
	{ "1642723200", 1642723200, TRUE },
};

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
	/* NOTE: keep in sync with test-mailbox-list.c */
	struct mail_storage storage;
	enum mail_error mail_error;
	const char *errstr, *errstr_suffix = "";

	test_begin("mail storage errors");
	test_init_storage(&storage);

	/* try a regular error */
	mail_storage_set_error(&storage, MAIL_ERROR_PERM, "error1");
	test_assert(strcmp(mail_storage_get_last_error(&storage, &mail_error),
			   "error1") == 0);
	test_assert(mail_error == MAIL_ERROR_PERM);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error),
			   "error1") == 0);
	test_assert(mail_error == MAIL_ERROR_PERM);
	test_assert(!storage.last_error_is_internal);

	/* set the error to itself */
	mail_storage_set_error(&storage, MAIL_ERROR_PARAMS,
		mail_storage_get_last_error(&storage, &mail_error));
	test_assert(strcmp(mail_storage_get_last_error(&storage, &mail_error),
			   "error1") == 0);
	test_assert(mail_error == MAIL_ERROR_PARAMS);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error),
			   "error1") == 0);
	test_assert(mail_error == MAIL_ERROR_PARAMS);
	test_assert(!storage.last_error_is_internal);

	/* clear the error - asking for it afterwards is a bug */
	mail_storage_clear_error(&storage);
	test_assert(strcmp(mail_storage_get_last_error(&storage, &mail_error),
			   "BUG: Unknown internal error") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error),
			   "BUG: Unknown internal error") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(!storage.last_error_is_internal);

	/* set internal error in preparation for the next test */
	test_expect_error_string("critical0");
	mail_storage_set_critical(&storage, "critical0");
	test_expect_no_more_errors();
	test_assert(strstr(mail_storage_get_last_error(&storage, &mail_error),
			   MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error),
			   "critical0") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(storage.last_error_is_internal);

	/* internal error without specifying what it is. this needs to clear
	   the previous internal error. */
	mail_storage_set_internal_error(&storage);
	test_assert(strstr(mail_storage_get_last_error(&storage, &mail_error),
			   MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strstr(mail_storage_get_last_internal_error(&storage, &mail_error),
			   MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(!storage.last_error_is_internal);

	/* proper internal error */
	test_expect_error_string("critical1");
	mail_storage_set_critical(&storage, "critical1");
	test_expect_no_more_errors();
	test_assert(strstr(mail_storage_get_last_error(&storage, &mail_error),
			   MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error),
			   "critical1") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(storage.last_error_is_internal);

	/* use it in the following internal error */
	test_expect_error_string("critical2: critical1");
	mail_storage_set_critical(&storage, "critical2: %s",
		mail_storage_get_last_internal_error(&storage, &mail_error));
	test_expect_no_more_errors();
	test_assert(strstr(mail_storage_get_last_error(&storage, &mail_error),
			   MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error),
			   "critical2: critical1") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(storage.last_error_is_internal);

	/* use the previous non-internal error as part of the internal error */
	test_expect_error_string("critical3: "MAIL_ERRSTR_CRITICAL_MSG);
	mail_storage_set_critical(&storage, "critical3: %s",
		mail_storage_get_last_error(&storage, &mail_error));
	test_expect_no_more_errors();
	test_assert(strstr(mail_storage_get_last_error(&storage, &mail_error),
			   MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	errstr = mail_storage_get_last_internal_error(&storage, &mail_error);
	test_assert(str_begins(errstr, "critical3: ", &errstr_suffix));
	test_assert(strstr(errstr_suffix, MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(storage.last_error_is_internal);

	/* clear the error again and check that all is as expected */
	mail_storage_clear_error(&storage);
	test_assert(strcmp(mail_storage_get_last_error(&storage, &mail_error),
			   "BUG: Unknown internal error") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error),
			   "BUG: Unknown internal error") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(!storage.last_error_is_internal);

	/* use internal error as a regular error (although that really
	   shouldn't be done) */
	test_expect_error_string("critical4");
	mail_storage_set_critical(&storage, "critical4");
	mail_storage_set_error(&storage, MAIL_ERROR_PARAMS,
		mail_storage_get_last_internal_error(&storage, &mail_error));
	test_expect_no_more_errors();
	test_assert(strcmp(mail_storage_get_last_error(&storage, &mail_error),
			   "critical4") == 0);
	test_assert(mail_error == MAIL_ERROR_PARAMS);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error),
			   "critical4") == 0);
	test_assert(mail_error == MAIL_ERROR_PARAMS);
	test_assert(!storage.last_error_is_internal);

	test_deinit_storage(&storage);
	test_end();
}

static void test_mail_storage_last_error_push_pop(void)
{
	/* NOTE: keep in sync with test-mailbox-list.c */
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
	test_assert(strstr(mail_storage_get_last_error(&storage, &mail_error),
			   MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error),
			   "critical error 2") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(storage.last_error_is_internal);

	/* regular error 2 pop */
	mail_storage_last_error_pop(&storage);
	test_assert(strcmp(mail_storage_get_last_error(&storage, &mail_error),
			   "regular error 2") == 0);
	test_assert(mail_error == MAIL_ERROR_PARAMS);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error),
			   "regular error 2") == 0);
	test_assert(mail_error == MAIL_ERROR_PARAMS);
	test_assert(!storage.last_error_is_internal);

	/* critical error 1 pop */
	mail_storage_last_error_pop(&storage);
	test_assert(strstr(mail_storage_get_last_error(&storage, &mail_error),
			   MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error),
			   "critical error 1") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(storage.last_error_is_internal);

	/* regular error 1 pop */
	mail_storage_last_error_pop(&storage);
	test_assert(strcmp(mail_storage_get_last_error(&storage, &mail_error),
			   "regular error 1") == 0);
	test_assert(mail_error == MAIL_ERROR_PERM);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error),
			   "regular error 1") == 0);
	test_assert(mail_error == MAIL_ERROR_PERM);
	test_assert(!storage.last_error_is_internal);

	test_deinit_storage(&storage);
	test_end();
}

struct mailbox_verify_test_cases {
	char ns_sep;
	char list_sep;
	const char *box;
	int ret;
} test_cases[] = {
	{ '\0', '\0', "INBOX", 0 },
	{ '/', '/', ".DUMPSTER", 0 },
	{ '\0', '\0', "DUMPSTER", 0 },
	{ '\0', '\0', "~DUMPSTER", -1 },
	{ '/', '.', "INBOX/INBOX", 0 },
	{ '/', '/', "INBOX/INBOX", 0 },
	{ '.', '.', "INBOX/INBOX", 0 },
	{ '.', '/', "INBOX/INBOX", -1 },
	{ '\0', '\0', "/etc/passwd", -1 },
	{ '.', '.', "foo.bar", 0 },
	{ '/', '.', "foo.bar", -1 },
	{ '.', '/', "foo.bar", 0 },
	{ '/', '/', "foo.bar", 0 },
	{ '/', '\0', "/foo", -1 },
	{ '/', '\0', "foo/", -1 },
	{ '/', '\0', "foo//bar", -1 },
	{ '.', '/', "/foo", -1 },
	{ '.', '/', "foo/", -1 },
	{ '.', '/', "foo//bar", -1 },
	{ '.', '.', ".foo", -1 },
	{ '.', '.', "foo.", -1 },
	{ '.', '.', "foo..bar", -1 },
	{ '.', '/', ".foo", -1 },
	{ '.', '/', "foo.", -1 },
	{ '.', '/', "foo..bar", -1 },
	{ '.', '/', "/", -1 },
	{ '.', '.', ".", -1 },
	{ '/', '\0', "/", -1 },
	{ '\0', '/', "/", -1 },
	{ '\0', '\0', "", -1 },
};

struct mailbox_verify_test_cases layout_index_test_cases[] = {
	{ '\0', '\0', "INBOX", 0 },
	{ '/', '/', ".DUMPSTER", 0 },
	{ '\0', '\0', "DUMPSTER", 0 },
	{ '\0', '\0', "~DUMPSTER", 0 },
	{ '\0', '\0', "^DUMPSTER", 0 },
	{ '\0', '\0', "%DUMPSTER", 0 },
	{ '/', '.', "INBOX/INBOX", 0 },
	{ '/', '/', "INBOX/INBOX", 0 },
	{ '.', '.', "INBOX/INBOX", 0 },
	{ '.', '/', "INBOX/INBOX", -1 },
	{ '/', '\0', "/etc/passwd", -1 },
	{ '.', '\0', "/etc/passwd", 0 },
	{ '.', '.', "foo.bar", 0 },
	{ '/', '.', "foo.bar", -1 },
	{ '.', '/', "foo.bar", 0 },
	{ '/', '/', "foo.bar", 0 },
	{ '/', '\0', "/foo", -1 },
	{ '/', '\0', "foo/", -1 },
	{ '/', '\0', "foo//bar", -1 },
	{ '.', '/', "/foo", -1 },
	{ '.', '/', "foo/", -1 },
	{ '.', '/', "foo//bar", -1 },
	{ '.', '.', ".foo", -1 },
	{ '.', '.', "foo.", -1 },
	{ '.', '.', "foo..bar", -1 },
	{ '.', '/', ".foo", -1 },
	{ '.', '/', "foo.", -1 },
	{ '.', '/', "foo..bar", -1 },
	{ '.', '/', "/", -1 },
	{ '.', '.', ".", -1 },
	{ '/', '\0', "/", -1 },
	{ '\0', '/', "/", -1 },
	{ '\0', '\0', "", -1 },
};

static void
test_mailbox_verify_name_one(struct mailbox_verify_test_cases *test_case,
			     struct mail_namespace *ns,
			     size_t i)
{
	struct mailbox *box;
	int ret;

	box = mailbox_alloc(ns->list, test_case->box, 0);
	ret = mailbox_verify_name(box);
#ifdef DEBUG
	if (ret != test_case->ret) {
		i_debug("%c == %c %c == %c",
			test_case->ns_sep, mail_namespace_get_sep(ns),
			test_case->list_sep, mailbox_list_get_hierarchy_sep(ns->list));
		const char *error = "should have failed";
		if (ret < 0)
			error = mailbox_get_last_error(box, NULL);
		i_debug("Failed test for mailbox %s: %s", test_case->box, error);
	}
#endif
	test_assert_idx(ret == test_case->ret, i);

	/* Cannot rename to INBOX */
	if (strcmp(test_case->box, "INBOX") == 0) {
		ret = mailbox_create(box, NULL, FALSE);
		test_assert_idx(ret == 0, i);
		mailbox_delete(box);
		mailbox_free(&box);
		return;
	}

	struct mailbox *src = mailbox_alloc(ns->list, "RENAME", 0);
	enum mailbox_existence exists;
	/* check if the mailbox exists */
	ret = mailbox_exists(src, FALSE, &exists);
	test_assert_idx(ret == 0, i);
	if (ret != 0) {
		mailbox_free(&box);
		mailbox_free(&src);
		return;
	}
	if (exists == MAILBOX_EXISTENCE_NONE)
		(void)mailbox_create(src, NULL, FALSE);
	ret = mailbox_rename(src, box);
	#ifdef DEBUG
        if (ret != test_case->ret) {
                i_debug("%c == %c %c == %c",
                        test_case->ns_sep, mail_namespace_get_sep(ns),
                        test_case->list_sep, mailbox_list_get_hierarchy_sep(ns->list));
                const char *error = "should have failed";
                if (ret < 0)
                        error = mailbox_get_last_error(box, NULL);
                i_debug("Failed test for mailbox %s: %s", test_case->box, error);
        }
#endif
	test_assert_idx(ret == test_case->ret, i);
	mailbox_delete(box);
	mailbox_free(&box);
	mailbox_free(&src);
}

static void
test_mailbox_verify_name_continue(struct mailbox_verify_test_cases *test_cases,
				  size_t ncases, struct test_mail_storage_ctx *ctx)
{
	struct mail_namespace *ns =
		mail_namespace_find_inbox(ctx->user->namespaces);

	for(size_t i = 0; i < ncases; i++) {
		if ((test_cases[i].ns_sep != '\0' &&
		    (test_cases[i].ns_sep != mail_namespace_get_sep(ns))) ||
		    (test_cases[i].list_sep != '\0' &&
		     test_cases[i].list_sep != mailbox_list_get_hierarchy_sep(ns->list)))
			continue;
		test_mailbox_verify_name_one(&test_cases[i], ns, i);
	}
}

static void test_mailbox_verify_name_driver_slash(const char *driver,
						  const char *driver_opts,
						  struct test_mail_storage_ctx *ctx)
{
	const char *const ns2[] = {
		"namespace=subspace",
		"namespace/subspace/separator=/",
		"namespace/subspace/prefix=SubSpace/",
		NULL
	};
	struct test_mail_storage_settings set = {
		.driver = driver,
		.driver_opts = driver_opts,
		.hierarchy_sep = "/",
		.extra_input = ns2,
	};
	test_mail_storage_init_user(ctx, &set);

	if (strcmp(driver_opts, ":LAYOUT=INDEX") == 0)
		test_mailbox_verify_name_continue(layout_index_test_cases, N_ELEMENTS(layout_index_test_cases), ctx);
	else
		test_mailbox_verify_name_continue(test_cases, N_ELEMENTS(test_cases), ctx);

	test_mail_storage_deinit_user(ctx);
}

static void test_mailbox_verify_name_driver_dot(const char *driver,
						const char *driver_opts,
						struct test_mail_storage_ctx *ctx)
{
	const char *const ns2[] = {
		"namespace=subspace",
		"namespace/subspace/separator=.",
		"namespace/subspace/prefix=SubSpace.",
		NULL
	};
	struct test_mail_storage_settings set = {
		.driver = driver,
		.driver_opts = driver_opts,
		.hierarchy_sep = ".",
		.extra_input = ns2,
	};
	test_mail_storage_init_user(ctx, &set);

	if (strcmp(driver_opts, ":LAYOUT=INDEX") == 0)
		test_mailbox_verify_name_continue(layout_index_test_cases, N_ELEMENTS(layout_index_test_cases), ctx);
	else
		test_mailbox_verify_name_continue(test_cases, N_ELEMENTS(test_cases), ctx);

	test_mail_storage_deinit_user(ctx);
}

static void test_mailbox_verify_name(void)
{
	struct {
		const char *name;
		const char *driver;
		const char *opts;
	} test_cases[] = {
		{ "mbox", "mbox", "" },
		{ "mbox LAYOUT=FS", "mbox", ":LAYOUT=FS" },
		{ "mbox LAYOUT=INDEX", "mbox", ":LAYOUT=INDEX" },
		{ "maildir LAYOUT=INDEX", "maildir", ":LAYOUT=INDEX" },
		{ "sdbox", "sdbox", "" },
		{ "sdbox LAYOUT=FS", "sdbox", ":LAYOUT=FS" },
		{ "sdbox LAYOUT=INDEX", "sdbox", ":LAYOUT=INDEX" },
		{ "mdbox", "mdbox", "" },
		{ "mdbox LAYOUT=FS", "mdbox", ":LAYOUT=FS" },
		{ "mdbox LAYOUT=INDEX", "mdbox", ":LAYOUT=INDEX" },
	};
	struct test_mail_storage_ctx *ctx = test_mail_storage_init();

	for(unsigned int i = 0; i < N_ELEMENTS(test_cases); i++) T_BEGIN {
		test_begin(t_strdup_printf("mailbox_verify_name (%s SEP=.)", test_cases[i].name));
		test_mailbox_verify_name_driver_dot(test_cases[i].driver, test_cases[i].opts, ctx);
		test_end();
		test_begin(t_strdup_printf("mailbox_verify_name (%s SEP=/)", test_cases[i].name));
		test_mailbox_verify_name_driver_slash(test_cases[i].driver, test_cases[i].opts, ctx);
		test_end();
	} T_END;

	test_mail_storage_deinit(&ctx);
}

static void test_mailbox_list_maildir_continue(struct test_mail_storage_ctx *ctx)
{
	struct mailbox_verify_test_cases test_cases[] = {
		{ '\0', '\0', "INBOX", 0 },
		{ '/', '/', ".DUMPSTER", 0 },
		{ '\0', '\0', "DUMPSTER", 0 },
		{ '\0', '\0', "~DUMPSTER", -1 },
		{ '\0', '/', "INBOX/new", -1 },
		{ '\0', '/', "INBOX/cur", -1 },
		{ '\0', '/', "INBOX/tmp", -1 },
		{ '\0', '\0', "/etc/passwd", -1 },
		{ '\0', '/', "SubSpace/new", -1 },
		{ '\0', '/', "SubSpace/cur", -1 },
		{ '\0', '/', "SubSpace/tmp", -1 },
		{ '.', '/', "INBOX.new", -1 },
		{ '.', '/', "INBOX.cur", -1 },
		{ '.', '/', "INBOX.tmp", -1 },
		{ '.', '/', "SubSpace.new", -1 },
		{ '.', '/', "SubSpace.cur", -1 },
		{ '.', '/', "SubSpace.tmp", -1 },
		{ '/', '.', "INBOX/INBOX", 0 },
		{ '/', '/', "INBOX/INBOX", 0 },
		{ '.', '.', "INBOX/INBOX", -1 },
		{ '.', '/', "INBOX/INBOX", -1 },
		{ '.', '.', "foo.bar", 0 },
		{ '/', '.', "foo.bar", -1 },
		{ '.', '/', "foo.bar", 0 },
		{ '/', '/', "foo.bar", 0 },
		{ '/', '\0', "/foo", -1 },
		{ '/', '\0', "foo/", -1 },
		{ '/', '\0', "foo//bar", -1 },
		{ '.', '/', "/foo", -1 },
		{ '.', '/', "foo/", -1 },
		{ '.', '/', "foo//bar", -1 },
		{ '.', '.', ".foo", -1 },
		{ '.', '.', "foo.", -1 },
		{ '.', '.', "foo..bar", -1 },
		{ '.', '/', ".foo", -1 },
		{ '.', '/', "foo.", -1 },
		{ '.', '/', "foo..bar", -1 },
		{ '.', '/', "/", -1 },
		{ '.', '.', ".", -1 },
		{ '/', '\0', "/", -1 },
		{ '\0', '/', "/", -1 },
		{ '\0', '\0', "", -1 },
	};

	test_mailbox_verify_name_continue(test_cases, N_ELEMENTS(test_cases), ctx);
}

static void test_mailbox_list_maildir_init(struct test_mail_storage_ctx *ctx,
					   const char *driver_opts, const char *sep)
{
	const char *error ATTR_UNUSED;
	const char *const ns2[] = {
		"namespace=subspace",
		t_strdup_printf("namespace/subspace/separator=%s", sep),
		t_strdup_printf("namespace/subspace/prefix=SubSpace%s", sep),
		NULL
	};

	struct test_mail_storage_settings set = {
		.driver = "maildir",
		.driver_opts = driver_opts,
		.hierarchy_sep = sep,
		.extra_input = ns2,
	};
	test_mail_storage_init_user(ctx, &set);
	test_mailbox_list_maildir_continue(ctx);

	struct mail_namespace *ns =
		mail_namespace_find_prefix(ctx->user->namespaces,
					   t_strdup_printf("SubSpace%s", sep));

	struct mailbox *box = mailbox_alloc(ns->list, "SubSpace", 0);
	int ret = mailbox_verify_name(box);
	test_assert(ret == 0);
#ifdef DEBUG
	if (ret < 0) {
		error = mailbox_get_last_error(box, NULL);
		i_debug("Failed test for mailbox %s: %s",
			mailbox_get_vname(box), error);
	}
#endif
	mailbox_free(&box);
	box = mailbox_alloc(ns->list, t_strdup_printf("SubSpace%sInner", sep), 0);
	ret = mailbox_verify_name(box);
	test_assert(ret == 0);
#ifdef DEBUG
	if (ret < 0) {
		error = mailbox_get_last_error(box, NULL);
		i_debug("Failed test for mailbox %s: %s",
			mailbox_get_vname(box), error);
	}
#endif
	mailbox_free(&box);

	test_mail_storage_deinit_user(ctx);
}

static void test_mailbox_list_maildir(void)
{
	struct test_mail_storage_ctx *ctx = test_mail_storage_init();

	test_begin("mailbox_verify_name (maildir SEP=.)");
	test_mailbox_list_maildir_init(ctx, "", ".");
	test_end();

	test_begin("mailbox_verify_name (maildir SEP=/)");
	test_mailbox_list_maildir_init(ctx, "", "/");
	test_end();

	test_begin("mailbox_verify_name (maildir SEP=. LAYOUT=FS)");
	test_mailbox_list_maildir_init(ctx, "LAYOUT=FS", ".");
	test_end();

	test_begin("mailbox_verify_name (maildir SEP=/ LAYOUT=FS)");
	test_mailbox_list_maildir_init(ctx, "LAYOUT=FS", "/");
	test_end();

	test_mail_storage_deinit(&ctx);
}

static void test_mailbox_list_mbox(void)
{
	struct test_mail_storage_ctx *ctx;
	struct mailbox_verify_test_cases test_case;
	struct mail_namespace *ns;

	test_begin("mailbox_list_mbox");

	ctx = test_mail_storage_init();

	/* check that .lock cannot be used */
	struct test_mail_storage_settings set = {
		.driver = "mbox",
		.hierarchy_sep = ".",
	};
	test_mail_storage_init_user(ctx, &set);

	test_case.list_sep = '/';
	test_case.ns_sep = '.';
	test_case.box = "INBOX/.lock";
	test_case.ret = -1;

	ns = mail_namespace_find_inbox(ctx->user->namespaces);
	test_mailbox_verify_name_one(&test_case, ns, 0);

	test_mail_storage_deinit_user(ctx);
	test_mail_storage_deinit(&ctx);

	test_end();
}

static void test_mail_parse_human_timestamp(void)
{
	int ret;
	time_t timestamp;
	bool is_utc;

	test_begin("mail_parse_human_timestamp()");

	for (unsigned int i = 0; i < N_ELEMENTS(human_timestamp_tests); i++) {
		ret = mail_parse_human_timestamp(human_timestamp_tests[i].str,
						 &timestamp, &is_utc);

		test_assert_idx(ret == 0, i);
		test_assert_idx(timestamp == human_timestamp_tests[i].timestamp, i);
		test_assert_idx(is_utc == human_timestamp_tests[i].utc, i);
	}

	test_end();
}

static void test_mail_parse_human_timestamp_time_interval(void)
{
	int ret;
	time_t timestamp;
	bool is_utc;

	test_begin("mail_parse_human_timestamp (time interval)");

	/* make sure the time interval of 5 minutes (=300 seconds) is
	   correctly parsed and reduced from the main ioloop's timestamp */
	ret = mail_parse_human_timestamp("5 mins", &timestamp, &is_utc);

	test_assert(ret == 0);
	test_assert(timestamp == ioloop_time - 300);
	test_assert(is_utc);

	test_end();
}

static const char *invalid_timestamps[] = {
	/* ISO format, upper case 's' instead of numeric '5' */
	"1234-S6-78",
	/* IMAP format, incorrect month abbreviation "Jam" */
	"01-Jam-2022",
	/* IMAP format, missing '-' separators */
	"02 Feb 2022",
	/* unix timestamp, upper case 'o' instead of numeric '0' */
	"148314240O",
	/* time interval, spelling error */
	"1minsa",
	/* time interval, negative value */
	"-100D",
	/* Note: for further tests regarding time interval, see
		 `src/lib-settings/test-settings-parser.c` */

	/* arbitrary string */
	"invalid timestamp"
};

static void test_mail_parse_human_timestamp_fail(void)
{
	unsigned int i;
	test_begin("mail_parse_human_timestamp (fail)");
	for (i = 0; i < N_ELEMENTS(invalid_timestamps); i++) {
		const char *item = invalid_timestamps[i];
		test_assert_idx(
			mail_parse_human_timestamp(item, NULL, NULL) == -1, i);
	}
	test_end();
}

int main(int argc, char **argv)
{
	int ret;
	void (*const tests[])(void) = {
		test_mail_storage_errors,
		test_mail_storage_last_error_push_pop,
		test_mailbox_verify_name,
		test_mailbox_list_maildir,
		test_mailbox_list_mbox,
		test_mail_parse_human_timestamp,
		test_mail_parse_human_timestamp_time_interval,
		test_mail_parse_human_timestamp_fail,
		NULL
	};

	master_service = master_service_init("test-mail-storage",
					     MASTER_SERVICE_FLAG_STANDALONE |
					     MASTER_SERVICE_FLAG_DONT_SEND_STATS |
					     MASTER_SERVICE_FLAG_NO_CONFIG_SETTINGS |
					     MASTER_SERVICE_FLAG_NO_SSL_INIT |
					     MASTER_SERVICE_FLAG_NO_INIT_DATASTACK_FRAME,
					     &argc, &argv, "");

	ret = test_run(tests);

	master_service_deinit(&master_service);

	return ret;
}
