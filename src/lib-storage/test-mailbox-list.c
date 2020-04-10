/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "test-common.h"
#include "mailbox-list-private.h"

enum test_flags {
	TEST_FLAG_NO_VNAME		= BIT(0),
	TEST_FLAG_NO_STORAGE_NAME	= BIT(1),
	TEST_FLAG_NO_MUTF7		= BIT(2),
	TEST_FLAG_NO_UTF8		= BIT(3),
};

struct test_mailbox_list_name {
	const char *vname;
	const char *storage_name;
	enum test_flags flags;
	char *ns_prefix;
	enum namespace_flags ns_flags;
	char ns_sep;
	char list_sep;
	char vname_escape_char;
	char storage_name_escape_char;
	const char *maildir_name;
};

static char list_hierarchy_sep;
static char ns_sep[2] = { '\0', '\0' };

static void test_init_list(struct mailbox_list *list_r)
{
	i_zero(list_r);
	list_r->ns = t_new(struct mail_namespace, 1);
	list_r->ns->user = t_new(struct mail_user, 1);
	list_r->ns->user->event = event_create(NULL);
}

static void test_deinit_list(struct mailbox_list *list)
{
	mailbox_list_clear_error(list);
	if (array_is_created(&list->error_stack)) {
		mailbox_list_clear_error(list);
		i_assert(array_count(&list->error_stack) == 0);
		array_free(&list->error_stack);
	}
	event_unref(&list->ns->user->event);
}

static void test_mailbox_list_errors(void)
{
	/* NOTE: keep in sync with test-mail-storage.c */
	struct mailbox_list list;
	enum mail_error mail_error;
	const char *errstr, *suffix = "";

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
	test_assert(str_begins(errstr, "critical3: ", &suffix));
	test_assert(strstr(suffix, MAIL_ERRSTR_CRITICAL_MSG) != NULL);
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

static char
test_mailbox_list_get_hierarchy_sep(struct mailbox_list *list ATTR_UNUSED)
{
	return list_hierarchy_sep;
}

static void
test_maibox_list_name_init(struct mailbox_list *list,
			   const struct test_mailbox_list_name *test,
			   bool mutf7)
{
	list->ns->prefix = test->ns_prefix == NULL ? "" :
		test->ns_prefix;
	list->ns->prefix_len = strlen(list->ns->prefix);
	list->ns->flags = test->ns_flags;
	ns_sep[0] = test->ns_sep;
	list_hierarchy_sep = test->list_sep;
	list->set.utf8 = !mutf7;
	list->set.vname_escape_char = test->vname_escape_char;
	list->set.storage_name_escape_char =
		test->storage_name_escape_char;
	list->set.maildir_name = test->maildir_name == NULL ? "" :
		test->maildir_name;
}

static void test_mailbox_list_get_names(void)
{
	const struct test_mailbox_list_name tests[] = {
		{ .vname = "parent/child",
		  .storage_name = "parent/child",
		  .ns_sep = '/', .list_sep = '/' },
		{ .vname = "parent/child",
		  .storage_name = "parent.child",
		  .ns_sep = '/', .list_sep = '.' },
		{ .vname = "ns_prefix/parent/child",
		  .storage_name = "parent.child",
		  .ns_prefix = "ns_prefix/", .ns_sep = '/', .list_sep = '.' },
		{ .vname = "ns/prefix/parent/child",
		  .storage_name = "parent.child",
		  .ns_prefix = "ns/prefix/", .ns_sep = '/', .list_sep = '.' },
		{ .vname = "ns/prefix",
		  .storage_name = "",
		  .ns_prefix = "ns/prefix/", .ns_sep = '/', .list_sep = '.' },
		{ .vname = "\xC3\xA4/\xC3\xB6",
		  .storage_name = "&APY-",
		  .flags = TEST_FLAG_NO_UTF8,
		  .ns_prefix = "\xC3\xA4/", .ns_sep = '/', .list_sep = '.' },
		{ .vname = "\xC3\xA4/\xC3\xB6&test",
		  .storage_name = "\xC3\xB6&test",
		  .flags = TEST_FLAG_NO_MUTF7,
		  .ns_prefix = "\xC3\xA4/", .ns_sep = '/', .list_sep = '.' },

		/* storage_name escaping: */
		{ .vname = "~home",
		  .storage_name = "%7ehome",
		  .ns_sep = '/', .list_sep = '.',
		  .storage_name_escape_char = '%' },
		{ .vname = "es%cape%",
		  .storage_name = "es%25cape%25",
		  .ns_sep = '/', .list_sep = '.',
		  .storage_name_escape_char = '%' },
		{ .vname = "slash/",
		  .storage_name = "slash%2f",
		  .ns_sep = '^', .list_sep = '.',
		  .storage_name_escape_char = '%' },
		{ .vname = "list.separator",
		  .storage_name = "list%2eseparator",
		  .ns_sep = '/', .list_sep = '.',
		  .storage_name_escape_char = '%' },
		{ .vname = "Maildir",
		  .storage_name = "%4daildir",
		  .ns_sep = '^', .list_sep = '.',
		  .storage_name_escape_char = '%',
		  .maildir_name = "Maildir" },
		{ .vname = "~Maildir",
		  .storage_name = "%7eMaildir",
		  .ns_sep = '^', .list_sep = '.',
		  .storage_name_escape_char = '%',
		  .maildir_name = "Maildir" },
		{ .vname = "Maildir/suffix",
		  .storage_name = "%4daildir%2fsuffix",
		  .ns_sep = '^', .list_sep = '.',
		  .storage_name_escape_char = '%',
		  .maildir_name = "Maildir" },
		{ .vname = "prefix/Maildir",
		  .storage_name = "prefix%2f%4daildir",
		  .ns_sep = '^', .list_sep = '.',
		  .storage_name_escape_char = '%',
		  .maildir_name = "Maildir" },
		{ .vname = "sep/Maildir/sep",
		  .storage_name = "sep.%4daildir.sep",
		  .ns_sep = '/', .list_sep = '.',
		  .storage_name_escape_char = '%',
		  .maildir_name = "Maildir" },
		{ .vname = "~/.%--Maildir",
		  .storage_name = "%4daildir",
		  .ns_prefix = "~/.%--",
		  .ns_sep = '/', .list_sep = '.',
		  .storage_name_escape_char = '%',
		  .maildir_name = "Maildir" },
		{ .vname = "%foo",
		  .storage_name = "%foo",
		  .flags = TEST_FLAG_NO_STORAGE_NAME,
		  .ns_sep = '/', .list_sep = '.',
		  .storage_name_escape_char = '%' },
		{ .vname = "A/B.C%D",
		  .storage_name = "A.B%2eC%25D",
		  .storage_name_escape_char='%',
		  .ns_sep = '/', .list_sep = '.' },

		/* vname escaping: */
		{ .vname = "%7c|child",
		  .storage_name = "|.child",
		  .ns_sep = '|', .list_sep = '.',
		  .vname_escape_char = '%' },
		{ .vname = "%7c|child.",
		  .storage_name = "|.child+2e",
		  .ns_sep = '|', .list_sep = '.',
		  .storage_name_escape_char = '+',
		  .vname_escape_char = '%' },
		{ .vname = "%7c|child.",
		  .storage_name = "|.child%2e",
		  .ns_sep = '|', .list_sep = '.',
		  .storage_name_escape_char = '%',
		  .vname_escape_char = '%' },
		{ .vname = "%2f/child",
		  .storage_name = "/.child",
		  .ns_sep = '/', .list_sep = '.',
		  .vname_escape_char = '%' },
		{ .vname = "%2f/child.",
		  .storage_name = "+2f.child+2e",
		  .ns_sep = '/', .list_sep = '.',
		  .storage_name_escape_char = '+',
		  .vname_escape_char = '%' },
		{ .vname = "%2f/child.",
		  .storage_name = "%2f.child%2e",
		  .ns_sep = '/', .list_sep = '.',
		  .storage_name_escape_char = '%',
		  .vname_escape_char = '%' },
		{ .vname = "%25escaped+",
		  .storage_name = "%escaped+2b",
		  .ns_sep = '/', .list_sep = '.',
		  .storage_name_escape_char = '+',
		  .vname_escape_char = '%' },
		{ .vname = "x%2666-y",
		  .storage_name = "x&66-y",
		  .flags = TEST_FLAG_NO_UTF8,
		  .ns_sep = '/', .list_sep = '.',
		  .vname_escape_char = '%' },
		{ .vname = "p\xC3\xA4iv\xC3\xA4 & y%26APY %ff m\xC3\xB6h",
		  .storage_name = "p&AOQ-iv&AOQ- &- y&APY \xff m&APY-h",
		  .flags = TEST_FLAG_NO_UTF8,
		  .ns_sep = '/', .list_sep = '.',
		  .vname_escape_char = '%' },
		{ .vname = "%foo",
		  .storage_name = "%foo",
		  .flags = TEST_FLAG_NO_VNAME,
		  .ns_sep = '/', .list_sep = '.',
		  .vname_escape_char = '%' },
		{ .vname = "A%2fB/C%25D",
		  .storage_name = "A/B.C%D",
		  .ns_sep = '/', .list_sep = '.',
		  .vname_escape_char = '%' },

		/* INBOX: */
		{ .vname = "inBox",
		  .storage_name = "inBox",
		  .ns_sep = '/', .list_sep = '.' },
		{ .vname = "inBox",
		  .storage_name = "INBOX",
		  .flags = TEST_FLAG_NO_VNAME,
		  .ns_flags = NAMESPACE_FLAG_INBOX_USER,
		  .ns_sep = '/', .list_sep = '.' },
		{ .vname = "inBox",
		  .storage_name = "INBOX",
		  .flags = TEST_FLAG_NO_VNAME,
		  .ns_flags = NAMESPACE_FLAG_INBOX_USER,
		  .ns_prefix = "prefix/", .ns_sep = '/', .list_sep = '.' },
		{ .vname = "prefix/inBox",
		  .storage_name = "inBox",
		  .ns_flags = NAMESPACE_FLAG_INBOX_USER,
		  .ns_prefix = "prefix/", .ns_sep = '/', .list_sep = '.' },
		{ .vname = "prefix/INBOX",
		  .storage_name = "+49NBOX",
		  .ns_flags = NAMESPACE_FLAG_INBOX_USER,
		  .ns_prefix = "prefix/", .ns_sep = '/', .list_sep = '.',
		  .storage_name_escape_char = '+' },

		/* Problematic cases - not reversible: */
		{ .vname = "parent.child",
		  .storage_name = "parent.child",
		  .flags = TEST_FLAG_NO_VNAME,
		  .ns_sep = '/', .list_sep = '.' },
		{ .vname = "prefix/INBOX",
		  .storage_name = "INBOX",
		  .flags = TEST_FLAG_NO_VNAME,
		  .ns_flags = NAMESPACE_FLAG_INBOX_USER,
		  .ns_prefix = "prefix/", .ns_sep = '/', .list_sep = '.' },
		{ .vname = "invalid&mutf7",
		  .storage_name = "invalid&mutf7",
		  .flags = TEST_FLAG_NO_STORAGE_NAME,
		  .ns_sep = '/', .list_sep = '.' },
	};
	struct mail_namespace_settings ns_set = {
		.separator = ns_sep,
	};
	struct mail_namespace ns = {
		.set = &ns_set,
	};
	struct mailbox_list list = {
		.ns = &ns,
		.v = {
			.get_hierarchy_sep = test_mailbox_list_get_hierarchy_sep,
		},
	};

	test_begin("mailbox list get names");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		if ((tests[i].flags & TEST_FLAG_NO_MUTF7) == 0) {
			test_maibox_list_name_init(&list, &tests[i], TRUE);
			if ((tests[i].flags & TEST_FLAG_NO_STORAGE_NAME) == 0) {
				test_assert_strcmp_idx(mailbox_list_default_get_storage_name(&list, tests[i].vname),
						       tests[i].storage_name, i);
			}
			if ((tests[i].flags & TEST_FLAG_NO_VNAME) == 0) {
				test_assert_strcmp_idx(mailbox_list_default_get_vname(&list, tests[i].storage_name),
						       tests[i].vname, i);
			}
		}
		if ((tests[i].flags & TEST_FLAG_NO_UTF8) == 0) {
			test_maibox_list_name_init(&list, &tests[i], FALSE);
			if ((tests[i].flags & TEST_FLAG_NO_STORAGE_NAME) == 0) {
				test_assert_strcmp_idx(mailbox_list_default_get_storage_name(&list, tests[i].vname),
						       tests[i].storage_name, i);
			}
			if ((tests[i].flags & TEST_FLAG_NO_VNAME) == 0) {
				test_assert_strcmp_idx(mailbox_list_default_get_vname(&list, tests[i].storage_name),
						       tests[i].vname, i);
			}
		}
	}
	test_end();
}

int main(void)
{
	void (*const tests[])(void) = {
		test_mailbox_list_errors,
		test_mailbox_list_last_error_push_pop,
		test_mailbox_list_get_names,
		NULL
	};
	return test_run(tests);
}
