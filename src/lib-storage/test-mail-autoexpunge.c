/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "file-lock.h"
#include "test-common.h"
#include "test-dir.h"
#include "settings.h"
#include "master-service.h"
#include "mail-user.h"
#include "mail-storage-settings.h"
#include "mail-autoexpunge.h"
#include "test-mail-storage-common.h"

#define TEST_AUTOEXPUNGE_SECS (60*60)

static void test_save_mail(struct mail_user *user, const char *vname,
			   time_t save_date)
{
	struct mail_namespace *ns =
		mail_namespace_find_inbox(user->namespaces);
	struct mailbox *box = mailbox_alloc(ns->list, vname, 0);
	struct mailbox_transaction_context *trans;
	struct mail_save_context *save_ctx;
	struct istream *input;
	int ret;

	if (mailbox_create(box, NULL, FALSE) < 0 &&
	    mailbox_get_last_mail_error(box) != MAIL_ERROR_EXISTS)
		i_fatal("mailbox_create(%s) failed", vname);
	if (mailbox_open(box) < 0)
		i_fatal("mailbox_open(%s) failed", vname);

	input = i_stream_create_from_data("Subject: test\n\nbody\n", 20);
	trans = mailbox_transaction_begin(box,
		MAILBOX_TRANSACTION_FLAG_EXTERNAL, __func__);
	save_ctx = mailbox_save_alloc(trans);
	mailbox_save_set_save_date(save_ctx, save_date);
	if (mailbox_save_begin(&save_ctx, input) < 0)
		i_fatal("mailbox_save_begin() failed");
	while ((ret = i_stream_read(input)) > 0) {
		if (mailbox_save_continue(save_ctx) < 0)
			i_fatal("mailbox_save_continue() failed");
	}
	i_assert(ret == -1);
	if (mailbox_save_finish(&save_ctx) < 0)
		i_fatal("mailbox_save_finish() failed");
	if (mailbox_transaction_commit(&trans) < 0)
		i_fatal("mailbox_transaction_commit() failed");
	i_stream_unref(&input);
	mailbox_free(&box);
}

static unsigned int test_mailbox_count(struct mail_user *user,
				       const char *vname)
{
	struct mail_namespace *ns =
		mail_namespace_find_inbox(user->namespaces);
	struct mailbox *box = mailbox_alloc(ns->list, vname, 0);
	struct mailbox_status status;

	if (mailbox_get_status(box, STATUS_MESSAGES, &status) < 0)
		i_fatal("mailbox_get_status(%s) failed", vname);
	mailbox_free(&box);
	return status.messages;
}

static void
test_autoexpunge_init_user(struct test_mail_storage_ctx *ctx,
			   unsigned int autoexpunge_secs,
			   const char *extra_setting)
{
	const char *const extra_input[] = {
		extra_setting,
		NULL
	};
	struct test_mail_storage_settings set = {
		.driver = "sdbox",
		.extra_input = extra_input,
	};
	struct settings_root *set_root =
		master_service_get_settings_root(master_service);

	/* mailbox filters can't be set via userdb */
	settings_root_override(set_root, "namespace/inbox/mailbox", "Trash",
			       SETTINGS_OVERRIDE_TYPE_CLI_PARAM);
	settings_root_override(set_root,
		"namespace/inbox/mailbox/Trash/autoexpunge",
		t_strdup_printf("%us", autoexpunge_secs),
		SETTINGS_OVERRIDE_TYPE_CLI_PARAM);
	test_mail_storage_init_user(ctx, &set);
}

static void
test_autoexpunge_deinit_user(struct test_mail_storage_ctx *ctx)
{
	struct settings_root *set_root =
		master_service_get_settings_root(master_service);

	test_mail_storage_deinit_user(ctx);
	settings_root_override_remove(set_root, "namespace/inbox/mailbox",
				      SETTINGS_OVERRIDE_TYPE_CLI_PARAM);
	settings_root_override_remove(set_root,
		"namespace/inbox/mailbox/Trash/autoexpunge",
		SETTINGS_OVERRIDE_TYPE_CLI_PARAM);
}

static void test_autoexpunge_lock_lazy(void)
{
	struct test_mail_storage_ctx *ctx;

	test_begin("autoexpunge: lock only when something is expunged");
	ctx = test_mail_storage_init();
	/* The lock can't be created without a home directory */
	test_autoexpunge_init_user(ctx, TEST_AUTOEXPUNGE_SECS, "home=");

	/* nothing to expunge: no lock creation attempt, so no error */
	test_assert(mail_user_autoexpunge(ctx->user, NULL) == 0);

	/* something to expunge: lock creation fails, but the mail is
	   expunged anyway */
	test_save_mail(ctx->user, "Trash",
		       ioloop_time - TEST_AUTOEXPUNGE_SECS - 10);
	test_expect_error_string("Couldn't create dovecot.autoexpunge.lock lock");
	test_assert(mail_user_autoexpunge(ctx->user, NULL) == 1);
	test_expect_no_more_errors();
	test_assert(test_mailbox_count(ctx->user, "Trash") == 0);

	/* only a new mail: nothing to expunge, no error */
	test_save_mail(ctx->user, "Trash", ioloop_time);
	test_assert(mail_user_autoexpunge(ctx->user, NULL) == 0);
	test_assert(test_mailbox_count(ctx->user, "Trash") == 1);

	test_autoexpunge_deinit_user(ctx);
	test_mail_storage_deinit(&ctx);
	test_end();
}

static void test_autoexpunge_lock_busy(void)
{
	struct test_mail_storage_ctx *ctx;
	struct file_lock *lock;
	const char *error;
	time_t next_check;

	test_begin("autoexpunge: lock held by another process");
	ctx = test_mail_storage_init();
	/* flock() locks conflict also within the same process */
	test_autoexpunge_init_user(ctx, TEST_AUTOEXPUNGE_SECS,
				   "lock_method=flock");

	test_save_mail(ctx->user, "Trash",
		       ioloop_time - TEST_AUTOEXPUNGE_SECS - 10);
	test_assert(mail_user_lock_file_create(ctx->user,
		"dovecot.autoexpunge.lock", 0, &lock, &error) > 0);
	test_assert(mail_user_autoexpunge(ctx->user, &next_check) == 0);
	test_assert(test_mailbox_count(ctx->user, "Trash") == 1);
	/* not all mailboxes were checked */
	test_assert(next_check == 0);

	file_lock_free(&lock);
	test_assert(mail_user_autoexpunge(ctx->user, NULL) == 1);
	test_assert(test_mailbox_count(ctx->user, "Trash") == 0);

	test_autoexpunge_deinit_user(ctx);
	test_mail_storage_deinit(&ctx);
	test_end();
}

static void test_autoexpunge_next_check(void)
{
	struct test_mail_storage_ctx *ctx;
	struct file_lock *lock;
	const char *error;
	time_t next_check;

	test_begin("autoexpunge: next check");
	ctx = test_mail_storage_init();
	test_autoexpunge_init_user(ctx, TEST_AUTOEXPUNGE_SECS,
				   "lock_method=flock");

	/* empty mailbox: the smallest autoexpunge interval */
	test_assert(mail_user_autoexpunge(ctx->user, &next_check) == 0);
	test_assert(next_check == ioloop_time + TEST_AUTOEXPUNGE_SECS);

	/* the first mail is expunged, the next check is when the second
	   mail expires */
	test_save_mail(ctx->user, "Trash",
		       ioloop_time - TEST_AUTOEXPUNGE_SECS - 10);
	test_save_mail(ctx->user, "Trash", ioloop_time - 1800);
	test_assert(mail_user_autoexpunge(ctx->user, &next_check) == 1);
	test_assert(next_check == ioloop_time - 1800 + TEST_AUTOEXPUNGE_SECS);

	/* nothing to expunge: the same result from the quick check */
	test_assert(mail_user_autoexpunge(ctx->user, &next_check) == 0);
	test_assert(next_check == ioloop_time - 1800 + TEST_AUTOEXPUNGE_SECS);

	/* another process is autoexpunging, but nothing needs to be
	   expunged so the lock isn't needed */
	test_save_mail(ctx->user, "Trash", ioloop_time);
	test_assert(mail_user_lock_file_create(ctx->user,
		"dovecot.autoexpunge.lock", 0, &lock, &error) > 0);
	test_assert(mail_user_autoexpunge(ctx->user, &next_check) == 0);
	test_assert(next_check == ioloop_time - 1800 + TEST_AUTOEXPUNGE_SECS);
	file_lock_free(&lock);

	test_autoexpunge_deinit_user(ctx);
	test_mail_storage_deinit(&ctx);
	test_end();

	test_begin("autoexpunge: next check with long autoexpunge interval");
	ctx = test_mail_storage_init();
	test_autoexpunge_init_user(ctx, 7*24*60*60, NULL);

	/* empty mailbox: at most 24 hours */
	test_assert(mail_user_autoexpunge(ctx->user, &next_check) == 0);
	test_assert(next_check == ioloop_time +
		    MAIL_AUTOEXPUNGE_CHECK_MAX_INTERVAL_SECS);

	/* the mail expires after the maximum interval */
	test_save_mail(ctx->user, "Trash", ioloop_time - 60);
	test_assert(mail_user_autoexpunge(ctx->user, &next_check) == 0);
	test_assert(next_check == ioloop_time +
		    MAIL_AUTOEXPUNGE_CHECK_MAX_INTERVAL_SECS);

	test_autoexpunge_deinit_user(ctx);
	test_mail_storage_deinit(&ctx);
	test_end();
}

int main(int argc, char **argv)
{
	int ret;
	void (*const tests[])(void) = {
		test_autoexpunge_lock_lazy,
		test_autoexpunge_lock_busy,
		test_autoexpunge_next_check,
		NULL
	};

	master_service = master_service_init("test-mail-autoexpunge",
					     MASTER_SERVICE_FLAG_STANDALONE |
					     MASTER_SERVICE_FLAG_DONT_SEND_STATS |
					     MASTER_SERVICE_FLAG_CONFIG_BUILTIN |
					     MASTER_SERVICE_FLAG_NO_SSL_INIT |
					     MASTER_SERVICE_FLAG_NO_INIT_DATASTACK_FRAME,
					     &argc, &argv, "");
	/* needed for the mailbox filter settings overrides */
	settings_info_register(&mail_namespace_setting_parser_info);
	settings_info_register(&mailbox_setting_parser_info);
	test_dir_init("test-mail-autoexpunge");
	ret = test_run(tests);

	master_service_deinit(&master_service);

	return ret;
}
