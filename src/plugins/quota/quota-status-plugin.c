/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "quota-private.h"
#include "quota-plugin.h"
#include "quota-status.h"
#include "quota-status-plugin.h"

const char *quota_status_plugin_version = DOVECOT_ABI_VERSION;

static enum quota_alloc_result
quota_status_plugin_check(struct mail_user *user, uoff_t mail_size,
			  const char **error_r)
{
	struct quota_user *quser = QUOTA_USER_CONTEXT(user);
	struct mail_namespace *ns;
	struct mailbox *box;
	struct quota_transaction_context *ctx;
	enum quota_alloc_result ret;

	if (quser == NULL) {
		/* no quota for user */
		e_debug(user->event, "User has no quota");
		*error_r = quota_alloc_result_errstr(QUOTA_ALLOC_RESULT_OK,
						     NULL);
		return QUOTA_ALLOC_RESULT_OK;
	}

	ns = mail_namespace_find_inbox(user->namespaces);
	box = mailbox_alloc(ns->list, "INBOX", MAILBOX_FLAG_POST_SESSION);

	ctx = quota_transaction_begin(box);
	const char *internal_error;
	ret = quota_test_alloc(ctx, I_MAX(1, mail_size), NULL, 0,
			       QUOTA_ALLOC_FLAGS_NONE, NULL, &internal_error);
	if (ret == QUOTA_ALLOC_RESULT_TEMPFAIL)
		e_error(user->event, "quota check failed: %s", internal_error);
	*error_r = quota_alloc_result_errstr(ret, ctx);
	quota_transaction_rollback(&ctx);

	mailbox_free(&box);
	return ret;
}

void quota_status_plugin_init(struct module *module ATTR_UNUSED)
{
	quota_status_set_check(quota_status_plugin_check);
}

void quota_status_plugin_deinit(void)
{
	quota_status_set_check(NULL);
}

const struct setting_plugin_info quota_status_plugin_info = {
	.plugin = "lib11_quota_status_plugin",
	.required_plugins = (const char *const []) { "quota", NULL },
};
const char quota_status_plugin_binary_dependency[] = "quota-status";
