/* Copyright (c) 2005-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "module-dir.h"
#include "quota-plugin.h"
#include "quota-private.h"
#include "doveadm-mail.h"

#include <stdio.h>

const char *doveadm_quota_plugin_version = DOVECOT_VERSION;

void doveadm_quota_plugin_init(struct module *module);
void doveadm_quota_plugin_deinit(void);

static void cmd_quota_get_root(struct mail_user *user, struct quota_root *root)
{
	const char *const *res;
	uint64_t value, limit;
	int ret;

	printf("%s(%s): ", user->username, root->set->name);
	res = quota_root_get_resources(root);
	for (; *res != NULL; res++) {
		ret = quota_get_resource(root, "", *res, &value, &limit);
		printf("%s ", *res);
		if (ret > 0) {
			printf("%llu/%llu",
			       (unsigned long long)value,
			       (unsigned long long)limit);
		} else if (ret == 0)
			printf("none");
		else
			printf("error");
		if (res[1] != NULL)
			printf(", ");
	}
	printf("\n");
}

static void cmd_quota_get(struct mail_user *user, struct quota *quota)
{
	struct quota_root *const *root;

	array_foreach(&quota->roots, root)
		cmd_quota_get_root(user, *root);
}

static void cmd_quota_recalc(struct quota *quota)
{
	struct quota_root *const *root;
	struct quota_transaction_context trans;

	memset(&trans, 0, sizeof(trans));
	trans.quota = quota;
	trans.recalculate = TRUE;

	array_foreach(&quota->roots, root)
		(void)(*root)->backend.v.update(*root, &trans);
}

static void cmd_quota(struct mail_user *user, const char *args[])
{
	struct quota_user *quser = QUOTA_USER_CONTEXT(user);
	struct quota *quota;
	const char *subcmd = args[0];

	if (subcmd == NULL)
		doveadm_mail_help_name("quota");

	if (quser == NULL)
		i_fatal("User has no quota");

	quota = quser->quota;
	if (strcmp(subcmd, "get") == 0)
		cmd_quota_get(user, quota);
	else if (strcmp(subcmd, "recalc") == 0)
		cmd_quota_recalc(quota);
	else
		doveadm_mail_help_name("quota");
}

static struct doveadm_mail_cmd quota_cmd = {
	cmd_quota, "quota", "get|recalc"
};

void doveadm_quota_plugin_init(struct module *module ATTR_UNUSED)
{
	doveadm_mail_register_cmd(&quota_cmd);
}

void doveadm_quota_plugin_deinit(void)
{
}
