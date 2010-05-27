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
		} else if (ret == 0) {
			printf("%llu/unlimited",
			       (unsigned long long)value);
		} else
			printf("error");
		if (res[1] != NULL)
			printf(", ");
	}
	printf("\n");
}

static void
cmd_quota_get_run(struct doveadm_mail_cmd_context *ctx ATTR_UNUSED,
		  struct mail_user *user)
{
	struct quota_user *quser = QUOTA_USER_CONTEXT(user);
	struct quota_root *const *root;

	array_foreach(&quser->quota->roots, root)
		cmd_quota_get_root(user, *root);
}

static struct doveadm_mail_cmd_context *
cmd_quota_get_alloc(void)
{
	struct doveadm_mail_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct doveadm_mail_cmd_context);
	ctx->v.run = cmd_quota_get_run;
	return ctx;
}

static void
cmd_quota_recalc_run(struct doveadm_mail_cmd_context *ctx ATTR_UNUSED,
		     struct mail_user *user)
{
	struct quota_user *quser = QUOTA_USER_CONTEXT(user);
	struct quota_root *const *root;
	struct quota_transaction_context trans;

	memset(&trans, 0, sizeof(trans));
	trans.quota = quser->quota;
	trans.recalculate = TRUE;

	array_foreach(&quser->quota->roots, root)
		(void)(*root)->backend.v.update(*root, &trans);
}

static struct doveadm_mail_cmd_context *
cmd_quota_recalc_alloc(void)
{
	struct doveadm_mail_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct doveadm_mail_cmd_context);
	ctx->v.run = cmd_quota_recalc_run;
	return ctx;
}

static struct doveadm_mail_cmd quota_commands[] = {
	{ cmd_quota_get_alloc, "quota get", NULL },
	{ cmd_quota_recalc_alloc, "quota recalc", NULL }
};

void doveadm_quota_plugin_init(struct module *module ATTR_UNUSED)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(quota_commands); i++)
		doveadm_mail_register_cmd(&quota_commands[i]);
}

void doveadm_quota_plugin_deinit(void)
{
}
