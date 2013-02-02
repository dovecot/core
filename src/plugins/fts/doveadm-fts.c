/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-namespace.h"
#include "fts-storage.h"
#include "doveadm-mail.h"
#include "doveadm-fts.h"

const char *doveadm_fts_plugin_version = DOVECOT_ABI_VERSION;

static int
fts_namespace_find(struct mail_user *user, const char *ns_prefix,
		   struct mail_namespace **ns_r)
{
	struct mail_namespace *ns;

	if (ns_prefix == NULL)
		ns = mail_namespace_find_inbox(user->namespaces);
	else {
		ns = mail_namespace_find_prefix(user->namespaces, ns_prefix);
		if (ns == NULL) {
			i_error("Namespace prefix not found: %s", ns_prefix);
			return -1;
		}
	}

	if (fts_list_backend(ns->list) == NULL) {
		i_error("fts not enabled for user's namespace %s", ns_prefix);
		return -1;
	}
	*ns_r = ns;
	return 0;
}

static int
cmd_fts_optimize_run(struct doveadm_mail_cmd_context *ctx,
		     struct mail_user *user)
{
	const char *ns_prefix = ctx->args[0];
	struct mail_namespace *ns;
	struct fts_backend *backend;

	if (fts_namespace_find(user, ns_prefix, &ns) < 0) {
		doveadm_mail_failed_error(ctx, MAIL_ERROR_NOTFOUND);
		return -1;
	}
	backend = fts_list_backend(ns->list);
	if (fts_backend_optimize(backend) < 0) {
		i_error("fts optimize failed");
		doveadm_mail_failed_error(ctx, MAIL_ERROR_TEMP);
		return -1;
	}
	return 0;
}

static void
cmd_fts_optimize_init(struct doveadm_mail_cmd_context *ctx ATTR_UNUSED,
		      const char *const args[])
{
	if (str_array_length(args) > 1)
		doveadm_mail_help_name("fts optimize");
}

static struct doveadm_mail_cmd_context *
cmd_fts_optimize_alloc(void)
{
	struct doveadm_mail_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct doveadm_mail_cmd_context);
	ctx->v.run = cmd_fts_optimize_run;
	ctx->v.init = cmd_fts_optimize_init;
	return ctx;
}

static int
cmd_fts_rescan_run(struct doveadm_mail_cmd_context *ctx, struct mail_user *user)
{
	const char *ns_prefix = ctx->args[0];
	struct mail_namespace *ns;
	struct fts_backend *backend;

	if (fts_namespace_find(user, ns_prefix, &ns) < 0) {
		doveadm_mail_failed_error(ctx, MAIL_ERROR_NOTFOUND);
		return -1;
	}
	backend = fts_list_backend(ns->list);
	if (fts_backend_rescan(backend) < 0) {
		i_error("fts rescan failed");
		doveadm_mail_failed_error(ctx, MAIL_ERROR_TEMP);
		return -1;
	}
	return 0;
}

static void
cmd_fts_rescan_init(struct doveadm_mail_cmd_context *ctx ATTR_UNUSED,
		    const char *const args[])
{
	if (str_array_length(args) > 1)
		doveadm_mail_help_name("fts rescan");
}

static struct doveadm_mail_cmd_context *
cmd_fts_rescan_alloc(void)
{
	struct doveadm_mail_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct doveadm_mail_cmd_context);
	ctx->v.run = cmd_fts_rescan_run;
	ctx->v.init = cmd_fts_rescan_init;
	return ctx;
}

static struct doveadm_mail_cmd fts_commands[] = {
	{ cmd_fts_optimize_alloc, "fts optimize", "[<namespace>]" },
	{ cmd_fts_rescan_alloc, "fts rescan", "[<namespace>]" }
};

void doveadm_fts_plugin_init(struct module *module ATTR_UNUSED)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(fts_commands); i++)
		doveadm_mail_register_cmd(&fts_commands[i]);
	doveadm_dump_fts_expunge_log_init();
}

void doveadm_fts_plugin_deinit(void)
{
}
