/* Copyright (c) 2011-2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "imap-util.h"
#include "mail-namespace.h"
#include "mail-search.h"
#include "mailbox-list-iter.h"
#include "fts-storage.h"
#include "fts-search-args.h"
#include "doveadm-mail.h"
#include "doveadm-mailbox-list-iter.h"
#include "doveadm-fts.h"

const char *doveadm_fts_plugin_version = DOVECOT_ABI_VERSION;

static int
cmd_search_box(struct doveadm_mail_cmd_context *ctx,
	       const struct mailbox_info *info)
{
	struct mailbox *box;
	struct fts_backend *backend;
	struct fts_result result;
	int ret = 0;

	backend = fts_list_backend(info->ns->list);
	if (backend == NULL) {
		i_error("fts not enabled for %s", info->vname);
		ctx->exit_code = EX_CONFIG;
		return -1;
	}

	memset(&result, 0, sizeof(result));
	i_array_init(&result.definite_uids, 16);
	i_array_init(&result.maybe_uids, 16);
	i_array_init(&result.scores, 16);

	box = mailbox_alloc(info->ns->list, info->vname, 0);
	if (fts_backend_lookup(backend, box, ctx->search_args->args,
				      FTS_LOOKUP_FLAG_AND_ARGS, &result) < 0) {
		i_error("fts lookup failed");
		doveadm_mail_failed_error(ctx, MAIL_ERROR_TEMP);
		ret = -1;
	} else {
		printf("%s: ", info->vname);
		if (array_count(&result.definite_uids) == 0)
			printf("no results\n");
		else T_BEGIN {
			string_t *str = t_str_new(128);
			imap_write_seq_range(str, &result.definite_uids);
			printf("%s\n", str_c(str));
		} T_END;
		if (array_count(&result.maybe_uids) > 0) T_BEGIN {
			string_t *str = t_str_new(128);
			imap_write_seq_range(str, &result.maybe_uids);
			printf(" - maybe: %s\n", str_c(str));
		} T_END;
		fts_backend_lookup_done(backend);
	}
	mailbox_free(&box);
	array_free(&result.definite_uids);
	array_free(&result.maybe_uids);
	array_free(&result.scores);
	return ret;
}

static int
cmd_fts_lookup_run(struct doveadm_mail_cmd_context *ctx,
		   struct mail_user *user)
{
	const enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_NO_AUTO_BOXES |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	struct doveadm_mailbox_list_iter *iter;
	const struct mailbox_info *info;
	int ret = 0;

	iter = doveadm_mailbox_list_iter_init(ctx, user, ctx->search_args,
					      iter_flags);
	while ((info = doveadm_mailbox_list_iter_next(iter)) != NULL) T_BEGIN {
		if (cmd_search_box(ctx, info) < 0)
			ret = -1;
	} T_END;
	if (doveadm_mailbox_list_iter_deinit(&iter) < 0)
		ret = -1;
	return ret;
}

static void
cmd_fts_lookup_init(struct doveadm_mail_cmd_context *ctx,
		    const char *const args[])
{
	if (args[0] == NULL)
		doveadm_mail_help_name("fts lookup");

	ctx->search_args = doveadm_mail_build_search_args(args);
}

static struct doveadm_mail_cmd_context *
cmd_fts_lookup_alloc(void)
{
	struct doveadm_mail_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct doveadm_mail_cmd_context);
	ctx->v.run = cmd_fts_lookup_run;
	ctx->v.init = cmd_fts_lookup_init;
	return ctx;
}

static int
cmd_fts_expand_run(struct doveadm_mail_cmd_context *ctx,
		   struct mail_user *user)
{
	struct mail_namespace *ns = mail_namespace_find_inbox(user->namespaces);
	struct mailbox *box;
	struct fts_backend *backend;
	string_t *str = t_str_new(128);

	backend = fts_list_backend(ns->list);
	if (backend == NULL) {
		i_error("fts not enabled for INBOX");
		ctx->exit_code = EX_CONFIG;
		return -1;
	}

	box = mailbox_alloc(ns->list, "INBOX", 0);
	mail_search_args_init(ctx->search_args, box, FALSE, NULL);

	if (fts_search_args_expand(backend, ctx->search_args) < 0)
		i_fatal("Couldn't expand search args");
	mail_search_args_to_cmdline(str, ctx->search_args->args);
	printf("%s\n", str_c(str));
	mailbox_free(&box);
	return 0;
}

static void
cmd_fts_expand_init(struct doveadm_mail_cmd_context *ctx,
		    const char *const args[])
{
	if (args[0] == NULL)
		doveadm_mail_help_name("fts expand");

	ctx->search_args = doveadm_mail_build_search_args(args);
}

static struct doveadm_mail_cmd_context *
cmd_fts_expand_alloc(void)
{
	struct doveadm_mail_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct doveadm_mail_cmd_context);
	ctx->v.run = cmd_fts_expand_run;
	ctx->v.init = cmd_fts_expand_init;
	return ctx;
}

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
		i_error("fts not enabled for user's namespace %s",
			ns_prefix != NULL ? ns_prefix : "INBOX");
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
	{ cmd_fts_lookup_alloc, "fts lookup", "<search query>" },
	{ cmd_fts_expand_alloc, "fts expand", "<search query>" },
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
