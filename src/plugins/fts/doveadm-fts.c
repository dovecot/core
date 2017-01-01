/* Copyright (c) 2011-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "imap-util.h"
#include "mail-namespace.h"
#include "mail-search.h"
#include "mailbox-list-iter.h"
#include "fts-tokenizer.h"
#include "fts-filter.h"
#include "fts-language.h"
#include "fts-storage.h"
#include "fts-search-args.h"
#include "fts-user.h"
#include "doveadm-print.h"
#include "doveadm-mail.h"
#include "doveadm-mailbox-list-iter.h"
#include "doveadm-fts.h"

const char *doveadm_fts_plugin_version = DOVECOT_ABI_VERSION;

struct fts_tokenize_cmd_context {
	struct doveadm_mail_cmd_context ctx;
	const char *language;
	const char *tokens;
};

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

	i_zero(&result);
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
cmd_fts_tokenize_run(struct doveadm_mail_cmd_context *_ctx,
		     struct mail_user *user)
{
	struct fts_tokenize_cmd_context *ctx =
		(struct fts_tokenize_cmd_context *)_ctx;
	struct mail_namespace *ns = mail_namespace_find_inbox(user->namespaces);
	struct fts_backend *backend;
	struct fts_user_language *user_lang;
	const struct fts_language *lang = NULL;
	int ret, ret2;
	bool final = FALSE;

	backend = fts_list_backend(ns->list);
	if (backend == NULL) {
		i_error("fts not enabled for INBOX");
		_ctx->exit_code = EX_CONFIG;
		return -1;
	}

	if (ctx->language == NULL) {
		struct fts_language_list *lang_list =
			fts_user_get_language_list(user);
		enum fts_language_result result;

		result = fts_language_detect(lang_list,
		    (const unsigned char *)ctx->tokens, strlen(ctx->tokens),
                    &lang);
		if (lang == NULL)
			lang = fts_language_list_get_first(lang_list);
		switch (result) {
		case FTS_LANGUAGE_RESULT_SHORT:
			i_warning("Text too short, can't detect its language - assuming %s", lang->name);
			break;
		case FTS_LANGUAGE_RESULT_UNKNOWN:
			i_warning("Can't detect its language - assuming %s", lang->name);
			break;
		case FTS_LANGUAGE_RESULT_OK:
			break;
		case FTS_LANGUAGE_RESULT_ERROR:
			i_error("Language detection library initialization failed");
			_ctx->exit_code = EX_CONFIG;
			return -1;
		default:
			i_unreached();
		}
	} else {
		lang = fts_language_find(ctx->language);
		if (lang == NULL) {
			i_error("Unknown language: %s", ctx->language);
			_ctx->exit_code = EX_USAGE;
			return -1;
		}
	}
	user_lang = fts_user_language_find(user, lang);
	if (user_lang == NULL) {
		i_error("Language not enabled for user: %s", ctx->language);
		_ctx->exit_code = EX_USAGE;
		return -1;
	}

	fts_tokenizer_reset(user_lang->index_tokenizer);
	for (;;) {
		const char *token, *error;

		if (!final) {
			ret = fts_tokenizer_next(user_lang->index_tokenizer,
				(const unsigned char *)ctx->tokens, strlen(ctx->tokens),
				&token, &error);
		} else {
			ret = fts_tokenizer_final(user_lang->index_tokenizer,
						  &token, &error);
		}
		if (ret < 0)
			break;
		if (ret > 0 && user_lang->filter != NULL) {
			ret2 = fts_filter_filter(user_lang->filter, &token, &error);
			if (ret2 > 0)
				doveadm_print(token);
			else if (ret2 < 0)
				i_error("Couldn't create indexable tokens: %s", error);
		}
		if (ret == 0) {
			if (final)
				break;
			final = TRUE;
		}
	}
	return 0;
}

static void
cmd_fts_tokenize_init(struct doveadm_mail_cmd_context *_ctx,
		      const char *const args[])
{
	struct fts_tokenize_cmd_context *ctx =
		(struct fts_tokenize_cmd_context *)_ctx;

	if (args[0] == NULL)
		doveadm_mail_help_name("fts tokenize");

	ctx->tokens = p_strdup(_ctx->pool, t_strarray_join(args, " "));

	doveadm_print_init(DOVEADM_PRINT_TYPE_FLOW);
	doveadm_print_header("token", "token", DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);
}

static bool
cmd_fts_tokenize_parse_arg(struct doveadm_mail_cmd_context *_ctx, int c)
{
	struct fts_tokenize_cmd_context *ctx =
		(struct fts_tokenize_cmd_context *)_ctx;

	switch (c) {
	case 'l':
		ctx->language = p_strdup(_ctx->pool, optarg);
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

static struct doveadm_mail_cmd_context *
cmd_fts_tokenize_alloc(void)
{
	struct fts_tokenize_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct fts_tokenize_cmd_context);
	ctx->ctx.v.run = cmd_fts_tokenize_run;
	ctx->ctx.v.init = cmd_fts_tokenize_init;
	ctx->ctx.v.parse_arg = cmd_fts_tokenize_parse_arg;
	ctx->ctx.getopt_args = "l";
	return &ctx->ctx;
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

static struct doveadm_cmd_ver2 fts_commands[] = {
{
	.name = "fts lookup",
	.mail_cmd = cmd_fts_lookup_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX "<search query>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('\0', "query", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "fts expand",
	.mail_cmd = cmd_fts_expand_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX "<search query>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('\0', "query", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "fts tokenize",
	.mail_cmd = cmd_fts_tokenize_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX "<text>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('l', "language", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "text", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "fts optimize",
	.mail_cmd = cmd_fts_optimize_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX "[<namespace>]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('\0', "namespace", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "fts rescan",
	.mail_cmd = cmd_fts_rescan_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX "[<namespace>]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('\0', "namespace", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
};

void doveadm_fts_plugin_init(struct module *module ATTR_UNUSED)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(fts_commands); i++)
		doveadm_cmd_register_ver2(&fts_commands[i]);
	doveadm_dump_fts_expunge_log_init();
}

void doveadm_fts_plugin_deinit(void)
{
}
