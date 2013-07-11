/* Copyright (c) 2009-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "lib-signals.h"
#include "ioloop.h"
#include "str.h"
#include "unichar.h"
#include "module-dir.h"
#include "wildcard-match.h"
#include "master-service.h"
#include "mail-user.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mail-storage-settings.h"
#include "mail-storage-service.h"
#include "mail-search-build.h"
#include "mail-search-parser.h"
#include "mailbox-list-iter.h"
#include "doveadm.h"
#include "doveadm-settings.h"
#include "doveadm-print.h"
#include "dsync/doveadm-dsync.h"
#include "doveadm-mail.h"

#include <stdio.h>
#include <stdlib.h>

ARRAY_TYPE(doveadm_mail_cmd) doveadm_mail_cmds;
void (*hook_doveadm_mail_init)(struct doveadm_mail_cmd_context *ctx);
struct doveadm_mail_cmd_module_register
	doveadm_mail_cmd_module_register = { 0 };
char doveadm_mail_cmd_hide = '\0';

static int killed_signo = 0;

void doveadm_mail_failed_error(struct doveadm_mail_cmd_context *ctx,
			       enum mail_error error)
{
	int exit_code = 0;

	switch (error) {
	case MAIL_ERROR_NONE:
		i_unreached();
	case MAIL_ERROR_TEMP:
		exit_code = EX_TEMPFAIL;
		break;
	case MAIL_ERROR_NOTPOSSIBLE:
	case MAIL_ERROR_EXISTS:
	case MAIL_ERROR_CONVERSION:
	case MAIL_ERROR_INVALIDDATA:
		exit_code = DOVEADM_EX_NOTPOSSIBLE;
		break;
	case MAIL_ERROR_PARAMS:
		exit_code = EX_USAGE;
		break;
	case MAIL_ERROR_PERM:
		exit_code = EX_NOPERM;
		break;
	case MAIL_ERROR_NOSPACE:
		exit_code = EX_CANTCREAT;
		break;
	case MAIL_ERROR_NOTFOUND:
		exit_code = DOVEADM_EX_NOTFOUND;
		break;
	case MAIL_ERROR_EXPUNGED:
	case MAIL_ERROR_INUSE:
		exit_code = EX_TEMPFAIL;
		break;
	}
	/* tempfail overrides all other exit codes, otherwise use whatever
	   error happened first */
	if (ctx->exit_code == 0 || exit_code == EX_TEMPFAIL)
		ctx->exit_code = exit_code;
}

void doveadm_mail_failed_storage(struct doveadm_mail_cmd_context *ctx,
				 struct mail_storage *storage)
{
	enum mail_error error;

	mail_storage_get_last_error(storage, &error);
	doveadm_mail_failed_error(ctx, error);
}

void doveadm_mail_failed_mailbox(struct doveadm_mail_cmd_context *ctx,
				 struct mailbox *box)
{
	doveadm_mail_failed_storage(ctx, mailbox_get_storage(box));
}

struct doveadm_mail_cmd_context *
doveadm_mail_cmd_alloc_size(size_t size)
{
	struct doveadm_mail_cmd_context *ctx;
	pool_t pool;

	i_assert(size >= sizeof(struct doveadm_mail_cmd_context));

	pool = pool_alloconly_create("doveadm mail cmd", 1024);
	ctx = p_malloc(pool, size);
	ctx->pool = pool;
	return ctx;
}

static int
cmd_purge_run(struct doveadm_mail_cmd_context *ctx, struct mail_user *user)
{
	struct mail_namespace *ns;
	struct mail_storage *storage;
	int ret = 0;

	for (ns = user->namespaces; ns != NULL; ns = ns->next) {
		if (ns->type != MAIL_NAMESPACE_TYPE_PRIVATE ||
		    ns->alias_for != NULL)
			continue;

		storage = mail_namespace_get_default_storage(ns);
		if (mail_storage_purge(storage) < 0) {
			i_error("Purging namespace '%s' failed: %s", ns->prefix,
				mail_storage_get_last_error(storage, NULL));
			doveadm_mail_failed_storage(ctx, storage);
			ret = -1;
		}
	}
	return ret;
}

static struct doveadm_mail_cmd_context *cmd_purge_alloc(void)
{
	struct doveadm_mail_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct doveadm_mail_cmd_context);
	ctx->v.run = cmd_purge_run;
	return ctx;
}

struct mailbox *
doveadm_mailbox_find(struct mail_user *user, const char *mailbox)
{
	struct mail_namespace *ns;

	if (!uni_utf8_str_is_valid(mailbox)) {
		i_fatal_status(EX_DATAERR,
			       "Mailbox name not valid UTF-8: %s", mailbox);
	}

	ns = mail_namespace_find(user->namespaces, mailbox);
	return mailbox_alloc(ns->list, mailbox, MAILBOX_FLAG_IGNORE_ACLS);
}

static int
doveadm_mailbox_find_and_open(struct mail_user *user, const char *mailbox,
			      struct mailbox **box_r)
{
	struct mailbox *box;

	box = doveadm_mailbox_find(user, mailbox);
	if (mailbox_open(box) < 0) {
		i_error("Opening mailbox %s failed: %s", mailbox,
			mailbox_get_last_error(box, NULL));
		mailbox_free(&box);
		return -1;
	}
	*box_r = box;
	return 0;
}

int doveadm_mailbox_find_and_sync(struct mail_user *user, const char *mailbox,
				  struct mailbox **box_r)
{
	if (doveadm_mailbox_find_and_open(user, mailbox, box_r) < 0)
		return -1;
	if (mailbox_sync(*box_r, MAILBOX_SYNC_FLAG_FULL_READ) < 0) {
		i_error("Syncing mailbox %s failed: %s", mailbox,
			mailbox_get_last_error(*box_r, NULL));
		mailbox_free(box_r);
		mailbox_free(box_r);
		return -1;
	}
	return 0;
}

struct mail_search_args *
doveadm_mail_build_search_args(const char *const args[])
{
	struct mail_search_parser *parser;
	struct mail_search_args *sargs;
	const char *error, *charset = "UTF-8";

	parser = mail_search_parser_init_cmdline(args);
	if (mail_search_build(mail_search_register_get_human(),
			      parser, &charset, &sargs, &error) < 0)
		i_fatal("%s", error);
	mail_search_parser_deinit(&parser);
	return sargs;
}

static int cmd_force_resync_box(struct doveadm_mail_cmd_context *ctx,
				const struct mailbox_info *info)
{
	struct mailbox *box;
	int ret = 0;

	box = mailbox_alloc(info->ns->list, info->vname,
			    MAILBOX_FLAG_IGNORE_ACLS);
	if (mailbox_open(box) < 0) {
		i_error("Opening mailbox %s failed: %s", info->vname,
			mailbox_get_last_error(box, NULL));
		doveadm_mail_failed_mailbox(ctx, box);
		ret = -1;
	} else if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FORCE_RESYNC |
				MAILBOX_SYNC_FLAG_FIX_INCONSISTENT) < 0) {
		i_error("Forcing a resync on mailbox %s failed: %s",
			info->vname, mailbox_get_last_error(box, NULL));
		doveadm_mail_failed_mailbox(ctx, box);
		ret = -1;
	}
	mailbox_free(&box);
	return ret;
}

static int cmd_force_resync_run(struct doveadm_mail_cmd_context *ctx,
				struct mail_user *user)
{
	const enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS |
		MAILBOX_LIST_ITER_STAR_WITHIN_NS;
	const enum mail_namespace_type ns_mask = MAIL_NAMESPACE_TYPE_MASK_ALL;
	struct mailbox_list_iterate_context *iter;
	const struct mailbox_info *info;
	int ret = 0;

	iter = mailbox_list_iter_init_namespaces(user->namespaces, ctx->args,
						 ns_mask, iter_flags);
	while ((info = mailbox_list_iter_next(iter)) != NULL) {
		if ((info->flags & (MAILBOX_NOSELECT |
				    MAILBOX_NONEXISTENT)) == 0) T_BEGIN {
			if (cmd_force_resync_box(ctx, info) < 0)
				ret = -1;
		} T_END;
	}
	if (mailbox_list_iter_deinit(&iter) < 0) {
		i_error("Listing mailboxes failed");
		ret = -1;
	}
	return ret;
}

static void
cmd_force_resync_init(struct doveadm_mail_cmd_context *_ctx ATTR_UNUSED,
		      const char *const args[])
{
	if (args[0] == NULL)
		doveadm_mail_help_name("force-resync");
}

static struct doveadm_mail_cmd_context *cmd_force_resync_alloc(void)
{
	struct doveadm_mail_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct doveadm_mail_cmd_context);
	ctx->v.init = cmd_force_resync_init;
	ctx->v.run = cmd_force_resync_run;
	return ctx;
}

static int
doveadm_mail_next_user(struct doveadm_mail_cmd_context *ctx,
		       const struct mail_storage_service_input *input,
		       const char **error_r)
{
	const char *error;
	int ret;

	i_set_failure_prefix("doveadm(%s): ", input->username);

	/* see if we want to execute this command via (another)
	   doveadm server */
	ret = doveadm_mail_server_user(ctx, input, error_r);
	if (ret != 0)
		return ret;

	ret = mail_storage_service_lookup(ctx->storage_service, input,
					  &ctx->cur_service_user, &error);
	if (ret <= 0) {
		if (ret < 0) {
			*error_r = t_strdup_printf("User lookup failed: %s",
						   error);
		}
		return ret;
	}

	if (ctx->v.prerun != NULL) {
		if (ctx->v.prerun(ctx, ctx->cur_service_user, error_r) < 0) {
			mail_storage_service_user_free(&ctx->cur_service_user);
			return -1;
		}
	}

	ret = mail_storage_service_next(ctx->storage_service,
					ctx->cur_service_user,
					&ctx->cur_mail_user);
	if (ret < 0) {
		*error_r = "User init failed";
		mail_storage_service_user_free(&ctx->cur_service_user);
		return ret;
	}

	if (ctx->v.run(ctx, ctx->cur_mail_user) < 0) {
		i_assert(ctx->exit_code != 0);
	}
	mail_user_unref(&ctx->cur_mail_user);
	mail_storage_service_user_free(&ctx->cur_service_user);
	return 1;
}

int doveadm_mail_single_user(struct doveadm_mail_cmd_context *ctx,
			     const struct mail_storage_service_input *input,
			     const char **error_r)
{
	i_assert(input->username != NULL);

	ctx->cur_username = input->username;
	ctx->storage_service_input = *input;
	ctx->storage_service = mail_storage_service_init(master_service, NULL,
							 ctx->service_flags);
	ctx->v.init(ctx, ctx->args);
	if (hook_doveadm_mail_init != NULL)
		hook_doveadm_mail_init(ctx);

	return doveadm_mail_next_user(ctx, input, error_r);
}

static void sig_die(const siginfo_t *si, void *context ATTR_UNUSED)
{
	killed_signo = si->si_signo;
}

static void
doveadm_mail_all_users(struct doveadm_mail_cmd_context *ctx, char *argv[],
		       const char *wildcard_user)
{
	struct mail_storage_service_input input;
	unsigned int user_idx;
	const char *user, *error;
	int ret;

	ctx->service_flags |= MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP;

	memset(&input, 0, sizeof(input));
	input.service = "doveadm";

	ctx->storage_service_input = input;
	ctx->storage_service = mail_storage_service_init(master_service, NULL,
							 ctx->service_flags);
        lib_signals_set_handler(SIGINT, 0, sig_die, NULL);
	lib_signals_set_handler(SIGTERM, 0, sig_die, NULL);

	ctx->v.init(ctx, (const void *)argv);

	mail_storage_service_all_init(ctx->storage_service);

	if (hook_doveadm_mail_init != NULL)
		hook_doveadm_mail_init(ctx);

	user_idx = 0;
	while ((ret = ctx->v.get_next_user(ctx, &user)) > 0) {
		if (wildcard_user != NULL) {
			if (!wildcard_match_icase(user, wildcard_user))
				continue;
		}
		input.username = user;
		ctx->cur_username = user;
		doveadm_print_sticky("username", user);
		T_BEGIN {
			ret = doveadm_mail_next_user(ctx, &input, &error);
			if (ret < 0)
				i_error("%s", error);
			else if (ret == 0)
				i_info("User no longer exists, skipping");
		} T_END;
		if (ret == -1)
			break;
		if (doveadm_verbose) {
			if (++user_idx % 100 == 0) {
				printf("\r%d", user_idx);
				fflush(stdout);
			}
		}
		if (killed_signo != 0) {
			i_warning("Killed with signal %d", killed_signo);
			ret = -1;
			break;
		}
	}
	if (doveadm_verbose)
		printf("\n");
	i_set_failure_prefix("doveadm: ");
	if (ret < 0) {
		i_error("Failed to iterate through some users");
		ctx->exit_code = EX_TEMPFAIL;
	}
}

static void
doveadm_mail_cmd_init_noop(struct doveadm_mail_cmd_context *ctx ATTR_UNUSED,
			   const char *const args[] ATTR_UNUSED)
{
}

static int
doveadm_mail_cmd_get_next_user(struct doveadm_mail_cmd_context *ctx,
			       const char **username_r)
{
	return mail_storage_service_all_next(ctx->storage_service, username_r);
}

static void
doveadm_mail_cmd_deinit_noop(struct doveadm_mail_cmd_context *ctx ATTR_UNUSED)
{
}

struct doveadm_mail_cmd_context *
doveadm_mail_cmd_init(const struct doveadm_mail_cmd *cmd,
		      const struct doveadm_settings *set)
{
	struct doveadm_mail_cmd_context *ctx;

	ctx = cmd->alloc();
	ctx->set = set;
	ctx->cmd = cmd;
	if (ctx->v.init == NULL)
		ctx->v.init = doveadm_mail_cmd_init_noop;
	if (ctx->v.get_next_user == NULL)
		ctx->v.get_next_user = doveadm_mail_cmd_get_next_user;
	if (ctx->v.deinit == NULL)
		ctx->v.deinit = doveadm_mail_cmd_deinit_noop;

	p_array_init(&ctx->module_contexts, ctx->pool, 5);
	return ctx;
}

static void
doveadm_mail_cmd(const struct doveadm_mail_cmd *cmd, int argc, char *argv[])
{
	struct doveadm_mail_cmd_context *ctx;
	const char *getopt_args, *wildcard_user, *error;
	int ret, c;

	ctx = doveadm_mail_cmd_init(cmd, doveadm_settings);
	ctx->full_args = (const void *)(argv + 1);

	ctx->service_flags |= MAIL_STORAGE_SERVICE_FLAG_NO_LOG_INIT;
	if (doveadm_debug)
		ctx->service_flags |= MAIL_STORAGE_SERVICE_FLAG_DEBUG;

	getopt_args = "AS:u:";
	/* keep context's getopt_args first in case it contains '+' */
	if (ctx->getopt_args != NULL)
		getopt_args = t_strconcat(ctx->getopt_args, getopt_args, NULL);
	ctx->cur_username = getenv("USER");
	wildcard_user = NULL;
	while ((c = getopt(argc, argv, getopt_args)) > 0) {
		switch (c) {
		case 'A':
			ctx->iterate_all_users = TRUE;
			break;
		case 'S':
			doveadm_settings->doveadm_socket_path = optarg;
			if (doveadm_settings->doveadm_worker_count == 0)
				doveadm_settings->doveadm_worker_count = 1;
			break;
		case 'u':
			ctx->service_flags |=
				MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP;
			ctx->cur_username = optarg;
			if (strchr(ctx->cur_username, '*') != NULL ||
			    strchr(ctx->cur_username, '?') != NULL) {
				wildcard_user = ctx->cur_username;
				ctx->cur_username = NULL;
			}
			break;
		default:
			if (ctx->v.parse_arg == NULL ||
			    !ctx->v.parse_arg(ctx, c))
				doveadm_mail_help(cmd);
		}
	}
	argv += optind;
	if (argv[0] != NULL && cmd->usage_args == NULL) {
		i_fatal_status(EX_USAGE, "doveadm %s: Unknown parameter: %s",
			       cmd->name, argv[0]);
	}
	ctx->args = (const void *)argv;
	if (ctx->v.preinit != NULL)
		ctx->v.preinit(ctx);

	ctx->iterate_single_user =
		!ctx->iterate_all_users && wildcard_user == NULL;
	if (doveadm_print_is_initialized() && !ctx->iterate_single_user) {
		doveadm_print_header("username", "Username",
				     DOVEADM_PRINT_HEADER_FLAG_STICKY |
				     DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);
	}

	if (ctx->iterate_single_user) {
		struct mail_storage_service_input input;

		if (ctx->cur_username == NULL)
			i_fatal_status(EX_USAGE, "USER environment is missing and -u option not used");

		memset(&input, 0, sizeof(input));
		input.service = "doveadm";
		input.username = ctx->cur_username;
		ret = doveadm_mail_single_user(ctx, &input, &error);
		if (ret < 0)
			i_fatal("%s", error);
		else if (ret == 0)
			i_fatal_status(EX_NOUSER, "User doesn't exist");
	} else {
		ctx->service_flags |= MAIL_STORAGE_SERVICE_FLAG_TEMP_PRIV_DROP;
		doveadm_mail_all_users(ctx, argv, wildcard_user);
	}
	if (ctx->search_args != NULL)
		mail_search_args_unref(&ctx->search_args);
	doveadm_mail_server_flush();
	ctx->v.deinit(ctx);
	doveadm_print_flush();

	/* service deinit unloads mail plugins, so do it late */
	mail_storage_service_deinit(&ctx->storage_service);

	if (ctx->exit_code != 0)
		doveadm_exit_code = ctx->exit_code;
	pool_unref(&ctx->pool);
}

static bool
doveadm_mail_cmd_try_find_multi_word(const struct doveadm_mail_cmd *cmd,
				     const char *cmdname, int *argc,
				     const char *const **argv)
{
	unsigned int len;

	if (*argc < 2)
		return FALSE;
	*argc -= 1;
	*argv += 1;

	len = strlen((*argv)[0]);
	if (strncmp(cmdname, (*argv)[0], len) != 0)
		return FALSE;

	if (cmdname[len] == ' ') {
		/* more args */
		return doveadm_mail_cmd_try_find_multi_word(cmd, cmdname + len + 1,
							    argc, argv);
	}
	if (cmdname[len] != '\0')
		return FALSE;

	/* match */
	return TRUE;
}

const struct doveadm_mail_cmd *
doveadm_mail_cmd_find_from_argv(const char *cmd_name, int *argc,
				const char *const **argv)
{
	const struct doveadm_mail_cmd *cmd;
	unsigned int cmd_name_len;
	const char *const *orig_argv;
	int orig_argc;

	i_assert(*argc > 0);

	cmd_name_len = strlen(cmd_name);
	array_foreach(&doveadm_mail_cmds, cmd) {
		if (strcmp(cmd->name, cmd_name) == 0)
			return cmd;

		/* see if it matches a multi-word command */
		if (strncmp(cmd->name, cmd_name, cmd_name_len) == 0 &&
		    cmd->name[cmd_name_len] == ' ') {
			const char *subcmd = cmd->name + cmd_name_len + 1;

			orig_argc = *argc;
			orig_argv = *argv;
			if (doveadm_mail_cmd_try_find_multi_word(cmd, subcmd,
								 argc, argv))
				return cmd;
			*argc = orig_argc;
			*argv = orig_argv;
		}
	}

	return FALSE;
}

bool doveadm_mail_try_run(const char *cmd_name, int argc, char *argv[])
{
	const struct doveadm_mail_cmd *cmd;

	cmd = doveadm_mail_cmd_find_from_argv(cmd_name, &argc, (void *)&argv);
	if (cmd == NULL)
		return FALSE;
	doveadm_mail_cmd(cmd, argc, argv);
	return TRUE;
}

void doveadm_mail_register_cmd(const struct doveadm_mail_cmd *cmd)
{
	/* for now we'll just assume that cmd will be permanently in memory */
	array_append(&doveadm_mail_cmds, cmd, 1);
}

const struct doveadm_mail_cmd *doveadm_mail_cmd_find(const char *cmd_name)
{
	const struct doveadm_mail_cmd *cmd;

	array_foreach(&doveadm_mail_cmds, cmd) {
		if (strcmp(cmd->name, cmd_name) == 0)
			return cmd;
	}
	return NULL;
}

void doveadm_mail_usage(string_t *out)
{
	const struct doveadm_mail_cmd *cmd;

	array_foreach(&doveadm_mail_cmds, cmd) {
		if (cmd->usage_args == &doveadm_mail_cmd_hide)
			continue;
		str_printfa(out, "%s\t[-u <user>|-A] [-S <socket_path>]",
			    cmd->name);
		if (cmd->usage_args != NULL)
			str_printfa(out, " %s", cmd->usage_args);
		str_append_c(out, '\n');
	}
}

void doveadm_mail_help(const struct doveadm_mail_cmd *cmd)
{
	fprintf(stderr, "doveadm %s [-u <user>|-A] [-S <socket_path>] %s\n",
		cmd->name, cmd->usage_args == NULL ? "" : cmd->usage_args);
	exit(EX_USAGE);
}

void doveadm_mail_try_help_name(const char *cmd_name)
{
	const struct doveadm_mail_cmd *cmd;

	cmd = doveadm_mail_cmd_find(cmd_name);
	if (cmd != NULL)
		doveadm_mail_help(cmd);
}

bool doveadm_mail_has_subcommands(const char *cmd_name)
{
	const struct doveadm_mail_cmd *cmd;
	unsigned int len = strlen(cmd_name);

	array_foreach(&doveadm_mail_cmds, cmd) {
		if (strncmp(cmd->name, cmd_name, len) == 0 &&
		    cmd->name[len] == ' ')
			return TRUE;
	}
	return FALSE;
}

void doveadm_mail_help_name(const char *cmd_name)
{
	doveadm_mail_try_help_name(cmd_name);
	i_fatal("Missing help for command %s", cmd_name);
}

static struct doveadm_mail_cmd cmd_force_resync = {
	cmd_force_resync_alloc, "force-resync", "<mailbox mask>"
};
static struct doveadm_mail_cmd cmd_purge = {
	cmd_purge_alloc, "purge", NULL
};

static struct doveadm_mail_cmd *mail_commands[] = {
	&cmd_force_resync,
	&cmd_purge,
	&cmd_expunge,
	&cmd_search,
	&cmd_fetch,
	&cmd_flags_add,
	&cmd_flags_remove,
	&cmd_flags_replace,
	&cmd_import,
	&cmd_index,
	&cmd_altmove,
	&cmd_copy,
	&cmd_deduplicate,
	&cmd_move,
	&cmd_mailbox_list,
	&cmd_mailbox_create,
	&cmd_mailbox_delete,
	&cmd_mailbox_rename,
	&cmd_mailbox_subscribe,
	&cmd_mailbox_unsubscribe,
	&cmd_mailbox_status,
	&cmd_batch,
	&cmd_dsync_backup,
	&cmd_dsync_mirror,
	&cmd_dsync_server
};

void doveadm_mail_init(void)
{
	struct module_dir_load_settings mod_set;
	unsigned int i;

	i_array_init(&doveadm_mail_cmds, 32);
	for (i = 0; i < N_ELEMENTS(mail_commands); i++)
		doveadm_mail_register_cmd(mail_commands[i]);

	memset(&mod_set, 0, sizeof(mod_set));
	mod_set.abi_version = DOVECOT_ABI_VERSION;
	mod_set.require_init_funcs = TRUE;
	mod_set.debug = doveadm_debug;
	mod_set.binary_name = "doveadm";

	/* load all configured mail plugins */
	mail_storage_service_modules =
		module_dir_load_missing(mail_storage_service_modules,
					doveadm_settings->mail_plugin_dir,
					doveadm_settings->mail_plugins,
					&mod_set);
}

void doveadm_mail_deinit(void)
{
	array_free(&doveadm_mail_cmds);
}
