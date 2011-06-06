/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "lib-signals.h"
#include "ioloop.h"
#include "str.h"
#include "module-dir.h"
#include "wildcard-match.h"
#include "master-service.h"
#include "imap-utf7.h"
#include "mail-user.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mail-storage-settings.h"
#include "mail-storage-service.h"
#include "mail-search-build.h"
#include "mail-search-parser.h"
#include "doveadm.h"
#include "doveadm-settings.h"
#include "doveadm-print.h"
#include "doveadm-mail.h"

#include <stdio.h>
#include <stdlib.h>

ARRAY_TYPE(doveadm_mail_cmd) doveadm_mail_cmds;
void (*hook_doveadm_mail_init)(struct doveadm_mail_cmd_context *ctx);
struct doveadm_mail_cmd_module_register
	doveadm_mail_cmd_module_register = { 0 };

static int killed_signo = 0;

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

static void
cmd_purge_run(struct doveadm_mail_cmd_context *ctx ATTR_UNUSED,
	      struct mail_user *user)
{
	struct mail_namespace *ns;

	for (ns = user->namespaces; ns != NULL; ns = ns->next) {
		if (ns->type != NAMESPACE_PRIVATE || ns->alias_for != NULL)
			continue;

		if (mail_storage_purge(ns->storage) < 0) {
			i_error("Purging namespace '%s' failed: %s", ns->prefix,
				mail_storage_get_last_error(ns->storage, NULL));
		}
	}
}

static struct doveadm_mail_cmd_context *cmd_purge_alloc(void)
{
	struct doveadm_mail_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct doveadm_mail_cmd_context);
	ctx->v.run = cmd_purge_run;
	return ctx;
}

static int mailbox_find_and_open(struct mail_user *user, const char *mailbox,
				 struct mailbox **box_r)
{
	struct mail_namespace *ns;
	struct mailbox *box;
	string_t *str;
	const char *orig_mailbox = mailbox;

	str = t_str_new(128);
	if (imap_utf8_to_utf7(mailbox, str) < 0)
		i_fatal("Mailbox name not valid UTF-8: %s", mailbox);
	mailbox = str_c(str);

	ns = mail_namespace_find(user->namespaces, &mailbox);
	if (ns == NULL)
		i_fatal("Can't find namespace for mailbox %s", mailbox);

	box = mailbox_alloc(ns->list, mailbox, MAILBOX_FLAG_KEEP_RECENT |
			    MAILBOX_FLAG_IGNORE_ACLS);
	if (mailbox_open(box) < 0) {
		i_error("Opening mailbox %s failed: %s", orig_mailbox,
			mail_storage_get_last_error(mailbox_get_storage(box),
						    NULL));
		mailbox_free(&box);
		return -1;
	}
	*box_r = box;
	return 0;
}

int doveadm_mailbox_find_and_sync(struct mail_user *user, const char *mailbox,
				  struct mailbox **box_r)
{
	if (mailbox_find_and_open(user, mailbox, box_r) < 0)
		return -1;
	if (mailbox_sync(*box_r, MAILBOX_SYNC_FLAG_FULL_READ) < 0) {
		i_error("Syncing mailbox %s failed: %s", mailbox,
			mail_storage_get_last_error(mailbox_get_storage(*box_r),
						    NULL));
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
	const char *error;

	parser = mail_search_parser_init_cmdline(args);
	if (mail_search_build(mail_search_register_get_human(),
			      parser, "UTF-8", &sargs, &error) < 0)
		i_fatal("%s", error);
	mail_search_parser_deinit(&parser);
	return sargs;
}

struct force_resync_cmd_context {
	struct doveadm_mail_cmd_context ctx;
	const char *mailbox;
};

static void cmd_force_resync_run(struct doveadm_mail_cmd_context *_ctx,
				 struct mail_user *user)
{
	struct force_resync_cmd_context *ctx =
		(struct force_resync_cmd_context *)_ctx;
	struct mail_storage *storage;
	struct mailbox *box;

	if (mailbox_find_and_open(user, ctx->mailbox, &box) < 0) {
		_ctx->failed = TRUE;
		return;
	}
	storage = mailbox_get_storage(box);
	if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FORCE_RESYNC |
			 MAILBOX_SYNC_FLAG_FIX_INCONSISTENT) < 0) {
		i_error("Forcing a resync on mailbox %s failed: %s",
			ctx->mailbox,
			mail_storage_get_last_error(storage, NULL));
		_ctx->failed = TRUE;
	}
	mailbox_free(&box);
}

static void cmd_force_resync_init(struct doveadm_mail_cmd_context *_ctx,
				  const char *const args[])
{
	struct force_resync_cmd_context *ctx =
		(struct force_resync_cmd_context *)_ctx;
	const char *mailbox = args[0];

	if (mailbox == NULL || args[1] != NULL)
		doveadm_mail_help_name("force-resync");

	ctx->mailbox = p_strdup(ctx->ctx.pool, mailbox);
}

static struct doveadm_mail_cmd_context *cmd_force_resync_alloc(void)
{
	struct force_resync_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct force_resync_cmd_context);
	ctx->ctx.v.init = cmd_force_resync_init;
	ctx->ctx.v.run = cmd_force_resync_run;
	return &ctx->ctx;
}

static int
doveadm_mail_next_user(struct doveadm_mail_cmd_context *ctx,
		       const struct mail_storage_service_input *input,
		       const char **error_r)
{
	struct mail_storage_service_user *service_user;
	const char *error;
	int ret;

	i_set_failure_prefix(t_strdup_printf("doveadm(%s): ", input->username));

	/* see if we want to execute this command via (another)
	   doveadm server */
	ret = doveadm_mail_server_user(ctx, input, error_r);
	if (ret != 0)
		return ret;

	ret = mail_storage_service_lookup(ctx->storage_service, input,
					  &service_user, &error);
	if (ret <= 0) {
		if (ret < 0) {
			*error_r = t_strdup_printf("User lookup failed: %s",
						   error);
		}
		return ret;
	}

	ret = mail_storage_service_next(ctx->storage_service, service_user,
					&ctx->cur_mail_user);
	if (ret < 0) {
		*error_r = "User init failed";
		mail_storage_service_user_free(&service_user);
		return ret;
	}

	ctx->v.run(ctx, ctx->cur_mail_user);
	mail_user_unref(&ctx->cur_mail_user);
	mail_storage_service_user_free(&service_user);
	return 1;
}

void doveadm_mail_single_user(struct doveadm_mail_cmd_context *ctx, char *argv[],
			      const struct mail_storage_service_input *input,
			      enum mail_storage_service_flags service_flags)
{
	const char *error;
	int ret;

	i_assert(input->username != NULL);

	ctx->storage_service = mail_storage_service_init(master_service, NULL,
							 service_flags);
	ctx->v.init(ctx, (const void *)argv);
	if (hook_doveadm_mail_init != NULL)
		hook_doveadm_mail_init(ctx);

	ret = doveadm_mail_next_user(ctx, input, &error);
	if (ret < 0)
		i_fatal("%s", error);
	else if (ret == 0)
		i_fatal("User doesn't exist");
}

static void sig_die(const siginfo_t *si, void *context ATTR_UNUSED)
{
	killed_signo = si->si_signo;
}

static void
doveadm_mail_all_users(struct doveadm_mail_cmd_context *ctx, char *argv[],
		       const char *wildcard_user,
		       enum mail_storage_service_flags service_flags)
{
	struct mail_storage_service_input input;
	unsigned int user_idx, user_count, interval, n;
	const char *user, *error;
	int ret;

	service_flags |= MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP;

	memset(&input, 0, sizeof(input));
	input.service = "doveadm";

	ctx->storage_service = mail_storage_service_init(master_service, NULL,
							 service_flags);
        lib_signals_set_handler(SIGINT, 0, sig_die, NULL);
	lib_signals_set_handler(SIGTERM, 0, sig_die, NULL);

	ctx->v.init(ctx, (const void *)argv);
	if (hook_doveadm_mail_init != NULL)
		hook_doveadm_mail_init(ctx);

	user_count = mail_storage_service_all_init(ctx->storage_service);
	n = user_count / 10000;
	for (interval = 10; n > 0 && interval < 1000; interval *= 10)
		n /= 10;

	user_idx = 0;
	while ((ret = ctx->v.get_next_user(ctx, &user)) > 0) {
		if (wildcard_user != NULL) {
			if (!wildcard_match_icase(user, wildcard_user))
				continue;
		}
		input.username = user;
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
			if (++user_idx % interval == 0) {
				printf("\r%d / %d", user_idx, user_count);
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
	if (ret < 0)
		i_error("Failed to iterate through some users");
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
	enum mail_storage_service_flags service_flags =
		MAIL_STORAGE_SERVICE_FLAG_NO_LOG_INIT;
	struct doveadm_mail_cmd_context *ctx;
	const char *getopt_args, *username, *wildcard_user;
	int c;

	if (doveadm_debug)
		service_flags |= MAIL_STORAGE_SERVICE_FLAG_DEBUG;

	ctx = doveadm_mail_cmd_init(cmd, doveadm_settings);

	getopt_args = t_strconcat("AS:u:", ctx->getopt_args, NULL);
	username = getenv("USER");
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
			service_flags |=
				MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP;
			username = optarg;
			if (strchr(username, '*') != NULL ||
			    strchr(username, '?') != NULL)
				wildcard_user = username;
			break;
		default:
			if (ctx->v.parse_arg == NULL ||
			    !ctx->v.parse_arg(ctx, c))
				doveadm_mail_help(cmd);
		}
	}
	argv += optind;
	if (argv[0] != NULL && cmd->usage_args == NULL) {
		i_fatal("doveadm %s: Unknown parameter: %s",
			cmd->name, argv[0]);
	}
	ctx->args = (const void *)argv;

	ctx->iterate_single_user =
		!ctx->iterate_all_users && wildcard_user == NULL;
	if (doveadm_print_is_initialized() && !ctx->iterate_single_user) {
		doveadm_print_header("username", "Username",
				     DOVEADM_PRINT_HEADER_FLAG_STICKY |
				     DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);
	}

	if (ctx->iterate_single_user) {
		struct mail_storage_service_input input;

		if (username == NULL)
			i_fatal("USER environment is missing and -u option not used");

		memset(&input, 0, sizeof(input));
		input.service = "doveadm";
		input.username = username;
		doveadm_mail_single_user(ctx, argv, &input, service_flags);
	} else {
		service_flags |= MAIL_STORAGE_SERVICE_FLAG_TEMP_PRIV_DROP;
		doveadm_mail_all_users(ctx, argv, wildcard_user, service_flags);
	}
	if (ctx->search_args != NULL)
		mail_search_args_unref(&ctx->search_args);
	doveadm_mail_server_flush();
	ctx->v.deinit(ctx);
	doveadm_print_flush();

	/* service deinit unloads mail plugins, so do it late */
	mail_storage_service_deinit(&ctx->storage_service);

	if (ctx->failed)
		exit(FATAL_DEFAULT);
	pool_unref(&ctx->pool);
}

static bool
doveadm_mail_try_run_multi_word(const struct doveadm_mail_cmd *cmd,
				const char *cmdname, int argc, char *argv[])
{
	unsigned int len;

	if (argc < 2)
		return FALSE;

	len = strlen(argv[1]);
	if (strncmp(cmdname, argv[1], len) != 0)
		return FALSE;

	if (cmdname[len] == ' ') {
		/* more args */
		return doveadm_mail_try_run_multi_word(cmd, cmdname + len + 1,
						       argc - 1, argv + 1);
	}
	if (cmdname[len] != '\0')
		return FALSE;

	/* match */
	doveadm_mail_cmd(cmd, argc - 1, argv + 1);
	return TRUE;
}

bool doveadm_mail_try_run(const char *cmd_name, int argc, char *argv[])
{
	const struct doveadm_mail_cmd *cmd;
	unsigned int cmd_name_len;

	i_assert(argc > 0);

	cmd_name_len = strlen(cmd_name);
	array_foreach(&doveadm_mail_cmds, cmd) {
		if (strcmp(cmd->name, cmd_name) == 0) {
			doveadm_mail_cmd(cmd, argc, argv);
			return TRUE;
		}

		/* see if it matches a multi-word command */
		if (strncmp(cmd->name, cmd_name, cmd_name_len) == 0 &&
		    cmd->name[cmd_name_len] == ' ') {
			const char *subcmd = cmd->name + cmd_name_len + 1;

			if (doveadm_mail_try_run_multi_word(cmd, subcmd,
							    argc, argv))
				return TRUE;
		}
	}

	return FALSE;
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
	exit(1);
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
	cmd_force_resync_alloc, "force-resync", "<mailbox>"
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
	&cmd_import,
	&cmd_index,
	&cmd_altmove,
	&cmd_move,
	&cmd_mailbox_list,
	&cmd_mailbox_create,
	&cmd_mailbox_delete,
	&cmd_mailbox_rename,
	&cmd_mailbox_subscribe,
	&cmd_mailbox_unsubscribe,
	&cmd_mailbox_status
};

void doveadm_mail_init(void)
{
	struct module_dir_load_settings mod_set;
	unsigned int i;

	i_array_init(&doveadm_mail_cmds, 32);
	for (i = 0; i < N_ELEMENTS(mail_commands); i++)
		doveadm_mail_register_cmd(mail_commands[i]);

	memset(&mod_set, 0, sizeof(mod_set));
	mod_set.version = master_service_get_version_string(master_service);
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
