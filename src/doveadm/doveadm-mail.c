/* Copyright (c) 2009-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "lib-signals.h"
#include "ioloop.h"
#include "module-dir.h"
#include "master-service.h"
#include "mail-user.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mail-storage-settings.h"
#include "mail-storage-service.h"
#include "doveadm.h"
#include "doveadm-settings.h"
#include "doveadm-mail.h"

#include <stdio.h>
#include <stdlib.h>

ARRAY_TYPE(doveadm_mail_cmd) doveadm_mail_cmds;

static int killed_signo = 0;

static void cmd_purge(struct mail_user *user, const char *args[] ATTR_UNUSED)
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

static struct mailbox *
mailbox_find_and_open(struct mail_user *user, const char *mailbox)
{
	struct mail_namespace *ns;
	struct mailbox *box;
	const char *orig_mailbox = mailbox;

	ns = mail_namespace_find(user->namespaces, &mailbox);
	if (ns == NULL)
		i_fatal("Can't find namespace for mailbox %s", mailbox);

	box = mailbox_alloc(ns->list, mailbox, MAILBOX_FLAG_KEEP_RECENT |
			    MAILBOX_FLAG_IGNORE_ACLS);
	if (mailbox_open(box) < 0) {
		i_fatal("Opening mailbox %s failed: %s", orig_mailbox,
			mail_storage_get_last_error(mailbox_get_storage(box),
						    NULL));
	}
	return box;
}

static void cmd_force_resync(struct mail_user *user, const char *args[])
{
	const char *mailbox = args[0];
	struct mail_storage *storage;
	struct mailbox *box;

	if (mailbox == NULL)
		doveadm_mail_help_name("force-resync");

	box = mailbox_find_and_open(user, mailbox);
	storage = mailbox_get_storage(box);
	if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FORCE_RESYNC |
			 MAILBOX_SYNC_FLAG_FIX_INCONSISTENT) < 0) {
		i_fatal("Forcing a resync on mailbox %s failed: %s", mailbox,
			mail_storage_get_last_error(storage, NULL));
	}
	mailbox_free(&box);
}

static int
doveadm_mail_next_user(doveadm_mail_command_t *cmd,
		       struct mail_storage_service_ctx *storage_service,
		       const struct mail_storage_service_input *input,
		       const char *args[], const char **error_r)
{
	struct mail_storage_service_user *service_user;
	struct mail_user *mail_user;
	const char *error;
	int ret;

	i_set_failure_prefix(t_strdup_printf("doveadm(%s): ", input->username));
	ret = mail_storage_service_lookup(storage_service, input,
					  &service_user, &error);
	if (ret <= 0) {
		if (ret < 0) {
			*error_r = t_strdup_printf("User lookup failed: %s",
						   error);
		}
		return ret;
	}

	if (mail_storage_service_next(storage_service, service_user,
				      &mail_user, &error) < 0) {
		*error_r = t_strdup_printf("User init failed: %s", error);
		mail_storage_service_user_free(&service_user);
		return -1;
	}

	cmd(mail_user, args);
	mail_storage_service_user_free(&service_user);
	mail_user_unref(&mail_user);
	return 1;
}

static void
doveadm_mail_single_user(doveadm_mail_command_t *cmd, const char *username,
			 enum mail_storage_service_flags service_flags,
			 const char *args[])
{
	struct mail_storage_service_ctx *storage_service;
	struct mail_storage_service_input input;
	const char *error;
	int ret;

	if (username == NULL)
		i_fatal("USER environment is missing and -u option not used");

	memset(&input, 0, sizeof(input));
	input.username = username;

	storage_service = mail_storage_service_init(master_service, NULL,
						    service_flags);
	ret = doveadm_mail_next_user(cmd, storage_service, &input,
				     args, &error);
	if (ret < 0)
		i_fatal("%s", error);
	else if (ret == 0)
		i_fatal("User no longer exists");
	mail_storage_service_deinit(&storage_service);
}

static void sig_die(const siginfo_t *si, void *context ATTR_UNUSED)
{
	killed_signo = si->si_signo;
}

static void
doveadm_mail_all_users(doveadm_mail_command_t *cmd,
		       enum mail_storage_service_flags service_flags,
		       const char *args[])
{
	struct mail_storage_service_input input;
	struct mail_storage_service_ctx *storage_service;
	unsigned int user_idx, user_count, interval, n;
	const char *user, *error;
	int ret;

	service_flags |= MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP;

	memset(&input, 0, sizeof(input));
	input.service = "doveadm";

	storage_service = mail_storage_service_init(master_service, NULL,
						    service_flags);

        lib_signals_set_handler(SIGINT, FALSE, sig_die, NULL);
	lib_signals_set_handler(SIGTERM, FALSE, sig_die, NULL);

	user_count = mail_storage_service_all_init(storage_service);
	n = user_count / 10000;
	for (interval = 10; n > 0 && interval < 1000; interval *= 10)
		n /= 10;
	
	user_idx = 0;
	while ((ret = mail_storage_service_all_next(storage_service,
						    &user)) > 0) {
		input.username = user;
		T_BEGIN {
			ret = doveadm_mail_next_user(cmd, storage_service,
						     &input, args, &error);
			if (ret < 0)
				i_error("%s", error);
			else if (ret == 0)
				i_info("User no longer exists, skipping");
		} T_END;
		if (ret < 0)
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
	mail_storage_service_deinit(&storage_service);
}

static void
doveadm_mail_cmd(const struct doveadm_mail_cmd *cmd, int argc, char *argv[])
{
	enum mail_storage_service_flags service_flags =
		MAIL_STORAGE_SERVICE_FLAG_NO_LOG_INIT;
	const char *username;
	bool all_users = FALSE;
	int c;

	if (doveadm_debug)
		service_flags |= MAIL_STORAGE_SERVICE_FLAG_DEBUG;

	while ((c = getopt(argc, argv, "a")) > 0) {
		switch (c) {
		case 'a':
			all_users = TRUE;
			break;
		default:
			doveadm_mail_help(cmd);
		}
	}
	if (!all_users) {
		if (optind == argc)
			doveadm_mail_help(cmd);
		service_flags |= MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP;
		username = argv[optind++];
		doveadm_mail_single_user(cmd->cmd, username, service_flags,
					 (const char **)argv + optind);
	} else {
		service_flags |= MAIL_STORAGE_SERVICE_FLAG_TEMP_PRIV_DROP;
		doveadm_mail_all_users(cmd->cmd, service_flags,
				       (const char **)argv + optind);
	}
}

bool doveadm_mail_try_run(const char *cmd_name, int argc, char *argv[])
{
	const struct doveadm_mail_cmd *cmd;

	array_foreach(&doveadm_mail_cmds, cmd) {
		if (strcmp(cmd->name, cmd_name) == 0) {
			doveadm_mail_cmd(cmd, argc, argv);
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

void doveadm_mail_usage(void)
{
	const struct doveadm_mail_cmd *cmd;

	array_foreach(&doveadm_mail_cmds, cmd) {
		fprintf(stderr, USAGE_CMDNAME_FMT" <user>|-a", cmd->name);
		if (cmd->usage_args != NULL)
			fprintf(stderr, " %s", cmd->usage_args);
		fputc('\n', stderr);
	}
}

void doveadm_mail_help(const struct doveadm_mail_cmd *cmd)
{
	fprintf(stderr, "doveadm %s <user>|-a %s\n", cmd->name,
		cmd->usage_args == NULL ? "" : cmd->usage_args);
	exit(0);
}

void doveadm_mail_help_name(const char *cmd_name)
{
	const struct doveadm_mail_cmd *cmd;

	array_foreach(&doveadm_mail_cmds, cmd) {
		if (strcmp(cmd->name, cmd_name) == 0)
			doveadm_mail_help(cmd);
	}
}

static struct doveadm_mail_cmd mail_commands[] = {
	{ cmd_purge, "purge", NULL },
	{ cmd_force_resync, "force-resync", "<mailbox>" }
};

void doveadm_mail_init(void)
{
	struct module_dir_load_settings mod_set;
	unsigned int i;

	i_array_init(&doveadm_mail_cmds, 32);
	for (i = 0; i < N_ELEMENTS(mail_commands); i++)
		doveadm_mail_register_cmd(&mail_commands[i]);

	memset(&mod_set, 0, sizeof(mod_set));
	mod_set.version = master_service_get_version_string(master_service);
	mod_set.require_init_funcs = TRUE;
	mod_set.debug = doveadm_debug;

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
