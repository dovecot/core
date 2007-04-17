/* Copyright (C) 2005 Timo Sirainen */

#include "common.h"
#include "str.h"
#include "imap-quote.h"
#include "commands.h"
#include "quota.h"
#include "quota-plugin.h"
#include "imap-quota-plugin.h"

#include <stdlib.h>

const char *imap_quota_plugin_version = PACKAGE_VERSION;

static void
quota_send(struct client_command_context *cmd, struct quota_root *root)
{
        const char *const *list;
	string_t *str;
	unsigned int i;
	uint64_t value, limit;
	int ret;

	t_push();

	str = t_str_new(128);
	str_append(str, "* QUOTA ");
	imap_quote_append_string(str, quota_root_get_name(root), FALSE);

	str_append(str, " (");
	list = quota_root_get_resources(root);
	for (i = 0; *list != NULL; list++) {
		ret = quota_get_resource(root, "", *list, &value, &limit);
		if (ret > 0) {
			if (i > 0)
				str_append_c(str, ' ');
			str_printfa(str, "%s %llu %llu", *list,
				    (unsigned long long)value,
				    (unsigned long long)limit);
			i++;
		} else if (ret < 0) {
			client_send_line(cmd->client, 
				"* BAD Internal quota calculation error");
		}
	}
	str_append_c(str, ')');
	client_send_line(cmd->client, str_c(str));

	t_pop();
}

static bool cmd_getquotaroot(struct client_command_context *cmd)
{
	struct mail_storage *storage;
	struct mailbox *box;
	struct quota_root_iter *iter;
        struct quota_root *root;
	const char *orig_mailbox, *mailbox;
	string_t *str;

	/* <mailbox> */
	if (!client_read_string_args(cmd, 1, &mailbox))
		return FALSE;

	orig_mailbox = mailbox;
	storage = client_find_storage(cmd, &mailbox);
	if (storage == NULL)
		return TRUE;

	box = mailbox_open(storage, mailbox, NULL, (MAILBOX_OPEN_READONLY |
						    MAILBOX_OPEN_FAST |
						    MAILBOX_OPEN_KEEP_RECENT));
	if (box == NULL) {
		client_send_storage_error(cmd, storage);
		return TRUE;
	}

	if (quota_set == NULL) {
		mailbox_close(&box);
		client_send_tagline(cmd, "OK No quota.");
		return TRUE;
	}

	/* send QUOTAROOT reply */
	str = t_str_new(128);
	str_append(str, "* QUOTAROOT ");
	imap_quote_append_string(str, orig_mailbox, FALSE);

	iter = quota_root_iter_init(quota_set, box);
	while ((root = quota_root_iter_next(iter)) != NULL) {
		str_append_c(str, ' ');
		imap_quote_append_string(str, quota_root_get_name(root), FALSE);
	}
	quota_root_iter_deinit(&iter);
	client_send_line(cmd->client, str_c(str));

	/* send QUOTA reply for each quotaroot */
	iter = quota_root_iter_init(quota_set, box);
	while ((root = quota_root_iter_next(iter)) != NULL)
		quota_send(cmd, root);
	quota_root_iter_deinit(&iter);
	mailbox_close(&box);

	client_send_tagline(cmd, "OK Getquotaroot completed.");
	return TRUE;
}

static bool cmd_getquota(struct client_command_context *cmd)
{
	const char *root_name;
        struct quota_root *root;

	/* <quota root> */
	if (!client_read_string_args(cmd, 1, &root_name))
		return FALSE;

	if (quota_set == NULL) {
		client_send_tagline(cmd, "OK No quota.");
		return TRUE;
	}

	root = quota_root_lookup(quota_set, root_name);
	if (root == NULL) {
		client_send_tagline(cmd, "NO Quota root doesn't exist.");
		return TRUE;
	}

	quota_send(cmd, root);
	client_send_tagline(cmd, "OK Getquota completed.");
	return TRUE;
}

static bool cmd_setquota(struct client_command_context *cmd)
{
	struct quota_root *root;
        struct imap_arg *args, *arg;
	const char *root_name, *name, *error;
	uint64_t value;

	/* <quota root> <resource limits> */
	if (!client_read_args(cmd, 2, 0, &args))
		return FALSE;

	root_name = imap_arg_string(&args[0]);
	if (args[1].type != IMAP_ARG_LIST || root_name == NULL) {
		client_send_command_error(cmd, "Invalid arguments.");
		return TRUE;
	}

	if (quota_set == NULL) {
		client_send_tagline(cmd, "OK No quota.");
		return TRUE;
	}

	root = quota_root_lookup(quota_set, root_name);
	if (root == NULL) {
		client_send_tagline(cmd, "NO Quota root doesn't exist.");
		return TRUE;
	}

        arg = IMAP_ARG_LIST(&args[1])->args;
	for (; arg->type != IMAP_ARG_EOL; arg += 2) {
		name = imap_arg_string(arg);
		if (name == NULL || arg[1].type != IMAP_ARG_ATOM ||
		    !is_numeric(IMAP_ARG_STR(&arg[1]), '\0')) {
			client_send_command_error(cmd, "Invalid arguments.");
			return TRUE;
		}

                value = strtoull(IMAP_ARG_STR_NONULL(&arg[1]), NULL, 10);
		if (quota_set_resource(root, name, value, &error) < 0) {
			client_send_command_error(cmd, error);
			return TRUE;
		}
	}

	client_send_tagline(cmd, "OK Setquota completed.");
	return TRUE;
}

void imap_quota_plugin_init(void)
{
	command_register("GETQUOTAROOT", cmd_getquotaroot);
	command_register("GETQUOTA", cmd_getquota);
	command_register("SETQUOTA", cmd_setquota);
	str_append(capability_string, " QUOTA");
}

void imap_quota_plugin_deinit(void)
{
	command_unregister("GETQUOTAROOT");
	command_unregister("GETQUOTA");
	command_unregister("SETQUOTA");
}
