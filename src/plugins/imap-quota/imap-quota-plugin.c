/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "str.h"
#include "ostream.h"
#include "imap-quote.h"
#include "mail-namespace.h"
#include "imap-commands.h"
#include "quota.h"
#include "quota-plugin.h"
#include "imap-quota-plugin.h"

#include <stdlib.h>

#define QUOTA_USER_SEPARATOR ':'

const char *imap_quota_plugin_version = DOVECOT_VERSION;

static struct module *imap_quota_module;
static void (*next_hook_client_created)(struct client **client);

static const char *
imap_quota_root_get_name(struct mail_user *user, struct mail_user *owner,
			 struct quota_root *root)
{
	const char *name;

	name = quota_root_get_name(root);
	if (user == owner || owner == NULL)
		return name;
	return t_strdup_printf("%s%c%s", owner->username,
			       QUOTA_USER_SEPARATOR, name);
}

static void
quota_reply_write(string_t *str, struct mail_user *user,
		  struct mail_user *owner, struct quota_root *root)
{
        const char *name, *const *list;
	unsigned int i;
	uint64_t value, limit;
	int ret = 0;

	str_append(str, "* QUOTA ");
	name = imap_quota_root_get_name(user, owner, root);
	imap_quote_append_string(str, name, FALSE);

	str_append(str, " (");
	list = quota_root_get_resources(root);
	for (i = 0; *list != NULL; list++) {
		ret = quota_get_resource(root, "", *list, &value, &limit);
		if (ret < 0)
			break;
		if (ret > 0) {
			if (i > 0)
				str_append_c(str, ' ');
			str_printfa(str, "%s %llu %llu", *list,
				    (unsigned long long)value,
				    (unsigned long long)limit);
			i++;
		}
	}
	str_append(str, ")\r\n");

	if (ret < 0)
		str_append(str, "* BAD Internal quota calculation error\r\n");
}

static bool cmd_getquotaroot(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct quota_user *quser = QUOTA_USER_CONTEXT(client->user);
	struct mail_namespace *ns;
	struct mailbox *box;
	struct quota_root_iter *iter;
        struct quota_root *root;
	enum mailbox_name_status status;
	const char *mailbox, *storage_name, *name;
	string_t *quotaroot_reply, *quota_reply;

	/* <mailbox> */
	if (!client_read_string_args(cmd, 1, &mailbox))
		return FALSE;

	ns = client_find_namespace(cmd, mailbox, &storage_name, &status);
	if (ns == NULL)
		return TRUE;

	if (quser == NULL) {
		client_send_tagline(cmd, "OK No quota.");
		return TRUE;
	}
	if (ns->owner != NULL && ns->owner != client->user &&
	    !client->user->admin) {
		client_send_tagline(cmd, "NO Not showing other users' quota.");
		return TRUE;
	}
	if (status == MAILBOX_NAME_INVALID) {
		client_fail_mailbox_name_status(cmd, mailbox, NULL, status);
		return TRUE;
	}

	box = mailbox_alloc(ns->list, storage_name, MAILBOX_FLAG_READONLY |
			    MAILBOX_FLAG_KEEP_RECENT);

	/* build QUOTAROOT reply and QUOTA reply for all quota roots */
	quotaroot_reply = t_str_new(128);
	quota_reply = t_str_new(256);
	str_append(quotaroot_reply, "* QUOTAROOT ");
	imap_quote_append_string(quotaroot_reply, mailbox, FALSE);

	iter = quota_root_iter_init(box);
	while ((root = quota_root_iter_next(iter)) != NULL) {
		str_append_c(quotaroot_reply, ' ');
		name = imap_quota_root_get_name(client->user, ns->owner, root);
		imap_quote_append_string(quotaroot_reply, name, FALSE);

		quota_reply_write(quota_reply, client->user, ns->owner, root);
	}
	quota_root_iter_deinit(&iter);
	mailbox_free(&box);

	/* send replies */
	if (str_len(quota_reply) == 0)
		client_send_tagline(cmd, "OK No quota.");
	else {
		client_send_line(client, str_c(quotaroot_reply));
		o_stream_send(client->output, str_data(quota_reply),
			      str_len(quota_reply));
		client_send_tagline(cmd, "OK Getquotaroot completed.");
	}
	return TRUE;
}

static bool cmd_getquota(struct client_command_context *cmd)
{
	struct mail_user *owner = cmd->client->user;
        struct quota_root *root;
	const char *root_name, *p;
	string_t *quota_reply;

	/* <quota root> */
	if (!client_read_string_args(cmd, 1, &root_name))
		return FALSE;

	root = quota_root_lookup(cmd->client->user, root_name);
	if (root == NULL && cmd->client->user->admin) {
		/* we're an admin. see if there's a quota root for another
		   user. */
		p = strchr(root_name, QUOTA_USER_SEPARATOR);
		if (p != NULL) {
			owner = mail_user_find(cmd->client->user,
					       t_strdup_until(root_name, p));
			root = owner == NULL ? NULL :
				quota_root_lookup(owner, p + 1);
		}
	}
	if (root == NULL) {
		client_send_tagline(cmd, "NO Quota root doesn't exist.");
		return TRUE;
	}

	quota_reply = t_str_new(128);
	quota_reply_write(quota_reply, cmd->client->user, owner, root);
	o_stream_send(cmd->client->output, str_data(quota_reply),
		      str_len(quota_reply));

	client_send_tagline(cmd, "OK Getquota completed.");
	return TRUE;
}

static bool cmd_setquota(struct client_command_context *cmd)
{
	struct quota_root *root;
        const struct imap_arg *args, *list_args;
	const char *root_name, *name, *value_str, *error;
	uint64_t value;

	/* <quota root> <resource limits> */
	if (!client_read_args(cmd, 2, 0, &args))
		return FALSE;

	if (!imap_arg_get_astring(&args[0], &root_name) ||
	    !imap_arg_get_list(&args[1], &list_args)) {
		client_send_command_error(cmd, "Invalid arguments.");
		return TRUE;
	}

	root = quota_root_lookup(cmd->client->user, root_name);
	if (root == NULL) {
		client_send_tagline(cmd, "NO Quota root doesn't exist.");
		return TRUE;
	}

	for (; !IMAP_ARG_IS_EOL(list_args); list_args += 2) {
		if (!imap_arg_get_atom(&list_args[0], &name) ||
		    !imap_arg_get_atom(&list_args[1], &value_str) ||
		    str_to_uint64(value_str, &value) < 0) {
			client_send_command_error(cmd, "Invalid arguments.");
			return TRUE;
		}

		if (quota_set_resource(root, name, value, &error) < 0) {
			client_send_command_error(cmd, error);
			return TRUE;
		}
	}

	client_send_tagline(cmd, "OK Setquota completed.");
	return TRUE;
}

static void imap_quota_client_created(struct client **client)
{
	if (mail_user_is_plugin_loaded((*client)->user, imap_quota_module))
		str_append((*client)->capability_string, " QUOTA");

	if (next_hook_client_created != NULL)
		next_hook_client_created(client);
}

void imap_quota_plugin_init(struct module *module)
{
	command_register("GETQUOTAROOT", cmd_getquotaroot, 0);
	command_register("GETQUOTA", cmd_getquota, 0);
	command_register("SETQUOTA", cmd_setquota, 0);

	imap_quota_module = module;
	next_hook_client_created =
		imap_client_created_hook_set(imap_quota_client_created);
}

void imap_quota_plugin_deinit(void)
{
	command_unregister("GETQUOTAROOT");
	command_unregister("GETQUOTA");
	command_unregister("SETQUOTA");

	imap_client_created_hook_set(next_hook_client_created);
}

const char *imap_quota_plugin_dependencies[] = { "quota", NULL };
const char imap_quota_plugin_binary_dependency[] = "imap";
