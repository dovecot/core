/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ostream.h"
#include "connection.h"
#include "restrict-access.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mail-storage-settings.h"
#include "mail-storage-service.h"
#include "quota-private.h"
#include "quota-plugin.h"

enum quota_protocol {
	QUOTA_PROTOCOL_UNKNOWN = 0,
	QUOTA_PROTOCOL_POSTFIX
};

struct quota_client {
	struct connection conn;

	char *recipient;
	uoff_t size;
};

static enum quota_protocol protocol;
static struct mail_storage_service_ctx *storage_service;
static struct connection_list *clients;
static char *nouser_reply;

static void client_connected(struct master_service_connection *conn)
{
	struct quota_client *client;

	client = i_new(struct quota_client, 1);
	connection_init_server(clients, &client->conn,
			       "(quota client)", conn->fd, conn->fd);
	master_service_client_connection_accept(conn);
}

static void client_reset(struct quota_client *client)
{
	i_free_and_null(client->recipient);
}

static int
quota_check(struct mail_user *user, uoff_t mail_size,
	    const char **error_r, bool *too_large_r)
{
	struct quota_user *quser = QUOTA_USER_CONTEXT(user);
	struct mail_namespace *ns;
	struct mailbox *box;
	struct quota_transaction_context *ctx;
	int ret;

	if (quser == NULL) {
		/* no quota for user */
		return 1;
	}

	ns = mail_namespace_find_inbox(user->namespaces);
	box = mailbox_alloc(ns->list, "INBOX", 0);

	ctx = quota_transaction_begin(box);
	ret = quota_test_alloc(ctx, I_MAX(1, mail_size), too_large_r);
	quota_transaction_rollback(&ctx);

	mailbox_free(&box);

	if (ret < 0)
		*error_r = "Internal quota calculation error";
	else if (ret == 0)
		*error_r = quser->quota->set->quota_exceeded_msg;
	return ret;
}

static void client_handle_request(struct quota_client *client)
{
	struct mail_storage_service_input input;
	struct mail_storage_service_user *service_user;
	struct mail_user *user;
	const char *value = NULL, *error;
	bool too_large;
	int ret;

	if (client->recipient == NULL) {
		o_stream_send_str(client->conn.output, "action=DUNNO\n\n");
		return;
	}

	memset(&input, 0, sizeof(input));
	input.username = client->recipient;

	ret = mail_storage_service_lookup_next(storage_service, &input,
					       &service_user, &user, &error);
	restrict_access_allow_coredumps(TRUE);
	if (ret == 0) {
		value = nouser_reply;
	} else if (ret > 0) {
		if ((ret = quota_check(user, client->size, &error, &too_large)) > 0) {
			/* under quota */
			value = mail_user_plugin_getenv(user, "quota_status_success");
			if (value == NULL)
				value = "OK";
		} else if (ret == 0) {
			if (too_large) {
				/* even over maximum quota */
				value = mail_user_plugin_getenv(user, "quota_status_toolarge");
			}
			if (value == NULL)
				value = mail_user_plugin_getenv(user, "quota_status_overquota");
			if (value == NULL)
				value = t_strdup_printf("554 5.2.2 %s", error);
		}
		value = t_strdup(value); /* user's pool is being freed */
		mail_user_unref(&user);
		mail_storage_service_user_free(&service_user);
	}
	if (ret < 0) {
		/* temporary failure */
		o_stream_send_str(client->conn.output, t_strdup_printf(
			"action=DEFER_IF_PERMIT %s\n\n", error));
	} else {
		o_stream_send_str(client->conn.output,
				  t_strdup_printf("action=%s\n\n", value));
	}
}

static int client_input_line(struct connection *conn, const char *line)
{
	struct quota_client *client = (struct quota_client *)conn;

	if (*line == '\0') {
		o_stream_cork(conn->output);
		client_handle_request(client);
		o_stream_uncork(conn->output);
		client_reset(client);
		return 1;
	}
	if (client->recipient == NULL &&
	    strncmp(line, "recipient=", 10) == 0)
		client->recipient = i_strdup(line + 10);
	else if (strncmp(line, "size=", 5) == 0) {
		if (str_to_uoff(line+5, &client->size) < 0)
			client->size = 0;
	}
	return 1;
}

static void client_destroy(struct connection *conn)
{
	struct quota_client *client = (struct quota_client *)conn;

	connection_deinit(&client->conn);
	client_reset(client);
	i_free(client);

	master_service_client_connection_destroyed(master_service);
}

static struct connection_settings client_set = {
	.input_max_size = (size_t)-1,
	.output_max_size = (size_t)-1,
	.client = FALSE
};

static const struct connection_vfuncs client_vfuncs = {
	.destroy = client_destroy,
	.input_line = client_input_line
};

static void main_preinit(void)
{
	restrict_access_by_env(NULL, FALSE);
	restrict_access_allow_coredumps(TRUE);
}

static void main_init(void)
{
	struct mail_storage_service_input input;
	const struct setting_parser_info *user_info;
	const struct setting_parser_context *set_parser;
	const struct mail_user_settings *user_set;
	const char *value, *error;
	pool_t pool;

	clients = connection_list_init(&client_set, &client_vfuncs);
	storage_service = mail_storage_service_init(master_service, NULL,
		MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP |
		MAIL_STORAGE_SERVICE_FLAG_TEMP_PRIV_DROP |
		MAIL_STORAGE_SERVICE_FLAG_ENABLE_CORE_DUMPS |
		MAIL_STORAGE_SERVICE_FLAG_NO_CHDIR);

	memset(&input, 0, sizeof(input));
	input.service = "quota-status";
	input.module = "mail";
	input.username = "";

	pool = pool_alloconly_create("service all settings", 4096);
	if (mail_storage_service_read_settings(storage_service, &input, pool,
					       &user_info, &set_parser,
					       &error) < 0)
		i_fatal("%s", error);
	user_set = master_service_settings_parser_get_others(master_service,
							     set_parser)[0];
	value = mail_user_set_plugin_getenv(user_set, "quota_status_nouser");
	nouser_reply = value != NULL ? i_strdup(value) :
		i_strdup("REJECT Unknown user");
	pool_unref(&pool);
}

static void main_deinit(void)
{
	i_free(nouser_reply);
	connection_list_deinit(&clients);
	mail_storage_service_deinit(&storage_service);
}

int main(int argc, char *argv[])
{
	enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_KEEP_CONFIG_OPEN;
	int c;

	protocol = QUOTA_PROTOCOL_UNKNOWN;
	master_service = master_service_init("quota-status", service_flags,
					     &argc, &argv, "p:");
	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'p':
			if (strcmp(optarg, "postfix") == 0)
				protocol = QUOTA_PROTOCOL_POSTFIX;
			else
				i_fatal("Unknown -p parameter: '%s'", optarg);
			break;
		default:
			return FATAL_DEFAULT;
		}
	}
	if (protocol == QUOTA_PROTOCOL_UNKNOWN)
		i_fatal("Missing -p parameter");

	master_service_init_log(master_service, "quota-status: ");
	main_preinit();

	main_init();
	master_service_init_finish(master_service);
	master_service_run(master_service, client_connected);
	main_deinit();
	master_service_deinit(&master_service);
	return 0;
}
