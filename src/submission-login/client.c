/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "login-common.h"
#include "base64.h"
#include "buffer.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "randgen.h"
#include "hostpid.h"
#include "safe-memset.h"
#include "str.h"
#include "strescape.h"
#include "master-service.h"
#include "master-service-ssl-settings.h"
#include "client.h"
#include "client-authenticate.h"
#include "auth-client.h"
#include "submission-proxy.h"
#include "submission-login-settings.h"

/* Disconnect client when it sends too many bad commands */
#define CLIENT_MAX_BAD_COMMANDS 10

static const struct smtp_server_callbacks smtp_callbacks;

static struct smtp_server *smtp_server = NULL;

static void
client_parse_backend_capabilities(struct submission_client *subm_client )
{
	const struct submission_login_settings *set = subm_client->set;
	const char *const *str;

	if (set->submission_backend_capabilities == NULL) {
		subm_client->backend_capabilities = SMTP_CAPABILITY_8BITMIME;
		return;
	}

	subm_client->backend_capabilities = SMTP_CAPABILITY_NONE;
	str = t_strsplit_spaces(set->submission_backend_capabilities, " ,");
	for (; *str != NULL; str++) {
		enum smtp_capability cap = smtp_capability_find_by_name(*str);

		if (cap == SMTP_CAPABILITY_NONE) {
			i_warning("Unknown SMTP capability in submission_backend_capabilities: "
				  "%s", *str);
			continue;
		}

		subm_client->backend_capabilities |= cap;
	}

	/* Make sure CHUNKING support is always enabled when BINARYMIME is
	   enabled by explicit configuration. */
	if (HAS_ALL_BITS(subm_client->backend_capabilities,
			 SMTP_CAPABILITY_BINARYMIME)) {
		subm_client->backend_capabilities |= SMTP_CAPABILITY_CHUNKING;
	}
}

static int submission_login_start_tls(void *conn_ctx,
	struct istream **input, struct ostream **output)
{
	struct submission_client *subm_client = conn_ctx;
	struct client *client = &subm_client->common;

	client->starttls = TRUE;
	if (client_init_ssl(client) < 0) {
		client_notify_disconnect(client,
			CLIENT_DISCONNECT_INTERNAL_ERROR,
			"TLS initialization failed.");
		client_destroy(client,
			"Disconnected: TLS initialization failed.");
		return -1;
	}
	login_refresh_proctitle();

	*input = client->input;
	*output = client->output;
	return 0;
}

static struct client *submission_client_alloc(pool_t pool)
{
	struct submission_client *subm_client;

	subm_client = p_new(pool, struct submission_client, 1);
	return &subm_client->common;
}

static void submission_client_create(struct client *client,
				     void **other_sets)
{
	static const char *const xclient_extensions[] =
		{ "SESSION", "FORWARD", NULL };
	struct submission_client *subm_client =
		container_of(client, struct submission_client, common);
	struct smtp_server_settings smtp_set;

	subm_client->set = other_sets[0];
	client_parse_backend_capabilities(subm_client);

	i_zero(&smtp_set);
	smtp_set.capabilities = SMTP_CAPABILITY_SIZE |
		SMTP_CAPABILITY_ENHANCEDSTATUSCODES | SMTP_CAPABILITY_AUTH |
		SMTP_CAPABILITY_XCLIENT;
	if (client_is_tls_enabled(client))
		smtp_set.capabilities |= SMTP_CAPABILITY_STARTTLS;
	smtp_set.hostname = subm_client->set->hostname;
	smtp_set.login_greeting = client->set->login_greeting;
	smtp_set.tls_required = !client->secured &&
		(strcmp(client->ssl_set->ssl, "required") == 0);
	smtp_set.xclient_extensions = xclient_extensions;
	smtp_set.debug = client->set->auth_debug;

	subm_client->conn = smtp_server_connection_create_from_streams(
		smtp_server, client->input, client->output,
		&client->real_remote_ip, client->real_remote_port,
		&smtp_set, &smtp_callbacks, subm_client);
}

static void submission_client_destroy(struct client *client)
{
	struct submission_client *subm_client =
		container_of(client, struct submission_client, common);

	if (subm_client->conn != NULL)
		smtp_server_connection_close(&subm_client->conn, NULL);
	i_free_and_null(subm_client->proxy_xclient);
}

static void submission_client_notify_auth_ready(struct client *client)
{
	struct submission_client *subm_client =
		container_of(client, struct submission_client, common);

	smtp_server_connection_start(subm_client->conn);
}

static void
submission_client_notify_disconnect(struct client *_client,
				    enum client_disconnect_reason reason,
				    const char *text)
{
	struct submission_client *client =
		container_of(_client, struct submission_client, common);
	struct smtp_server_connection *conn;

	conn = client->conn;
	client->conn = NULL;
	if (conn != NULL) {
		switch (reason) {
		case CLIENT_DISCONNECT_TIMEOUT:
			smtp_server_connection_terminate(&conn, "4.4.2", text);
			break;
		case CLIENT_DISCONNECT_SYSTEM_SHUTDOWN:
			smtp_server_connection_terminate(&conn, "4.3.2", text);
			break;
		case CLIENT_DISCONNECT_INTERNAL_ERROR:
		default:
			smtp_server_connection_terminate(&conn, "4.0.0", text);
			break;
		}
	}
}

static void
client_connection_cmd_xclient(void *context,
			      struct smtp_server_cmd_ctx *cmd,
			      struct smtp_proxy_data *data)
{
	unsigned int i;

	struct submission_client *client = context;

	if (data->source_ip.family != 0)
		client->common.ip = data->source_ip;
	if (data->source_port != 0)
		client->common.remote_port = data->source_port;
	if (data->ttl_plus_1 > 0)
		client->common.proxy_ttl = data->ttl_plus_1 - 1;

	for (i = 0; i < data->extra_fields_count; i++) {
		const char *name = data->extra_fields[i].name;
		const char *value = data->extra_fields[i].value;

		if (strcasecmp(name, "FORWARD") == 0) {
			size_t value_len = strlen(value);
			if (client->common.forward_fields != NULL) {
				str_truncate(client->common.forward_fields, 0);
			} else {
				client->common.forward_fields =	str_new(
					client->common.preproxy_pool,
					MAX_BASE64_DECODED_SIZE(value_len));
				if (base64_decode(value, value_len, NULL,
					  client->common.forward_fields) < 0) {
					smtp_server_reply(cmd, 501, "5.5.4",
						"Invalid FORWARD parameter");
				}
			}
		} else if (strcasecmp(name, "SESSION") == 0) {
			if (client->common.session_id != NULL)
				continue;
			client->common.session_id =
				p_strdup(client->common.pool, value);
		}
	}
}

static void client_connection_disconnect(void *context, const char *reason)
{
	struct submission_client *client = context;

	client->pending_auth = NULL;
	client_disconnect(&client->common, reason);
}

static void client_connection_destroy(void *context)
{
	struct submission_client *client = context;

	if (client->conn == NULL)
		return;
	client->conn = NULL;
	client_destroy(&client->common, NULL);
}

static bool client_connection_is_trusted(void *context)
{
	struct submission_client *client = context;

	return client->common.trusted;
}

static void submission_login_die(void)
{
	/* do nothing. submission connections typically die pretty quick anyway.
	 */
}

static void submission_login_preinit(void)
{
	login_set_roots = submission_login_setting_roots;
}

static void submission_login_init(void)
{
	struct smtp_server_settings smtp_server_set;

	/* override the default login_die() */
	master_service_set_die_callback(master_service, submission_login_die);

	/* initialize SMTP server */
	i_zero(&smtp_server_set);
	smtp_server_set.protocol = SMTP_PROTOCOL_SMTP;
	smtp_server_set.max_pipelined_commands = 5;
	smtp_server_set.max_bad_commands = CLIENT_MAX_BAD_COMMANDS;
	smtp_server = smtp_server_init(&smtp_server_set);
}

static void submission_login_deinit(void)
{
	clients_destroy_all();

	smtp_server_deinit(&smtp_server);
}

static const struct smtp_server_callbacks smtp_callbacks = {
	.conn_cmd_helo = cmd_helo,

	.conn_start_tls = submission_login_start_tls,

	.conn_cmd_auth = cmd_auth,
	.conn_cmd_auth_continue = cmd_auth_continue,

	.conn_cmd_xclient = client_connection_cmd_xclient,

	.conn_disconnect = client_connection_disconnect,
	.conn_destroy = client_connection_destroy,

	.conn_is_trusted = client_connection_is_trusted
};

static struct client_vfuncs submission_client_vfuncs = {
	.alloc = submission_client_alloc,
	.create = submission_client_create,
	.destroy = submission_client_destroy,
	.notify_auth_ready = submission_client_notify_auth_ready,
	.notify_disconnect = submission_client_notify_disconnect,
	.auth_send_challenge = submission_client_auth_send_challenge,
	.auth_result = submission_client_auth_result,
	.proxy_reset = submission_proxy_reset,
	.proxy_parse_line = submission_proxy_parse_line,
	.proxy_error = submission_proxy_error,
	.proxy_get_state = submission_proxy_get_state,
};

static struct login_binary submission_login_binary = {
	.protocol = "submission",
	.process_name = "submission-login",
	.default_port = 587,

	.client_vfuncs = &submission_client_vfuncs,
	.preinit = submission_login_preinit,
	.init = submission_login_init,
	.deinit = submission_login_deinit,

	.sasl_support_final_reply = FALSE,
	.anonymous_login_acceptable = FALSE,
};

int main(int argc, char *argv[])
{
	return login_binary_run(&submission_login_binary, argc, argv);
}
