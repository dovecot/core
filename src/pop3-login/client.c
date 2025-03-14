/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "login-common.h"
#include "base64.h"
#include "buffer.h"
#include "connection.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "randgen.h"
#include "hostpid.h"
#include "str.h"
#include "master-service.h"
#include "pop3-protocol.h"
#include "client.h"
#include "client-authenticate.h"
#include "auth-client.h"
#include "pop3-proxy.h"

#include <ctype.h>

/* Disconnect client when it sends too many bad commands */
#define CLIENT_MAX_BAD_COMMANDS 3
#define CLIENT_MAX_CMD_LEN 8

static bool cmd_stls(struct pop3_client *client)
{
	client_cmd_starttls(&client->common);
	return TRUE;
}

static bool cmd_quit(struct pop3_client *client)
{
	client_send_reply(&client->common, POP3_CMD_REPLY_OK, "Logging out");
	client_destroy(&client->common, CLIENT_UNAUTHENTICATED_LOGOUT_MSG);
	return TRUE;
}

static bool cmd_xclient(struct pop3_client *client, const char *args)
{
	const char *const *tmp, *value;
	in_port_t remote_port;
	bool args_ok = TRUE;

	if (!client->common.connection_trusted) {
		client_send_reply(&client->common, POP3_CMD_REPLY_OK,
				  "You are not from trusted IP - ignoring");
		return TRUE;
	}
	for (tmp = t_strsplit(args, " "); *tmp != NULL; tmp++) {
		if (str_begins_icase(*tmp, "ADDR=", &value)) {
			if (net_addr2ip(value, &client->common.ip) < 0)
				args_ok = FALSE;
		} else if (str_begins_icase(*tmp, "PORT=", &value)) {
			if (net_str2port(value, &remote_port) < 0)
				args_ok = FALSE;
			else
				client->common.remote_port = remote_port;
		} else if (str_begins_icase(*tmp, "SESSION=", &value)) {
			if (strlen(value) <= LOGIN_MAX_SESSION_ID_LEN) {
				client->common.session_id =
					p_strdup(client->common.pool, value);
			}
		} else if (str_begins_icase(*tmp, "TTL=", &value)) {
			if (str_to_uint(value, &client->common.proxy_ttl) < 0)
				args_ok = FALSE;
		} else if (str_begins_icase(*tmp, "CLIENT-TRANSPORT=", &value)) {
			client->common.end_client_tls_secured_set = TRUE;
			client->common.end_client_tls_secured =
				str_begins_with(value, CLIENT_TRANSPORT_TLS);
		} else if (str_begins_icase(*tmp, "DESTNAME=", &value)) {
			if (!connection_is_valid_dns_name(value))
				args_ok = FALSE;
			else {
				client->common.local_name =
					p_strdup(client->common.preproxy_pool, value);
			}
		} else if (str_begins_icase(*tmp, "FORWARD=", &value)) {
			if (!client_forward_decode_base64(&client->common, value))
				args_ok = FALSE;
		}
	}
	if (!args_ok) {
		client_send_reply(&client->common, POP3_CMD_REPLY_ERROR,
				  "Invalid parameters");
		return TRUE;
	}

	/* args ok, set them and reset the state */
	client_send_reply(&client->common, POP3_CMD_REPLY_OK, "Updated");
	return TRUE;
}

static bool client_command_execute(struct pop3_client *client, const char *cmd,
				   const char *args)
{
	if (strcmp(cmd, "CAPA") == 0)
		return cmd_capa(client, args);
	if (strcmp(cmd, "USER") == 0)
		return cmd_user(client, args);
	if (strcmp(cmd, "PASS") == 0)
		return cmd_pass(client, args);
	if (strcmp(cmd, "APOP") == 0)
		return cmd_apop(client, args);
	if (strcmp(cmd, "STLS") == 0)
		return cmd_stls(client);
	if (strcmp(cmd, "QUIT") == 0)
		return cmd_quit(client);
	if (strcmp(cmd, "XCLIENT") == 0)
		return cmd_xclient(client, args);
	if (strcmp(cmd, "XOIP") == 0) {
		/* Compatibility with Zimbra's patched nginx */
		return cmd_xclient(client, t_strconcat("ADDR=", args, NULL));
	}

	client_send_reply(&client->common, POP3_CMD_REPLY_ERROR,
			  "Unknown command.");
	return FALSE;
}

static void pop3_client_input(struct client *client)
{
	i_assert(!client->authenticating);

	if (!client_read(client))
		return;

	client_ref(client);

	o_stream_cork(client->output);
	/* if a command starts an authentication, stop processing further
	   commands until the authentication is finished. */
	while (!client->output->closed && !client->authenticating &&
	       auth_client_is_connected(auth_client)) {
		if (!client->v.input_next_cmd(client))
			break;
	}

	if (auth_client != NULL && !auth_client_is_connected(auth_client))
		client->input_blocked = TRUE;

	o_stream_uncork(client->output);
	client_unref(&client);
}

static bool client_read_cmd_name(struct client *client, const char **cmd_r)
{
	const unsigned char *data;
	size_t size, i;
	string_t *cmd = t_str_new(CLIENT_MAX_CMD_LEN);
	if (i_stream_read_more(client->input, &data, &size) <= 0)
		return FALSE;
	for(i = 0; i < size; i++) {
		if (data[i] == '\r') continue;
		if (data[i] == ' ' ||
		    data[i] == '\n' ||
		    data[i] == '\0' ||
		    i >= CLIENT_MAX_CMD_LEN) {
			*cmd_r = str_c(cmd);
			/* only skip ws */
			i_stream_skip(client->input, i + (data[i] == ' ' ? 1 : 0));
			return TRUE;
		}
		str_append_c(cmd, i_toupper(data[i]));
	}
	return FALSE;
}

static bool pop3_client_input_next_cmd(struct client *client)
{
	struct pop3_client *pop3_client = (struct pop3_client *)client;
	const char *cmd, *args;

	if (pop3_client->current_cmd == NULL) {
		if (!client_read_cmd_name(client, &cmd))
			return FALSE;
		pop3_client->current_cmd = i_strdup(cmd);
	}

	if (strcmp(pop3_client->current_cmd, "AUTH") == 0) {
		if (cmd_auth(pop3_client) <= 0) {
			/* Need more input / destroyed. We also get here when
			   SASL authentication is actually started. */
			return FALSE;
		}
		/* AUTH command finished already (SASL probe or ERR reply) */
		i_free(pop3_client->current_cmd);
		return TRUE;
	}

	if ((args = i_stream_next_line(client->input)) == NULL)
		return FALSE;

	if (client_command_execute(pop3_client, pop3_client->current_cmd, args))
		client->bad_counter = 0;
	else if (++client->bad_counter >= CLIENT_MAX_BAD_COMMANDS) {
		client_send_reply(client, POP3_CMD_REPLY_ERROR,
				  "Too many invalid bad commands.");
		client_destroy(client,
			       "Disconnected: Too many bad commands");
		return FALSE;
	}
	i_free(pop3_client->current_cmd);
	return TRUE;
}

static struct client *pop3_client_alloc(pool_t pool)
{
	struct pop3_client *pop3_client;

	pop3_client = p_new(pool, struct pop3_client, 1);
	return &pop3_client->common;
}

static int pop3_client_create(struct client *client ATTR_UNUSED)
{
	return 0;
}

static void pop3_client_destroy(struct client *client)
{
	struct pop3_client *pop3_client = (struct pop3_client *)client;

	i_free_and_null(pop3_client->current_cmd);
	i_free_and_null(pop3_client->last_user);
	i_free_and_null(pop3_client->apop_challenge);
}

static char *get_apop_challenge(struct pop3_client *client)
{
	unsigned char buffer[16];
	unsigned char buffer_base64[MAX_BASE64_ENCODED_SIZE(sizeof(buffer)) + 1];
	buffer_t buf;

	if (sasl_server_find_available_mech(&client->common, "APOP") == NULL) {
		/* disabled, no need to present the challenge */
		return NULL;
	}

	auth_client_get_connect_id(auth_client, &client->apop_server_pid,
				   &client->apop_connect_uid);

	random_fill(buffer, sizeof(buffer));
	buffer_create_from_data(&buf, buffer_base64, sizeof(buffer_base64));
	base64_encode(buffer, sizeof(buffer), &buf);
	buffer_append_c(&buf, '\0');

	return i_strdup_printf("<%x.%x.%lx.%s@%s>",
			       client->apop_server_pid,
			       client->apop_connect_uid,
			       (unsigned long)ioloop_time,
			       (const char *)buf.data, my_hostname);
}

static void pop3_client_notify_auth_ready(struct client *client)
{
	struct pop3_client *pop3_client = (struct pop3_client *)client;
	string_t *str;

	i_assert(client->io == NULL);
	client->io = io_add_istream(client->input, client_input, client);

	str = t_str_new(128);
	if (client->connection_trusted) {
		/* Dovecot extension to avoid extra roundtrip for CAPA */
		str_append(str, "[XCLIENT] ");
	}
	str_append(str, client->set->login_greeting);

	pop3_client->apop_challenge = get_apop_challenge(pop3_client);
	if (pop3_client->apop_challenge != NULL)
		str_printfa(str, " %s", pop3_client->apop_challenge);
	client_send_reply(client, POP3_CMD_REPLY_OK, str_c(str));

	client->banner_sent = TRUE;
}

static void
pop3_client_notify_starttls(struct client *client,
			    bool success, const char *text)
{
	if (success)
		client_send_reply(client, POP3_CMD_REPLY_OK, text);
	else
		client_send_reply(client, POP3_CMD_REPLY_ERROR, text);
}

static void pop3_client_starttls(struct client *client ATTR_UNUSED)
{
}

void client_send_reply(struct client *client, enum pop3_cmd_reply reply,
		       const char *text)
{
	const char *prefix = "-ERR";

	switch (reply) {
	case POP3_CMD_REPLY_OK:
		prefix = "+OK";
		break;
	case POP3_CMD_REPLY_TEMPFAIL:
		prefix = "-ERR [SYS/TEMP]";
		break;
	case POP3_CMD_REPLY_AUTH_ERROR:
		if (text[0] == '[')
			prefix = "-ERR";
		else
			prefix = "-ERR [AUTH]";
		break;
	case POP3_CMD_REPLY_ERROR:
		break;
	}

	T_BEGIN {
		string_t *line = t_str_new(256);

		str_append(line, prefix);
		str_append_c(line, ' ');
		str_append(line, text);
		str_append(line, "\r\n");

		client_send_raw_data(client, str_data(line), str_len(line));
	} T_END;
}

static void
pop3_client_notify_disconnect(struct client *client,
			      enum client_disconnect_reason reason,
			      const char *text)
{
	if (reason == CLIENT_DISCONNECT_INTERNAL_ERROR)
		client_send_reply(client, POP3_CMD_REPLY_TEMPFAIL, text);
	else
		client_send_reply(client, POP3_CMD_REPLY_ERROR, text);
}

static void pop3_login_die(void)
{
	/* do nothing. pop3 connections typically die pretty quick anyway. */
}

static void pop3_login_preinit(void)
{
}

static void pop3_login_init(void)
{
	/* override the default login_die() */
	master_service_set_die_callback(master_service, pop3_login_die);
}

static void pop3_login_deinit(void)
{
	clients_destroy_all();
}

static struct client_vfuncs pop3_client_vfuncs = {
	.alloc = pop3_client_alloc,
	.create = pop3_client_create,
	.destroy = pop3_client_destroy,
	.notify_auth_ready = pop3_client_notify_auth_ready,
	.notify_disconnect = pop3_client_notify_disconnect,
	.notify_starttls = pop3_client_notify_starttls,
	.starttls = pop3_client_starttls,
	.input = pop3_client_input,
	.auth_result = pop3_client_auth_result,
	.proxy_reset = pop3_proxy_reset,
	.proxy_parse_line = pop3_proxy_parse_line,
	.proxy_failed = pop3_proxy_failed,
	.proxy_get_state = pop3_proxy_get_state,
	.send_raw_data = client_common_send_raw_data,
	.input_next_cmd  = pop3_client_input_next_cmd,
	.free = client_common_default_free,
};

static struct login_binary pop3_login_binary = {
	.protocol = "pop3",
	.process_name = "pop3-login",
	.default_port = POP3_DEFAULT_PORT,
	.default_ssl_port = POP3S_DEFAULT_PORT,

	.event_category = {
		.name = "pop3",
	},

	.client_vfuncs = &pop3_client_vfuncs,
	.preinit = pop3_login_preinit,
	.init = pop3_login_init,
	.deinit = pop3_login_deinit,

	.sasl_support_final_reply = FALSE,
	.anonymous_login_acceptable = TRUE,

	.application_protocols = (const char* const[]) {
		"pop3", NULL
	},
};

int main(int argc, char *argv[])
{
	return login_binary_run(&pop3_login_binary, argc, argv);
}
