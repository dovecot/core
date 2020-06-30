/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

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
#include "client.h"
#include "client-authenticate.h"
#include "auth-client.h"
#include "pop3-proxy.h"
#include "pop3-login-settings.h"

/* Disconnect client when it sends too many bad commands */
#define CLIENT_MAX_BAD_COMMANDS 3

static bool cmd_stls(struct pop3_client *client)
{
	client_cmd_starttls(&client->common);	
	return TRUE;
}

static bool cmd_quit(struct pop3_client *client)
{
	client_send_reply(&client->common, POP3_CMD_REPLY_OK, "Logging out");
	client_destroy(&client->common, "Aborted login");
	return TRUE;
}

static bool cmd_xclient(struct pop3_client *client, const char *args)
{
	const char *const *tmp;
	in_port_t remote_port;
	bool args_ok = TRUE;

	if (!client->common.trusted) {
		client_send_reply(&client->common, POP3_CMD_REPLY_OK,
				  "You are not from trusted IP - ignoring");
		return TRUE;
	}
	for (tmp = t_strsplit(args, " "); *tmp != NULL; tmp++) {
		if (strncasecmp(*tmp, "ADDR=", 5) == 0) {
			if (net_addr2ip(*tmp + 5, &client->common.ip) < 0)
				args_ok = FALSE;
		} else if (strncasecmp(*tmp, "PORT=", 5) == 0) {
			if (net_str2port(*tmp + 5, &remote_port) < 0)
				args_ok = FALSE;
			else
				client->common.remote_port = remote_port;
		} else if (strncasecmp(*tmp, "SESSION=", 8) == 0) {
			const char *value = *tmp + 8;

			if (strlen(value) <= LOGIN_MAX_SESSION_ID_LEN) {
				client->common.session_id =
					p_strdup(client->common.pool, value);
			}
		} else if (strncasecmp(*tmp, "TTL=", 4) == 0) {
			if (str_to_uint(*tmp + 4, &client->common.proxy_ttl) < 0)
				args_ok = FALSE;
		} else if (strncasecmp(*tmp, "FORWARD=", 8) == 0) {
			size_t value_len = strlen((*tmp)+8);
			client->common.forward_fields =
				str_new(client->common.preproxy_pool,
					MAX_BASE64_DECODED_SIZE(value_len));
			if (base64_decode((*tmp)+8, value_len, NULL,
					  client->common.forward_fields) < 0)
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
	cmd = t_str_ucase(cmd);
	if (strcmp(cmd, "CAPA") == 0)
		return cmd_capa(client, args);
	if (strcmp(cmd, "USER") == 0)
		return cmd_user(client, args);
	if (strcmp(cmd, "PASS") == 0)
		return cmd_pass(client, args);
	if (strcmp(cmd, "AUTH") == 0)
		return cmd_auth(client, args);
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
	if (i_stream_read_more(client->input, &data, &size) <= 0)
		return FALSE;
	for(i = 0; i < size; i++) {
		if (data[i] == ' ' ||
		    data[i] == '\r' ||
		    data[i] == '\n') {
			*cmd_r = t_str_ucase(t_strndup(data, i));
			i_stream_skip(client->input, i+1);
			return TRUE;
		}
	}
	return FALSE;
}

static bool pop3_client_input_next_cmd(struct client *client)
{
	struct pop3_client *pop3_client = (struct pop3_client *)client;
	const char *cmd, *args;
	bool parsed;

	if (!client_read_cmd_name(client, &cmd))
		return FALSE;
	if ((args = i_stream_next_line(client->input)) == NULL)
		return FALSE;

	if (client_command_execute(pop3_client, cmd, args))
		client->bad_counter = 0;
	else if (++client->bad_counter >= CLIENT_MAX_BAD_COMMANDS) {
		client_send_reply(client, POP3_CMD_REPLY_ERROR,
				  "Too many invalid bad commands.");
		client_destroy(client,
			       "Disconnected: Too many bad commands");
		return FALSE;
	}
	return TRUE;
}

static struct client *pop3_client_alloc(pool_t pool)
{
	struct pop3_client *pop3_client;

	pop3_client = p_new(pool, struct pop3_client, 1);
	return &pop3_client->common;
}

static void pop3_client_create(struct client *client ATTR_UNUSED,
			       void **other_sets ATTR_UNUSED)
{
}

static void pop3_client_destroy(struct client *client)
{
	struct pop3_client *pop3_client = (struct pop3_client *)client;

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

	client->io = io_add_istream(client->input, client_input, client);

	str = t_str_new(128);
	if (client->trusted) {
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
	login_set_roots = pop3_login_setting_roots;
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
	.proxy_error = pop3_proxy_error,
	.proxy_get_state = pop3_proxy_get_state,
	.send_raw_data = client_common_send_raw_data,
	.input_next_cmd  = pop3_client_input_next_cmd,
	.free = client_common_default_free,
};

static struct login_binary pop3_login_binary = {
	.protocol = "pop3",
	.process_name = "pop3-login",
	.default_port = 110,
	.default_ssl_port = 995,

	.event_category = {
		.name = "pop3",
	},

	.client_vfuncs = &pop3_client_vfuncs,
	.preinit = pop3_login_preinit,
	.init = pop3_login_init,
	.deinit = pop3_login_deinit,

	.sasl_support_final_reply = FALSE,
	.anonymous_login_acceptable = TRUE,
};

int main(int argc, char *argv[])
{
	return login_binary_run(&pop3_login_binary, argc, argv);
}
