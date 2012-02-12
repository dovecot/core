/* Copyright (c) 2002-2012 Dovecot authors, see the included COPYING file */

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
#include "ssl-proxy.h"
#include "pop3-proxy.h"
#include "pop3-login-settings.h"

/* Disconnect client when it sends too many bad commands */
#define CLIENT_MAX_BAD_COMMANDS 10

static bool cmd_stls(struct pop3_client *client)
{
	client_cmd_starttls(&client->common);
	return TRUE;
}

static bool cmd_quit(struct pop3_client *client)
{
	client_send_line(&client->common, CLIENT_CMD_REPLY_OK, "Logging out");
	client_destroy(&client->common, "Aborted login");
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

	client_send_line(&client->common, CLIENT_CMD_REPLY_BAD,
			 "Unknown command.");
	return FALSE;
}

static void pop3_client_input(struct client *client)
{
	struct pop3_client *pop3_client = (struct pop3_client *)client;
	char *line, *args;

	i_assert(!client->authenticating);

	if (!client_read(client))
		return;

	client_ref(client);

	o_stream_cork(client->output);
	/* if a command starts an authentication, stop processing further
	   commands until the authentication is finished. */
	while (!client->output->closed && !client->authenticating &&
	       auth_client_is_connected(auth_client) &&
	       (line = i_stream_next_line(client->input)) != NULL) {
		args = strchr(line, ' ');
		if (args != NULL)
			*args++ = '\0';

		if (client_command_execute(pop3_client, line,
					   args != NULL ? args : ""))
			client->bad_counter = 0;
		else if (++client->bad_counter > CLIENT_MAX_BAD_COMMANDS) {
			client_send_line(client, CLIENT_CMD_REPLY_BYE,
				"Too many invalid bad commands.");
			client_destroy(client,
				       "Disconnected: Too many bad commands");
		}
	}

	if (auth_client != NULL && !auth_client_is_connected(auth_client))
		client->input_blocked = TRUE;

	if (client_unref(&client))
		o_stream_uncork(client->output);
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

	if (auth_client_find_mech(auth_client, "APOP") == NULL) {
		/* disabled, no need to present the challenge */
		return NULL;
	}

	auth_client_get_connect_id(auth_client, &client->apop_server_pid,
				   &client->apop_connect_uid);

	random_fill(buffer, sizeof(buffer));
	buffer_create_data(&buf, buffer_base64, sizeof(buffer_base64));
	base64_encode(buffer, sizeof(buffer), &buf);
	buffer_append_c(&buf, '\0');

	return i_strdup_printf("<%x.%x.%lx.%s@%s>",
			       client->apop_server_pid,
			       client->apop_connect_uid,
			       (unsigned long)ioloop_time,
			       (const char *)buf.data, my_hostname);
}

static void pop3_client_send_greeting(struct client *client)
{
	struct pop3_client *pop3_client = (struct pop3_client *)client;

	client->io = io_add(client->fd, IO_READ, client_input, client);

	pop3_client->apop_challenge = get_apop_challenge(pop3_client);
	if (pop3_client->apop_challenge == NULL) {
		client_send_line(client, CLIENT_CMD_REPLY_OK,
				 client->set->login_greeting);
	} else {
		client_send_line(client, CLIENT_CMD_REPLY_OK,
			t_strconcat(client->set->login_greeting, " ",
				    pop3_client->apop_challenge, NULL));
	}
	client->greeting_sent = TRUE;
}

static void pop3_client_starttls(struct client *client ATTR_UNUSED)
{
}

static void
pop3_client_send_line(struct client *client, enum client_cmd_reply reply,
		      const char *text)
{
	const char *prefix = "-ERR";

	switch (reply) {
	case CLIENT_CMD_REPLY_OK:
		prefix = "+OK";
		break;
	case CLIENT_CMD_REPLY_AUTH_FAIL_TEMP:
		prefix = "-ERR [IN-USE]";
		break;
	case CLIENT_CMD_REPLY_AUTH_FAILED:
	case CLIENT_CMD_REPLY_AUTHZ_FAILED:
	case CLIENT_CMD_REPLY_AUTH_FAIL_REASON:
	case CLIENT_CMD_REPLY_AUTH_FAIL_NOSSL:
	case CLIENT_CMD_REPLY_BAD:
	case CLIENT_CMD_REPLY_BYE:
		break;
	case CLIENT_CMD_REPLY_STATUS:
	case CLIENT_CMD_REPLY_STATUS_BAD:
		/* can't send status notifications */
		return;
	}

	T_BEGIN {
		string_t *line = t_str_new(256);

		str_append(line, prefix);
		str_append_c(line, ' ');
		str_append(line, text);
		str_append(line, "\r\n");

		client_send_raw_data(client, str_data(line),
				     str_len(line));
	} T_END;
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
	pop3_client_alloc,
	pop3_client_create,
	pop3_client_destroy,
	pop3_client_send_greeting,
	pop3_client_starttls,
	pop3_client_input,
	pop3_client_send_line,
	pop3_client_auth_handle_reply,
	NULL,
	NULL,
	pop3_proxy_reset,
	pop3_proxy_parse_line
};

static const struct login_binary pop3_login_binary = {
	.protocol = "pop3",
	.process_name = "pop3-login",
	.default_port = 110,
	.default_ssl_port = 995,

	.client_vfuncs = &pop3_client_vfuncs,
	.preinit = pop3_login_preinit,
	.init = pop3_login_init,
	.deinit = pop3_login_deinit,

	.sasl_support_final_reply = FALSE
};

int main(int argc, char *argv[])
{
	return login_binary_run(&pop3_login_binary, argc, argv);
}
