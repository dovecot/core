/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#include "login-common.h"
#include "buffer.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "safe-memset.h"
#include "str.h"
#include "strescape.h"
#include "imap-parser.h"
#include "imap-id.h"
#include "imap-resp-code.h"
#include "master-service.h"
#include "master-auth.h"
#include "client.h"
#include "client-authenticate.h"
#include "auth-client.h"
#include "ssl-proxy.h"
#include "imap-proxy.h"
#include "imap-login-settings.h"

#include <stdlib.h>

/* maximum length for IMAP command line. */
#define MAX_IMAP_LINE 8192

/* Disconnect client when it sends too many bad commands */
#define CLIENT_MAX_BAD_COMMANDS 10

const struct login_binary login_binary = {
	.protocol = "imap",
	.process_name = "imap-login",
	.default_port = 143,
	.default_ssl_port = 993
};

void login_process_preinit(void)
{
	login_set_roots = imap_login_setting_roots;
}

/* Skip incoming data until newline is found,
   returns TRUE if newline was found. */
bool client_skip_line(struct imap_client *client)
{
	const unsigned char *data;
	size_t i, data_size;

	data = i_stream_get_data(client->common.input, &data_size);

	for (i = 0; i < data_size; i++) {
		if (data[i] == '\n') {
			i_stream_skip(client->common.input, i+1);
			return TRUE;
		}
	}

	return FALSE;
}

static const char *get_capability(struct client *client)
{
	struct imap_client *imap_client = (struct imap_client *)client;
	const char *auths, *cap_str;

	cap_str = *imap_client->set->imap_capability != '\0' ?
		imap_client->set->imap_capability : CAPABILITY_BANNER_STRING;
	auths = client_authenticate_get_capabilities(client);
	return t_strconcat(cap_str,
			   (ssl_initialized && !client->tls) ? " STARTTLS" : "",
			   client->set->disable_plaintext_auth &&
			   !client->secured ? " LOGINDISABLED" : "",
			   auths, NULL);
}

static int cmd_capability(struct imap_client *imap_client)
{
	struct client *client = &imap_client->common;

	/* Client is required to send CAPABILITY after STARTTLS, so the
	   capability resp-code workaround checks only pre-STARTTLS
	   CAPABILITY commands. */
	if (!client->starttls)
		imap_client->client_ignores_capability_resp_code = TRUE;
	client_send_raw(client, t_strconcat(
		"* CAPABILITY ", get_capability(client), "\r\n", NULL));
	client_send_line(client, CLIENT_CMD_REPLY_OK, "Capability completed.");
	return 1;
}

static int cmd_starttls(struct imap_client *client)
{
	client_cmd_starttls(&client->common);
	return 1;
}

static void
client_update_info(struct imap_client *client, const struct imap_arg *args)
{
	const char *key, *value;

	if (!imap_arg_get_list(args, &args))
		return;

	while (imap_arg_get_string(&args[0], &key) &&
	       imap_arg_get_nstring(&args[1], &value)) {
		if (strcasecmp(key, "x-originating-ip") == 0)
			(void)net_addr2ip(value, &client->common.ip);
		else if (strcasecmp(key, "x-originating-port") == 0)
			client->common.remote_port = atoi(value);
		else if (strcasecmp(key, "x-connected-ip") == 0)
			(void)net_addr2ip(value, &client->common.local_ip);
		else if (strcasecmp(key, "x-connected-port") == 0)
			client->common.local_port = atoi(value);
		args += 2;
	}
}

static int cmd_id(struct imap_client *client, const struct imap_arg *args)
{
	const char *env, *value;

	if (!client->id_logged) {
		client->id_logged = TRUE;
		if (client->common.trusted)
			client_update_info(client, args);

		env = getenv("IMAP_ID_LOG");
		value = imap_id_args_get_log_reply(args, env);
		if (value != NULL) {
			client_log(&client->common,
				   t_strdup_printf("ID sent: %s", value));
		}
	}

	env = getenv("IMAP_ID_SEND");
	client_send_raw(&client->common,
		t_strdup_printf("* ID %s\r\n", imap_id_reply_generate(env)));
	client_send_line(&client->common, CLIENT_CMD_REPLY_OK, "ID completed.");
	return 1;
}

static int cmd_noop(struct imap_client *client)
{
	client_send_line(&client->common, CLIENT_CMD_REPLY_OK,
			 "NOOP completed.");
	return 1;
}

static int cmd_logout(struct imap_client *client)
{
	client_send_line(&client->common, CLIENT_CMD_REPLY_BYE, "Logging out");
	client_send_line(&client->common, CLIENT_CMD_REPLY_OK,
			 "Logout completed.");
	client_destroy(&client->common, "Aborted login");
	return 1;
}

static int cmd_enable(struct imap_client *client)
{
	client_send_raw(&client->common, "* ENABLED\r\n");
	client_send_line(&client->common, CLIENT_CMD_REPLY_OK,
			 "ENABLE ignored in non-authenticated state.");
	return 1;
}

static int client_command_execute(struct imap_client *client, const char *cmd,
				  const struct imap_arg *args)
{
	cmd = t_str_ucase(cmd);
	if (strcmp(cmd, "LOGIN") == 0)
		return cmd_login(client, args);
	if (strcmp(cmd, "AUTHENTICATE") == 0)
		return cmd_authenticate(client, args);
	if (strcmp(cmd, "CAPABILITY") == 0)
		return cmd_capability(client);
	if (strcmp(cmd, "STARTTLS") == 0)
		return cmd_starttls(client);
	if (strcmp(cmd, "ID") == 0)
		return cmd_id(client, args);
	if (strcmp(cmd, "NOOP") == 0)
		return cmd_noop(client);
	if (strcmp(cmd, "LOGOUT") == 0)
		return cmd_logout(client);
	if (strcmp(cmd, "ENABLE") == 0)
		return cmd_enable(client);

	return -2;
}

static bool client_handle_input(struct imap_client *client)
{
	const struct imap_arg *args;
	const char *msg;
	int ret;
	bool fatal;

	i_assert(!client->common.authenticating);

	if (client->cmd_finished) {
		/* clear the previous command from memory. don't do this
		   immediately after handling command since we need the
		   cmd_tag to stay some time after authentication commands. */
		client->cmd_tag = NULL;
		client->cmd_name = NULL;
		imap_parser_reset(client->parser);

		/* remove \r\n */
		if (client->skip_line) {
			if (!client_skip_line(client))
				return FALSE;
                        client->skip_line = FALSE;
		}

		client->cmd_finished = FALSE;
	}

	if (client->cmd_tag == NULL) {
                client->cmd_tag = imap_parser_read_word(client->parser);
		if (client->cmd_tag == NULL)
			return FALSE; /* need more data */
	}

	if (client->cmd_name == NULL) {
                client->cmd_name = imap_parser_read_word(client->parser);
		if (client->cmd_name == NULL)
			return FALSE; /* need more data */
	}

	switch (imap_parser_read_args(client->parser, 0, 0, &args)) {
	case -1:
		/* error */
		msg = imap_parser_get_error(client->parser, &fatal);
		if (fatal) {
			client_send_line(&client->common,
					 CLIENT_CMD_REPLY_BYE, msg);
			client_destroy(&client->common,
				t_strconcat("Disconnected: ", msg, NULL));
			return FALSE;
		}

		client_send_line(&client->common, CLIENT_CMD_REPLY_BAD, msg);
		client->cmd_finished = TRUE;
		client->skip_line = TRUE;
		return TRUE;
	case -2:
		/* not enough data */
		return FALSE;
	}
	/* we read the entire line - skip over the CRLF */
	if (!client_skip_line(client))
		i_unreached();

	if (*client->cmd_tag == '\0')
		ret = -1;
	else
		ret = client_command_execute(client, client->cmd_name, args);

	client->cmd_finished = TRUE;
	if (ret == -2 && strcasecmp(client->cmd_tag, "LOGIN") == 0) {
		client_send_line(&client->common, CLIENT_CMD_REPLY_BAD,
			"First parameter in line is IMAP's command tag, "
			"not the command name. Add that before the command, "
			"like: a login user pass");
	} else if (ret < 0) {
		if (*client->cmd_tag == '\0')
			client->cmd_tag = "*";
		if (++client->common.bad_counter >= CLIENT_MAX_BAD_COMMANDS) {
			client_send_line(&client->common, CLIENT_CMD_REPLY_BYE,
				"Too many invalid IMAP commands.");
			client_destroy(&client->common,
				"Disconnected: Too many invalid commands");
			return FALSE;
		}
		client_send_line(&client->common, CLIENT_CMD_REPLY_BAD,
			"Error in IMAP command received by server.");
	}

	return ret != 0 && !client->common.destroyed;
}

static void imap_client_input(struct client *client)
{
	struct imap_client *imap_client = (struct imap_client *)client;

	if (!client_read(client))
		return;

	client_ref(client);
	o_stream_cork(imap_client->common.output);
	for (;;) {
		if (!auth_client_is_connected(auth_client)) {
			/* we're not currently connected to auth process -
			   don't allow any commands */
			client_send_line(client, CLIENT_CMD_REPLY_STATUS,
					 AUTH_SERVER_WAITING_MSG);
			if (client->to_auth_waiting != NULL)
				timeout_remove(&client->to_auth_waiting);

			client->input_blocked = TRUE;
			break;
		} else {
			if (!client_handle_input(imap_client))
				break;
		}
	}
	o_stream_uncork(imap_client->common.output);
	client_unref(&client);
}

static struct client *imap_client_alloc(pool_t pool)
{
	struct imap_client *imap_client;

	imap_client = p_new(pool, struct imap_client, 1);
	return &imap_client->common;
}

static void imap_client_create(struct client *client, void **other_sets)
{
	struct imap_client *imap_client = (struct imap_client *)client;

	imap_client->set = other_sets[0];
	imap_client->parser =
		imap_parser_create(imap_client->common.input,
				   imap_client->common.output, MAX_IMAP_LINE);
	client->io = io_add(client->fd, IO_READ, client_input, client);
}

static void imap_client_destroy(struct client *client)
{
	struct imap_client *imap_client = (struct imap_client *)client;

	i_free_and_null(imap_client->proxy_backend_capability);
	imap_parser_destroy(&imap_client->parser);
}

static void imap_client_send_greeting(struct client *client)
{
	string_t *greet;

	greet = t_str_new(128);
	str_append(greet, "* OK ");
	str_printfa(greet, "[CAPABILITY %s] ", get_capability(client));
	str_append(greet, client->set->login_greeting);
	str_append(greet, "\r\n");

	client_send_raw(client, str_c(greet));
	client->greeting_sent = TRUE;
}

static void imap_client_starttls(struct client *client)
{
	struct imap_client *imap_client = (struct imap_client *)client;

	imap_parser_destroy(&imap_client->parser);
	imap_client->parser =
		imap_parser_create(imap_client->common.input,
				   imap_client->common.output, MAX_IMAP_LINE);

	/* CRLF is lost from buffer when streams are reopened. */
	imap_client->skip_line = FALSE;
}

static void
imap_client_send_line(struct client *client, enum client_cmd_reply reply,
		      const char *text)
{
	struct imap_client *imap_client = (struct imap_client *)client;
	const char *resp_code = NULL;
	const char *prefix = "NO";
	bool tagged = TRUE;

	switch (reply) {
	case CLIENT_CMD_REPLY_OK:
		prefix = "OK";
		break;
	case CLIENT_CMD_REPLY_AUTH_FAILED:
		resp_code = IMAP_RESP_CODE_AUTHFAILED;
		break;
	case CLIENT_CMD_REPLY_AUTHZ_FAILED:
		resp_code = IMAP_RESP_CODE_AUTHZFAILED;
		break;
	case CLIENT_CMD_REPLY_AUTH_FAIL_TEMP:
		resp_code = IMAP_RESP_CODE_UNAVAILABLE;
		break;
	case CLIENT_CMD_REPLY_AUTH_FAIL_REASON:
		resp_code = "ALERT";
		break;
	case CLIENT_CMD_REPLY_AUTH_FAIL_NOSSL:
		resp_code = IMAP_RESP_CODE_PRIVACYREQUIRED;
		break;
	case CLIENT_CMD_REPLY_BAD:
		prefix = "BAD";
		break;
	case CLIENT_CMD_REPLY_BYE:
		prefix = "BYE";
		tagged = FALSE;
		break;
	case CLIENT_CMD_REPLY_STATUS:
		prefix = "OK";
		tagged = FALSE;
		break;
	case CLIENT_CMD_REPLY_STATUS_BAD:
		prefix = "BAD";
		tagged = FALSE;
		resp_code = "ALERT";
		break;
	}

	T_BEGIN {
		string_t *line = t_str_new(256);

		if (tagged)
			str_append(line, imap_client->cmd_tag);
		else
			str_append_c(line, '*');
		str_append_c(line, ' ');
		str_append(line, prefix);
		str_append_c(line, ' ');
		if (resp_code != NULL)
			str_printfa(line, "[%s] ", resp_code);
		str_append(line, text);
		str_append(line, "\r\n");

		client_send_raw_data(client, str_data(line),
				     str_len(line));
	} T_END;
}

void clients_init(void)
{
}

void clients_deinit(void)
{
	clients_destroy_all();
}

struct client_vfuncs client_vfuncs = {
	imap_client_alloc,
	imap_client_create,
	imap_client_destroy,
	imap_client_send_greeting,
	imap_client_starttls,
	imap_client_input,
	imap_client_send_line,
	imap_client_auth_handle_reply,
	NULL,
	NULL,
	imap_proxy_reset,
	imap_proxy_parse_line
};
