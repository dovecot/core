/* Copyright (c) 2002-2017 Dovecot authors, see the included COPYING file */

#include "login-common.h"
#include "buffer.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "safe-memset.h"
#include "str.h"
#include "imap-parser.h"
#include "imap-id.h"
#include "imap-resp-code.h"
#include "master-service.h"
#include "master-service-ssl-settings.h"
#include "master-auth.h"
#include "imap-login-client.h"
#include "client-authenticate.h"
#include "auth-client.h"
#include "ssl-proxy.h"
#include "imap-proxy.h"
#include "imap-quote.h"
#include "imap-login-commands.h"
#include "imap-login-settings.h"

#if LOGIN_MAX_INBUF_SIZE < 1024+2
#  error LOGIN_MAX_INBUF_SIZE too short to fit all ID command parameters
#endif

/* maximum length for IMAP command line. */
#define MAX_IMAP_LINE 8192

/* Disconnect client when it sends too many bad commands */
#define CLIENT_MAX_BAD_COMMANDS 3

static const char *const imap_login_reserved_id_keys[] = {
	"x-originating-ip",
	"x-originating-port",
	"x-connected-ip",
	"x-connected-port",
	"x-proxy-ttl",
	"x-session-id",
	"x-session-ext-id",
	NULL
};

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

static bool client_handle_parser_error(struct imap_client *client,
				       struct imap_parser *parser)
{
	const char *msg;
	bool fatal;

	msg = imap_parser_get_error(parser, &fatal);
	if (fatal) {
		client_send_reply(&client->common,
				  IMAP_CMD_REPLY_BYE, msg);
		client_destroy(&client->common,
			       t_strconcat("Disconnected: ", msg, NULL));
		return FALSE;
	}

	client_send_reply(&client->common, IMAP_CMD_REPLY_BAD, msg);
	client->cmd_finished = TRUE;
	client->skip_line = TRUE;
	return TRUE;
}

static bool is_login_cmd_disabled(struct client *client)
{
	if (client->secured) {
		if (auth_client_find_mech(auth_client, "PLAIN") == NULL) {
			/* no PLAIN authentication, can't use LOGIN command */
			return TRUE;
		}
		return FALSE;
	}
	if (client->set->disable_plaintext_auth)
		return TRUE;
	if (strcmp(client->ssl_set->ssl, "required") == 0)
		return TRUE;
	return FALSE;
}

static const char *get_capability(struct client *client)
{
	struct imap_client *imap_client = (struct imap_client *)client;
	string_t *cap_str = t_str_new(256);

	if (*imap_client->set->imap_capability == '\0')
		str_append(cap_str, CAPABILITY_BANNER_STRING);
	else if (*imap_client->set->imap_capability != '+')
		str_append(cap_str, imap_client->set->imap_capability);
	else {
		str_append(cap_str, CAPABILITY_BANNER_STRING);
		str_append_c(cap_str, ' ');
		str_append(cap_str, imap_client->set->imap_capability + 1);
	}

	if (client_is_tls_enabled(client) && !client->tls)
		str_append(cap_str, " STARTTLS");
	if (is_login_cmd_disabled(client))
		str_append(cap_str, " LOGINDISABLED");

	client_authenticate_get_capabilities(client, cap_str);
	return str_c(cap_str);
}

static int cmd_capability(struct imap_client *imap_client,
			  const struct imap_arg *args ATTR_UNUSED)
{
	struct client *client = &imap_client->common;

	/* Client is required to send CAPABILITY after STARTTLS, so the
	   capability resp-code workaround checks only pre-STARTTLS
	   CAPABILITY commands. */
	if (!client->starttls)
		imap_client->client_ignores_capability_resp_code = TRUE;
	client_send_raw(client, t_strconcat(
		"* CAPABILITY ", get_capability(client), "\r\n", NULL));
	client_send_reply(client, IMAP_CMD_REPLY_OK,
		"Pre-login capabilities listed, post-login capabilities have more.");
	return 1;
}

static int cmd_starttls(struct imap_client *client,
			const struct imap_arg *args ATTR_UNUSED)
{
	client_cmd_starttls(&client->common);
	return 1;
}

static void
imap_client_notify_starttls(struct client *client,
			    bool success, const char *text)
{
	if (success)
		client_send_reply(client, IMAP_CMD_REPLY_OK, text);
	else
		client_send_reply(client, IMAP_CMD_REPLY_BAD, text);
}

static bool
client_update_info(struct imap_client *client,
		   const char *key, const char *value)
{
	/* do not try to process NIL value */
	if (value == NULL)
		return FALSE;

	/* SYNC WITH imap_login_reserved_id_keys */

	if (strcasecmp(key, "x-originating-ip") == 0) {
		(void)net_addr2ip(value, &client->common.ip);
	} else if (strcasecmp(key, "x-originating-port") == 0) {
		(void)net_str2port(value, &client->common.remote_port);
	} else if (strcasecmp(key, "x-connected-ip") == 0) {
		(void)net_addr2ip(value, &client->common.local_ip);
	} else if (strcasecmp(key, "x-connected-port") == 0) {
		(void)net_str2port(value, &client->common.local_port);
	}	else if (strcasecmp(key, "x-proxy-ttl") == 0) {
		if (str_to_uint(value, &client->common.proxy_ttl) < 0) {
			/* nothing */
		}
	} else if (strcasecmp(key, "x-session-id") == 0 ||
		 strcasecmp(key, "x-session-ext-id") == 0) {
		if (strlen(value) <= LOGIN_MAX_SESSION_ID_LEN) {
			client->common.session_id =
				p_strdup(client->common.pool, value);
		}
	} else if (strncasecmp(key, "x-forward-", 10) == 0) {
		/* handle extra field */
		client_add_forward_field(&client->common, key+10, value);
	} else {
		return FALSE;
	}
	return TRUE;
}

static bool client_id_reserved_word(const char *key)
{
	i_assert(key != NULL);
	return (strncasecmp(key, "x-forward-", 10) == 0 ||
		str_array_icase_find(imap_login_reserved_id_keys, key));
}

static void cmd_id_handle_keyvalue(struct imap_client *client,
				   const char *key, const char *value)
{
	bool client_id_str;
	/* length of key + length of value (NIL for NULL) and two set of
	   quotes and space */
	size_t kvlen = strlen(key) + 2 + 1 +
		       (value == NULL ? 3 : strlen(value)) + 2;

	if (client->common.trusted && !client->id_logged) {
		client_id_str = !client_update_info(client, key, value);
		i_assert(client_id_str == !client_id_reserved_word(key));
	} else {
		client_id_str = !client_id_reserved_word(key);
	}

	if (client->set->imap_id_retain && client_id_str &&
	    (client->common.client_id == NULL ||
	     str_len(client->common.client_id) + kvlen < LOGIN_MAX_CLIENT_ID_LEN)) {
		if (client->common.client_id == NULL) {
			client->common.client_id = str_new(client->common.preproxy_pool, 64);
		} else {
			str_append_c(client->common.client_id, ' ');
		}
		imap_append_quoted(client->common.client_id, key);
		str_append_c(client->common.client_id, ' ');
		if (value == NULL)
			str_append(client->common.client_id, "NIL");
		else
			imap_append_quoted(client->common.client_id, value);
	}

	if (client->cmd_id->log_reply != NULL &&
	    (client->cmd_id->log_keys == NULL ||
	     str_array_icase_find((void *)client->cmd_id->log_keys, key)))
		imap_id_log_reply_append(client->cmd_id->log_reply, key, value);
}

static int cmd_id_handle_args(struct imap_client *client,
			      const struct imap_arg *arg)
{
	struct imap_client_cmd_id *id = client->cmd_id;
	const char *key, *value;

	switch (id->state) {
	case IMAP_CLIENT_ID_STATE_LIST:
		if (arg->type == IMAP_ARG_NIL)
			return 1;
		if (arg->type != IMAP_ARG_LIST)
			return -1;
		if (client->set->imap_id_log[0] == '\0') {
			/* no ID logging */
		} else if (client->id_logged) {
			/* already logged the ID reply */
		} else {
			id->log_reply = str_new(default_pool, 64);
			if (strcmp(client->set->imap_id_log, "*") == 0) {
				/* log all keys */
			} else {
				/* log only specified keys */
				id->log_keys = p_strsplit_spaces(default_pool,
					client->set->imap_id_log, " ");
			}
		}
		id->state = IMAP_CLIENT_ID_STATE_KEY;
		break;
	case IMAP_CLIENT_ID_STATE_KEY:
		if (!imap_arg_get_string(arg, &key))
			return -1;
		if (i_strocpy(id->key, key, sizeof(id->key)) < 0)
			return -1;
		id->state = IMAP_CLIENT_ID_STATE_VALUE;
		break;
	case IMAP_CLIENT_ID_STATE_VALUE:
		if (!imap_arg_get_nstring(arg, &value))
			return -1;
		cmd_id_handle_keyvalue(client, id->key, value);
		id->state = IMAP_CLIENT_ID_STATE_KEY;
		break;
	}
	return 0;
}

static void cmd_id_finish(struct imap_client *client)
{
	/* finished handling the parameters */
	if (!client->id_logged) {
		client->id_logged = TRUE;

		if (client->cmd_id->log_reply != NULL) {
			client_log(&client->common, t_strdup_printf(
				"ID sent: %s", str_c(client->cmd_id->log_reply)));
		}
	}

	client_send_raw(&client->common,
		t_strdup_printf("* ID %s\r\n",
			imap_id_reply_generate(client->set->imap_id_send)));
	client_send_reply(&client->common, IMAP_CMD_REPLY_OK, "ID completed.");
}

static void cmd_id_free(struct imap_client *client)
{
	struct imap_client_cmd_id *id = client->cmd_id;

	if (id->log_reply != NULL)
		str_free(&id->log_reply);
	if (id->log_keys != NULL)
		p_strsplit_free(default_pool, id->log_keys);
	imap_parser_unref(&id->parser);

	i_free_and_null(client->cmd_id);
	client->skip_line = TRUE;
}

static int cmd_id(struct imap_client *client)
{
	struct imap_client_cmd_id *id;
	enum imap_parser_flags parser_flags;
	const struct imap_arg *args;
	int ret;

	if (client->common.client_id != NULL)
		str_truncate(client->common.client_id, 0);

	if (client->cmd_id == NULL) {
		client->cmd_id = id = i_new(struct imap_client_cmd_id, 1);
		id->parser = imap_parser_create(client->common.input,
						client->common.output,
						MAX_IMAP_LINE);
		parser_flags = IMAP_PARSE_FLAG_STOP_AT_LIST;
	} else {
		id = client->cmd_id;
		parser_flags = IMAP_PARSE_FLAG_INSIDE_LIST;
	}

	while ((ret = imap_parser_read_args(id->parser, 1, parser_flags, &args)) > 0) {
		i_assert(ret == 1);

		if ((ret = cmd_id_handle_args(client, args)) < 0) {
			client_send_reply(&client->common,
					  IMAP_CMD_REPLY_BAD,
					  "Invalid ID parameters");
			cmd_id_free(client);
			return -1;
		}
		if (ret > 0) {
			/* NIL parameter */
			ret = 0;
			break;
		}
		imap_parser_reset(id->parser);
		parser_flags = IMAP_PARSE_FLAG_INSIDE_LIST;
	}
	if (ret == 0) {
		/* finished the line */
		cmd_id_finish(client);
		cmd_id_free(client);
		return 1;
	} else if (ret == -1) {
		if (!client_handle_parser_error(client, id->parser))
			return 0;
		cmd_id_free(client);
		return -1;
	} else {
		i_assert(ret == -2);
		return 0;
	}
}

static int cmd_noop(struct imap_client *client,
		    const struct imap_arg *args ATTR_UNUSED)
{
	client_send_reply(&client->common, IMAP_CMD_REPLY_OK,
			  "NOOP completed.");
	return 1;
}

static int cmd_logout(struct imap_client *client,
		      const struct imap_arg *args ATTR_UNUSED)
{
	client_send_reply(&client->common, IMAP_CMD_REPLY_BYE, "Logging out");
	client_send_reply(&client->common, IMAP_CMD_REPLY_OK,
			  "Logout completed.");
	client_destroy(&client->common, "Aborted login");
	return 1;
}

static int cmd_enable(struct imap_client *client,
		      const struct imap_arg *args ATTR_UNUSED)
{
	client_send_raw(&client->common, "* ENABLED\r\n");
	client_send_reply(&client->common, IMAP_CMD_REPLY_OK,
			  "ENABLE ignored in non-authenticated state.");
	return 1;
}

static int client_command_execute(struct imap_client *client, const char *cmd,
				  const struct imap_arg *args)
{
	struct imap_login_command *login_cmd;

	login_cmd = imap_login_command_lookup(cmd);
	if (login_cmd == NULL)
		return -2;
	return login_cmd->func(client, args);
}

static bool imap_is_valid_tag(const char *tag)
{
	for (; *tag != '\0'; tag++) {
		switch (*tag) {
		case '+':
		/* atom-specials: */
		case '(':
		case ')':
		case '{':
		case '/':
		case ' ':
		/* list-wildcards: */
		case '%':
		case '*':
		/* quoted-specials: */
		case '"':
		case '\\':
			return FALSE;
		default:
			if (*tag < ' ') /* CTL */
				return FALSE;
			break;
		}
	}
	return TRUE;
}

static int client_parse_command(struct imap_client *client,
				const struct imap_arg **args_r)
{
	switch (imap_parser_read_args(client->parser, 0, 0, args_r)) {
	case -1:
		/* error */
		if (!client_handle_parser_error(client, client->parser)) {
			/* client destroyed */
			return 0;
		}
		return -1;
	case -2:
		/* not enough data */
		return 0;
	default:
		/* we read the entire line - skip over the CRLF */
		if (!client_skip_line(client))
			i_unreached();
		return 1;
	}
}

static bool client_handle_input(struct imap_client *client)
{
	const struct imap_arg *args;
	bool parsed;
	int ret;

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
		if (!imap_is_valid_tag(client->cmd_tag) ||
		    strlen(client->cmd_tag) > IMAP_TAG_MAX_LEN) {
			/* the tag is invalid, don't allow it and don't
			   send it back. this attempts to prevent any
			   potentially dangerous replies in case someone tries
			   to access us using HTTP protocol. */
			client->cmd_tag = "";
		}
	}

	if (client->cmd_name == NULL) {
                client->cmd_name = imap_parser_read_word(client->parser);
		if (client->cmd_name == NULL)
			return FALSE; /* need more data */
	}

	if (strcasecmp(client->cmd_name, "AUTHENTICATE") == 0) {
		/* SASL-IR may need more space than input buffer's size,
		   so we'll handle it as a special case. */
		ret = cmd_authenticate(client, &parsed);
		if (ret == 0 && !parsed)
			return FALSE;
	} else if (strcasecmp(client->cmd_name, "ID") == 0) {
		/* ID extensions allows max. 30 parameters,
		   each max. 1024 bytes long. that brings us over the input
		   buffer's size, so handle the parameters one at a time */
		ret = cmd_id(client);
		if (ret == 0)
			return FALSE;
		if (ret < 0)
			ret = 1; /* don't send the error reply again */
	} else {
		ret = client_parse_command(client, &args);
		if (ret < 0)
			return TRUE;
		if (ret == 0)
			return FALSE;
		ret = *client->cmd_tag == '\0' ? -1 :
			client_command_execute(client, client->cmd_name, args);
	}

	client->cmd_finished = TRUE;
	if (ret == -2 && strcasecmp(client->cmd_tag, "LOGIN") == 0) {
		client_send_reply(&client->common, IMAP_CMD_REPLY_BAD,
			"First parameter in line is IMAP's command tag, "
			"not the command name. Add that before the command, "
			"like: a login user pass");
	} else if (ret < 0) {
		if (*client->cmd_tag == '\0')
			client->cmd_tag = "*";
		if (++client->common.bad_counter >= CLIENT_MAX_BAD_COMMANDS) {
			client_send_reply(&client->common, IMAP_CMD_REPLY_BYE,
				"Too many invalid IMAP commands.");
			client_destroy(&client->common,
				"Disconnected: Too many invalid commands");
			return FALSE;
		}
		client_send_reply(&client->common, IMAP_CMD_REPLY_BAD,
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
			client_notify_status(client, FALSE,
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
	imap_parser_unref(&imap_client->parser);
}

static void imap_client_notify_auth_ready(struct client *client)
{
	string_t *greet;

	greet = t_str_new(128);
	str_append(greet, "* OK ");
	str_printfa(greet, "[CAPABILITY %s] ", get_capability(client));
	str_append(greet, client->set->login_greeting);
	str_append(greet, "\r\n");

	client_send_raw(client, str_c(greet));
}

static void imap_client_starttls(struct client *client)
{
	struct imap_client *imap_client = (struct imap_client *)client;

	imap_parser_unref(&imap_client->parser);
	imap_client->parser =
		imap_parser_create(imap_client->common.input,
				   imap_client->common.output, MAX_IMAP_LINE);

	/* CRLF is lost from buffer when streams are reopened. */
	imap_client->skip_line = FALSE;
}

static void ATTR_NULL(3)
client_send_reply_raw(struct client *client,
		      const char *prefix, const char *resp_code,
		      const char *text, bool tagged)
{
	struct imap_client *imap_client = (struct imap_client *)client;

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

		client_send_raw_data(client, str_data(line), str_len(line));
	} T_END;
}

void client_send_reply_code(struct client *client, enum imap_cmd_reply reply,
			    const char *resp_code, const char *text)
{
	const char *prefix = "NO";
	bool tagged = TRUE;

	switch (reply) {
	case IMAP_CMD_REPLY_OK:
		prefix = "OK";
		break;
	case IMAP_CMD_REPLY_NO:
		break;
	case IMAP_CMD_REPLY_BAD:
		prefix = "BAD";
		break;
	case IMAP_CMD_REPLY_BYE:
		prefix = "BYE";
		tagged = FALSE;
		break;
	}
	client_send_reply_raw(client, prefix, resp_code, text, tagged);
}

void client_send_reply(struct client *client, enum imap_cmd_reply reply,
		       const char *text)
{
	client_send_reply_code(client, reply, NULL, text);
}

static void
imap_client_notify_status(struct client *client, bool bad, const char *text)
{
	if (bad)
		client_send_reply_raw(client, "BAD", "ALERT", text, FALSE);
	else
		client_send_reply_raw(client, "OK", NULL, text, FALSE);
}

static void 
imap_client_notify_disconnect(struct client *client,
			      enum client_disconnect_reason reason,
			      const char *text)
{
	if (reason == CLIENT_DISCONNECT_INTERNAL_ERROR) {
		client_send_reply_code(client, IMAP_CMD_REPLY_BYE,
				       IMAP_RESP_CODE_UNAVAILABLE, text);
	} else {
		client_send_reply_code(client, IMAP_CMD_REPLY_BYE, NULL, text);
	}
}

static void imap_login_preinit(void)
{
	login_set_roots = imap_login_setting_roots;
}

static const struct imap_login_command imap_login_commands[] = {
	{ "LOGIN", cmd_login },
	{ "CAPABILITY", cmd_capability },
	{ "STARTTLS", cmd_starttls },
	{ "NOOP", cmd_noop },
	{ "LOGOUT", cmd_logout },
	{ "ENABLE", cmd_enable }
};

static void imap_login_init(void)
{
	imap_login_commands_init();
	imap_login_commands_register(imap_login_commands,
				     N_ELEMENTS(imap_login_commands));
}

static void imap_login_deinit(void)
{
	clients_destroy_all();
	imap_login_commands_deinit();
}

static struct client_vfuncs imap_client_vfuncs = {
	imap_client_alloc,
	imap_client_create,
	imap_client_destroy,
	imap_client_notify_auth_ready,
	imap_client_notify_disconnect,
	imap_client_notify_status,
	imap_client_notify_starttls,
	imap_client_starttls,
	imap_client_input,
	NULL,
	NULL,
	imap_client_auth_result,
	imap_proxy_reset,
	imap_proxy_parse_line,
	imap_proxy_error,
	imap_proxy_get_state,
};

static const struct login_binary imap_login_binary = {
	.protocol = "imap",
	.process_name = "imap-login",
	.default_port = 143,
	.default_ssl_port = 993,

	.client_vfuncs = &imap_client_vfuncs,
	.preinit = imap_login_preinit,
	.init = imap_login_init,
	.deinit = imap_login_deinit,

	.sasl_support_final_reply = FALSE
};

int main(int argc, char *argv[])
{
	return login_binary_run(&imap_login_binary, argc, argv);
}
