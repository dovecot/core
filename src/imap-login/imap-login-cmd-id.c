/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "login-common.h"
#include "str.h"
#include "imap-parser.h"
#include "imap-quote.h"
#include "imap-login-settings.h"
#include "imap-login-client.h"

struct imap_id_param_handler {
	const char *key;
	bool key_is_prefix;

	void (*callback)(struct imap_client *client,
			 const char *key, const char *value);
};

static void
cmd_id_x_originating_ip(struct imap_client *client,
			const char *key ATTR_UNUSED, const char *value)
{
	(void)net_addr2ip(value, &client->common.ip);
}

static void
cmd_id_x_originating_port(struct imap_client *client,
			  const char *key ATTR_UNUSED, const char *value)
{
	(void)net_str2port(value, &client->common.remote_port);
}

static void
cmd_id_x_connected_ip(struct imap_client *client,
		      const char *key ATTR_UNUSED, const char *value)
{
	(void)net_addr2ip(value, &client->common.local_ip);
}

static void
cmd_id_x_connected_port(struct imap_client *client,
			const char *key ATTR_UNUSED, const char *value)
{
	(void)net_str2port(value, &client->common.local_port);
}

static void
cmd_id_x_proxy_ttl(struct imap_client *client,
		   const char *key ATTR_UNUSED, const char *value)
{
	if (str_to_uint(value, &client->common.proxy_ttl) < 0) {
		/* nothing */
	}
}

static void
cmd_id_x_session_id(struct imap_client *client,
		    const char *key ATTR_UNUSED, const char *value)
{
	if (strlen(value) <= LOGIN_MAX_SESSION_ID_LEN) {
		client->common.session_id =
			p_strdup(client->common.pool, value);
	}
}

static void
cmd_id_x_forward_(struct imap_client *client,
		  const char *key, const char *value)
{
	i_assert(strncasecmp(key, "x-forward-", 10) == 0);
	client_add_forward_field(&client->common, key+10, value);
}

static const struct imap_id_param_handler imap_login_id_params[] = {
	{ "x-originating-ip", FALSE, cmd_id_x_originating_ip },
	{ "x-originating-port", FALSE, cmd_id_x_originating_port },
	{ "x-connected-ip", FALSE, cmd_id_x_connected_ip },
	{ "x-connected-port", FALSE, cmd_id_x_connected_port },
	{ "x-proxy-ttl", FALSE, cmd_id_x_proxy_ttl },
	{ "x-session-id", FALSE, cmd_id_x_session_id },
	{ "x-session-ext-id", FALSE, cmd_id_x_session_id },
	{ "x-forward-", TRUE, cmd_id_x_forward_ },

	{ NULL, FALSE, NULL }
};

static const struct imap_id_param_handler *
imap_id_param_handler_find(const char *key)
{
	for (unsigned int i = 0; imap_login_id_params[i].key != NULL; i++) {
		unsigned int prefix_len = strlen(imap_login_id_params[i].key);

		if (strncasecmp(imap_login_id_params[i].key, key, prefix_len) == 0 &&
		    (key[prefix_len] == '\0' ||
		     imap_login_id_params[i].key_is_prefix))
			return &imap_login_id_params[i];
	}
	return NULL;
}

static bool
client_try_update_info(struct imap_client *client,
		       const char *key, const char *value)
{
	const struct imap_id_param_handler *handler;

	handler = imap_id_param_handler_find(key);
	if (handler == NULL)
		return FALSE;

	/* do not try to process NIL values as client-info,
	   but store them for non-reserved keys */
	if (client->common.trusted && !client->id_logged && value != NULL)
		handler->callback(client, key, value);
	return TRUE;
}

static void cmd_id_handle_keyvalue(struct imap_client *client,
				   const char *key, const char *value)
{
	bool client_id_str;
	/* length of key + length of value (NIL for NULL) and two set of
	   quotes and space */
	size_t kvlen = strlen(key) + 2 + 1 +
		       (value == NULL ? 3 : strlen(value)) + 2;

	client_id_str = !client_try_update_info(client, key, value);

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
			e_info(client->common.event, "ID sent: %s",
			       str_c(client->cmd_id->log_reply));
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

	str_free(&id->log_reply);
	if (id->log_keys != NULL)
		p_strsplit_free(default_pool, id->log_keys);
	imap_parser_unref(&id->parser);

	i_free_and_null(client->cmd_id);
	client->skip_line = TRUE;
}

int cmd_id(struct imap_client *client)
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
						IMAP_LOGIN_MAX_LINE_LENGTH);
		if (client->set->imap_literal_minus)
			imap_parser_enable_literal_minus(id->parser);
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
