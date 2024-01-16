/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "login-common.h"
#include "str.h"
#include "str-sanitize.h"
#include "connection.h"
#include "imap-parser.h"
#include "imap-quote.h"
#include "imap-login-settings.h"
#include "imap-login-client.h"

struct imap_id_params_forward {
	const char *key;
	const char *value;
};

struct imap_id_params {
	pool_t pool;
	struct ip_addr local_ip;
	struct ip_addr ip;
	in_port_t local_port, remote_port;
	unsigned int proxy_ttl;
	const char *session_id;
	const char *local_name;
	ARRAY(struct imap_id_params_forward) forward_fields;
	bool end_client_tls_secured_set;
	bool end_client_tls_secured;
	bool multiplex;
};

struct imap_id_param_handler {
	const char *key;
	bool key_is_prefix;

	bool (*callback)(struct imap_id_params *params,
			 const char *key, const char *value);
};

static bool
cmd_id_x_originating_ip(struct imap_id_params *params,
			const char *key ATTR_UNUSED, const char *value)
{
	return net_addr2ip(value, &params->ip) == 0;
}

static bool
cmd_id_x_originating_port(struct imap_id_params *params,
			  const char *key ATTR_UNUSED, const char *value)
{
	return net_str2port(value, &params->remote_port) == 0;
}

static bool
cmd_id_x_connected_ip(struct imap_id_params *params,
		      const char *key ATTR_UNUSED, const char *value)
{
	return net_addr2ip(value, &params->local_ip) == 0;
}

static bool
cmd_id_x_connected_port(struct imap_id_params *params,
			const char *key ATTR_UNUSED, const char *value)
{
	return net_str2port(value, &params->local_port) == 0;
}

static bool
cmd_id_x_proxy_ttl(struct imap_id_params *params,
		   const char *key ATTR_UNUSED, const char *value)
{
	return str_to_uint(value, &params->proxy_ttl) == 0 &&
	       params->proxy_ttl != 0;
}

static bool
cmd_id_x_session_id(struct imap_id_params *params,
		    const char *key ATTR_UNUSED, const char *value)
{
	if (*value == '\0')
		return FALSE;
	if (strlen(value) <= LOGIN_MAX_SESSION_ID_LEN) {
		params->session_id =
			p_strdup_empty(params->pool, value);
		return TRUE;
	}
	return FALSE;
}

static bool
cmd_id_x_client_transport(struct imap_id_params *params,
			  const char *key ATTR_UNUSED, const char *value)
{
	/* for now values are either "insecure" or "TLS", but plan ahead already
	   in case we want to transfer e.g. the TLS security string */
	params->end_client_tls_secured_set = TRUE;
	params->end_client_tls_secured =
		str_begins_with(value, CLIENT_TRANSPORT_TLS);
	return TRUE;
}

static bool
cmd_id_x_forward_(struct imap_id_params *params,
		  const char *key, const char *value)
{
	const char *suffix;

	if (!str_begins_icase(key, "x-forward-", &suffix))
		i_unreached();
	if (!array_is_created(&params->forward_fields))
		p_array_init(&params->forward_fields, params->pool, 1);
	if (*suffix == '\0')
		return FALSE;
	struct imap_id_params_forward *fwd =
		array_append_space(&params->forward_fields);
	fwd->key = p_strdup(params->pool, suffix);
	fwd->value = p_strdup(params->pool, value);
	return TRUE;
}

static bool
cmd_id_x_multiplex(struct imap_id_params *params,
		   const char *key ATTR_UNUSED, const char *value)
{
	/* <version=0> [<capability> ...] */
	const char *const *args = t_strsplit(value, " ");
	if (args[0] == NULL || strcmp(args[0], "0") != 0)
		return FALSE;

	params->multiplex = TRUE;
	return TRUE;
}

static bool
cmd_id_x_connected_name(struct imap_id_params *params,
			const char *key ATTR_UNUSED, const char *value)
{
	if (connection_is_valid_dns_name(value)) {
		params->local_name = p_strdup(params->pool, value);
		return TRUE;
	}
	return FALSE;
}

static const struct imap_id_param_handler imap_login_id_params[] = {
	{ "x-originating-ip", FALSE, cmd_id_x_originating_ip },
	{ "x-originating-port", FALSE, cmd_id_x_originating_port },
	{ "x-connected-ip", FALSE, cmd_id_x_connected_ip },
	{ "x-connected-port", FALSE, cmd_id_x_connected_port },
	{ "x-connected-name", FALSE, cmd_id_x_connected_name },
	{ "x-proxy-ttl", FALSE, cmd_id_x_proxy_ttl },
	{ "x-session-id", FALSE, cmd_id_x_session_id },
	{ "x-session-ext-id", FALSE, cmd_id_x_session_id },
	{ "x-client-transport", FALSE, cmd_id_x_client_transport },
	{ "x-forward-", TRUE, cmd_id_x_forward_ },
	{ "x-multiplex", FALSE, cmd_id_x_multiplex },

	{ NULL, FALSE, NULL }
};

static const struct imap_id_param_handler *
imap_id_param_handler_find(const char *key)
{
	const char *suffix;

	for (unsigned int i = 0; imap_login_id_params[i].key != NULL; i++) {
		if (str_begins_icase(key, imap_login_id_params[i].key, &suffix) &&
		    (suffix[0] == '\0' ||
		     imap_login_id_params[i].key_is_prefix))
			return &imap_login_id_params[i];
	}
	return NULL;
}

static bool cmd_id_handle_keyvalue(struct imap_client *client,
				   struct imap_id_log_entry *log_entry,
				   const char *key, const char *value)
{
	/* length of key + length of value (NIL for NULL) and two set of
	   quotes and space */
	size_t kvlen = strlen(key) + 2 + 1 +
		       (value == NULL ? 3 : strlen(value)) + 2;
	const struct imap_id_param_handler *handler =
		imap_id_param_handler_find(key);
	bool is_login_id_param = handler != NULL;

	if (is_login_id_param && client->common.connection_trusted &&
	    !client->id_logged && value != NULL) {
		if (!handler->callback(client->cmd_id->params, key, value)) {
			e_debug(client->common.event,
				"Client sent invalid ID parameter '%s'", key);
			return FALSE;
		}
	}

	if (client->set->imap_id_retain && !is_login_id_param &&
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

	if (!is_login_id_param)
		imap_id_add_log_entry(log_entry, key, value);
	return TRUE;
}

static int cmd_id_handle_args(struct imap_client *client,
			      struct imap_id_log_entry *log_entry,
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
		if (!client->id_logged)
			id->log_reply = str_new(default_pool, 64);
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
		if (!client->id_logged && id->log_reply != NULL) {
			log_entry->reply = id->log_reply;
			if (!cmd_id_handle_keyvalue(client, log_entry, id->key, value))
				return -1;
		}
		id->state = IMAP_CLIENT_ID_STATE_KEY;
		break;
	}
	return 0;
}

static void cmd_id_copy_params(struct imap_client *client,
			       struct imap_id_params *params)
{
	if (params->ip.family != AF_UNSPEC)
		client->common.ip = params->ip;
	if (params->local_ip.family != AF_UNSPEC)
		client->common.local_ip = params->local_ip;
	if (params->local_port != 0)
		client->common.local_port = params->local_port;
	if (params->remote_port != 0)
		client->common.remote_port = params->remote_port;
	if (params->proxy_ttl != 0)
		client->common.proxy_ttl = params->proxy_ttl;
	if (params->session_id != NULL) {
		client->common.session_id = p_strdup(client->common.pool,
						     params->session_id);
	}
	if (params->local_name != NULL) {
		client->common.local_name = p_strdup(client->common.preproxy_pool,
						     params->local_name);
	}
	if (params->end_client_tls_secured_set) {
		client->common.end_client_tls_secured_set = params->end_client_tls_secured_set;
		client->common.end_client_tls_secured = params->end_client_tls_secured;
	}
	if (!array_is_created(&params->forward_fields))
		return;
	const struct imap_id_params_forward *elem;
	array_foreach(&params->forward_fields, elem) {
		i_assert(elem->key != NULL && *elem->key != '\0');
		client_add_forward_field(&client->common, elem->key, elem->value);
	}
}

static void cmd_id_finish(struct imap_client *client)
{
	if (!client->id_logged) {
		client->id_logged = TRUE;

		if (client->cmd_id->log_reply != NULL &&
		    str_len(client->cmd_id->log_reply) > 0) {
			e_debug(client->cmd_id->params_event,
				"Pre-login ID sent: %s",
				str_sanitize(str_c(client->cmd_id->log_reply),
					     IMAP_ID_PARAMS_LOG_MAX_LEN));
		}
	}

	client_send_raw(&client->common,
		t_strdup_printf("* ID %s\r\n",
			imap_id_reply_generate(&client->set->imap_id_send)));
	const char *msg = "ID completed.";
	if (client->common.connection_trusted) {
		if (client->cmd_id->params->multiplex &&
		    client->common.multiplex_output == NULL) {
			client_send_raw(&client->common, "* MULTIPLEX 0\r\n");
			client_multiplex_output_start(&client->common);
		}
		cmd_id_copy_params(client, client->cmd_id->params);
		msg = "Trusted ID completed.";
	}
	client_send_reply(&client->common, IMAP_CMD_REPLY_OK, msg);
}

void cmd_id_free(struct imap_client *client)
{
	struct imap_client_cmd_id *id = client->cmd_id;

	event_unref(&id->params_event);
	str_free(&id->log_reply);
	imap_parser_unref(&id->parser);
	pool_unref(&client->cmd_id->params->pool);

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
		pool_t param_pool =
			pool_alloconly_create(MEMPOOL_GROWING"ID parameter pool", 64);
		client->cmd_id = id = i_new(struct imap_client_cmd_id, 1);
		id->params = p_new(param_pool, struct imap_id_params, 1);
		id->params->pool = param_pool;
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

	if (id->params_event == NULL) {
		id->params_event = event_create(client->common.event);
		event_set_name(id->params_event, "imap_id_received");
	}
	struct imap_id_log_entry log_entry = {
		.event = id->params_event,
	};
	while ((ret = imap_parser_read_args(id->parser, 1, parser_flags, &args)) > 0) {
		i_assert(ret == 1);

		if ((ret = cmd_id_handle_args(client, &log_entry, args)) < 0) {
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
