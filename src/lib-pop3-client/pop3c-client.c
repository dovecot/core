/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "net.h"
#include "istream.h"
#include "istream-chain.h"
#include "istream-dot.h"
#include "istream-seekable.h"
#include "ostream.h"
#include "iostream-rawlog.h"
#include "iostream-ssl.h"
#include "safe-mkstemp.h"
#include "base64.h"
#include "str.h"
#include "settings.h"
#include "dns-lookup.h"
#include "client-auth-settings.h"
#include "dsasl-client.h"
#include "pop3-protocol.h"
#include "pop3c-client.h"

#include <unistd.h>

#define POP3_LINE_LENGTH_LIMIT 255
#define POP3C_MAX_INBUF_SIZE (1024*32)

const char *pop3c_command_state_names[] = {
	"OK", "ERR", "(disconnected)"
};
static_assert_array_size(pop3c_command_state_names,
			 POP3C_COMMAND_STATE_DISCONNECTED + 1);

enum pop3c_client_state {
	/* No connection */
	POP3C_CLIENT_STATE_DISCONNECTED = 0,
	/* Trying to connect */
	POP3C_CLIENT_STATE_CONNECTING,
	POP3C_CLIENT_STATE_STARTTLS,
	/* Connected, trying to authenticate */
	POP3C_CLIENT_STATE_USER,
	POP3C_CLIENT_STATE_AUTH,
	POP3C_CLIENT_STATE_PASS,
	/* Post-authentication, asking for capabilities */
	POP3C_CLIENT_STATE_CAPA,
	/* Authenticated, ready to accept commands */
	POP3C_CLIENT_STATE_DONE,

	POP3C_CLIENT_STATE_COUNT
};
static const char *pop3c_client_state_names[] = {
	"disconnected",
	"connecting",
	"starttls",
	"USER",
	"AUTH",
	"PASS",
	"CAPA",
	"authenticated",
};
static_assert_array_size(pop3c_client_state_names, POP3C_CLIENT_STATE_COUNT);

struct pop3c_client_sync_cmd_ctx {
	enum pop3c_command_state state;
	char *reply;
};

struct pop3c_client_cmd {
	struct istream *input;
	struct istream_chain *chain;
	bool reading_dot;

	pop3c_cmd_callback_t *callback;
	void *context;
};

struct pop3c_client {
	pool_t pool;
	struct event *event;
	const struct pop3c_client_settings *set;
	struct pop3c_parameters params;
	enum pop3c_client_ssl_mode ssl_mode;
	struct ip_addr ip;

	int fd;
	struct io *io;
	struct istream *input, *raw_input;
	struct ostream *output, *raw_output;
	struct ssl_iostream *ssl_iostream;
	struct timeout *to;
	struct dns_lookup *dns_lookup;

	enum pop3c_client_state state;
	enum pop3c_capability capabilities;

	const struct client_auth_settings *auth_set;
	struct dsasl_client *sasl_client;
	struct dsasl_client_session *sasl_session;
	const char *const *sasl_mechanisms;
	char *sasl_ir;
	const char *auth_mech;

	pop3c_login_callback_t *login_callback;
	void *login_context;

	ARRAY(struct pop3c_client_cmd) commands;
	const char *input_line;
	struct istream *dot_input;

	bool running:1;
	bool capa_not_supported:1;
	bool authenticated:1;
};

static void
pop3c_dns_callback(const struct dns_lookup_result *result,
		   struct pop3c_client *client);
static void pop3c_client_connect_ip(struct pop3c_client *client);
static int pop3c_client_ssl_init(struct pop3c_client *client);
static void pop3c_client_input(struct pop3c_client *client);

int pop3c_client_init(const struct pop3c_parameters *params,
		      struct event *event_parent,
		      struct pop3c_client **client_r, const char **error_r)
{
	struct event *event;
	struct pop3c_client_settings *set;
	struct dsasl_client *sasl_client;
	struct pop3c_client *client;
	pool_t pool;

	*client_r = NULL;
	*error_r = NULL;

	i_assert(params->temp_path_prefix != NULL &&
		 *params->temp_path_prefix != '\0');

	event = event_create(event_parent);
	settings_event_add_filter_name(event, POP3C_SETTINGS_FILTER);

	if (settings_get(event, &pop3c_client_setting_parser_info, 0,
			 &set, error_r) < 0) {
		event_unref(&event);
		return -1;
	}

	sasl_client = dsasl_client_create(event);
	if (dsasl_client_check_settings(sasl_client, error_r) < 0) {
		dsasl_client_unref(&sasl_client);
		settings_free(set);
		event_unref(&event);
		return -1;
	}

	pool = pool_alloconly_create("pop3c client", 1024);
	client = p_new(pool, struct pop3c_client, 1);
	client->pool = pool;
	client->event = event;
	client->set = set;
	client->sasl_client = sasl_client;

	client->params.temp_path_prefix =
		p_strdup(pool, params->temp_path_prefix);

	event_set_append_log_prefix(client->event, t_strdup_printf(
		"pop3c(%s:%u): ", client->set->pop3c_host, client->set->pop3c_port));

	client->ssl_mode = POP3C_CLIENT_SSL_MODE_NONE;
	if (strcmp(client->set->pop3c_ssl, "pop3s") == 0)
		client->ssl_mode = POP3C_CLIENT_SSL_MODE_IMMEDIATE;
	else if (strcmp(client->set->pop3c_ssl, "starttls") == 0)
		client->ssl_mode = POP3C_CLIENT_SSL_MODE_STARTTLS;

	client->fd = -1;
	p_array_init(&client->commands, pool, 16);

	*client_r = client;
	return 0;
}

static void
client_login_callback(struct pop3c_client *client,
		      enum pop3c_command_state state, const char *reason)
{
	pop3c_login_callback_t *callback = client->login_callback;
	void *context = client->login_context;

	if (client->login_callback != NULL) {
		client->login_callback = NULL;
		client->login_context = NULL;
		callback(state, reason, context);
	}
}

static void
pop3c_client_async_callback(struct pop3c_client *client,
			    enum pop3c_command_state state, const char *reply)
{
	struct pop3c_client_cmd *cmd, cmd_copy;
	bool running = client->running;

	i_assert(reply != NULL);
	i_assert(array_count(&client->commands) > 0);

	cmd = array_front_modifiable(&client->commands);
	if (cmd->input != NULL && state == POP3C_COMMAND_STATE_OK &&
	    !cmd->reading_dot) {
		/* read the full input into seekable-istream before calling
		   the callback */
		i_assert(client->dot_input == NULL);
		i_stream_chain_append(cmd->chain, client->input);
		client->dot_input = cmd->input;
		cmd->reading_dot = TRUE;
		return;
	}
	cmd_copy = *cmd;
	array_pop_front(&client->commands);

	if (cmd_copy.input != NULL) {
		i_stream_seek(cmd_copy.input, 0);
		i_stream_unref(&cmd_copy.input);
	}
	if (cmd_copy.callback != NULL)
		cmd_copy.callback(state, reply, cmd_copy.context);
	if (running)
		io_loop_stop(current_ioloop);
}

static void
pop3c_client_async_callback_disconnected(struct pop3c_client *client)
{
	pop3c_client_async_callback(client, POP3C_COMMAND_STATE_DISCONNECTED,
				    "Disconnected");
}

static void pop3c_client_reset_state(struct pop3c_client *client)
{
	i_zero(&client->ip);
	client->capabilities = 0;
	client->sasl_mechanisms = NULL;
	client->capa_not_supported = FALSE;
	client->authenticated = FALSE;
	client->dot_input = NULL;
}

static void pop3c_client_disconnect(struct pop3c_client *client)
{
	client->state = POP3C_CLIENT_STATE_DISCONNECTED;

	e_debug(client->event, "Disconnected");

	if (client->running)
		io_loop_stop(current_ioloop);

	if (client->dns_lookup != NULL)
		dns_lookup_abort(&client->dns_lookup);
	dsasl_client_session_destroy(&client->sasl_session);
	i_free(client->sasl_ir);
	pop3c_client_reset_state(client);

	timeout_remove(&client->to);
	io_remove(&client->io);
	i_stream_destroy(&client->input);
	o_stream_destroy(&client->output);
	ssl_iostream_destroy(&client->ssl_iostream);
	i_close_fd(&client->fd);
	while (array_count(&client->commands) > 0)
		pop3c_client_async_callback_disconnected(client);
	client_login_callback(client, POP3C_COMMAND_STATE_DISCONNECTED,
			      "Disconnected");
}

void pop3c_client_deinit(struct pop3c_client **_client)
{
	struct pop3c_client *client = *_client;

	settings_free(client->set);
	settings_free(client->auth_set);

	pop3c_client_disconnect(client);

	dsasl_client_unref(&client->sasl_client);
	event_unref(&client->event);
	pool_unref(&client->pool);
}

static void pop3c_client_ioloop_changed(struct pop3c_client *client)
{
	if (client->to != NULL)
		client->to = io_loop_move_timeout(&client->to);
	if (client->io != NULL)
		client->io = io_loop_move_io(&client->io);
	if (client->output != NULL)
		o_stream_switch_ioloop(client->output);
}

static void pop3c_client_timeout(struct pop3c_client *client)
{
	switch (client->state) {
	case POP3C_CLIENT_STATE_CONNECTING:
		e_error(client->event,
			"connect(%s, %u) timed out after %u.%03u seconds",
			net_ip2addr(&client->ip), client->set->pop3c_port,
			client->set->pop3c_connect_timeout_msecs / 1000,
			client->set->pop3c_connect_timeout_msecs % 1000);
		break;
	case POP3C_CLIENT_STATE_DONE:
		e_error(client->event,
			"Command timed out after %u.%03u seconds",
			client->set->pop3c_cmd_timeout_msecs / 1000,
			client->set->pop3c_cmd_timeout_msecs % 1000);
		break;
	default:
		e_error(client->event,
			"Timed out in state %s after %u.%03u seconds",
			pop3c_client_state_names[client->state],
			client->set->pop3c_connect_timeout_msecs / 1000,
			client->set->pop3c_connect_timeout_msecs % 1000);
		break;
	}
	pop3c_client_disconnect(client);
}

static void pop3c_client_dns_lookup(struct pop3c_client *client)
{
	i_assert(client->state == POP3C_CLIENT_STATE_CONNECTING);

	/* The result is delivered asynchronously via
	   pop3c_dns_callback(). */
	dns_lookup(client->set->pop3c_host, NULL, client->event,
		   pop3c_dns_callback, client, &client->dns_lookup);
}

void pop3c_client_wait_one(struct pop3c_client *client)
{
	struct ioloop *ioloop, *prev_ioloop = current_ioloop;
	bool timeout_added = FALSE;

	if (client->state == POP3C_CLIENT_STATE_DISCONNECTED &&
	    array_count(&client->commands) > 0) {
		while (array_count(&client->commands) > 0)
			pop3c_client_async_callback_disconnected(client);
		return;
	}

	i_assert(client->fd != -1 ||
		 client->state == POP3C_CLIENT_STATE_CONNECTING);
	i_assert(array_count(&client->commands) > 0 ||
		 (client->state != POP3C_CLIENT_STATE_DISCONNECTED &&
		  client->state != POP3C_CLIENT_STATE_DONE));

	ioloop = io_loop_create();
	pop3c_client_ioloop_changed(client);

	if (client->ip.family == 0) {
		/* we're connecting, start DNS lookup after our ioloop
		   is created */
		pop3c_client_dns_lookup(client);
	} else if (client->to == NULL) {
		client->to = timeout_add(client->set->pop3c_cmd_timeout_msecs,
					 pop3c_client_timeout, client);
		timeout_added = TRUE;
	}

	client->running = TRUE;
	io_loop_run(ioloop);
	client->running = FALSE;

	if (timeout_added && client->to != NULL)
		timeout_remove(&client->to);

	io_loop_set_current(prev_ioloop);
	pop3c_client_ioloop_changed(client);
	io_loop_set_current(ioloop);
	io_loop_destroy(&ioloop);
}

static int pop3c_client_starttls(struct pop3c_client *client)
{
	if (HAS_NO_BITS(client->capabilities, POP3C_CAPABILITY_STLS)) {
		e_error(client->event, "STARTTLS not supported by server");
		return -1;
	}

	o_stream_nsend_str(client->output, "STLS\r\n");
	client->state = POP3C_CLIENT_STATE_STARTTLS;
	return 0;
}

static int
pop3c_connection_channel_bind_callback(const char *type, void *context,
				       const buffer_t **data_r,
				       const char **error_r)
{
	struct pop3c_client *client = context;

	return ssl_iostream_get_channel_binding(client->ssl_iostream,
						type, data_r, error_r);
}

static int
pop3c_client_auth_failed(struct pop3c_client *client, const char *error)
{
	const char *prefix = "";

	if (client->auth_mech != NULL) {
		prefix = t_strdup_printf("Authentication via %s failed: ",
					 client->auth_mech);
	}
	if (client->login_callback != NULL) {
		e_debug(client->event, "%s%s", prefix, error);
		client_login_callback(client, POP3C_COMMAND_STATE_ERR, error);
	} else {
		e_error(client->event, "%s%s", prefix, error);
	}
	return -1;
}

static void
pop3c_client_send_auth(struct pop3c_client *client, const char *mech_name,
		       const char *init_resp)
{
	if (init_resp == NULL) {
		o_stream_nsend_str(client->output,
				   t_strdup_printf("AUTH %s\r\n", mech_name));
	} else if (*init_resp == '\0') {
		o_stream_nsend_str(client->output,
				   t_strdup_printf("AUTH %s =\r\n", mech_name));
	} else {
		o_stream_nsend_str(client->output,
				   t_strdup_printf("AUTH %s %s\r\n",
						   mech_name, init_resp));
	}
	client->state = POP3C_CLIENT_STATE_AUTH;
}

static int pop3c_client_authenticate1(struct pop3c_client *client)
{
	const char *error;
	int ret;

	settings_free(client->auth_set);
	if (settings_get(client->event, &client_auth_setting_parser_info, 0,
			 &client->auth_set, &error) < 0) {
		e_error(client->event, "%s", error);
		return -1;
	}

	const char *authid = client->auth_set->authid;
	const char *authzid = client->auth_set->authzid;

	if (*authid == '\0') {
		authid = authzid;
		authzid = "";
	}
	if (*authzid == '\0' && *authid != '\0' &&
	    !client_auth_settings_mechanism_configured(client->auth_set)) {
		e_debug(client->event,
			"Authenticating as '%s' (with USER+PASS)", authid);
		o_stream_nsend_str(client->output,
				   t_strdup_printf("USER %s\r\n", authid));
		client->state = POP3C_CLIENT_STATE_USER;
		return 0;
	}

	if (HAS_NO_BITS(client->capabilities, POP3C_CAPABILITY_SASL)) {
		return pop3c_client_auth_failed(client,
			"SASL authentication not supported by server");
	}

	struct dsasl_client_parameters sasl_params = {
		.protocol = "pop",
		.host = client->set->pop3c_host,
		.port = client->set->pop3c_port,
		.server_mechanisms = client->sasl_mechanisms,
	};

	ret = dsasl_client_session_create(client->sasl_client, client->event,
					  &sasl_params, client->auth_set,
					  &client->sasl_session, &error);
	if (ret < 0)
		return pop3c_client_auth_failed(client, error);
	if (ret == 0) {
		return pop3c_client_auth_failed(client,
			"Authentication not configured");
	}

	const char *mech_name =
		dsasl_client_session_get_mech_name(client->sasl_session);

	client->auth_mech = p_strdup_printf(client->pool, "AUTH %s", mech_name);

	if (client->ssl_iostream != NULL) {
		dsasl_client_session_enable_channel_binding(
			client->sasl_session,
			ssl_iostream_get_protocol_version(client->ssl_iostream),
			pop3c_connection_channel_bind_callback, client);
	}

	const unsigned char *sasl_output;
	size_t sasl_output_len;
	string_t *sasl_output_base64;

	if (dsasl_client_session_output(client->sasl_session,
					&sasl_output, &sasl_output_len,
					&error) != DSASL_CLIENT_RESULT_OK)
		return pop3c_client_auth_failed(client, error);
	if (sasl_output == NULL) {
		pop3c_client_send_auth(client, mech_name, NULL);
		return 0;
	}
	if (sasl_output_len == 0) {
		pop3c_client_send_auth(client, mech_name, "");
		return 0;
	}

	sasl_output_base64 = t_str_new(MAX_BASE64_ENCODED_SIZE(sasl_output_len));
	base64_encode(sasl_output, sasl_output_len, sasl_output_base64);

	/* RFC 5034, Section 4:

	   For the purposes of the initial client response, the 255-octet limit
	   on the length of a single command, defined in Section 4 of [RFC2449],
	   still applies. If specifying an initial response would cause the AUTH
	   command to exceed this length, the client MUST NOT use the
	   initial-response parameter (and must proceed instead by sending its
	   initial response after an empty challenge from the server, as in
	   Section 3 of [RFC4422]).
	 */

	const char *init_resp = NULL;

	i_assert(client->sasl_ir == NULL);
	if ((5 + strlen(mech_name) + 1 + str_len(sasl_output_base64)) >
	    (POP3_LINE_LENGTH_LIMIT - 2))
		client->sasl_ir = i_strdup(str_c(sasl_output_base64));
	else
		init_resp = str_c(sasl_output_base64);

	pop3c_client_send_auth(client, mech_name, init_resp);
	return 0;
}

static int
pop3c_client_send_sasl_response(struct pop3c_client *client,
				const char *challenge)
{
	const unsigned char *sasl_output;
	size_t input_len, sasl_output_len;
	buffer_t *buf;
	const char *error;

	if (client->sasl_ir != NULL) {
		if (*challenge == '\0') {
			/* Send initial response */
			struct const_iovec iov[2];

			iov[0].iov_base = client->sasl_ir;
			iov[0].iov_len = strlen(client->sasl_ir);
			iov[1].iov_base = "\r\n";
			iov[1].iov_len = 2;

			o_stream_nsendv(client->output, iov, N_ELEMENTS(iov));
			i_free(client->sasl_ir);
			return 0;
		}
		return pop3c_client_auth_failed(client,
			t_strdup_printf(
				"Server sent unexpected server-first challenge for AUTH: %s",
				challenge));
	}

	input_len = strlen(challenge);
	buf = t_buffer_create(MAX_BASE64_DECODED_SIZE(input_len));
	if (base64_decode(challenge, input_len, buf) < 0) {
		return pop3c_client_auth_failed(client,
			t_strdup_printf(
				"Server sent bad base64 challenge for AUTH: %s",
				challenge));
	}
	if (dsasl_client_session_input(client->sasl_session,
				       buf->data, buf->used,
				       &error) != DSASL_CLIENT_RESULT_OK)
		return pop3c_client_auth_failed(client, error);
	if (dsasl_client_session_output(client->sasl_session,
					&sasl_output, &sasl_output_len,
					&error) != DSASL_CLIENT_RESULT_OK)
		return pop3c_client_auth_failed(client, error);

	if (sasl_output_len == 0) {
		o_stream_nsend_str(client->output, "\r\n");
	} else {
		string_t *imap_output =
			t_str_new(MAX_BASE64_ENCODED_SIZE(sasl_output_len) + 2);
		base64_encode(sasl_output, sasl_output_len, imap_output);
		str_append(imap_output, "\r\n");
		o_stream_nsend(client->output, str_data(imap_output),
			       str_len(imap_output));
	}
	return 0;
}

static void pop3c_client_login_finished(struct pop3c_client *client)
{
	io_remove(&client->io);
	client->io = io_add_istream(client->input,
				    pop3c_client_input, client);

	timeout_remove(&client->to);
	client->state = POP3C_CLIENT_STATE_DONE;

	if (client->running)
		io_loop_stop(current_ioloop);
}

static int pop3c_client_continue(struct pop3c_client *client)
{
	if (client->ssl_iostream == NULL &&
	    client->ssl_mode == POP3C_CLIENT_SSL_MODE_STARTTLS) {
		if (pop3c_client_starttls(client) < 0)
			return -1;
	} else if (!client->authenticated) {
		if (pop3c_client_authenticate1(client) < 0)
			return -1;
	} else {
		pop3c_client_login_finished(client);
	}
	return 0;
}

static int pop3c_client_update_capabilities(struct pop3c_client *client)
{
	if (client->capa_not_supported) {
		if (pop3c_client_continue(client) < 0)
			return -1;
	} else {
		client->capabilities = 0;
		o_stream_nsend_str(client->output, "CAPA\r\n");
		client->state = POP3C_CLIENT_STATE_CAPA;
	}
	return 0;
}

static int
pop3c_client_prelogin_input_line(struct pop3c_client *client, const char *line)
{
	bool success = line[0] == '+';
	const char *reply, *capa_params;

	switch (client->state) {
	case POP3C_CLIENT_STATE_CONNECTING:
		if (!success) {
			e_error(client->event,
				"Server sent invalid banner: %s", line);
			return -1;
		}
		if (pop3c_client_update_capabilities(client) < 0)
			return -1;
		break;
	case POP3C_CLIENT_STATE_STARTTLS:
		if (!success) {
			e_error(client->event, "STLS failed: %s", line);
			return -1;
		}
		if (pop3c_client_ssl_init(client) < 0)
			return -1;
		if (pop3c_client_update_capabilities(client) < 0)
			return -1;
		break;
	case POP3C_CLIENT_STATE_USER:
		if (!success) {
			e_error(client->event, "USER failed: %s", line);
			return -1;
		}

		/* the PASS reply can take a long time.
		   switch to command timeout. */
		timeout_remove(&client->to);
		client->to = timeout_add(client->set->pop3c_cmd_timeout_msecs,
					 pop3c_client_timeout, client);

		o_stream_nsend_str(client->output,
			t_strdup_printf("PASS %s\r\n",
					client->auth_set->password));
		client->state = POP3C_CLIENT_STATE_PASS;
		client->auth_mech = "USER+PASS";
		break;
	case POP3C_CLIENT_STATE_AUTH:
		if (str_begins_icase(line, "+ ", &reply)) {
			if (pop3c_client_send_sasl_response(client, reply) < 0)
				return -1;
			break;
		}
		if (strcmp(line, "+") == 0) {
			/* Interpret as empty server challenge with omitted
			   space. */
			if (pop3c_client_send_sasl_response(client, "") < 0)
				return -1;
			break;
		}
		dsasl_client_session_destroy(&client->sasl_session);
		i_free(client->sasl_ir);
		client->state = POP3C_CLIENT_STATE_PASS;
		/* fall through */
	case POP3C_CLIENT_STATE_PASS:
		if (client->login_callback != NULL) {
			if (!str_begins_icase(line, "+OK ", &reply) &&
			    !str_begins_icase(line, "-ERR ", &reply))
				reply = line;
			client_login_callback(client, success ?
					      POP3C_COMMAND_STATE_OK :
					      POP3C_COMMAND_STATE_ERR, reply);
		} else if (!success) {
			e_error(client->event,
				"Authentication via %s failed: %s",
				client->auth_mech, line);
		}
		if (!success)
			return -1;
		client->authenticated = TRUE;
		if (pop3c_client_update_capabilities(client) < 0)
			return -1;
		break;
	case POP3C_CLIENT_STATE_CAPA:
		if (str_begins_icase_with(line, "-ERR")) {
			/* CAPA command not supported.
			   Enable some extensions anyway */
			client->capa_not_supported = TRUE;
			client->capabilities |= POP3C_CAPABILITY_UIDL;
			client->capabilities |= POP3C_CAPABILITY_STLS;
			client->capabilities |= POP3C_CAPABILITY_SASL;
			client->sasl_mechanisms = (const char *const *)
				p_strsplit(client->pool, "PLAIN", " ");
			if (pop3c_client_continue(client) < 0)
				return -1;
			break;
		} else if (strcmp(line, ".") == 0) {
			if (pop3c_client_continue(client) < 0)
				return -1;
			break;
		}
		if ((client->set->parsed_features & POP3C_FEATURE_NO_PIPELINING) == 0 &&
		    strcasecmp(line, "PIPELINING") == 0)
			client->capabilities |= POP3C_CAPABILITY_PIPELINING;
		else if (strcasecmp(line, "TOP") == 0)
			client->capabilities |= POP3C_CAPABILITY_TOP;
		else if (strcasecmp(line, "UIDL") == 0)
			client->capabilities |= POP3C_CAPABILITY_UIDL;
		else if (strcasecmp(line, "STLS") == 0)
			client->capabilities |= POP3C_CAPABILITY_STLS;
		else if (str_begins_icase(line, "SASL ", &capa_params)) {
			client->capabilities |= POP3C_CAPABILITY_SASL;
			client->sasl_mechanisms = (const char *const *)
				p_strsplit(client->pool, capa_params, " ");
		}
		break;
	case POP3C_CLIENT_STATE_DISCONNECTED:
	case POP3C_CLIENT_STATE_DONE:
	case POP3C_CLIENT_STATE_COUNT:
		i_unreached();
	}
	return 0;
}

static void pop3c_client_prelogin_input(struct pop3c_client *client)
{
	const char *line, *errstr;

	i_assert(client->state != POP3C_CLIENT_STATE_DONE);

	/* we need to read as much as we can with SSL streams to avoid
	   hanging */
	while ((line = i_stream_read_next_line(client->input)) != NULL) {
		if (pop3c_client_prelogin_input_line(client, line) < 0) {
			pop3c_client_disconnect(client);
			return;
		}
	}

	if (client->input->closed || client->input->eof ||
	    client->input->stream_errno != 0) {
		/* disconnected */
		if (client->ssl_iostream == NULL) {
			e_error(client->event, "Server disconnected unexpectedly");
		} else {
			errstr = ssl_iostream_get_last_error(client->ssl_iostream);
			if (errstr == NULL) {
				errstr = client->input->stream_errno == 0 ? "EOF" :
					strerror(client->input->stream_errno);
			}
			e_error(client->event, "Server disconnected: %s", errstr);
		}
		pop3c_client_disconnect(client);
	}
}

static enum ssl_iostream_state
pop3c_client_ssl_handshaked(const char **error_r, void *context)
{
	struct pop3c_client *client = context;
	const char *error;
	enum ssl_iostream_cert_validity validity =
		ssl_iostream_check_cert_validity(client->ssl_iostream,
						 client->set->pop3c_host,
						 &error);

	if (validity == SSL_IOSTREAM_CERT_VALIDITY_OK)
		e_debug(client->event, "SSL handshake successful");
	else if (ssl_iostream_get_allow_invalid_cert(client->ssl_iostream)) {
		e_debug(client->event,
			"SSL handshake successful, "
			"ignoring invalid certificate: %s",
			error);
	} else {
		*error_r = error;
		return validity == SSL_IOSTREAM_CERT_VALIDITY_NAME_MISMATCH ?
			SSL_IOSTREAM_STATE_NAME_MISMATCH :
			SSL_IOSTREAM_STATE_INVALID_CERT;
	}
	return SSL_IOSTREAM_STATE_OK;
}

static int pop3c_client_ssl_init(struct pop3c_client *client)
{
	const char *error;

	e_debug(client->event, "Starting SSL handshake");

	if (client->raw_input != client->input) {
		/* recreate rawlog after STARTTLS */
		i_stream_ref(client->raw_input);
		o_stream_ref(client->raw_output);
		i_stream_destroy(&client->input);
		o_stream_destroy(&client->output);
		client->input = client->raw_input;
		client->output = client->raw_output;
	}

	const struct ssl_iostream_client_autocreate_parameters parameters = {
		.event_parent = client->event,
		.host = client->set->pop3c_host,
		.application_protocols = (const char *const[]) {
			"pop3", NULL
		},
	};
	if (io_stream_autocreate_ssl_client(&parameters,
					    &client->input, &client->output,
					    &client->ssl_iostream, &error) < 0) {
		e_error(client->event,
			"Couldn't initialize SSL client: %s", error);
		return -1;
	}
	ssl_iostream_set_handshake_callback(client->ssl_iostream,
					    pop3c_client_ssl_handshaked,
					    client);
	if (ssl_iostream_handshake(client->ssl_iostream) < 0) {
		e_error(client->event, "SSL handshake failed: %s",
			ssl_iostream_get_last_error(client->ssl_iostream));
		return -1;
	}

	if (client->set->pop3c_rawlog_dir != NULL &&
	    *client->set->pop3c_rawlog_dir != '\0') {
		iostream_rawlog_create(client->event, "pop3c_rawlog_dir",
				       client->set->pop3c_rawlog_dir,
				       &client->input, &client->output);
	}

	i_assert(client->io != NULL);
	io_remove(&client->io);
	client->io = io_add_istream(client->input,
				    pop3c_client_prelogin_input, client);
	return 0;
}

static void pop3c_client_connected(struct pop3c_client *client)
{
	int err;

	err = net_geterror(client->fd);
	if (err != 0) {
		e_error(client->event, "connect(%s, %u) failed: %s",
			net_ip2addr(&client->ip), client->set->pop3c_port,
			strerror(err));
		pop3c_client_disconnect(client);
		return;
	}
	io_remove(&client->io);
	client->io = io_add(client->fd, IO_READ,
			    pop3c_client_prelogin_input, client);

	if (client->ssl_mode == POP3C_CLIENT_SSL_MODE_IMMEDIATE) {
		if (pop3c_client_ssl_init(client) < 0)
			pop3c_client_disconnect(client);
	}
}

static void pop3c_client_connect_ip(struct pop3c_client *client)
{
	client->fd = net_connect_ip(&client->ip, client->set->pop3c_port, NULL);
	if (client->fd == -1) {
		pop3c_client_disconnect(client);
		return;
	}

	client->input = client->raw_input =
		i_stream_create_fd(client->fd, POP3C_MAX_INBUF_SIZE);
	client->output = client->raw_output =
		o_stream_create_fd(client->fd, SIZE_MAX);
	o_stream_set_no_error_handling(client->output, TRUE);

	if (client->set->pop3c_rawlog_dir != NULL &&
	    *client->set->pop3c_rawlog_dir != '\0' &&
	    client->ssl_mode != POP3C_CLIENT_SSL_MODE_IMMEDIATE) {
		iostream_rawlog_create(client->event, "pop3c_rawlog_dir",
				       client->set->pop3c_rawlog_dir,
				       &client->input, &client->output);
	}
	client->io = io_add(client->fd, IO_WRITE,
			    pop3c_client_connected, client);
	client->to = timeout_add(client->set->pop3c_connect_timeout_msecs,
				 pop3c_client_timeout, client);
	e_debug(client->event, "Connecting to %s:%u",
		net_ip2addr(&client->ip), client->set->pop3c_port);
}

static void
pop3c_dns_callback(const struct dns_lookup_result *result,
		   struct pop3c_client *client)
{
	/* We ended up here because dns_lookup_abort() was used */
	if (result->ret == EAI_CANCELED)
		return;
	client->dns_lookup = NULL;

	if (result->ret != 0) {
		e_error(client->event, "dns_lookup() failed: %s", result->error);
		pop3c_client_disconnect(client);
		return;
	}

	i_assert(result->ips_count > 0);
	client->ip = result->ips[0];
	pop3c_client_connect_ip(client);
}

void pop3c_client_login(struct pop3c_client *client,
			pop3c_login_callback_t *callback, void *context)
{
	if (client->fd != -1) {
		i_assert(callback == NULL);
		return;
	}
	i_assert(client->login_callback == NULL);
	client->login_callback = callback;
	client->login_context = context;
	client->state = POP3C_CLIENT_STATE_CONNECTING;

	e_debug(client->event, "Looking up IP address");
}

bool pop3c_client_is_connected(struct pop3c_client *client)
{
	return client->fd != -1;
}

enum pop3c_capability
pop3c_client_get_capabilities(struct pop3c_client *client)
{
	return client->capabilities;
}

static int pop3c_client_dot_input(struct pop3c_client *client)
{
	ssize_t ret;

	while ((ret = i_stream_read(client->dot_input)) > 0 || ret == -2) {
		i_stream_skip(client->dot_input,
			      i_stream_get_data_size(client->dot_input));
	}
	if (ret == 0)
		return 0;
	i_assert(ret == -1);

	if (client->dot_input->stream_errno == 0)
		ret = 1;
	client->dot_input = NULL;

	if (ret > 0) {
		/* currently we don't actually care about preserving the
		   +OK reply line for multi-line replies, so just return
		   it as empty */
		pop3c_client_async_callback(client, POP3C_COMMAND_STATE_OK, "");
		return 1;
	} else {
		pop3c_client_async_callback_disconnected(client);
		return -1;
	}
}

static int
pop3c_client_input_next_reply(struct pop3c_client *client)
{
	const char *line;
	enum pop3c_command_state state;

	line = i_stream_read_next_line(client->input);
	if (line == NULL)
		return client->input->eof ? -1 : 0;

	if (str_begins_icase(line, "+OK", &line))
		state = POP3C_COMMAND_STATE_OK;
	else if (str_begins_icase(line, "-ERR", &line))
		state = POP3C_COMMAND_STATE_ERR;
	else {
		e_error(client->event,
			"Server sent unrecognized line: %s", line);
		state = POP3C_COMMAND_STATE_ERR;
	}
	if (line[0] == ' ')
		line++;
	if (array_count(&client->commands) == 0) {
		e_error(client->event,
			"Server sent line when no command was running: %s", line);
	} else {
		pop3c_client_async_callback(client, state, line);
	}
	return 1;
}

static void pop3c_client_input(struct pop3c_client *client)
{
	int ret;

	if (client->to != NULL)
		timeout_reset(client->to);
	do {
		if (client->dot_input != NULL) {
			/* continue reading the current multiline reply */
			if ((ret = pop3c_client_dot_input(client)) == 0)
				return;
		} else {
			ret = pop3c_client_input_next_reply(client);
		}
	} while (ret > 0);

	if (ret < 0) {
		if (array_count(&client->commands) > 0) {
			e_error(client->event,
				"Server disconnected unexpectedly "
				"(%u commands pending)",
				array_count(&client->commands));
		}
		pop3c_client_disconnect(client);
	}
}

static void pop3c_client_cmd_reply(enum pop3c_command_state state,
				   const char *reply, void *context)
{
	struct pop3c_client_sync_cmd_ctx *ctx = context;

	i_assert(ctx->reply == NULL);

	ctx->state = state;
	ctx->reply = i_strdup(reply);
}

int pop3c_client_cmd_line(struct pop3c_client *client, const char *cmdline,
			  const char **reply_r)
{
	struct pop3c_client_sync_cmd_ctx ctx;

	i_zero(&ctx);
	pop3c_client_cmd_line_async(client, cmdline, pop3c_client_cmd_reply, &ctx);
	while (ctx.reply == NULL)
		pop3c_client_wait_one(client);
	*reply_r = t_strdup(ctx.reply);
	i_free(ctx.reply);
	return ctx.state == POP3C_COMMAND_STATE_OK ? 0 : -1;
}

struct pop3c_client_cmd *
pop3c_client_cmd_line_async(struct pop3c_client *client, const char *cmdline,
			    pop3c_cmd_callback_t *callback, void *context)
{
	struct pop3c_client_cmd *cmd;

	while (client->state != POP3C_CLIENT_STATE_DISCONNECTED &&
	       client->state != POP3C_CLIENT_STATE_DONE)
		pop3c_client_wait_one(client);

	if ((client->capabilities & POP3C_CAPABILITY_PIPELINING) == 0) {
		while (array_count(&client->commands) > 0)
			pop3c_client_wait_one(client);
	}
	i_assert(client->state == POP3C_CLIENT_STATE_DISCONNECTED ||
		 client->state == POP3C_CLIENT_STATE_DONE);
	if (client->state == POP3C_CLIENT_STATE_DONE)
		o_stream_nsend_str(client->output, cmdline);

	cmd = array_append_space(&client->commands);
	cmd->callback = callback;
	cmd->context = context;
	return cmd;
}

void pop3c_client_cmd_line_async_nocb(struct pop3c_client *client,
				      const char *cmdline)
{
	pop3c_client_cmd_line_async(client, cmdline, NULL, NULL);
}

static int seekable_fd_callback(const char **path_r, void *context)
{
	struct pop3c_client *client = context;
	string_t *path;
	int fd;

	i_assert(client->params.temp_path_prefix != NULL &&
		 *client->params.temp_path_prefix != '\0');

	path = t_str_new(128);
	str_append(path, client->params.temp_path_prefix);
	fd = safe_mkstemp(path, 0600, (uid_t)-1, (gid_t)-1);
	if (fd == -1) {
		e_error(client->event,
			"safe_mkstemp(%s) failed: %m", str_c(path));
		return -1;
	}

	/* we just want the fd, unlink it */
	if (i_unlink(str_c(path)) < 0) {
		/* shouldn't happen.. */
		i_close_fd(&fd);
		return -1;
	}

	*path_r = str_c(path);
	return fd;
}

int pop3c_client_cmd_stream(struct pop3c_client *client, const char *cmdline,
			    struct istream **input_r, const char **error_r)
{
	struct pop3c_client_sync_cmd_ctx ctx;
	const char *reply;

	if (client->state == POP3C_CLIENT_STATE_DISCONNECTED) {
		*error_r = "Disconnected from server";
		return -1;
	}

	i_zero(&ctx);
	*input_r = pop3c_client_cmd_stream_async(client, cmdline,
						 pop3c_client_cmd_reply, &ctx);
	while (ctx.reply == NULL)
		pop3c_client_wait_one(client);
	reply = t_strdup(ctx.reply);
	i_free(ctx.reply);

	if (ctx.state == POP3C_COMMAND_STATE_OK)
		return 0;
	i_stream_unref(input_r);
	*error_r = reply;
	return -1;
}

struct istream *
pop3c_client_cmd_stream_async(struct pop3c_client *client, const char *cmdline,
			      pop3c_cmd_callback_t *callback, void *context)
{
	struct istream *input, *inputs[2];
	struct pop3c_client_cmd *cmd;

	cmd = pop3c_client_cmd_line_async(client, cmdline, callback, context);

	input = i_stream_create_chain(&cmd->chain, POP3C_MAX_INBUF_SIZE);
	inputs[0] = i_stream_create_dot(input, ISTREAM_DOT_NO_TRIM |
					       ISTREAM_DOT_LOOSE_EOT);
	inputs[1] = NULL;
	cmd->input = i_stream_create_seekable(inputs, POP3C_MAX_INBUF_SIZE,
					      seekable_fd_callback, client);
	i_stream_unref(&input);
	i_stream_unref(&inputs[0]);

	i_stream_ref(cmd->input);
	return cmd->input;
}
