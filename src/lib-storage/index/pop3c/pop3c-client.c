/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

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
#include "dns-lookup.h"
#include "pop3c-client.h"

#include <unistd.h>

#define POP3C_MAX_INBUF_SIZE (1024*32)
#define POP3C_DNS_LOOKUP_TIMEOUT_MSECS (1000*30)
#define POP3C_CONNECT_TIMEOUT_MSECS (1000*30)
#define POP3C_COMMAND_TIMEOUT_MSECS (1000*60*5)

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
	POP3C_CLIENT_STATE_DONE
};

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
	struct pop3c_client_settings set;
	struct ssl_iostream_context *ssl_ctx;
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
	const char *auth_mech;

	pop3c_login_callback_t *login_callback;
	void *login_context;

	ARRAY(struct pop3c_client_cmd) commands;
	const char *input_line;
	struct istream *dot_input;

	bool running:1;
};

static void
pop3c_dns_callback(const struct dns_lookup_result *result,
		   struct pop3c_client *client);
static void pop3c_client_connect_ip(struct pop3c_client *client);
static int pop3c_client_ssl_init(struct pop3c_client *client);
static void pop3c_client_input(struct pop3c_client *client);

struct pop3c_client *
pop3c_client_init(const struct pop3c_client_settings *set)
{
	struct pop3c_client *client;
	const char *error;
	pool_t pool;

	pool = pool_alloconly_create("pop3c client", 1024);
	client = p_new(pool, struct pop3c_client, 1);
	client->pool = pool;
	client->fd = -1;
	p_array_init(&client->commands, pool, 16);

	client->set.debug = set->debug;
	client->set.host = p_strdup(pool, set->host);
	client->set.port = set->port;
	client->set.master_user = p_strdup_empty(pool, set->master_user);
	client->set.username = p_strdup(pool, set->username);
	client->set.password = p_strdup(pool, set->password);
	client->set.dns_client_socket_path =
		p_strdup(pool, set->dns_client_socket_path);
	client->set.temp_path_prefix = p_strdup(pool, set->temp_path_prefix);
	client->set.rawlog_dir = p_strdup(pool, set->rawlog_dir);
	client->set.ssl_mode = set->ssl_mode;

	if (set->ssl_mode != POP3C_CLIENT_SSL_MODE_NONE) {
		ssl_iostream_settings_init_from(client->pool, &client->set.ssl_set, &set->ssl_set);
		client->set.ssl_set.verbose_invalid_cert = !client->set.ssl_set.allow_invalid_cert;
		if (ssl_iostream_client_context_cache_get(&set->ssl_set,
							  &client->ssl_ctx,
							  &error) < 0) {
			i_error("pop3c(%s:%u): Couldn't initialize SSL context: %s",
				set->host, set->port, error);
		}
	}
	return client;
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

	cmd = array_first_modifiable(&client->commands);
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

static void pop3c_client_disconnect(struct pop3c_client *client)
{
	client->state = POP3C_CLIENT_STATE_DISCONNECTED;

	if (client->running)
		io_loop_stop(current_ioloop);

	if (client->dns_lookup != NULL)
		dns_lookup_abort(&client->dns_lookup);
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

	pop3c_client_disconnect(client);
	if (client->ssl_ctx != NULL)
		ssl_iostream_context_unref(&client->ssl_ctx);
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
		i_error("pop3c(%s): connect(%s, %u) timed out after %u seconds",
			client->set.host, net_ip2addr(&client->ip),
			client->set.port, POP3C_CONNECT_TIMEOUT_MSECS/1000);
		break;
	case POP3C_CLIENT_STATE_DONE:
		i_error("pop3c(%s): Command timed out after %u seconds",
			client->set.host, POP3C_COMMAND_TIMEOUT_MSECS/1000);
		break;
	default:
		i_error("pop3c(%s): Authentication timed out after %u seconds",
			client->set.host, POP3C_CONNECT_TIMEOUT_MSECS/1000);
		break;
	}
	pop3c_client_disconnect(client);
}

static int pop3c_client_dns_lookup(struct pop3c_client *client)
{
	struct dns_lookup_settings dns_set;

	i_assert(client->state == POP3C_CLIENT_STATE_CONNECTING);

	if (client->set.dns_client_socket_path[0] == '\0') {
		struct ip_addr *ips;
		unsigned int ips_count;
		int ret;

		ret = net_gethostbyname(client->set.host, &ips, &ips_count);
		if (ret != 0) {
			i_error("pop3c(%s): net_gethostbyname() failed: %s",
				client->set.host, net_gethosterror(ret));
			return -1;
		}
		i_assert(ips_count > 0);
		client->ip = ips[0];
		pop3c_client_connect_ip(client);
	} else {
		i_zero(&dns_set);
		dns_set.dns_client_socket_path =
			client->set.dns_client_socket_path;
		dns_set.timeout_msecs = POP3C_DNS_LOOKUP_TIMEOUT_MSECS;
		if (dns_lookup(client->set.host, &dns_set,
			       pop3c_dns_callback, client,
			       &client->dns_lookup) < 0)
			return -1;
	}
	return 0;
}

void pop3c_client_wait_one(struct pop3c_client *client)
{
	struct ioloop *ioloop, *prev_ioloop = current_ioloop;
	bool timeout_added = FALSE, failed = FALSE;

	if (client->state == POP3C_CLIENT_STATE_DISCONNECTED &&
	    array_count(&client->commands) > 0) {
		while (array_count(&client->commands) > 0)
			pop3c_client_async_callback_disconnected(client);
		return;
	}

	i_assert(client->fd != -1 ||
		 client->state == POP3C_CLIENT_STATE_CONNECTING);
	i_assert(array_count(&client->commands) > 0 ||
		 client->state == POP3C_CLIENT_STATE_CONNECTING);

	ioloop = io_loop_create();
	pop3c_client_ioloop_changed(client);

	if (client->ip.family == 0) {
		/* we're connecting, start DNS lookup after our ioloop
		   is created */
		if (pop3c_client_dns_lookup(client) < 0)
			failed = TRUE;
	} else if (client->to == NULL) {
		client->to = timeout_add(POP3C_COMMAND_TIMEOUT_MSECS,
					 pop3c_client_timeout, client);
		timeout_added = TRUE;
	}

	if (!failed) {
		client->running = TRUE;
		io_loop_run(ioloop);
		client->running = FALSE;
	}

	if (timeout_added && client->to != NULL)
		timeout_remove(&client->to);

	io_loop_set_current(prev_ioloop);
	pop3c_client_ioloop_changed(client);
	io_loop_set_current(ioloop);
	io_loop_destroy(&ioloop);
}

static void pop3c_client_starttls(struct pop3c_client *client)
{
	o_stream_nsend_str(client->output, "STLS\r\n");
	client->state = POP3C_CLIENT_STATE_STARTTLS;
}

static void pop3c_client_authenticate1(struct pop3c_client *client)
{
	const struct pop3c_client_settings *set = &client->set;

	if (client->set.debug) {
		if (set->master_user == NULL) {
			i_debug("pop3c(%s): Authenticating as '%s' (with USER+PASS)",
				client->set.host, set->username);
		} else {
			i_debug("pop3c(%s): Authenticating as master user '%s' for user '%s' (with SASL PLAIN)",
				client->set.host, set->master_user,
				set->username);
		}
	}

	if (set->master_user == NULL) {
		o_stream_nsend_str(client->output,
			t_strdup_printf("USER %s\r\n", set->username));
		client->state = POP3C_CLIENT_STATE_USER;
	} else {
		client->state = POP3C_CLIENT_STATE_AUTH;
		o_stream_nsend_str(client->output, "AUTH PLAIN\r\n");
	}
}

static const char *
pop3c_client_get_sasl_plain_request(struct pop3c_client *client)
{
	const struct pop3c_client_settings *set = &client->set;
	string_t *in, *out;

	in = t_str_new(128);
	if (set->master_user != NULL) {
		str_append(in, set->username);
		str_append_c(in, '\0');
		str_append(in, set->master_user);
	} else {
		str_append_c(in, '\0');
		str_append(in, set->username);
	}
	str_append_c(in, '\0');
	str_append(in, set->password);

	out = t_str_new(128);
	base64_encode(str_data(in), str_len(in), out);
	str_append(out, "\r\n");
	return str_c(out);
}

static void pop3c_client_login_finished(struct pop3c_client *client)
{
	io_remove(&client->io);
	client->io = io_add(client->fd, IO_READ, pop3c_client_input, client);

	timeout_remove(&client->to);
	client->state = POP3C_CLIENT_STATE_DONE;

	if (client->running)
		io_loop_stop(current_ioloop);
}

static int
pop3c_client_prelogin_input_line(struct pop3c_client *client, const char *line)
{
	bool success = line[0] == '+';
	const char *reply;

	switch (client->state) {
	case POP3C_CLIENT_STATE_CONNECTING:
		if (!success) {
			i_error("pop3c(%s): Server sent invalid banner: %s",
				client->set.host, line);
			return -1;
		}
		if (client->set.ssl_mode == POP3C_CLIENT_SSL_MODE_STARTTLS)
			pop3c_client_starttls(client);
		else
			pop3c_client_authenticate1(client);
		break;
	case POP3C_CLIENT_STATE_STARTTLS:
		if (!success) {
			i_error("pop3c(%s): STLS failed: %s",
				client->set.host, line);
			return -1;
		}
		if (pop3c_client_ssl_init(client) < 0)
			pop3c_client_disconnect(client);
		break;
	case POP3C_CLIENT_STATE_USER:
		if (!success) {
			i_error("pop3c(%s): USER failed: %s",
				client->set.host, line);
			return -1;
		}

		/* the PASS reply can take a long time.
		   switch to command timeout. */
		timeout_remove(&client->to);
		client->to = timeout_add(POP3C_COMMAND_TIMEOUT_MSECS,
					 pop3c_client_timeout, client);

		o_stream_nsend_str(client->output,
			t_strdup_printf("PASS %s\r\n", client->set.password));
		client->state = POP3C_CLIENT_STATE_PASS;
		client->auth_mech = "USER+PASS";
		break;
	case POP3C_CLIENT_STATE_AUTH:
		if (line[0] != '+') {
			i_error("pop3c(%s): AUTH PLAIN failed: %s",
				client->set.host, line);
			return -1;
		}
		o_stream_nsend_str(client->output,
			pop3c_client_get_sasl_plain_request(client));
		client->state = POP3C_CLIENT_STATE_PASS;
		client->auth_mech = "AUTH PLAIN";
		break;
	case POP3C_CLIENT_STATE_PASS:
		if (client->login_callback != NULL) {
			reply = strncasecmp(line, "+OK ", 4) == 0 ? line + 4 :
				strncasecmp(line, "-ERR ", 5) == 0 ? line + 5 :
				line;
			client_login_callback(client, success ?
					      POP3C_COMMAND_STATE_OK :
					      POP3C_COMMAND_STATE_ERR, reply);
		} else if (!success) {
			i_error("pop3c(%s): Authentication via %s failed: %s",
				client->set.host, client->auth_mech, line);
		}
		if (!success)
			return -1;

		o_stream_nsend_str(client->output, "CAPA\r\n");
		client->state = POP3C_CLIENT_STATE_CAPA;
		break;
	case POP3C_CLIENT_STATE_CAPA:
		if (strncasecmp(line, "-ERR", 4) == 0) {
			/* CAPA command not supported. some commands still
			   support UIDL though. */
			client->capabilities |= POP3C_CAPABILITY_UIDL;
			pop3c_client_login_finished(client);
			break;
		} else if (strcmp(line, ".") == 0) {
			pop3c_client_login_finished(client);
			break;
		}
		if ((client->set.parsed_features & POP3C_FEATURE_NO_PIPELINING) == 0 &&
		    strcasecmp(line, "PIPELINING") == 0)
			client->capabilities |= POP3C_CAPABILITY_PIPELINING;
		else if (strcasecmp(line, "TOP") == 0)
			client->capabilities |= POP3C_CAPABILITY_TOP;
		else if (strcasecmp(line, "UIDL") == 0)
			client->capabilities |= POP3C_CAPABILITY_UIDL;
		break;
	case POP3C_CLIENT_STATE_DISCONNECTED:
	case POP3C_CLIENT_STATE_DONE:
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
			i_error("pop3c(%s): Server disconnected unexpectedly",
				client->set.host);
		} else {
			errstr = ssl_iostream_get_last_error(client->ssl_iostream);
			if (errstr == NULL) {
				errstr = client->input->stream_errno == 0 ? "EOF" :
					strerror(client->input->stream_errno);
			}
			i_error("pop3c(%s): Server disconnected: %s",
				client->set.host, errstr);
		}
		pop3c_client_disconnect(client);
	}
}

static int pop3c_client_ssl_handshaked(const char **error_r, void *context)
{
	struct pop3c_client *client = context;
	const char *error;

	if (ssl_iostream_check_cert_validity(client->ssl_iostream,
					     client->set.host, &error) == 0) {
		if (client->set.debug) {
			i_debug("pop3c(%s): SSL handshake successful",
				client->set.host);
		}
		return 0;
	} else if (client->set.ssl_set.allow_invalid_cert) {
		if (client->set.debug) {
			i_debug("pop3c(%s): SSL handshake successful, "
				"ignoring invalid certificate: %s",
				client->set.host, error);
		}
		return 0;
	} else {
		*error_r = error;
		return -1;
	}
}

static int pop3c_client_ssl_init(struct pop3c_client *client)
{
	const char *error;

	if (client->ssl_ctx == NULL) {
		i_error("pop3c(%s): No SSL context", client->set.host);
		return -1;
	}

	if (client->set.debug)
		i_debug("pop3c(%s): Starting SSL handshake", client->set.host);

	if (client->raw_input != client->input) {
		/* recreate rawlog after STARTTLS */
		i_stream_ref(client->raw_input);
		o_stream_ref(client->raw_output);
		i_stream_destroy(&client->input);
		o_stream_destroy(&client->output);
		client->input = client->raw_input;
		client->output = client->raw_output;
	}

	if (io_stream_create_ssl_client(client->ssl_ctx, client->set.host,
					&client->set.ssl_set, &client->input,
					&client->output, &client->ssl_iostream, &error) < 0) {
		i_error("pop3c(%s): Couldn't initialize SSL client: %s",
			client->set.host, error);
		return -1;
	}
	ssl_iostream_set_handshake_callback(client->ssl_iostream,
					    pop3c_client_ssl_handshaked,
					    client);
	if (ssl_iostream_handshake(client->ssl_iostream) < 0) {
		i_error("pop3c(%s): SSL handshake failed: %s", client->set.host,
			ssl_iostream_get_last_error(client->ssl_iostream));
		return -1;
	}

	if (*client->set.rawlog_dir != '\0') {
		iostream_rawlog_create(client->set.rawlog_dir,
				       &client->input, &client->output);
	}
	return 0;
}

static void pop3c_client_connected(struct pop3c_client *client)
{
	int err;

	err = net_geterror(client->fd);
	if (err != 0) {
		i_error("pop3c(%s): connect(%s, %u) failed: %s",
			client->set.host, net_ip2addr(&client->ip),
			client->set.port, strerror(err));
		pop3c_client_disconnect(client);
		return;
	}
	io_remove(&client->io);
	client->io = io_add(client->fd, IO_READ,
			    pop3c_client_prelogin_input, client);

	if (client->set.ssl_mode == POP3C_CLIENT_SSL_MODE_IMMEDIATE) {
		if (pop3c_client_ssl_init(client) < 0)
			pop3c_client_disconnect(client);
	}
}

static void pop3c_client_connect_ip(struct pop3c_client *client)
{
	client->fd = net_connect_ip(&client->ip, client->set.port, NULL);
	if (client->fd == -1) {
		pop3c_client_disconnect(client);
		return;
	}

	client->input = client->raw_input =
		i_stream_create_fd(client->fd, POP3C_MAX_INBUF_SIZE);
	client->output = client->raw_output =
		o_stream_create_fd(client->fd, (size_t)-1);
	o_stream_set_no_error_handling(client->output, TRUE);

	if (*client->set.rawlog_dir != '\0' &&
	    client->set.ssl_mode != POP3C_CLIENT_SSL_MODE_IMMEDIATE) {
		iostream_rawlog_create(client->set.rawlog_dir,
				       &client->input, &client->output);
	}
	client->io = io_add(client->fd, IO_WRITE,
			    pop3c_client_connected, client);
	client->to = timeout_add(POP3C_CONNECT_TIMEOUT_MSECS,
				 pop3c_client_timeout, client);
	if (client->set.debug) {
		i_debug("pop3c(%s): Connecting to %s:%u", client->set.host,
			net_ip2addr(&client->ip), client->set.port);
	}
}

static void
pop3c_dns_callback(const struct dns_lookup_result *result,
		   struct pop3c_client *client)
{
	client->dns_lookup = NULL;

	if (result->ret != 0) {
		i_error("pop3c(%s): dns_lookup() failed: %s",
			client->set.host, result->error);
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

	if (client->set.debug)
		i_debug("pop3c(%s): Looking up IP address", client->set.host);
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

	if (strncasecmp(line, "+OK", 3) == 0) {
		line += 3;
		state = POP3C_COMMAND_STATE_OK;
	} else if (strncasecmp(line, "-ERR", 4) == 0) {
		line += 4;
		state = POP3C_COMMAND_STATE_ERR;
	} else {
		i_error("pop3c(%s): Server sent unrecognized line: %s",
			client->set.host, line);
		state = POP3C_COMMAND_STATE_ERR;
	}
	if (line[0] == ' ')
		line++;
	if (array_count(&client->commands) == 0) {
		i_error("pop3c(%s): Server sent line when no command was running: %s",
			client->set.host, line);
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
		i_error("pop3c(%s): Server disconnected unexpectedly",
			client->set.host);
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

	path = t_str_new(128);
	str_append(path, client->set.temp_path_prefix);
	fd = safe_mkstemp(path, 0600, (uid_t)-1, (gid_t)-1);
	if (fd == -1) {
		i_error("safe_mkstemp(%s) failed: %m", str_c(path));
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

	input = i_stream_create_chain(&cmd->chain);
	inputs[0] = i_stream_create_dot(input, TRUE);
	inputs[1] = NULL;
	cmd->input = i_stream_create_seekable(inputs, POP3C_MAX_INBUF_SIZE,
					      seekable_fd_callback, client);
	i_stream_unref(&input);
	i_stream_unref(&inputs[0]);

	i_stream_ref(cmd->input);
	return cmd->input;
}
