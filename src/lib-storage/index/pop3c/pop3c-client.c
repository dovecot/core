/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "net.h"
#include "istream.h"
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
#define POP3C_COMMAND_TIMEOUT_MSECS (1000*30)

enum pop3c_client_state {
	/* No connection */
	POP3C_CLIENT_STATE_DISCONNECTED = 0,
	/* Trying to connect */
	POP3C_CLIENT_STATE_CONNECTING,
	/* Connected, trying to authenticate */
	POP3C_CLIENT_STATE_USER,
	POP3C_CLIENT_STATE_AUTH,
	POP3C_CLIENT_STATE_PASS,
	/* Post-authentication, asking for capabilities */
	POP3C_CLIENT_STATE_CAPA,
	/* Authenticated, ready to accept commands */
	POP3C_CLIENT_STATE_DONE
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

	pop3c_login_callback_t *login_callback;
	void *login_context;

	unsigned int async_commands;
	const char *input_line;
	struct istream *dot_input;

	unsigned int running:1;
};

static void
pop3c_dns_callback(const struct dns_lookup_result *result,
		   struct pop3c_client *client);

struct pop3c_client *
pop3c_client_init(const struct pop3c_client_settings *set)
{
	struct pop3c_client *client;
	struct ssl_iostream_settings ssl_set;
	const char *error;
	pool_t pool;

	pool = pool_alloconly_create("pop3c client", 1024);
	client = p_new(pool, struct pop3c_client, 1);
	client->pool = pool;
	client->fd = -1;

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

	if (set->ssl_mode != POP3C_CLIENT_SSL_MODE_NONE) {
		client->set.ssl_mode = set->ssl_mode;
		client->set.ssl_ca_dir = p_strdup(pool, set->ssl_ca_dir);
		client->set.ssl_ca_file = p_strdup(pool, set->ssl_ca_file);
		client->set.ssl_verify = set->ssl_verify;

		memset(&ssl_set, 0, sizeof(ssl_set));
		ssl_set.ca_dir = set->ssl_ca_dir;
		ssl_set.ca_file = set->ssl_ca_file;
		ssl_set.verify_remote_cert = set->ssl_verify;
		ssl_set.crypto_device = set->ssl_crypto_device;

		if (ssl_iostream_context_init_client(&ssl_set, &client->ssl_ctx,
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

static void pop3c_client_disconnect(struct pop3c_client *client)
{
	client->state = POP3C_CLIENT_STATE_DISCONNECTED;
	client->async_commands = 0;

	if (client->running)
		io_loop_stop(current_ioloop);

	if (client->dns_lookup != NULL)
		dns_lookup_abort(&client->dns_lookup);
	if (client->to != NULL)
		timeout_remove(&client->to);
	if (client->io != NULL)
		io_remove(&client->io);
	if (client->input != NULL)
		i_stream_destroy(&client->input);
	if (client->output != NULL)
		o_stream_destroy(&client->output);
	if (client->ssl_iostream != NULL)
		ssl_iostream_unref(&client->ssl_iostream);
	if (client->fd != -1) {
		if (close(client->fd) < 0)
			i_error("close(pop3c) failed: %m");
		client->fd = -1;
	}
	client_login_callback(client, POP3C_COMMAND_STATE_DISCONNECTED,
			      "Disconnected");
}

void pop3c_client_deinit(struct pop3c_client **_client)
{
	struct pop3c_client *client = *_client;

	pop3c_client_disconnect(client);
	if (client->ssl_ctx != NULL)
		ssl_iostream_context_deinit(&client->ssl_ctx);
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

void pop3c_client_run(struct pop3c_client *client)
{
	struct ioloop *ioloop, *prev_ioloop = current_ioloop;
	bool timeout_added = FALSE, failed = FALSE;

	i_assert(client->fd != -1 ||
		 client->state == POP3C_CLIENT_STATE_CONNECTING);

	ioloop = io_loop_create();
	pop3c_client_ioloop_changed(client);

	if (client->ip.family == 0) {
		/* we're connecting, start DNS lookup after our ioloop
		   is created */
		struct dns_lookup_settings dns_set;

		i_assert(client->state == POP3C_CLIENT_STATE_CONNECTING);
		memset(&dns_set, 0, sizeof(dns_set));
		dns_set.dns_client_socket_path =
			client->set.dns_client_socket_path;
		dns_set.timeout_msecs = POP3C_DNS_LOOKUP_TIMEOUT_MSECS;
		if (dns_lookup(client->set.host, &dns_set,
			       pop3c_dns_callback, client,
			       &client->dns_lookup) < 0)
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

	current_ioloop = prev_ioloop;
	pop3c_client_ioloop_changed(client);
	current_ioloop = ioloop;
	io_loop_destroy(&ioloop);
}

static void pop3c_client_authenticate1(struct pop3c_client *client)
{
	const struct pop3c_client_settings *set = &client->set;

	if (client->set.debug) {
		if (set->master_user == NULL) {
			i_debug("pop3c(%s): Authenticating as %s",
				client->set.host, set->username);
		} else {
			i_debug("pop3c(%s): Authenticating as %s for user %s",
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
		pop3c_client_authenticate1(client);
		break;
	case POP3C_CLIENT_STATE_USER:
		if (!success) {
			i_error("pop3c(%s): USER failed: %s",
				client->set.host, line);
			return -1;
		}
		o_stream_nsend_str(client->output,
			t_strdup_printf("PASS %s\r\n", client->set.password));
		client->state = POP3C_CLIENT_STATE_PASS;
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
			i_error("pop3c(%s): Authentication failed: %s",
				client->set.host, line);
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
		if (strcasecmp(line, "PIPELINING") == 0)
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
	} else if (!client->set.ssl_verify) {
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
	struct ssl_iostream_settings ssl_set;
	struct stat st;
	const char *error;

	if (client->ssl_ctx == NULL) {
		i_error("pop3c(%s): No SSL context", client->set.host);
		return -1;
	}

	memset(&ssl_set, 0, sizeof(ssl_set));
	if (client->set.ssl_verify) {
		ssl_set.verbose_invalid_cert = TRUE;
		ssl_set.verify_remote_cert = TRUE;
		ssl_set.require_valid_cert = TRUE;
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
					&ssl_set, &client->input, &client->output,
					&client->ssl_iostream, &error) < 0) {
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

	if (*client->set.rawlog_dir != '\0' &&
	    stat(client->set.rawlog_dir, &st) == 0) {
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
	struct stat st;

	client->fd = net_connect_ip(&client->ip, client->set.port, NULL);
	if (client->fd == -1) {
		pop3c_client_disconnect(client);
		return;
	}

	client->input = client->raw_input =
		i_stream_create_fd(client->fd, POP3C_MAX_INBUF_SIZE, FALSE);
	client->output = client->raw_output =
		o_stream_create_fd(client->fd, (size_t)-1, FALSE);
	o_stream_set_no_error_handling(client->output, TRUE);

	if (*client->set.rawlog_dir != '\0' &&
	    client->set.ssl_mode != POP3C_CLIENT_SSL_MODE_IMMEDIATE &&
	    stat(client->set.rawlog_dir, &st) == 0) {
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

static void pop3c_client_input_reply(struct pop3c_client *client)
{
	i_assert(client->state == POP3C_CLIENT_STATE_DONE);

	if (client->to != NULL)
		timeout_reset(client->to);
	client->input_line = i_stream_read_next_line(client->input);
	if (client->input_line != NULL)
		io_loop_stop(current_ioloop);
	else if (client->input->closed || client->input->eof ||
		 client->input->stream_errno != 0) {
		/* disconnected */
		i_error("pop3c(%s): Server disconnected unexpectedly",
			client->set.host);
		pop3c_client_disconnect(client);
		io_loop_stop(current_ioloop);
	}
}

static int
pop3c_client_read_line(struct pop3c_client *client,
		       const char **line_r, const char **error_r)
{
	i_assert(client->io == NULL);
	i_assert(client->input_line == NULL);

	client->io = io_add(client->fd, IO_READ,
			    pop3c_client_input_reply, client);
	pop3c_client_input_reply(client);
	if (client->input_line == NULL && client->input != NULL)
		pop3c_client_run(client);

	if (client->input_line == NULL) {
		i_assert(client->io == NULL);
		*error_r = "Disconnected";
		return -1;
	}

	io_remove(&client->io);
	*line_r = t_strdup(client->input_line);
	client->input_line = NULL;
	return 0;
}

static int
pop3c_client_flush_asyncs(struct pop3c_client *client, const char **error_r)
{
	const char *line;

	if (client->state != POP3C_CLIENT_STATE_DONE) {
		i_assert(client->state == POP3C_CLIENT_STATE_DISCONNECTED);
		*error_r = "Disconnected";
		return -1;
	}

	while (client->async_commands > 0) {
		if (pop3c_client_read_line(client, &line, error_r) < 0)
			return -1;
		client->async_commands--;
	}
	return 0;
}

int pop3c_client_cmd_line(struct pop3c_client *client, const char *cmd,
			  const char **reply_r)
{
	const char *line;
	int ret;

	if (pop3c_client_flush_asyncs(client, reply_r) < 0)
		return -1;
	o_stream_nsend_str(client->output, cmd);
	if (pop3c_client_read_line(client, &line, reply_r) < 0)
		return -1;
	if (strncasecmp(line, "+OK", 3) == 0) {
		*reply_r = line + 3;
		ret = 0;
	} else if (strncasecmp(line, "-ERR", 4) == 0) {
		*reply_r = line + 4;
		ret = -1;
	} else {
		*reply_r = line;
		ret = -1;
	}
	if (**reply_r == ' ')
		*reply_r += 1;
	return ret;
}

void pop3c_client_cmd_line_async(struct pop3c_client *client, const char *cmd)
{
	const char *error;

	if (client->state != POP3C_CLIENT_STATE_DONE) {
		i_assert(client->state == POP3C_CLIENT_STATE_DISCONNECTED);
		return;
	}

	if ((client->capabilities & POP3C_CAPABILITY_PIPELINING) == 0) {
		if (pop3c_client_flush_asyncs(client, &error) < 0)
			return;
	}
	o_stream_nsend_str(client->output, cmd);
	client->async_commands++;
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
	if (unlink(str_c(path)) < 0) {
		/* shouldn't happen.. */
		i_error("unlink(%s) failed: %m", str_c(path));
		i_close_fd(&fd);
		return -1;
	}

	*path_r = str_c(path);
	return fd;
}

static void pop3c_client_dot_input(struct pop3c_client *client)
{
	ssize_t ret;

	if (client->to != NULL)
		timeout_reset(client->to);
	while ((ret = i_stream_read(client->dot_input)) > 0 || ret == -2) {
		i_stream_skip(client->dot_input,
			      i_stream_get_data_size(client->dot_input));
	}
	if (ret != 0) {
		i_assert(ret == -1);
		if (client->dot_input->stream_errno != 0) {
			i_error("pop3c(%s): Server disconnected unexpectedly",
				client->set.host);
			pop3c_client_disconnect(client);
		}
		if (client->running)
			io_loop_stop(current_ioloop);
	}
}

int pop3c_client_cmd_stream(struct pop3c_client *client, const char *cmd,
			    struct istream **input_r, const char **error_r)
{
	struct istream *inputs[2];

	*input_r = NULL;

	/* read the +OK / -ERR */
	if (pop3c_client_cmd_line(client, cmd, error_r) < 0)
		return -1;
	/* read the stream */
	inputs[0] = i_stream_create_dot(client->input, TRUE);
	inputs[1] = NULL;
	client->dot_input =
		i_stream_create_seekable(inputs, POP3C_MAX_INBUF_SIZE,
					 seekable_fd_callback, client);

	i_assert(client->io == NULL);
	client->io = io_add(client->fd, IO_READ,
			    pop3c_client_dot_input, client);
	/* read any pending data from the stream */
	pop3c_client_dot_input(client);
	if (!client->dot_input->eof)
		pop3c_client_run(client);

	if (client->input == NULL) {
		i_assert(client->io == NULL);
		i_stream_destroy(&client->dot_input);
		*error_r = "Disconnected";
		return -1;
	}
	io_remove(&client->io);
	i_stream_seek(client->dot_input, 0);
	/* if this stream is used by some filter stream, make the filter
	   stream blocking */
	client->dot_input->blocking = TRUE;

	*input_r = client->dot_input;
	client->dot_input = NULL;
	return 0;
}
