/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "istream.h"
#include "istream-tee.h"
#include "ostream.h"
#include "lmtp-client.h"
#include "lmtp-proxy.h"

#define LMTP_MAX_LINE_LEN 1024
#define LMTP_PROXY_DATA_INPUT_TIMEOUT_MSECS (1000*60)

struct lmtp_proxy_recipient {
	struct lmtp_proxy_connection *conn;
	const char *address;
	const char *reply;

	unsigned int rcpt_to_failed:1;
	unsigned int data_reply_received:1;
};

struct lmtp_proxy_connection {
	struct lmtp_proxy *proxy;
	struct lmtp_proxy_settings set;

	struct lmtp_client *client;
	struct istream *data_input;
	unsigned int failed:1;
};

struct lmtp_proxy {
	pool_t pool;
	const char *mail_from, *my_hostname;
	ARRAY_DEFINE(connections, struct lmtp_proxy_connection *);
	ARRAY_DEFINE(rcpt_to, struct lmtp_proxy_recipient);
	unsigned int next_data_reply_idx;

	struct timeout *to, *to_data_idle;
	struct io *io;
	struct istream *data_input, *orig_data_input;
	struct ostream *client_output;
	struct tee_istream *tee_data_input;

	unsigned int max_timeout_msecs;

	lmtp_proxy_finish_callback_t *finish_callback;
	void *finish_context;

	unsigned int finished:1;
	unsigned int input_timeout:1;
};

static void lmtp_conn_finish(void *context);
static void lmtp_proxy_data_input(struct lmtp_proxy *proxy);

struct lmtp_proxy *
lmtp_proxy_init(const char *my_hostname, struct ostream *client_output)
{
	struct lmtp_proxy *proxy;
	pool_t pool;

	o_stream_ref(client_output);

	pool = pool_alloconly_create("lmtp proxy", 1024);
	proxy = p_new(pool, struct lmtp_proxy, 1);
	proxy->pool = pool;
	proxy->my_hostname = p_strdup(pool, my_hostname);
	proxy->client_output = client_output;
	i_array_init(&proxy->rcpt_to, 32);
	i_array_init(&proxy->connections, 32);
	return proxy;
}

static void lmtp_proxy_connections_deinit(struct lmtp_proxy *proxy)
{
	struct lmtp_proxy_connection *const *conns;
	unsigned int i, count;

	conns = array_get(&proxy->connections, &count);
	for (i = 0; i < count; i++) {
		lmtp_client_fail(conns[i]->client, "451 4.3.0 Aborting");
		lmtp_client_deinit(&conns[i]->client);
	}
}

void lmtp_proxy_deinit(struct lmtp_proxy **_proxy)
{
	struct lmtp_proxy *proxy = *_proxy;

	*_proxy = NULL;

	lmtp_proxy_connections_deinit(proxy);
	if (proxy->data_input != NULL)
		i_stream_unref(&proxy->data_input);
	if (proxy->client_output != NULL)
		o_stream_unref(&proxy->client_output);
	if (proxy->to_data_idle != NULL)
		timeout_remove(&proxy->to_data_idle);
	if (proxy->to != NULL)
		timeout_remove(&proxy->to);
	if (proxy->io != NULL)
		io_remove(&proxy->io);
	array_free(&proxy->rcpt_to);
	array_free(&proxy->connections);
	pool_unref(&proxy->pool);
}

void lmtp_proxy_mail_from(struct lmtp_proxy *proxy, const char *value)
{
	proxy->mail_from = p_strdup(proxy->pool, value);
}

static struct lmtp_proxy_connection *
lmtp_proxy_get_connection(struct lmtp_proxy *proxy,
			  const struct lmtp_proxy_settings *set)
{
	struct lmtp_proxy_connection *const *conns, *conn;
	unsigned int i, count;

	i_assert(set->timeout_msecs > 0);

	conns = array_get(&proxy->connections, &count);
	for (i = 0; i < count; i++) {
		if (conns[i]->set.port == set->port &&
		    strcmp(conns[i]->set.host, set->host) == 0)
			return conns[i];
	}

	conn = p_new(proxy->pool, struct lmtp_proxy_connection, 1);
	conn->proxy = proxy;
	conn->set.host = p_strdup(proxy->pool, set->host);
	conn->set.port = set->port;
	conn->set.timeout_msecs = set->timeout_msecs;
	array_append(&proxy->connections, &conn, 1);
	conn->client = lmtp_client_init(proxy->mail_from, proxy->my_hostname,
					lmtp_conn_finish, conn);
	if (lmtp_client_connect_tcp(conn->client, set->protocol,
				    conn->set.host, conn->set.port) < 0)
		conn->failed = TRUE;

	if (proxy->max_timeout_msecs < set->timeout_msecs)
		proxy->max_timeout_msecs = set->timeout_msecs;
	return conn;
}

static bool lmtp_proxy_send_data_replies(struct lmtp_proxy *proxy)
{
	const struct lmtp_proxy_recipient *rcpt;
	unsigned int i, count;

	o_stream_cork(proxy->client_output);
	rcpt = array_get(&proxy->rcpt_to, &count);
	for (i = proxy->next_data_reply_idx; i < count; i++) {
		if (!(rcpt[i].rcpt_to_failed || rcpt[i].data_reply_received))
			break;
		o_stream_send_str(proxy->client_output,
				  t_strconcat(rcpt[i].reply, "\r\n", NULL));
	}
	o_stream_uncork(proxy->client_output);
	proxy->next_data_reply_idx = i;

	return i == count;
}

static void lmtp_proxy_finish(struct lmtp_proxy *proxy)
{
	i_assert(!proxy->finished);

	proxy->finished = TRUE;
	proxy->finish_callback(proxy->input_timeout, proxy->finish_context);
}

static void lmtp_proxy_try_finish(struct lmtp_proxy *proxy)
{
	if (lmtp_proxy_send_data_replies(proxy) &&
	    (proxy->data_input->eof || proxy->data_input->stream_errno != 0))
		lmtp_proxy_finish(proxy);
}

static void lmtp_conn_finish(void *context)
{
	struct lmtp_proxy_connection *conn = context;

	if (conn->data_input != NULL)
		i_stream_unref(&conn->data_input);
	lmtp_proxy_try_finish(conn->proxy);
}

static void lmtp_proxy_fail_all(struct lmtp_proxy *proxy, const char *reason)
{
	struct lmtp_proxy_connection *const *conns;
	unsigned int i, count;
	const char *line;

	pool_ref(proxy->pool);
	conns = array_get(&proxy->connections, &count);
	for (i = 0; i < count; i++) {
		line = t_strdup_printf(ERRSTR_TEMP_REMOTE_FAILURE
				" (%s while waiting for reply to %s)", reason,
				lmtp_client_state_to_string(conns[i]->client));
		lmtp_client_fail(conns[i]->client, line);

		if (!array_is_created(&proxy->connections))
			break;
	}
	pool_unref(&proxy->pool);
	/* either the whole proxy is destroyed now, or we still have some
	   DATA input to read. */
}

static void lmtp_proxy_data_input_timeout(struct lmtp_proxy *proxy)
{
	struct lmtp_proxy_connection *const *conns;
	unsigned int i, count;

	proxy->input_timeout = TRUE;
	i_stream_close(proxy->orig_data_input);

	pool_ref(proxy->pool);
	conns = array_get(&proxy->connections, &count);
	for (i = 0; i < count; i++) {
		lmtp_client_fail(conns[i]->client, ERRSTR_TEMP_REMOTE_FAILURE
				 " (timeout in DATA input)");
		if (!array_is_created(&proxy->connections)) {
			pool_unref(&proxy->pool);
			return;
		}
	}
	/* last client failure should have caused the proxy to be destroyed */
	i_unreached();
}

static void
lmtp_proxy_conn_rcpt_to(bool success, const char *reply, void *context)
{
	struct lmtp_proxy_recipient *rcpt = context;
	struct lmtp_proxy_connection *conn = rcpt->conn;

	i_assert(rcpt->reply == NULL);

	rcpt->reply = p_strdup(conn->proxy->pool, reply);
	rcpt->rcpt_to_failed = !success;
}

static void
lmtp_proxy_conn_data(bool success ATTR_UNUSED, const char *reply, void *context)
{
	struct lmtp_proxy_recipient *rcpt = context;
	struct lmtp_proxy_connection *conn = rcpt->conn;

	i_assert(!rcpt->rcpt_to_failed);
	i_assert(rcpt->reply != NULL);

	rcpt->reply = p_strdup(conn->proxy->pool, reply);
	rcpt->data_reply_received = TRUE;
}

int lmtp_proxy_add_rcpt(struct lmtp_proxy *proxy, const char *address,
			const struct lmtp_proxy_settings *set)
{
	struct lmtp_proxy_connection *conn;
	struct lmtp_proxy_recipient *rcpt;

	conn = lmtp_proxy_get_connection(proxy, set);
	if (conn->failed)
		return -1;

	rcpt = array_append_space(&proxy->rcpt_to);
	rcpt->conn = conn;
	rcpt->address = p_strdup(proxy->pool, address);

	lmtp_client_add_rcpt(conn->client, address, lmtp_proxy_conn_rcpt_to,
			     lmtp_proxy_conn_data, rcpt);
	return 0;
}

static size_t lmtp_proxy_find_max_data_input_size(struct lmtp_proxy *proxy)
{
	struct lmtp_proxy_connection *const *conns;
	unsigned int i, count;
	size_t size, max_size = 0;

	conns = array_get(&proxy->connections, &count);
	for (i = 0; i < count; i++) {
		(void)i_stream_get_data(conns[i]->data_input, &size);
		if (max_size < size)
			max_size = size;
	}
	return max_size;
}

static bool lmtp_proxy_disconnect_hanging_output(struct lmtp_proxy *proxy)
{
	struct lmtp_proxy_connection *const *conns;
	unsigned int i, count;
	size_t size, max_size;

	max_size = lmtp_proxy_find_max_data_input_size(proxy);
	if (max_size == 0)
		return FALSE;

	/* disconnect all connections that are keeping us from reading
	   more input. */
	conns = array_get(&proxy->connections, &count);
	for (i = 0; i < count; i++) {
		(void)i_stream_get_data(conns[i]->data_input, &size);
		if (size == max_size) {
			lmtp_client_fail(conns[i]->client,
					 ERRSTR_TEMP_REMOTE_FAILURE
					 " (DATA output timeout)");
		}
	}
	return TRUE;
}

static void lmtp_proxy_output_timeout(struct lmtp_proxy *proxy)
{
	timeout_remove(&proxy->to);

	/* drop the connection with the most unread data */
	if (lmtp_proxy_disconnect_hanging_output(proxy))
		lmtp_proxy_data_input(proxy);
	else {
		/* no such connection, so we've already sent everything but
		   some servers aren't replying to us. disconnect all of
		   them. */
		lmtp_proxy_fail_all(proxy, "timeout");
	}
}

static void lmtp_proxy_wait_for_output(struct lmtp_proxy *proxy)
{
	i_assert(proxy->to == NULL);

	if (proxy->io != NULL)
		io_remove(&proxy->io);
	proxy->to = timeout_add(proxy->max_timeout_msecs,
				lmtp_proxy_output_timeout, proxy);
}

static bool lmtp_proxy_data_read(struct lmtp_proxy *proxy)
{
	size_t size;

	timeout_reset(proxy->to_data_idle);

	switch (i_stream_read(proxy->data_input)) {
	case 0:
		if (!tee_i_stream_child_is_waiting(proxy->data_input)) {
			/* nothing new read */
			if (proxy->io != NULL)
				return FALSE;
			proxy->io = io_add(i_stream_get_fd(proxy->data_input),
					   IO_READ,
					   lmtp_proxy_data_input, proxy);
			return FALSE;
		}
		/* fall through */
	case -2:
		/* buffer full. someone's stalling. */
		lmtp_proxy_wait_for_output(proxy);
		return FALSE;
	case -1:
		if (proxy->data_input->stream_errno != 0)
			lmtp_proxy_fail_all(proxy, "disconnect");
		else {
			/* finished reading data input. now we'll just have to
			   wait for replies. */
			lmtp_proxy_wait_for_output(proxy);
			/* if all RCPT TOs failed, we can finish now */
			lmtp_proxy_try_finish(proxy);
		}
		return FALSE;
	default:
		/* something was read */
		(void)i_stream_get_data(proxy->data_input, &size);
		i_stream_skip(proxy->data_input, size);
		return TRUE;
	}
}

static void lmtp_proxy_data_input(struct lmtp_proxy *proxy)
{
	struct lmtp_proxy_connection *const *conns;
	unsigned int i, count;

	do {
		conns = array_get(&proxy->connections, &count);
		for (i = 0; i < count; i++)
			lmtp_client_send_more(conns[i]->client);
	} while (lmtp_proxy_data_read(proxy));
}

void lmtp_proxy_start(struct lmtp_proxy *proxy, struct istream *data_input,
		      const char *header,
		      lmtp_proxy_finish_callback_t *callback, void *context)
{
	struct lmtp_proxy_connection *const *conns;
	unsigned int i, count;

	proxy->finish_callback = callback;
	proxy->finish_context = context;
	proxy->orig_data_input = data_input;
	proxy->tee_data_input = tee_i_stream_create(data_input);
	proxy->data_input = tee_i_stream_create_child(proxy->tee_data_input);
	proxy->to_data_idle = timeout_add(LMTP_PROXY_DATA_INPUT_TIMEOUT_MSECS,
					  lmtp_proxy_data_input_timeout, proxy);

	conns = array_get(&proxy->connections, &count);
	for (i = 0; i < count; i++) {
		conns[i]->data_input =
			tee_i_stream_create_child(proxy->tee_data_input);
		lmtp_client_set_data_header(conns[i]->client, header);
		lmtp_client_send(conns[i]->client, conns[i]->data_input);
	}

	lmtp_proxy_data_input(proxy);
}
