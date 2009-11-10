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

	/* points to proxy->rcpt_to array. */
	unsigned int rcpt_next_reply_low_idx;
	unsigned int data_next_reply_low_idx;

	struct lmtp_client *client;
	struct istream *data_input;
	unsigned int failed:1;
};

struct lmtp_proxy {
	pool_t pool;
	const char *mail_from, *my_hostname;
	ARRAY_DEFINE(connections, struct lmtp_proxy_connection *);
	ARRAY_DEFINE(rcpt_to, struct lmtp_proxy_recipient);
	unsigned int rcpt_next_reply_idx;

	struct timeout *to, *to_data_idle;
	struct io *io;
	struct istream *data_input;
	struct ostream *client_output;
	struct tee_istream *tee_data_input;

	unsigned int max_timeout_msecs;

	void (*finish_callback)(void *);
	void *finish_context;

	unsigned int finished:1;
};

static void lmtp_proxy_conn_deinit(struct lmtp_proxy_connection *conn,
				   const char *reason);
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
	for (i = 0; i < count; i++)
		lmtp_proxy_conn_deinit(conns[i], "451 4.3.0 Aborting");
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
	conn->client = lmtp_client_init(proxy->mail_from, proxy->my_hostname);
	if (lmtp_client_connect_tcp(conn->client, set->protocol,
				    conn->set.host, conn->set.port) < 0)
		conn->failed = TRUE;

	if (proxy->max_timeout_msecs < set->timeout_msecs)
		proxy->max_timeout_msecs = set->timeout_msecs;
	return conn;
}

static void lmtp_proxy_conn_deinit(struct lmtp_proxy_connection *conn,
				   const char *reason)
{
	struct lmtp_proxy_recipient *rcpt;

	/* set failure replies to all recipients in this connection */
	array_foreach_modifiable(&conn->proxy->rcpt_to, rcpt) {
		if (rcpt->conn == conn && !rcpt->rcpt_to_failed)
			rcpt->reply = reason;
	}

	if (conn->client != NULL)
		lmtp_client_deinit(&conn->client);
	if (conn->data_input != NULL)
		i_stream_unref(&conn->data_input);
	conn->failed = TRUE;
}

static bool lmtp_proxy_send_replies(struct lmtp_proxy *proxy)
{
	const struct lmtp_proxy_recipient *rcpt;
	unsigned int i, count;

	o_stream_cork(proxy->client_output);
	rcpt = array_get(&proxy->rcpt_to, &count);
	for (i = proxy->rcpt_next_reply_idx; i < count; i++) {
		if (!(rcpt[i].rcpt_to_failed || rcpt[i].data_reply_received))
			break;
		o_stream_send_str(proxy->client_output,
				  t_strconcat(rcpt[i].reply, "\r\n", NULL));
	}
	o_stream_uncork(proxy->client_output);
	proxy->rcpt_next_reply_idx = i;

	return i == count;
}

static void lmtp_proxy_finish(struct lmtp_proxy *proxy)
{
	i_assert(!proxy->finished);

	proxy->finished = TRUE;
	proxy->finish_callback(proxy->finish_context);
}

static void lmtp_proxy_try_finish(struct lmtp_proxy *proxy)
{
	if (lmtp_proxy_send_replies(proxy))
		lmtp_proxy_finish(proxy);
}

static void lmtp_proxy_fail_all(struct lmtp_proxy *proxy, const char *line)
{
	struct lmtp_proxy_recipient *rcpt;
	unsigned int i, count;
	bool ret;

	rcpt = array_get_modifiable(&proxy->rcpt_to, &count);
	for (i = proxy->rcpt_next_reply_idx; i < count; i++) {
		if (!rcpt[i].rcpt_to_failed) {
			i_assert(!rcpt[i].data_reply_received);
			rcpt[i].reply = line;
			rcpt[i].data_reply_received = TRUE;
		}
	}
	ret = lmtp_proxy_send_replies(proxy);
	i_assert(ret);

	lmtp_proxy_finish(proxy);
}

static void lmtp_proxy_data_input_timeout(struct lmtp_proxy *proxy)
{
	lmtp_proxy_fail_all(proxy, "451 4.4.2 Input timeout in DATA");
}

static void lmtp_proxy_data_disconnected(struct lmtp_proxy *proxy)
{
	lmtp_proxy_fail_all(proxy, "451 4.4.2 Client disconnected in DATA");
}

static void
lmtp_proxy_conn_rcpt_to(bool success, const char *reply, void *context)
{
	struct lmtp_proxy_connection *conn = context;
	struct lmtp_proxy_recipient *rcpt;
	unsigned int i, count;

	rcpt = array_get_modifiable(&conn->proxy->rcpt_to, &count);
	for (i = conn->rcpt_next_reply_low_idx; i < count; i++) {
		if (rcpt[i].conn == conn) {
			i_assert(rcpt[i].reply == NULL);
			rcpt[i].reply = p_strdup(conn->proxy->pool, reply);
			rcpt[i].rcpt_to_failed = !success;
			conn->rcpt_next_reply_low_idx = i + 1;
			break;
		}
	}
	i_assert(i != count);

	/* send replies only if we've already sent DATA. */
	if (conn->proxy->data_input != NULL)
		lmtp_proxy_try_finish(conn->proxy);
}

static void
lmtp_proxy_conn_data(bool success ATTR_UNUSED, const char *reply, void *context)
{
	struct lmtp_proxy_connection *conn = context;
	struct lmtp_proxy_recipient *rcpt;
	unsigned int i, count;

	i_assert(conn->proxy->data_input != NULL);

	rcpt = array_get_modifiable(&conn->proxy->rcpt_to, &count);
	for (i = conn->data_next_reply_low_idx; i < count; i++) {
		if (rcpt[i].conn == conn && !rcpt[i].rcpt_to_failed) {
			i_assert(rcpt[i].reply != NULL);
			rcpt[i].reply = p_strdup(conn->proxy->pool, reply);
			rcpt[i].data_reply_received = TRUE;
			conn->data_next_reply_low_idx = i + 1;
			break;
		}
	}
	i_assert(i != count);
	lmtp_proxy_try_finish(conn->proxy);
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
			     lmtp_proxy_conn_data, conn);
	return 0;
}

static void lmtp_proxy_output_timeout(struct lmtp_proxy *proxy)
{
	struct lmtp_proxy_connection *const *conns, *max_conn = NULL;
	unsigned int i, count;
	size_t size, max_size = 0;

	timeout_remove(&proxy->to);

	/* drop the connection with the most unread data */
	conns = array_get(&proxy->connections, &count);
	for (i = 0; i < count; i++) {
		(void)i_stream_get_data(conns[i]->data_input, &size);
		if (max_size < size) {
			max_size = size;
			max_conn = conns[i];
		}
	}
	i_assert(max_conn != NULL);

	lmtp_proxy_conn_deinit(max_conn, ERRSTR_TEMP_REMOTE_FAILURE
			       " (timeout)");
}

static void lmtp_proxy_wait_for_output(struct lmtp_proxy *proxy)
{
	i_assert(proxy->to == NULL);

	if (proxy->io != NULL)
		io_remove(&proxy->io);
	if (array_count(&proxy->connections) > 1) {
		proxy->to = timeout_add(proxy->max_timeout_msecs,
					lmtp_proxy_output_timeout, proxy);
	}
}

static bool lmtp_proxy_data_read(struct lmtp_proxy *proxy)
{
	size_t size;

	timeout_reset(proxy->to_data_idle);

	switch (i_stream_read(proxy->data_input)) {
	case -2:
		/* buffer full. someone's stalling. */
		lmtp_proxy_wait_for_output(proxy);
		return FALSE;
	case -1:
		if (proxy->data_input->stream_errno != 0)
			lmtp_proxy_data_disconnected(proxy);
		else {
			/* finished reading data input. now we'll just have to
			   wait for replies. */
			lmtp_proxy_wait_for_output(proxy);
			/* if all RCPT TOs failed, we can finish now */
			lmtp_proxy_try_finish(proxy);
		}
		return FALSE;
	case 0:
		/* nothing new read */
		if (proxy->io == NULL) {
			proxy->io = io_add(i_stream_get_fd(proxy->data_input),
					   IO_READ,
					   lmtp_proxy_data_input, proxy);
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
		      void (*finish_callback)(void *), void *context)
{
	struct lmtp_proxy_connection *const *conns;
	unsigned int i, count;

	proxy->finish_callback = finish_callback;
	proxy->finish_context = context;
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
