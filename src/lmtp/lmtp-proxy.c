/* Copyright (c) 2009-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "lmtp-client.h"
#include "lmtp-proxy.h"

#define LMTP_MAX_LINE_LEN 1024

struct lmtp_proxy_recipient {
	struct lmtp_proxy_connection *conn;
	const char *address;
	const char *reply;

	unsigned int rcpt_to_failed:1;
	unsigned int data_reply_received:1;
};

struct lmtp_proxy_connection {
	struct lmtp_proxy *proxy;
	struct lmtp_proxy_rcpt_settings set;

	struct lmtp_client *client;
	struct istream *data_input;
	struct timeout *to;

	unsigned int finished:1;
	unsigned int failed:1;
};

struct lmtp_proxy {
	pool_t pool;
	const char *mail_from;
	struct lmtp_proxy_settings set;

	ARRAY(struct lmtp_proxy_connection *) connections;
	ARRAY(struct lmtp_proxy_recipient *) rcpt_to;
	unsigned int next_data_reply_idx;

	struct timeout *to_finish;
	struct istream *data_input;
	struct ostream *client_output;

	unsigned int max_timeout_msecs;

	lmtp_proxy_finish_callback_t *finish_callback;
	void *finish_context;

	unsigned int finished:1;
};

static void lmtp_conn_finish(void *context);

struct lmtp_proxy *
lmtp_proxy_init(const struct lmtp_proxy_settings *set,
		struct ostream *client_output)
{
	struct lmtp_proxy *proxy;
	pool_t pool;

	i_assert(set->proxy_ttl > 0);
	o_stream_ref(client_output);

	pool = pool_alloconly_create("lmtp proxy", 1024);
	proxy = p_new(pool, struct lmtp_proxy, 1);
	proxy->pool = pool;
	proxy->client_output = client_output;
	proxy->set.my_hostname = p_strdup(pool, set->my_hostname);
	proxy->set.dns_client_socket_path =
		p_strdup(pool, set->dns_client_socket_path);
	proxy->set.session_id = p_strdup(pool, set->session_id);
	proxy->set.source_ip = set->source_ip;
	proxy->set.source_port = set->source_port;
	proxy->set.proxy_ttl = set->proxy_ttl;
	i_array_init(&proxy->rcpt_to, 32);
	i_array_init(&proxy->connections, 32);
	return proxy;
}

static void lmtp_proxy_connections_deinit(struct lmtp_proxy *proxy)
{
	struct lmtp_proxy_connection *const *conns;

	array_foreach(&proxy->connections, conns) {
		struct lmtp_proxy_connection *conn = *conns;

		lmtp_client_deinit(&conn->client);
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
	if (proxy->to_finish != NULL)
		timeout_remove(&proxy->to_finish);
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
			  const struct lmtp_proxy_rcpt_settings *set)
{
	struct lmtp_proxy_connection *const *conns, *conn;
	struct lmtp_client_settings client_set;

	i_assert(set->timeout_msecs > 0);

	array_foreach(&proxy->connections, conns) {
		conn = *conns;

		if (conn->set.port == set->port &&
		    strcmp(conn->set.host, set->host) == 0)
			return conn;
	}

	memset(&client_set, 0, sizeof(client_set));
	client_set.mail_from = proxy->mail_from;
	client_set.my_hostname = proxy->set.my_hostname;
	client_set.dns_client_socket_path = proxy->set.dns_client_socket_path;
	client_set.source_ip = proxy->set.source_ip;
	client_set.source_port = proxy->set.source_port;
	client_set.proxy_ttl = proxy->set.proxy_ttl;
	client_set.proxy_timeout_secs = set->timeout_msecs/1000;

	conn = p_new(proxy->pool, struct lmtp_proxy_connection, 1);
	conn->proxy = proxy;
	conn->set.host = p_strdup(proxy->pool, set->host);
	conn->set.port = set->port;
	conn->set.timeout_msecs = set->timeout_msecs;
	array_append(&proxy->connections, &conn, 1);

	conn->client = lmtp_client_init(&client_set, lmtp_conn_finish, conn);
	if (lmtp_client_connect_tcp(conn->client, set->protocol,
				    conn->set.host, conn->set.port) < 0)
		conn->failed = TRUE;

	if (proxy->max_timeout_msecs < set->timeout_msecs)
		proxy->max_timeout_msecs = set->timeout_msecs;
	return conn;
}

static bool lmtp_proxy_send_data_replies(struct lmtp_proxy *proxy)
{
	struct lmtp_proxy_recipient *const *rcpt;
	unsigned int i, count;

	o_stream_cork(proxy->client_output);
	rcpt = array_get(&proxy->rcpt_to, &count);
	for (i = proxy->next_data_reply_idx; i < count; i++) {
		if (!(rcpt[i]->rcpt_to_failed || rcpt[i]->data_reply_received))
			break;
		o_stream_nsend_str(proxy->client_output,
				   t_strconcat(rcpt[i]->reply, "\r\n", NULL));
	}
	o_stream_uncork(proxy->client_output);
	proxy->next_data_reply_idx = i;

	return i == count;
}

static void lmtp_proxy_finish_timeout(struct lmtp_proxy *proxy)
{
	i_assert(!proxy->finished);

	timeout_remove(&proxy->to_finish);
	proxy->finished = TRUE;
	proxy->finish_callback(proxy->finish_context);
}

static void lmtp_proxy_try_finish(struct lmtp_proxy *proxy)
{
	if (proxy->finish_callback == NULL) {
		/* DATA command hasn't been sent yet */
		return;
	}
	if (!lmtp_proxy_send_data_replies(proxy)) {
		/* we can't received reply from all clients yet */
		return;
	}
	/* do the actual finishing in a timeout handler, since the finish
	   callback causes the proxy to be destroyed and the code leading up
	   to this function can be called from many different places. it's
	   easier this way rather than having all the callers check if the
	   proxy was already destroyed. */
	if (proxy->to_finish == NULL) {
		proxy->to_finish = timeout_add(0, lmtp_proxy_finish_timeout,
					       proxy);
	}
}

static void lmtp_conn_finish(void *context)
{
	struct lmtp_proxy_connection *conn = context;

	conn->finished = TRUE;
	if (conn->to != NULL)
		timeout_remove(&conn->to);
	if (conn->data_input != NULL)
		i_stream_unref(&conn->data_input);
	lmtp_proxy_try_finish(conn->proxy);
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

	/* reset timeout in case there are a lot of RCPT TOs */
	if (conn->to != NULL)
		timeout_reset(conn->to);

	rcpt->reply = p_strdup(conn->proxy->pool, reply);
	rcpt->data_reply_received = TRUE;

	lmtp_proxy_try_finish(conn->proxy);
}

int lmtp_proxy_add_rcpt(struct lmtp_proxy *proxy, const char *address,
			const struct lmtp_proxy_rcpt_settings *set)
{
	struct lmtp_proxy_connection *conn;
	struct lmtp_proxy_recipient *rcpt;

	conn = lmtp_proxy_get_connection(proxy, set);
	if (conn->failed)
		return -1;

	rcpt = p_new(proxy->pool, struct lmtp_proxy_recipient, 1);
	rcpt->conn = conn;
	rcpt->address = p_strdup(proxy->pool, address);
	array_append(&proxy->rcpt_to, &rcpt, 1);

	lmtp_client_add_rcpt(conn->client, address, lmtp_proxy_conn_rcpt_to,
			     lmtp_proxy_conn_data, rcpt);
	return 0;
}

static void lmtp_proxy_conn_timeout(struct lmtp_proxy_connection *conn)
{
	const char *line;

	line = t_strdup_printf(ERRSTR_TEMP_REMOTE_FAILURE
			       " (timeout while waiting for reply to %s) <%s>",
			       lmtp_client_state_to_string(conn->client),
			       conn->proxy->set.session_id);
	lmtp_client_fail(conn->client, line);
}

void lmtp_proxy_start(struct lmtp_proxy *proxy, struct istream *data_input,
		      const char *header,
		      lmtp_proxy_finish_callback_t *callback, void *context)
{
	struct lmtp_proxy_connection *const *conns;

	i_assert(data_input->seekable);

	proxy->finish_callback = callback;
	proxy->finish_context = context;
	proxy->data_input = data_input;
	i_stream_ref(proxy->data_input);

	array_foreach(&proxy->connections, conns) {
		struct lmtp_proxy_connection *conn = *conns;

		if (conn->finished) {
			/* this connection had already failed */
			continue;
		}

		conn->to = timeout_add(proxy->max_timeout_msecs,
				       lmtp_proxy_conn_timeout, conn);

		conn->data_input = i_stream_create_limit(data_input, (uoff_t)-1);
		lmtp_client_set_data_header(conn->client, header);
		lmtp_client_send(conn->client, conn->data_input);
		lmtp_client_send_more(conn->client);
	}
	/* finish if all of the connections have already failed */
	lmtp_proxy_try_finish(proxy);
}
