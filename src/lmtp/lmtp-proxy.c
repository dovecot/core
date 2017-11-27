/* Copyright (c) 2009-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "istream.h"
#include "istream-sized.h"
#include "ostream.h"
#include "str.h"
#include "time-util.h"
#include "smtp-reply.h"
#include "smtp-client.h"
#include "smtp-client-connection.h"
#include "smtp-client-transaction.h"
#include "lmtp-proxy.h"

#define LMTP_MAX_LINE_LEN 1024

struct lmtp_proxy_recipient {
	struct lmtp_proxy_connection *conn;
	const struct smtp_address *address;
	const char *reply;
	unsigned int idx;

	bool rcpt_to_failed:1;
	bool data_reply_received:1;
};

struct lmtp_proxy_connection {
	struct lmtp_proxy *proxy;
	struct lmtp_proxy_rcpt_settings set;

	struct smtp_client_transaction *lmtp_trans;
	struct istream *data_input;
	struct timeout *to;

	bool finished:1;
	bool failed:1;
};

struct lmtp_proxy {
	pool_t pool;
	const struct smtp_address *mail_from;
	struct smtp_params_mail mail_params;
	struct lmtp_proxy_settings set;
	struct smtp_server_transaction *trans;

	struct smtp_client *lmtp_client;

	ARRAY(struct lmtp_proxy_connection *) connections;
	ARRAY(struct lmtp_proxy_recipient *) rcpt_to;
	unsigned int next_data_reply_idx;

	struct timeout *to_finish;
	struct istream *data_input;
	struct ostream *client_output;

	unsigned int max_timeout_msecs;

	lmtp_proxy_finish_callback_t *finish_callback;
	void *finish_context;

	bool finished:1;
};

static void
lmtp_proxy_connection_finish(struct lmtp_proxy_connection *conn);
static void
lmtp_proxy_data_cb(const struct smtp_reply *reply,
		   struct lmtp_proxy_recipient *rcpt);

struct lmtp_proxy *
lmtp_proxy_init(const struct lmtp_proxy_settings *set,
		struct ostream *client_output)
{
	struct smtp_client_settings lmtp_set;
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

	i_zero(&lmtp_set);
	lmtp_set.my_hostname = set->my_hostname;
	lmtp_set.dns_client_socket_path = set->dns_client_socket_path;

	lmtp_set.proxy_data.source_ip = set->source_ip;
	lmtp_set.proxy_data.source_port = set->source_port;
	lmtp_set.proxy_data.ttl_plus_1 = set->proxy_ttl;
	if (lmtp_set.proxy_data.ttl_plus_1 == 0)
		lmtp_set.proxy_data.ttl_plus_1 = LMTP_PROXY_DEFAULT_TTL + 1;
	else
		lmtp_set.proxy_data.ttl_plus_1--;

	proxy->lmtp_client = smtp_client_init(&lmtp_set);
	return proxy;
}

static void lmtp_proxy_connections_deinit(struct lmtp_proxy *proxy)
{
	struct lmtp_proxy_connection *const *conns;

	array_foreach(&proxy->connections, conns) {
		struct lmtp_proxy_connection *conn = *conns;

		if (conn->lmtp_trans != NULL)
			smtp_client_transaction_destroy(&conn->lmtp_trans);
	}
}

void lmtp_proxy_deinit(struct lmtp_proxy **_proxy)
{
	struct lmtp_proxy *proxy = *_proxy;

	*_proxy = NULL;

	lmtp_proxy_connections_deinit(proxy);
	smtp_client_deinit(&proxy->lmtp_client);
	i_stream_unref(&proxy->data_input);
	o_stream_unref(&proxy->client_output);
	timeout_remove(&proxy->to_finish);
	array_free(&proxy->rcpt_to);
	array_free(&proxy->connections);
	pool_unref(&proxy->pool);
}

void lmtp_proxy_mail_from(struct lmtp_proxy *proxy,
			  const struct smtp_address *address,
			  const struct smtp_params_mail *params)
{
	proxy->mail_from = smtp_address_clone(proxy->pool, address);
	smtp_params_mail_copy(proxy->pool, &proxy->mail_params, params);
}

static void
lmtp_proxy_mail_cb(const struct smtp_reply *proxy_reply ATTR_UNUSED,
		   struct lmtp_proxy_connection *conn ATTR_UNUSED)
{
	/* nothing */
}

static struct lmtp_proxy_connection *
lmtp_proxy_get_connection(struct lmtp_proxy *proxy,
			  const struct lmtp_proxy_rcpt_settings *set)
{
	struct smtp_client_connection *lmtp_conn;
	struct lmtp_proxy_connection *const *conns, *conn;
	const char *host = (set->hostip.family == 0 ?
		set->host : net_ip2addr(&set->hostip));

	i_assert(set->timeout_msecs > 0);

	array_foreach(&proxy->connections, conns) {
		conn = *conns;

		if (conn->set.protocol == set->protocol &&
		    conn->set.port == set->port &&
		    strcmp(conn->set.host, host) == 0)
			return conn;
	}

	conn = p_new(proxy->pool, struct lmtp_proxy_connection, 1);
	conn->proxy = proxy;
	conn->set.protocol = set->protocol;
	conn->set.hostip = set->hostip;
	conn->set.host = p_strdup(proxy->pool, host);
	conn->set.port = set->port;
	conn->set.timeout_msecs = set->timeout_msecs;
	array_append(&proxy->connections, &conn, 1);

	lmtp_conn = smtp_client_connection_create(proxy->lmtp_client,
		set->protocol, conn->set.host, conn->set.port,
		SMTP_CLIENT_SSL_MODE_NONE, NULL);
	smtp_client_connection_connect(lmtp_conn, NULL, NULL);

	conn->lmtp_trans = smtp_client_transaction_create(lmtp_conn,
		proxy->mail_from, &proxy->mail_params,
		lmtp_proxy_connection_finish, conn);
	smtp_client_connection_unref(&lmtp_conn);

	smtp_client_transaction_start(conn->lmtp_trans,
				      lmtp_proxy_mail_cb, conn);

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

static void
lmtp_proxy_connection_finish(struct lmtp_proxy_connection *conn)
{
	conn->finished = TRUE;
	conn->lmtp_trans = NULL;
	timeout_remove(&conn->to);
	i_stream_unref(&conn->data_input);
	lmtp_proxy_try_finish(conn->proxy);
}

static void
lmtp_proxy_write_reply(string_t *reply, const struct smtp_reply *proxy_reply)
{
	if (smtp_reply_is_remote(proxy_reply)) {
		smtp_reply_write_one_line(reply, proxy_reply);
	} else {
		str_append(reply, "451 4.4.0 Remote server not answering");
		switch (proxy_reply->status) {
		case SMTP_CLIENT_COMMAND_ERROR_HOST_LOOKUP_FAILED:
			str_append(reply, " (DNS lookup)");
			break;
		case SMTP_CLIENT_COMMAND_ERROR_CONNECT_FAILED:
		case SMTP_CLIENT_COMMAND_ERROR_AUTH_FAILED:
			str_append(reply, " (connect)");
			break;
		case SMTP_CLIENT_COMMAND_ERROR_CONNECTION_LOST:
			str_append(reply, " (connection lost)");
			break;
		case SMTP_CLIENT_COMMAND_ERROR_BAD_REPLY:
			str_append(reply, " (bad reply)");
			break;			
		case SMTP_CLIENT_COMMAND_ERROR_TIMED_OUT:
			str_append(reply, " (timed out)");
			break;
		default:
			break;
		}
	}
}

static void
lmtp_proxy_rcpt_cb(const struct smtp_reply *proxy_reply,
		   struct lmtp_proxy_recipient *rcpt)
{
	struct lmtp_proxy_connection *conn = rcpt->conn;
	string_t *reply;

	i_assert(rcpt->reply == NULL);

	reply = t_str_new(128);
	lmtp_proxy_write_reply(reply, proxy_reply);

	rcpt->reply = p_strdup(conn->proxy->pool, str_c(reply));
	rcpt->rcpt_to_failed = !smtp_reply_is_success(proxy_reply);
}

static void
lmtp_proxy_data_cb(const struct smtp_reply *proxy_reply,
		   struct lmtp_proxy_recipient *rcpt)
{
	struct lmtp_proxy_connection *conn = rcpt->conn;
	const struct smtp_client_transaction_times *times =
		smtp_client_transaction_get_times(conn->lmtp_trans);
	string_t *reply;
	string_t *msg;

	i_assert(!rcpt->rcpt_to_failed);
	i_assert(rcpt->reply != NULL);

	/* reset timeout in case there are a lot of RCPT TOs */
	if (conn->to != NULL)
		timeout_reset(conn->to);

	reply = t_str_new(128);
	lmtp_proxy_write_reply(reply, proxy_reply);

	rcpt->reply = p_strdup(conn->proxy->pool, str_c(reply));
	rcpt->data_reply_received = TRUE;

	msg = t_str_new(128);
	str_printfa(msg, "%s: ", conn->proxy->set.session_id);
	if (smtp_reply_is_success(proxy_reply))
		str_append(msg, "Sent message to");
	else
		str_append(msg, "Failed to send message to");
	str_printfa(msg, " <%s> at %s:%u: %s (%u/%u at %u ms)",
		    smtp_address_encode(rcpt->address), conn->set.host,
		    conn->set.port, str_c(reply),
		    rcpt->idx + 1, array_count(&conn->proxy->rcpt_to),
		    timeval_diff_msecs(&ioloop_timeval, &times->started));
	if (smtp_reply_is_success(proxy_reply) ||
		smtp_reply_is_remote(proxy_reply)) {
		/* the problem isn't with the proxy, it's with the remote side.
		   so the remote side will log an error, while for us this is
		   just an info event */
		i_info("%s", str_c(msg));
	} else {
		i_error("%s", str_c(msg));
	}
	lmtp_proxy_try_finish(conn->proxy);
}

int lmtp_proxy_add_rcpt(struct lmtp_proxy *proxy,
			const struct smtp_address *address,
			const struct lmtp_proxy_rcpt_settings *set)
{
	struct lmtp_proxy_connection *conn;
	struct lmtp_proxy_recipient *rcpt;

	conn = lmtp_proxy_get_connection(proxy, set);
	if (conn->failed)
		return -1;

	rcpt = p_new(proxy->pool, struct lmtp_proxy_recipient, 1);
	rcpt->idx = array_count(&proxy->rcpt_to);
	rcpt->conn = conn;
	rcpt->address = smtp_address_clone(proxy->pool, address);
	array_append(&proxy->rcpt_to, &rcpt, 1);

	smtp_client_transaction_add_rcpt(conn->lmtp_trans, address,
		&set->params, lmtp_proxy_rcpt_cb, lmtp_proxy_data_cb, rcpt);
	return 0;
}

static void
lmtp_proxy_data_dummy_cb(const struct smtp_reply *proxy_reply ATTR_UNUSED,
			 struct lmtp_proxy_connection *conn ATTR_UNUSED)
{
	/* nothing */
}

void lmtp_proxy_start(struct lmtp_proxy *proxy, struct istream *data_input,
		      lmtp_proxy_finish_callback_t *callback, void *context)
{
	struct lmtp_proxy_connection *const *conns;
	uoff_t size;

	i_assert(data_input->seekable);
	i_assert(proxy->data_input == NULL);

	proxy->finish_callback = callback;
	proxy->finish_context = context;
	proxy->data_input = data_input;
	i_stream_ref(proxy->data_input);
	if (i_stream_get_size(proxy->data_input, TRUE, &size) < 0) {
		i_error("i_stream_get_size(data_input) failed: %s",
			i_stream_get_error(proxy->data_input));
		size = (uoff_t)-1;
	}

	/* create the data_input streams first */
	array_foreach(&proxy->connections, conns) {
		struct lmtp_proxy_connection *conn = *conns;

		if (conn->finished) {
			/* this connection had already failed */
			continue;
		}

		if (size == (uoff_t)-1)
			conn->data_input = i_stream_create_limit(data_input, (uoff_t)-1);
		else
			conn->data_input = i_stream_create_sized(data_input, size);
	}
	/* now that all the streams are created, start reading them
	   (reading them earlier could have caused the data_input parent's
	   offset to change) */
	array_foreach(&proxy->connections, conns) {
		struct lmtp_proxy_connection *conn = *conns;

		smtp_client_transaction_set_timeout(conn->lmtp_trans,
			proxy->max_timeout_msecs);
		if (conn->data_input != NULL) {
			smtp_client_transaction_send(conn->lmtp_trans,
				conn->data_input,
				lmtp_proxy_data_dummy_cb, conn);
		}
	}
	/* finish if all of the connections have already failed */
	lmtp_proxy_try_finish(proxy);
}
