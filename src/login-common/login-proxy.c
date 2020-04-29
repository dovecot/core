/* Copyright (c) 2004-2018 Dovecot authors, see the included COPYING file */

#include "login-common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "iostream.h"
#include "iostream-proxy.h"
#include "iostream-ssl.h"
#include "llist.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "time-util.h"
#include "master-service.h"
#include "master-service-ssl-settings.h"
#include "ipc-server.h"
#include "mail-user-hash.h"
#include "client-common.h"
#include "login-proxy-state.h"
#include "login-proxy.h"


#define MAX_PROXY_INPUT_SIZE 4096
#define PROXY_MAX_OUTBUF_SIZE 1024
#define LOGIN_PROXY_DIE_IDLE_SECS 2
#define LOGIN_PROXY_IPC_PATH "ipc-proxy"
#define LOGIN_PROXY_IPC_NAME "proxy"
#define KILLED_BY_ADMIN_REASON "Disconnected by proxy: Kicked by admin"
#define KILLED_BY_DIRECTOR_REASON "Disconnected by proxy: Kicked via director"
#define KILLED_BY_SHUTDOWN_REASON "Disconnected by proxy: Process shutting down"
#define PROXY_IMMEDIATE_FAILURE_SECS 30
#define PROXY_CONNECT_RETRY_MSECS 1000
#define PROXY_DISCONNECT_INTERVAL_MSECS 100

#define LOGIN_PROXY_SIDE_CLIENT IOSTREAM_PROXY_SIDE_LEFT
#define LOGIN_PROXY_SIDE_SERVER IOSTREAM_PROXY_SIDE_RIGHT

enum login_proxy_free_flags {
	LOGIN_PROXY_FREE_FLAG_DELAYED = BIT(0)
};

struct login_proxy {
	struct login_proxy *prev, *next;

	struct client *client;
	struct event *event;
	int server_fd;
	struct io *client_wait_io, *server_io;
	struct istream *client_input, *server_input;
	struct ostream *client_output, *server_output;
	struct iostream_proxy *iostream_proxy;
	struct ssl_iostream *server_ssl_iostream;

	struct timeval created;
	struct timeout *to, *to_notify;
	struct login_proxy_record *state_rec;

	struct ip_addr ip, source_ip;
	char *host;
	in_port_t port;
	unsigned int connect_timeout_msecs;
	unsigned int notify_refresh_secs;
	unsigned int reconnect_count;
	enum login_proxy_ssl_flags ssl_flags;

	proxy_callback_t *callback;

	bool connected:1;
	bool detached:1;
	bool destroying:1;
	bool delayed_disconnect:1;
	bool num_waiting_connections_updated:1;
};

static struct login_proxy_state *proxy_state;
static struct login_proxy *login_proxies = NULL;
static struct login_proxy *login_proxies_pending = NULL;
static struct login_proxy *login_proxies_disconnecting = NULL;
static struct ipc_server *login_proxy_ipc_server;
static unsigned int detached_login_proxies_count = 0;

static int login_proxy_connect(struct login_proxy *proxy);
static void login_proxy_disconnect(struct login_proxy *proxy);
static void login_proxy_ipc_cmd(struct ipc_cmd *cmd, const char *line);
static void login_proxy_free_final(struct login_proxy *proxy);

static void ATTR_NULL(2)
login_proxy_free_full(struct login_proxy **_proxy, const char *reason,
		      enum login_proxy_free_flags flags);

static time_t proxy_last_io(struct login_proxy *proxy)
{
	struct timeval tv1, tv2, tv3, tv4;

	i_stream_get_last_read_time(proxy->client_input, &tv1);
	i_stream_get_last_read_time(proxy->server_input, &tv2);
	o_stream_get_last_write_time(proxy->client_output, &tv3);
	o_stream_get_last_write_time(proxy->server_output, &tv4);
	return I_MAX(tv1.tv_sec, I_MAX(tv2.tv_sec, I_MAX(tv3.tv_sec, tv4.tv_sec)));
}

static void login_proxy_free_errstr(struct login_proxy **_proxy,
				    const char *errstr, bool server)
{
	struct login_proxy *proxy = *_proxy;
	string_t *reason = t_str_new(128);

	str_printfa(reason, "Disconnected by %s", server ? "server" : "client");
	if (errstr[0] != '\0')
		str_printfa(reason, ": %s", errstr);

	str_printfa(reason, " (%ds idle, in=%"PRIuUOFF_T", out=%"PRIuUOFF_T,
		    (int)(ioloop_time - proxy_last_io(proxy)),
		    proxy->server_output->offset, proxy->client_output->offset);
	if (o_stream_get_buffer_used_size(proxy->client_output) > 0) {
		str_printfa(reason, "+%zu",
			    o_stream_get_buffer_used_size(proxy->client_output));
	}
	if (iostream_proxy_is_waiting_output(proxy->iostream_proxy,
					     LOGIN_PROXY_SIDE_SERVER))
		str_append(reason, ", client output blocked");
	if (iostream_proxy_is_waiting_output(proxy->iostream_proxy,
					     LOGIN_PROXY_SIDE_CLIENT))
		str_append(reason, ", server output blocked");

	str_append_c(reason, ')');
	login_proxy_free_full(_proxy, str_c(reason),
			      server ? LOGIN_PROXY_FREE_FLAG_DELAYED : 0);
}

static void proxy_client_disconnected_input(struct login_proxy *proxy)
{
	/* we're already disconnected from server. either wait for
	   disconnection timeout or for client to disconnect itself. */
	if (i_stream_read(proxy->client_input) < 0)
		login_proxy_free_final(proxy);
	else {
		i_stream_skip(proxy->client_input,
			      i_stream_get_data_size(proxy->client_input));
	}
}

static void proxy_prelogin_input(struct login_proxy *proxy)
{
	proxy->callback(proxy->client);
}

static void proxy_plain_connected(struct login_proxy *proxy)
{
	proxy->server_input =
		i_stream_create_fd(proxy->server_fd, MAX_PROXY_INPUT_SIZE);
	proxy->server_output =
		o_stream_create_fd(proxy->server_fd, (size_t)-1);
	o_stream_set_no_error_handling(proxy->server_output, TRUE);

	proxy->server_io =
		io_add(proxy->server_fd, IO_READ, proxy_prelogin_input, proxy);
}

static void proxy_fail_connect(struct login_proxy *proxy)
{
	i_assert(!proxy->num_waiting_connections_updated);

	if (timeval_cmp(&proxy->created, &proxy->state_rec->last_success) < 0) {
		/* there was a successful connection done since we started
		   connecting. perhaps this is just a temporary one-off
		   failure. */
	} else {
		proxy->state_rec->last_failure = ioloop_timeval;
	}
	i_assert(proxy->state_rec->num_waiting_connections > 0);
	proxy->state_rec->num_waiting_connections--;
	proxy->num_waiting_connections_updated = TRUE;
}

static void
proxy_log_connect_error(struct login_proxy *proxy, bool reconnect)
{
	string_t *str = t_str_new(128);
	struct ip_addr local_ip;
	in_port_t local_port;

	if (!proxy->connected) {
		str_printfa(str, "connect(%s, %u) failed: %m",
			    net_ip2addr(&proxy->ip), proxy->port);
	} else {
		str_printfa(str, "Login timed out in state=%s",
			    client_proxy_get_state(proxy->client));
	}
	str_printfa(str, " (after %u secs",
		    (unsigned int)(ioloop_time - proxy->created.tv_sec));
	if (proxy->reconnect_count > 0)
		str_printfa(str, ", %u reconnects", proxy->reconnect_count);

	if (proxy->server_fd != -1 &&
	    net_getsockname(proxy->server_fd, &local_ip, &local_port) == 0) {
		str_printfa(str, ", local=%s:%u",
			    net_ip2addr(&local_ip), local_port);
	} else if (proxy->source_ip.family != 0) {
		str_printfa(str, ", local=%s",
			    net_ip2addr(&proxy->source_ip));
	}

	str_append_c(str, ')');
	if (!reconnect)
		e_error(proxy->event, "%s", str_c(str));
	else {
		str_printfa(str, " - reconnecting (attempt #%d)",
			    proxy->reconnect_count);
		e_debug(proxy->event, "%s", str_c(str));
	}
}

static void proxy_reconnect_timeout(struct login_proxy *proxy)
{
	timeout_remove(&proxy->to);
	if (login_proxy_connect(proxy) < 0)
		login_proxy_free(&proxy);
}

static bool proxy_try_reconnect(struct login_proxy *proxy)
{
	int since_started_msecs, left_msecs;

	if (proxy->reconnect_count >= proxy->client->set->login_proxy_max_reconnects)
		return FALSE;

	since_started_msecs =
		timeval_diff_msecs(&ioloop_timeval, &proxy->created);
	if (since_started_msecs < 0)
		return FALSE; /* time moved backwards */
	left_msecs = proxy->connect_timeout_msecs - since_started_msecs;
	if (left_msecs <= 0)
		return FALSE;

	login_proxy_disconnect(proxy);
	proxy->to = timeout_add(I_MIN(PROXY_CONNECT_RETRY_MSECS, left_msecs),
				proxy_reconnect_timeout, proxy);
	proxy->reconnect_count++;
	return TRUE;
}

static bool proxy_connect_failed(struct login_proxy *proxy)
{
	bool reconnect;

	proxy_fail_connect(proxy);
	reconnect = proxy_try_reconnect(proxy);
	proxy_log_connect_error(proxy, reconnect);
	if (!reconnect)
		login_proxy_free(&proxy);
	return reconnect;
}

static void proxy_wait_connect(struct login_proxy *proxy)
{
	errno = net_geterror(proxy->server_fd);
	if (errno != 0) {
		(void)proxy_connect_failed(proxy);
		return;
	}
	proxy->connected = TRUE;
	proxy->num_waiting_connections_updated = TRUE;
	proxy->state_rec->last_success = ioloop_timeval;
	i_assert(proxy->state_rec->num_waiting_connections > 0);
	proxy->state_rec->num_waiting_connections--;
	proxy->state_rec->num_proxying_connections++;
	proxy->state_rec->num_disconnects_since_ts = 0;

	io_remove(&proxy->server_io);
	proxy_plain_connected(proxy);

	if ((proxy->ssl_flags & PROXY_SSL_FLAG_YES) != 0 &&
	    (proxy->ssl_flags & PROXY_SSL_FLAG_STARTTLS) == 0) {
		if (login_proxy_starttls(proxy) < 0) {
			login_proxy_free(&proxy);
			return;
		}
	}
}

static void proxy_connect_timeout(struct login_proxy *proxy)
{
	errno = ETIMEDOUT;
	proxy_log_connect_error(proxy, FALSE);
	if (!proxy->connected)
		proxy_fail_connect(proxy);
	login_proxy_free(&proxy);
}

static int login_proxy_connect(struct login_proxy *proxy)
{
	struct login_proxy_record *rec = proxy->state_rec;

	/* this needs to be done early, since login_proxy_free() shrinks
	   num_waiting_connections. */
	proxy->num_waiting_connections_updated = FALSE;
	rec->num_waiting_connections++;

	if (rec->last_success.tv_sec == 0) {
		/* first connect to this IP. don't start immediately failing
		   the check below. */
		rec->last_success.tv_sec = ioloop_timeval.tv_sec - 1;
	}
	if (timeval_cmp(&rec->last_failure, &rec->last_success) > 0 &&
	    rec->last_failure.tv_sec - rec->last_success.tv_sec > PROXY_IMMEDIATE_FAILURE_SECS &&
	    rec->num_waiting_connections > 1) {
		/* the server is down. fail immediately */
		e_error(proxy->event, "Host is down");
		return -1;
	}

	proxy->server_fd = net_connect_ip(&proxy->ip, proxy->port,
					  proxy->source_ip.family == 0 ? NULL :
					  &proxy->source_ip);
	if (proxy->server_fd == -1) {
		proxy_log_connect_error(proxy, FALSE);
		return -1;
	}
	proxy->server_io = io_add(proxy->server_fd, IO_WRITE,
				  proxy_wait_connect, proxy);
	if (proxy->connect_timeout_msecs != 0) {
		proxy->to = timeout_add(proxy->connect_timeout_msecs,
					proxy_connect_timeout, proxy);
	}
	return 0;
}

int login_proxy_new(struct client *client, struct event *event,
		    const struct login_proxy_settings *set,
		    proxy_callback_t *callback)
{
	struct login_proxy *proxy;

	i_assert(set->host != NULL && set->host[0] != '\0');
	i_assert(client->login_proxy == NULL);

	if (client->proxy_ttl <= 1) {
		e_error(event, "TTL reached zero - proxies appear to be looping?");
		return -1;
	}

	proxy = i_new(struct login_proxy, 1);
	proxy->client = client;
	proxy->event = event;
	proxy->server_fd = -1;
	proxy->created = ioloop_timeval;
	proxy->ip = set->ip;
	proxy->source_ip = set->source_ip;
	proxy->host = i_strdup(set->host);
	proxy->port = set->port;
	proxy->connect_timeout_msecs = set->connect_timeout_msecs;
	proxy->notify_refresh_secs = set->notify_refresh_secs;
	proxy->ssl_flags = set->ssl_flags;
	proxy->state_rec = login_proxy_state_get(proxy_state, &proxy->ip,
						 proxy->port);
	client_ref(client);
	event_ref(proxy->event);

	if (login_proxy_connect(proxy) < 0) {
		login_proxy_free(&proxy);
		return -1;
	}

	DLLIST_PREPEND(&login_proxies_pending, proxy);

	proxy->callback = callback;
	client->login_proxy = proxy;
	return 0;
}

static void login_proxy_disconnect(struct login_proxy *proxy)
{
	timeout_remove(&proxy->to);
	timeout_remove(&proxy->to_notify);

	if (!proxy->num_waiting_connections_updated) {
		i_assert(proxy->state_rec->num_waiting_connections > 0);
		proxy->state_rec->num_waiting_connections--;
	}
	if (proxy->connected) {
		i_assert(proxy->state_rec->num_proxying_connections > 0);
		proxy->state_rec->num_proxying_connections--;
	}

	iostream_proxy_unref(&proxy->iostream_proxy);
	ssl_iostream_destroy(&proxy->server_ssl_iostream);

	io_remove(&proxy->server_io);
	i_stream_destroy(&proxy->server_input);
	o_stream_destroy(&proxy->server_output);
	if (proxy->server_fd != -1) {
		net_disconnect(proxy->server_fd);
		proxy->server_fd = -1;
	}
}

static void login_proxy_free_final(struct login_proxy *proxy)
{
	i_assert(proxy->server_ssl_iostream == NULL);

	if (proxy->delayed_disconnect) {
		DLLIST_REMOVE(&login_proxies_disconnecting, proxy);

		i_assert(proxy->state_rec->num_delayed_client_disconnects > 0);
		if (--proxy->state_rec->num_delayed_client_disconnects == 0)
			proxy->state_rec->num_disconnects_since_ts = 0;
		timeout_remove(&proxy->to);
	}

	io_remove(&proxy->client_wait_io);
	i_stream_destroy(&proxy->client_input);
	o_stream_destroy(&proxy->client_output);
	client_unref(&proxy->client);
	event_unref(&proxy->event);
	i_free(proxy->host);
	i_free(proxy);
}

static unsigned int login_proxy_delay_disconnect(struct login_proxy *proxy)
{
	struct login_proxy_record *rec = proxy->state_rec;
	const unsigned int max_delay =
		proxy->client->set->login_proxy_max_disconnect_delay;
	struct timeval disconnect_time_offset;
	unsigned int max_disconnects_per_sec, delay_msecs_since_ts, max_conns;
	int delay_msecs;

	if (rec->num_disconnects_since_ts == 0) {
		rec->disconnect_timestamp = ioloop_timeval;
		/* start from a slightly random timestamp. this way all proxy
		   processes will disconnect at slightly different times to
		   spread the load. */
		timeval_add_msecs(&rec->disconnect_timestamp,
				  i_rand_limit(PROXY_DISCONNECT_INTERVAL_MSECS));
	}
	rec->num_disconnects_since_ts++;
	if (proxy->to != NULL) {
		/* we were already lazily disconnecting this */
		return 0;
	}
	if (max_delay == 0) {
		/* delaying is disabled */
		return 0;
	}
	max_conns = rec->num_proxying_connections + rec->num_disconnects_since_ts;
	max_disconnects_per_sec = (max_conns + max_delay-1) / max_delay;
	if (rec->num_disconnects_since_ts <= max_disconnects_per_sec &&
	    rec->num_delayed_client_disconnects == 0) {
		/* wait delaying until we have 1 second's worth of clients
		   disconnected */
		return 0;
	}

	/* see at which time we should be disconnecting the client.
	   do it in 100ms intervals so the timeouts are triggered together. */
	disconnect_time_offset = rec->disconnect_timestamp;
	delay_msecs_since_ts = PROXY_DISCONNECT_INTERVAL_MSECS *
		(max_delay * rec->num_disconnects_since_ts *
		 (1000/PROXY_DISCONNECT_INTERVAL_MSECS) / max_conns);
	timeval_add_msecs(&disconnect_time_offset, delay_msecs_since_ts);
	delay_msecs = timeval_diff_msecs(&disconnect_time_offset, &ioloop_timeval);
	if (delay_msecs <= 0) {
		/* we already reached the time */
		return 0;
	}

	rec->num_delayed_client_disconnects++;
	proxy->delayed_disconnect = TRUE;
	proxy->to = timeout_add(delay_msecs, login_proxy_free_final, proxy);
	DLLIST_PREPEND(&login_proxies_disconnecting, proxy);
	return delay_msecs;
}

static void ATTR_NULL(2)
login_proxy_free_full(struct login_proxy **_proxy, const char *reason,
		      enum login_proxy_free_flags flags)
{
	struct login_proxy *proxy = *_proxy;
	struct client *client = proxy->client;
	unsigned int delay_ms = 0;

	*_proxy = NULL;

	if (proxy->destroying)
		return;
	proxy->destroying = TRUE;

	/* we'll disconnect server side in any case. */
	login_proxy_disconnect(proxy);

	if (proxy->detached) {
		/* detached proxy */
		i_assert(reason != NULL || proxy->client->destroyed);
		DLLIST_REMOVE(&login_proxies, proxy);

		if ((flags & LOGIN_PROXY_FREE_FLAG_DELAYED) != 0)
			delay_ms = login_proxy_delay_disconnect(proxy);

		if (delay_ms == 0)
			e_info(proxy->event, "%s", reason);
		else {
			e_info(proxy->event, "%s - disconnecting client in %ums",
			       reason, delay_ms);
		}

		i_assert(detached_login_proxies_count > 0);
		detached_login_proxies_count--;
	} else {
		i_assert(proxy->client_input == NULL);
		i_assert(proxy->client_output == NULL);

		DLLIST_REMOVE(&login_proxies_pending, proxy);

		if (proxy->callback != NULL)
			proxy->callback(proxy->client);
	}
	client->login_proxy = NULL;

	if (delay_ms == 0)
		login_proxy_free_final(proxy);
	else {
		i_assert(proxy->client_wait_io == NULL);
		proxy->client_wait_io = io_add_istream(proxy->client_input,
			proxy_client_disconnected_input, proxy);
	}
}

void login_proxy_free(struct login_proxy **_proxy)
{
	struct login_proxy *proxy = *_proxy;

	i_assert(!proxy->detached || proxy->client->destroyed);
	/* Note: The NULL error is never even attempted to be used here. */
	login_proxy_free_full(_proxy, NULL, 0);
}

bool login_proxy_is_ourself(const struct client *client, const char *host,
			    in_port_t port, const char *destuser)
{
	struct ip_addr ip;

	if (port != client->local_port)
		return FALSE;

	if (net_addr2ip(host, &ip) < 0)
		return FALSE;
	if (!net_ip_compare(&ip, &client->local_ip))
		return FALSE;

	return strcmp(client->virtual_user, destuser) == 0;
}

struct istream *login_proxy_get_istream(struct login_proxy *proxy)
{
	return proxy->server_input;
}

struct ostream *login_proxy_get_ostream(struct login_proxy *proxy)
{
	return proxy->server_output;
}

struct event *login_proxy_get_event(struct login_proxy *proxy)
{
	return proxy->event;
}

const char *login_proxy_get_host(const struct login_proxy *proxy)
{
	return proxy->host;
}

in_port_t login_proxy_get_port(const struct login_proxy *proxy)
{
	return proxy->port;
}

enum login_proxy_ssl_flags
login_proxy_get_ssl_flags(const struct login_proxy *proxy)
{
	return proxy->ssl_flags;
}

static void
login_proxy_finished(enum iostream_proxy_side side,
		     enum iostream_proxy_status status,
		     struct login_proxy *proxy)
{
	const char *errstr;
	bool server_side;

	server_side = side == LOGIN_PROXY_SIDE_SERVER;
	switch (status) {
	case IOSTREAM_PROXY_STATUS_INPUT_EOF:
		/* success */
		errstr = "";
		break;
	case IOSTREAM_PROXY_STATUS_INPUT_ERROR:
		errstr = side == LOGIN_PROXY_SIDE_CLIENT ?
			i_stream_get_error(proxy->client_input) :
			i_stream_get_error(proxy->server_input);
		break;
	case IOSTREAM_PROXY_STATUS_OTHER_SIDE_OUTPUT_ERROR:
		server_side = !server_side;
		errstr = side == LOGIN_PROXY_SIDE_CLIENT ?
			o_stream_get_error(proxy->server_output) :
			o_stream_get_error(proxy->client_output);
		break;
	default:
		i_unreached();
	}
	login_proxy_free_errstr(&proxy, errstr, server_side);
}

static void login_proxy_notify(struct login_proxy *proxy)
{
	login_proxy_state_notify(proxy_state, proxy->client->proxy_user);
}

void login_proxy_detach(struct login_proxy *proxy)
{
	struct client *client = proxy->client;

	pool_unref(&proxy->client->preproxy_pool);

	i_assert(!proxy->detached);
	i_assert(proxy->server_input != NULL);
	i_assert(proxy->server_output != NULL);

	timeout_remove(&proxy->to);
	io_remove(&proxy->server_io);

	proxy->detached = TRUE;
	proxy->client_input = client->input;
	proxy->client_output = client->output;

	i_stream_set_persistent_buffers(proxy->server_input, FALSE);
	i_stream_set_persistent_buffers(client->input, FALSE);
	o_stream_set_max_buffer_size(client->output, PROXY_MAX_OUTBUF_SIZE);
	client->input = NULL;
	client->output = NULL;

	/* from now on, just do dummy proxying */
	proxy->iostream_proxy =
		iostream_proxy_create(proxy->client_input, proxy->client_output,
				      proxy->server_input, proxy->server_output);
	iostream_proxy_set_completion_callback(proxy->iostream_proxy,
					       login_proxy_finished, proxy);
	iostream_proxy_start(proxy->iostream_proxy);

	if (proxy->notify_refresh_secs != 0) {
		proxy->to_notify =
			timeout_add(proxy->notify_refresh_secs * 1000,
				    login_proxy_notify, proxy);
	}

	proxy->callback = NULL;

	if (login_proxy_ipc_server == NULL) {
		login_proxy_ipc_server =
			ipc_server_init(LOGIN_PROXY_IPC_PATH,
					LOGIN_PROXY_IPC_NAME,
					login_proxy_ipc_cmd);
	}

	DLLIST_REMOVE(&login_proxies_pending, proxy);
	DLLIST_PREPEND(&login_proxies, proxy);
	detached_login_proxies_count++;

	client->login_proxy = NULL;
}

int login_proxy_starttls(struct login_proxy *proxy)
{
	struct ssl_iostream_context *ssl_ctx;
	struct ssl_iostream_settings ssl_set;
	const char *error;

	master_service_ssl_settings_to_iostream_set(proxy->client->ssl_set,
						    pool_datastack_create(),
						    MASTER_SERVICE_SSL_SETTINGS_TYPE_CLIENT,
						    &ssl_set);
	if ((proxy->ssl_flags & PROXY_SSL_FLAG_ANY_CERT) != 0)
		ssl_set.allow_invalid_cert = TRUE;
	/* NOTE: We're explicitly disabling ssl_client_ca_* settings for now
	   at least. The main problem is that we're chrooted, so we can't read
	   them at this point anyway. The second problem is that especially
	   ssl_client_ca_dir does blocking disk I/O, which could cause
	   unexpected hangs when login process handles multiple clients. */
	ssl_set.ca_file = ssl_set.ca_dir = NULL;

	io_remove(&proxy->server_io);
	if (ssl_iostream_client_context_cache_get(&ssl_set, &ssl_ctx, &error) < 0) {
		e_error(proxy->event, "Failed to create SSL client context: %s",
			error);
		return -1;
	}

	if (io_stream_create_ssl_client(ssl_ctx, proxy->host, &ssl_set,
					&proxy->server_input,
					&proxy->server_output,
					&proxy->server_ssl_iostream,
					&error) < 0) {
		e_error(proxy->event, "Failed to create SSL client: %s", error);
		ssl_iostream_context_unref(&ssl_ctx);
		return -1;
	}
	ssl_iostream_context_unref(&ssl_ctx);
	if (ssl_iostream_handshake(proxy->server_ssl_iostream) < 0) {
		error = ssl_iostream_get_last_error(proxy->server_ssl_iostream);
		e_error(proxy->event, "Failed to start SSL handshake: %s",
			ssl_iostream_get_last_error(proxy->server_ssl_iostream));
		return -1;
	}

	proxy->server_io = io_add_istream(proxy->server_input,
					  proxy_prelogin_input, proxy);
	return 0;
}

static void proxy_kill_idle(struct login_proxy *proxy)
{
	login_proxy_free_full(&proxy, KILLED_BY_SHUTDOWN_REASON, 0);
}

void login_proxy_kill_idle(void)
{
	struct login_proxy *proxy, *next;
	time_t now = time(NULL);
	time_t stop_timestamp = now - LOGIN_PROXY_DIE_IDLE_SECS;
	unsigned int stop_msecs;

	for (proxy = login_proxies; proxy != NULL; proxy = next) {
		next = proxy->next;
		time_t last_io = proxy_last_io(proxy);

		if (last_io <= stop_timestamp)
			proxy_kill_idle(proxy);
		else {
			i_assert(proxy->to == NULL);
			stop_msecs = (last_io - stop_timestamp) * 1000;
			proxy->to = timeout_add(stop_msecs,
						proxy_kill_idle, proxy);
		}
	}
}

static bool
want_kick_virtual_user(struct client *client, const char *const *args,
		       unsigned int key_idx ATTR_UNUSED)
{
	return str_array_find(args, client->virtual_user);
}

static bool
want_kick_alt_username(struct client *client, const char *const *args,
		       unsigned int key_idx)
{
	unsigned int i;

	if (client->alt_usernames == NULL)
		return FALSE;
	for (i = 0; i < key_idx; i++) {
		if (client->alt_usernames[i] == NULL)
			return FALSE;
	}
	if (client->alt_usernames[i] == NULL)
		return FALSE;
	return str_array_find(args, client->alt_usernames[i]);
}

static void
login_proxy_cmd_kick_full(struct ipc_cmd *cmd, const char *const *args,
			  bool (*want_kick)(struct client *, const char *const *,
					    unsigned int), unsigned int key_idx)
{
	struct login_proxy *proxy, *next;
	unsigned int count = 0;

	if (args[0] == NULL) {
		ipc_cmd_fail(&cmd, "Missing parameter");
		return;
	}

	for (proxy = login_proxies; proxy != NULL; proxy = next) {
		next = proxy->next;

		if (want_kick(proxy->client, args, key_idx)) {
			login_proxy_free_full(&proxy, KILLED_BY_ADMIN_REASON,
					      LOGIN_PROXY_FREE_FLAG_DELAYED);
			count++;
		}
	}
	for (proxy = login_proxies_pending; proxy != NULL; proxy = next) {
		next = proxy->next;

		if (want_kick(proxy->client, args, key_idx)) {
			client_destroy(proxy->client, KILLED_BY_ADMIN_REASON);
			count++;
		}
	}
	ipc_cmd_success_reply(&cmd, t_strdup_printf("%u", count));
}

static void
login_proxy_cmd_kick(struct ipc_cmd *cmd, const char *const *args)
{
	login_proxy_cmd_kick_full(cmd, args, want_kick_virtual_user, 0);
}

static void
login_proxy_cmd_kick_alt(struct ipc_cmd *cmd, const char *const *args)
{
	char *const *fields;
	unsigned int i, count;

	if (args[0] == NULL) {
		ipc_cmd_fail(&cmd, "Missing parameter");
		return;
	}
	fields = array_get(&global_alt_usernames, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(fields[i], args[0]) == 0)
			break;
	}
	if (i == count) {
		/* field doesn't exist, but it's not an error necessarily */
		ipc_cmd_success_reply(&cmd, "0");
		return;
	}

	login_proxy_cmd_kick_full(cmd, args+1, want_kick_alt_username, i);
}

static bool director_username_hash(struct client *client, unsigned int *hash_r)
{
	const char *error;

	if (client->director_username_hash_cache != 0) {
		/* already set */
	} else if (!mail_user_hash(client->virtual_user,
				   client->set->director_username_hash,
				   &client->director_username_hash_cache,
				   &error)) {
		e_error(client->event,
			"Failed to expand director_username_hash=%s: %s",
			client->set->director_username_hash, error);
		return FALSE;
	}

	*hash_r = client->director_username_hash_cache;
	return TRUE;
}

static void
login_proxy_cmd_kick_director_hash(struct ipc_cmd *cmd, const char *const *args)
{
	struct login_proxy *proxy, *next;
	struct ip_addr except_ip;
	unsigned int hash, proxy_hash, count = 0;

	if (args[0] == NULL || str_to_uint(args[0], &hash) < 0) {
		ipc_cmd_fail(&cmd, "Invalid parameters");
		return;
	}
	/* optional except_ip parameter specifies that we're not killing the
	   connections that are proxying to the except_ip backend */
	except_ip.family = 0;
	if (args[1] != NULL && args[1][0] != '\0' &&
	    net_addr2ip(args[1], &except_ip) < 0) {
		ipc_cmd_fail(&cmd, "Invalid except_ip parameter");
		return;
	}

	for (proxy = login_proxies; proxy != NULL; proxy = next) {
		next = proxy->next;

		if (director_username_hash(proxy->client, &proxy_hash) &&
		    proxy_hash == hash &&
		    !net_ip_compare(&proxy->ip, &except_ip)) {
			login_proxy_free_full(&proxy, KILLED_BY_DIRECTOR_REASON,
					      LOGIN_PROXY_FREE_FLAG_DELAYED);
			count++;
		}
	}
	for (proxy = login_proxies_pending; proxy != NULL; proxy = next) {
		next = proxy->next;

		if (director_username_hash(proxy->client, &proxy_hash) &&
		    proxy_hash == hash &&
		    !net_ip_compare(&proxy->ip, &except_ip)) {
			client_destroy(proxy->client, KILLED_BY_DIRECTOR_REASON);
			count++;
		}
	}
	ipc_cmd_success_reply(&cmd, t_strdup_printf("%u", count));
}

static void
login_proxy_cmd_list_reply(struct ipc_cmd *cmd, string_t *str,
			   struct login_proxy *proxy)
{
	unsigned int i, alt_count = array_count(&global_alt_usernames);

	str_truncate(str, 0);
	str_append_tabescaped(str, proxy->client->virtual_user);
	str_append_c(str, '\t');
	i = 0;
	if (proxy->client->alt_usernames != NULL) {
		for (; proxy->client->alt_usernames[i] != NULL; i++) {
			str_append_tabescaped(str, proxy->client->alt_usernames[i]);
			str_append_c(str, '\t');
		}
		i_assert(i <= alt_count);
	}
	for (; i < alt_count; i++)
		str_append_c(str, '\t');

	str_printfa(str, "%s\t%s\t%s\t%u", login_binary->protocol,
		    net_ip2addr(&proxy->client->ip),
		    net_ip2addr(&proxy->ip), proxy->port);
	ipc_cmd_send(cmd, str_c(str));
}

static void
login_proxy_cmd_list(struct ipc_cmd *cmd, const char *const *args ATTR_UNUSED)
{
	struct login_proxy *proxy;
	char *const *fieldp;
	string_t *str = t_str_new(64);

	str_append(str, "username\t");
	array_foreach(&global_alt_usernames, fieldp) {
		str_append_tabescaped(str, *fieldp);
		str_append_c(str, '\t');
	}
	str_append(str, "service\tsrc-ip\tdest-ip\tdest-port");

	ipc_cmd_send(cmd, str_c(str));

	for (proxy = login_proxies; proxy != NULL; proxy = proxy->next)
		login_proxy_cmd_list_reply(cmd, str, proxy);
	for (proxy = login_proxies_pending; proxy != NULL; proxy = proxy->next)
		login_proxy_cmd_list_reply(cmd, str, proxy);
	ipc_cmd_success(&cmd);
}

static void login_proxy_ipc_cmd(struct ipc_cmd *cmd, const char *line)
{
	const char *const *args = t_strsplit_tabescaped(line);
	const char *name = args[0];

	args++;
	if (strcmp(name, "KICK") == 0)
		login_proxy_cmd_kick(cmd, args);
	else if (strcmp(name, "KICK-ALT") == 0)
		login_proxy_cmd_kick_alt(cmd, args);
	else if (strcmp(name, "KICK-DIRECTOR-HASH") == 0)
		login_proxy_cmd_kick_director_hash(cmd, args);
	else if (strcmp(name, "LIST-FULL") == 0)
		login_proxy_cmd_list(cmd, args);
	else
		ipc_cmd_fail(&cmd, "Unknown command");
}

unsigned int login_proxies_get_detached_count(void)
{
	return detached_login_proxies_count;
}

struct client *login_proxies_get_first_detached_client(void)
{
	return login_proxies == NULL ? NULL : login_proxies->client;
}

void login_proxy_init(const char *proxy_notify_pipe_path)
{
	proxy_state = login_proxy_state_init(proxy_notify_pipe_path);
}

void login_proxy_deinit(void)
{
	struct login_proxy *proxy;

	while (login_proxies != NULL) {
		proxy = login_proxies;
		login_proxy_free_full(&proxy, KILLED_BY_SHUTDOWN_REASON, 0);
	}
	i_assert(detached_login_proxies_count == 0);

	while (login_proxies_disconnecting != NULL)
		login_proxy_free_final(login_proxies_disconnecting);
	if (login_proxy_ipc_server != NULL)
		ipc_server_deinit(&login_proxy_ipc_server);
	login_proxy_state_deinit(&proxy_state);
}
