/* Copyright (c) 2004-2011 Dovecot authors, see the included COPYING file */

#include "login-common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "llist.h"
#include "str-sanitize.h"
#include "time-util.h"
#include "master-service.h"
#include "dns-lookup.h"
#include "client-common.h"
#include "ssl-proxy.h"
#include "login-proxy-state.h"
#include "login-proxy.h"

#define MAX_PROXY_INPUT_SIZE 4096
#define OUTBUF_THRESHOLD 1024
#define LOGIN_PROXY_DIE_IDLE_SECS 2
#define LOGIN_PROXY_DNS_WARN_MSECS 500

struct login_proxy {
	struct login_proxy *prev, *next;

	struct client *client;
	int client_fd, server_fd;
	struct io *client_io, *server_io;
	struct istream *server_input;
	struct ostream *client_output, *server_output;
	struct ssl_proxy *ssl_server_proxy;
	time_t last_io;

	struct timeval created;
	struct timeout *to, *to_notify;
	struct login_proxy_record *state_rec;

	struct ip_addr ip;
	char *host;
	unsigned int port;
	unsigned int connect_timeout_msecs;
	unsigned int notify_refresh_secs;
	enum login_proxy_ssl_flags ssl_flags;

	proxy_callback_t *callback;

	unsigned int destroying:1;
	unsigned int disconnecting:1;
};

static struct login_proxy_state *proxy_state;
static struct login_proxy *login_proxies = NULL;

static void server_input(struct login_proxy *proxy)
{
	unsigned char buf[OUTBUF_THRESHOLD];
	ssize_t ret;

	proxy->last_io = ioloop_time;
	if (o_stream_get_buffer_used_size(proxy->client_output) >
	    OUTBUF_THRESHOLD) {
		/* client's output buffer is already quite full.
		   don't send more until we're below threshold. */
		io_remove(&proxy->server_io);
		return;
	}

	ret = net_receive(proxy->server_fd, buf, sizeof(buf));
	if (ret < 0 || o_stream_send(proxy->client_output, buf, ret) != ret)
                login_proxy_free(&proxy);
}

static void proxy_client_input(struct login_proxy *proxy)
{
	unsigned char buf[OUTBUF_THRESHOLD];
	ssize_t ret;

	proxy->last_io = ioloop_time;
	if (o_stream_get_buffer_used_size(proxy->server_output) >
	    OUTBUF_THRESHOLD) {
		/* proxy's output buffer is already quite full.
		   don't send more until we're below threshold. */
		io_remove(&proxy->client_io);
		return;
	}

	ret = net_receive(proxy->client_fd, buf, sizeof(buf));
	if (ret < 0 || o_stream_send(proxy->server_output, buf, ret) != ret)
                login_proxy_free(&proxy);
}

static int server_output(struct login_proxy *proxy)
{
	proxy->last_io = ioloop_time;
	if (o_stream_flush(proxy->server_output) < 0) {
                login_proxy_free(&proxy);
		return 1;
	}

	if (proxy->client_io == NULL &&
	    o_stream_get_buffer_used_size(proxy->server_output) <
	    OUTBUF_THRESHOLD) {
		/* there's again space in proxy's output buffer, so we can
		   read more from client. */
		proxy->client_io = io_add(proxy->client_fd, IO_READ,
					  proxy_client_input, proxy);
	}
	return 1;
}

static int proxy_client_output(struct login_proxy *proxy)
{
	proxy->last_io = ioloop_time;
	if (o_stream_flush(proxy->client_output) < 0) {
                login_proxy_free(&proxy);
		return 1;
	}

	if (proxy->server_io == NULL &&
	    o_stream_get_buffer_used_size(proxy->client_output) <
	    OUTBUF_THRESHOLD) {
		/* there's again space in client's output buffer, so we can
		   read more from proxy. */
		proxy->server_io =
			io_add(proxy->server_fd, IO_READ, server_input, proxy);
	}
	return 1;
}

static void proxy_prelogin_input(struct login_proxy *proxy)
{
	proxy->callback(proxy->client);
}

static void proxy_plain_connected(struct login_proxy *proxy)
{
	proxy->server_input =
		i_stream_create_fd(proxy->server_fd, MAX_PROXY_INPUT_SIZE,
				   FALSE);
	proxy->server_output =
		o_stream_create_fd(proxy->server_fd, (size_t)-1, FALSE);

	proxy->server_io =
		io_add(proxy->server_fd, IO_READ, proxy_prelogin_input, proxy);
}

static void proxy_fail_connect(struct login_proxy *proxy)
{
	if (timeval_cmp(&proxy->created, &proxy->state_rec->last_success) < 0) {
		/* there was a successful connection done since we started
		   connecting. perhaps this is just a temporary one-off
		   failure. */
	} else {
		proxy->state_rec->last_failure = ioloop_timeval;
	}
	proxy->state_rec->num_waiting_connections--;
	proxy->state_rec = NULL;
}

static void proxy_wait_connect(struct login_proxy *proxy)
{
	int err;

	err = net_geterror(proxy->server_fd);
	if (err != 0) {
		i_error("proxy: connect(%s, %u) failed: %s",
			proxy->host, proxy->port, strerror(err));
		proxy_fail_connect(proxy);
                login_proxy_free(&proxy);
		return;
	}
	proxy->state_rec->last_success = ioloop_timeval;
	proxy->state_rec->num_waiting_connections--;
	proxy->state_rec = NULL;

	if (proxy->to != NULL)
		timeout_remove(&proxy->to);

	if ((proxy->ssl_flags & PROXY_SSL_FLAG_YES) != 0 &&
	    (proxy->ssl_flags & PROXY_SSL_FLAG_STARTTLS) == 0) {
		if (login_proxy_starttls(proxy) < 0) {
			login_proxy_free(&proxy);
			return;
		}
	} else {
		io_remove(&proxy->server_io);
		proxy_plain_connected(proxy);
	}
}

static void proxy_connect_timeout(struct login_proxy *proxy)
{
	i_error("proxy: connect(%s, %u) timed out", proxy->host, proxy->port);
	proxy_fail_connect(proxy);
	login_proxy_free(&proxy);
}

static int login_proxy_connect(struct login_proxy *proxy)
{
	struct login_proxy_record *rec;

	rec = login_proxy_state_get(proxy_state, &proxy->ip, proxy->port);
	if (timeval_cmp(&rec->last_failure, &rec->last_success) > 0 &&
	    rec->num_waiting_connections != 0) {
		/* the server is down. fail immediately */
		i_error("proxy(%s): Host %s:%u is down",
			proxy->client->virtual_user, proxy->host, proxy->port);
		login_proxy_free(&proxy);
		return -1;
	}

	proxy->server_fd = net_connect_ip(&proxy->ip, proxy->port, NULL);
	if (proxy->server_fd == -1) {
		i_error("proxy(%s): connect(%s, %u) failed: %m",
			proxy->client->virtual_user, proxy->host, proxy->port);
		login_proxy_free(&proxy);
		return -1;
	}
	proxy->server_io = io_add(proxy->server_fd, IO_WRITE,
				  proxy_wait_connect, proxy);
	if (proxy->connect_timeout_msecs != 0) {
		proxy->to = timeout_add(proxy->connect_timeout_msecs,
					proxy_connect_timeout, proxy);
	}

	proxy->state_rec = rec;
	proxy->state_rec->num_waiting_connections++;
	return 0;
}

static void login_proxy_dns_done(const struct dns_lookup_result *result,
				 struct login_proxy *proxy)
{
	if (result->ret != 0) {
		i_error("proxy(%s): DNS lookup of %s failed: %s",
			proxy->client->virtual_user, proxy->host,
			result->error);
		login_proxy_free(&proxy);
	} else {
		if (result->msecs > LOGIN_PROXY_DNS_WARN_MSECS) {
			i_warning("proxy(%s): DNS lookup for %s took %u.%03u s",
				  proxy->client->virtual_user, proxy->host,
				  result->msecs/1000, result->msecs % 1000);
		}

		proxy->ip = result->ips[0];
		(void)login_proxy_connect(proxy);
	}
}

int login_proxy_new(struct client *client,
		    const struct login_proxy_settings *set,
		    proxy_callback_t *callback)
{
	struct login_proxy *proxy;
	struct dns_lookup_settings dns_lookup_set;

	i_assert(client->login_proxy == NULL);

	if (set->host == NULL || *set->host == '\0') {
		i_error("proxy(%s): host not given", client->virtual_user);
		return -1;
	}

	proxy = i_new(struct login_proxy, 1);
	proxy->client = client;
	proxy->client_fd = -1;
	proxy->server_fd = -1;
	proxy->created = ioloop_timeval;
	proxy->host = i_strdup(set->host);
	proxy->port = set->port;
	proxy->connect_timeout_msecs = set->connect_timeout_msecs;
	proxy->notify_refresh_secs = set->notify_refresh_secs;
	proxy->ssl_flags = set->ssl_flags;
	client_ref(client);

	memset(&dns_lookup_set, 0, sizeof(dns_lookup_set));
	dns_lookup_set.dns_client_socket_path = set->dns_client_socket_path;
	dns_lookup_set.timeout_msecs = set->connect_timeout_msecs;

	if (net_addr2ip(set->host, &proxy->ip) < 0) {
		if (dns_lookup(set->host, &dns_lookup_set,
			       login_proxy_dns_done, proxy) < 0)
			return -1;
	} else {
		if (login_proxy_connect(proxy) < 0)
			return -1;
	}

	proxy->callback = callback;
	client->login_proxy = proxy;
	return 0;
}

void login_proxy_free(struct login_proxy **_proxy)
{
	struct login_proxy *proxy = *_proxy;
	struct client *client = proxy->client;
	const char *ipstr;

	*_proxy = NULL;

	if (proxy->destroying)
		return;
	proxy->destroying = TRUE;

	if (proxy->to != NULL)
		timeout_remove(&proxy->to);
	if (proxy->to_notify != NULL)
		timeout_remove(&proxy->to_notify);

	if (proxy->state_rec != NULL)
		proxy->state_rec->num_waiting_connections--;
	if (proxy->to != NULL)
		timeout_remove(&proxy->to);

	if (proxy->server_io != NULL)
		io_remove(&proxy->server_io);
	if (proxy->server_input != NULL)
		i_stream_destroy(&proxy->server_input);
	if (proxy->server_output != NULL)
		o_stream_destroy(&proxy->server_output);

	if (proxy->client_fd != -1) {
		/* detached proxy */
		DLLIST_REMOVE(&login_proxies, proxy);

		ipstr = net_ip2addr(&proxy->client->ip);
		i_info("proxy(%s): disconnecting %s",
		       proxy->client->virtual_user,
		       ipstr != NULL ? ipstr : "");

		if (proxy->client_io != NULL)
			io_remove(&proxy->client_io);
		if (proxy->client_output != NULL)
			o_stream_destroy(&proxy->client_output);
		net_disconnect(proxy->client_fd);
	} else {
		i_assert(proxy->client_io == NULL);
		i_assert(proxy->client_output == NULL);

		if (proxy->callback != NULL)
			proxy->callback(proxy->client);
	}

	if (proxy->server_fd != -1)
		net_disconnect(proxy->server_fd);

	if (proxy->ssl_server_proxy != NULL)
		ssl_proxy_free(&proxy->ssl_server_proxy);
	i_free(proxy->host);
	i_free(proxy);

	client->login_proxy = NULL;
	client_unref(&client);
}

bool login_proxy_is_ourself(const struct client *client, const char *host,
			    unsigned int port, const char *destuser)
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
	return proxy->disconnecting ? NULL : proxy->server_input;
}

struct ostream *login_proxy_get_ostream(struct login_proxy *proxy)
{
	return proxy->server_output;
}

const char *login_proxy_get_host(const struct login_proxy *proxy)
{
	return proxy->host;
}

unsigned int login_proxy_get_port(const struct login_proxy *proxy)
{
	return proxy->port;
}

enum login_proxy_ssl_flags
login_proxy_get_ssl_flags(const struct login_proxy *proxy)
{
	return proxy->ssl_flags;
}

static void login_proxy_notify(struct login_proxy *proxy)
{
	login_proxy_state_notify(proxy_state, proxy->client->proxy_user);
}

void login_proxy_detach(struct login_proxy *proxy)
{
	struct client *client = proxy->client;
	const unsigned char *data;
	size_t size;

	i_assert(proxy->client_fd == -1);
	i_assert(proxy->server_output != NULL);

	proxy->client_fd = i_stream_get_fd(client->input);
	proxy->client_output = client->output;

	o_stream_set_max_buffer_size(client->output, (size_t)-1);
	o_stream_set_flush_callback(client->output, proxy_client_output, proxy);
	client->output = NULL;

	/* send all pending client input to proxy and get rid of the stream */
	data = i_stream_get_data(client->input, &size);
	if (size != 0)
		(void)o_stream_send(proxy->server_output, data, size);

	/* from now on, just do dummy proxying */
	io_remove(&proxy->server_io);
	proxy->server_io =
		io_add(proxy->server_fd, IO_READ, server_input, proxy);
	proxy->client_io =
		io_add(proxy->client_fd, IO_READ, proxy_client_input, proxy);
	o_stream_set_flush_callback(proxy->server_output, server_output, proxy);
	i_stream_destroy(&proxy->server_input);

	if (proxy->notify_refresh_secs != 0) {
		proxy->to_notify =
			timeout_add(proxy->notify_refresh_secs * 1000,
				    login_proxy_notify, proxy);
	}

	proxy->callback = NULL;

	DLLIST_PREPEND(&login_proxies, proxy);

	client->fd = -1;
	client->login_proxy = NULL;
}

static int login_proxy_ssl_handshaked(void *context)
{
	struct login_proxy *proxy = context;

	if ((proxy->ssl_flags & PROXY_SSL_FLAG_ANY_CERT) != 0 ||
	    ssl_proxy_has_valid_client_cert(proxy->ssl_server_proxy))
		return 0;

	if (!ssl_proxy_has_broken_client_cert(proxy->ssl_server_proxy)) {
		client_log_err(proxy->client, t_strdup_printf(
			"proxy: SSL certificate not received from %s:%u",
			proxy->host, proxy->port));
	} else {
		client_log_err(proxy->client, t_strdup_printf(
			"proxy: Received invalid SSL certificate from %s:%u",
			proxy->host, proxy->port));
	}
	proxy->disconnecting = TRUE;
	return -1;
}

int login_proxy_starttls(struct login_proxy *proxy)
{
	int fd;

	if (proxy->server_input != NULL)
		i_stream_destroy(&proxy->server_input);
	if (proxy->server_output != NULL)
		o_stream_destroy(&proxy->server_output);
	io_remove(&proxy->server_io);

	fd = ssl_proxy_client_alloc(proxy->server_fd, &proxy->client->ip,
				    proxy->client->set,
				    login_proxy_ssl_handshaked, proxy,
				    &proxy->ssl_server_proxy);
	if (fd < 0) {
		client_log_err(proxy->client, t_strdup_printf(
			"proxy: SSL handshake failed to %s:%u",
			proxy->host, proxy->port));
		return -1;
	}
	ssl_proxy_set_client(proxy->ssl_server_proxy, proxy->client);
	ssl_proxy_start(proxy->ssl_server_proxy);

	proxy->server_fd = fd;
	proxy_plain_connected(proxy);
	return 0;
}

static void proxy_kill_idle(struct login_proxy *proxy)
{
	login_proxy_free(&proxy);
}

void login_proxy_kill_idle(void)
{
	struct login_proxy *proxy, *next;
	time_t now = time(NULL);
	time_t stop_timestamp = now - LOGIN_PROXY_DIE_IDLE_SECS;
	unsigned int stop_msecs;

	for (proxy = login_proxies; proxy != NULL; proxy = next) {
		next = proxy->next;

		if (proxy->last_io <= stop_timestamp)
			proxy_kill_idle(proxy);
		else {
			i_assert(proxy->to == NULL);
			stop_msecs = (proxy->last_io - stop_timestamp) * 1000;
			proxy->to = timeout_add(stop_msecs,
						proxy_kill_idle, proxy);
		}
	}
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
		login_proxy_free(&proxy);
	}
	login_proxy_state_deinit(&proxy_state);
}
