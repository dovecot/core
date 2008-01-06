/* Copyright (c) 2004-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "llist.h"
#include "str-sanitize.h"
#include "client-common.h"
#include "login-proxy.h"

#define MAX_PROXY_INPUT_SIZE 4096
#define OUTBUF_THRESHOLD 1024

struct login_proxy {
	struct login_proxy *prev, *next;

	int client_fd, server_fd;
	struct io *client_io, *server_io;
	struct istream *server_input;
	struct ostream *client_output, *server_output;
	struct ip_addr ip;

	char *host, *user;
	unsigned int port;

	proxy_callback_t *callback;
	void *context;

	unsigned int destroying:1;
};

static struct login_proxy *login_proxies = NULL;
static unsigned int login_proxy_count = 0;

static void server_input(struct login_proxy *proxy)
{
	unsigned char buf[OUTBUF_THRESHOLD];
	ssize_t ret;

	if (o_stream_get_buffer_used_size(proxy->client_output) >
	    OUTBUF_THRESHOLD) {
		/* client's output buffer is already quite full.
		   don't send more until we're below threshold. */
		io_remove(&proxy->server_io);
		return;
	}

	ret = net_receive(proxy->server_fd, buf, sizeof(buf));
	if (ret < 0 || o_stream_send(proxy->client_output, buf, ret) != ret)
                login_proxy_free(proxy);
}

static void proxy_client_input(struct login_proxy *proxy)
{
	unsigned char buf[OUTBUF_THRESHOLD];
	ssize_t ret;

	if (o_stream_get_buffer_used_size(proxy->server_output) >
	    OUTBUF_THRESHOLD) {
		/* proxy's output buffer is already quite full.
		   don't send more until we're below threshold. */
		io_remove(&proxy->client_io);
		return;
	}

	ret = net_receive(proxy->client_fd, buf, sizeof(buf));
	if (ret < 0 || o_stream_send(proxy->server_output, buf, ret) != ret)
                login_proxy_free(proxy);
}

static int server_output(struct login_proxy *proxy)
{
	if (o_stream_flush(proxy->server_output) < 0) {
                login_proxy_free(proxy);
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
	if (o_stream_flush(proxy->client_output) < 0) {
                login_proxy_free(proxy);
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
	proxy->callback(proxy->server_input, proxy->server_output,
			proxy->context);
}

static void proxy_wait_connect(struct login_proxy *proxy)
{
	int err;

	err = net_geterror(proxy->server_fd);
	if (err != 0) {
		i_error("proxy: connect(%s, %u) failed: %s",
			proxy->host, proxy->port, strerror(err));
                login_proxy_free(proxy);
		return;
	}

	/* connect successful */
	proxy->server_input =
		i_stream_create_fd(proxy->server_fd, MAX_PROXY_INPUT_SIZE,
				   FALSE);
	proxy->server_output =
		o_stream_create_fd(proxy->server_fd, (size_t)-1, FALSE);

	io_remove(&proxy->server_io);
	proxy->server_io =
		io_add(proxy->server_fd, IO_READ, proxy_prelogin_input, proxy);
}

#undef login_proxy_new
struct login_proxy *
login_proxy_new(struct client *client, const char *host, unsigned int port,
		proxy_callback_t *callback, void *context)
{
	struct login_proxy *proxy;
	struct ip_addr ip;
	int fd;

	if (host == NULL) {
		i_error("proxy(%s): host not given", client->virtual_user);
		return NULL;
	}

	if (net_addr2ip(host, &ip) < 0) {
		i_error("proxy(%s): %s is not a valid IP",
			client->virtual_user, host);
		return NULL;
	}

	fd = net_connect_ip(&ip, port, NULL);
	if (fd < 0) {
		i_error("proxy(%s): connect(%s, %u) failed: %m",
			client->virtual_user, host, port);
		return NULL;
	}

	proxy = i_new(struct login_proxy, 1);
	proxy->host = i_strdup(host);
	proxy->user = i_strdup(client->virtual_user);
	proxy->port = port;

	proxy->server_fd = fd;
	proxy->server_io = io_add(fd, IO_WRITE, proxy_wait_connect, proxy);

	proxy->callback = callback;
	proxy->context = context;

	proxy->ip = client->ip;
	proxy->client_fd = -1;
	return proxy;
}

void login_proxy_free(struct login_proxy *proxy)
{
	const char *ipstr;

	if (proxy->destroying)
		return;
	proxy->destroying = TRUE;

	if (proxy->client_fd != -1) {
		/* detached proxy */
		main_unref();
		DLLIST_REMOVE(&login_proxies, proxy);
		login_proxy_count--;

		ipstr = net_ip2addr(&proxy->ip);
		i_info("proxy(%s): disconnecting %s",
		       str_sanitize(proxy->user, 80),
		       ipstr != NULL ? ipstr : "");

		if (proxy->client_io != NULL)
			io_remove(&proxy->client_io);
		if (proxy->client_output != NULL)
			o_stream_destroy(&proxy->client_output);
		net_disconnect(proxy->client_fd);
	} else {
		i_assert(proxy->client_io == NULL);
		i_assert(proxy->client_output == NULL);

		proxy->callback(NULL, NULL, proxy->context);
	}

	if (proxy->server_io != NULL)
		io_remove(&proxy->server_io);
	if (proxy->server_input != NULL)
		i_stream_destroy(&proxy->server_input);
	if (proxy->server_output != NULL)
		o_stream_destroy(&proxy->server_output);
	net_disconnect(proxy->server_fd);

	i_free(proxy->host);
	i_free(proxy->user);
	i_free(proxy);

	main_listen_start();
}

bool login_proxy_is_ourself(struct client *client, const char *host,
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

const char *login_proxy_get_host(struct login_proxy *proxy)
{
	return proxy->host;
}

unsigned int login_proxy_get_port(struct login_proxy *proxy)
{
	return proxy->port;
}

unsigned int login_proxy_get_count(void)
{
	return login_proxy_count;
}

void login_proxy_detach(struct login_proxy *proxy, struct istream *client_input,
			struct ostream *client_output)
{
	const unsigned char *data;
	size_t size;

	i_assert(proxy->client_fd == -1);
	i_assert(proxy->server_output != NULL);

	proxy->client_fd = i_stream_get_fd(client_input);
	proxy->client_output = client_output;

	o_stream_set_max_buffer_size(client_output, (size_t)-1);
	o_stream_set_flush_callback(client_output, proxy_client_output, proxy);

	/* send all pending client input to proxy and get rid of the stream */
	data = i_stream_get_data(client_input, &size);
	if (size != 0)
		(void)o_stream_send(proxy->server_output, data, size);
	i_stream_unref(&client_input);

	/* from now on, just do dummy proxying */
	io_remove(&proxy->server_io);
	proxy->server_io =
		io_add(proxy->server_fd, IO_READ, server_input, proxy);
	proxy->client_io =
		io_add(proxy->client_fd, IO_READ, proxy_client_input, proxy);
	o_stream_set_flush_callback(proxy->server_output, server_output, proxy);
	i_stream_destroy(&proxy->server_input);

	proxy->callback = NULL;
	proxy->context = NULL;

	login_proxy_count++;
	DLLIST_PREPEND(&login_proxies, proxy);
	main_ref();
}

void login_proxy_deinit(void)
{
	while (login_proxies != NULL)
		login_proxy_free(login_proxies);
}
