/* Copyright (C) 2004 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "safe-memset.h"
#include "hash.h"
#include "client-common.h"
#include "login-proxy.h"

#define MAX_INBUF_SIZE 4096
#define OUTBUF_THRESHOLD 1024

struct login_proxy {
	struct client *client;

	int client_fd, proxy_fd;
	struct io *client_io, *proxy_io;
	struct ostream *client_output, *proxy_output;

	char *host, *user, *login_cmd;
	unsigned int port;
};

static struct hash_table *login_proxies;

static void login_proxy_free(struct login_proxy *proxy);

static void proxy_input(void *context)
{
	struct login_proxy *proxy = context;
	unsigned char buf[OUTBUF_THRESHOLD];
	ssize_t ret;

	if (o_stream_get_buffer_used_size(proxy->client_output) >
	    OUTBUF_THRESHOLD) {
		/* client's output buffer is already quite full.
		   don't send more until we're below threshold. */
		io_remove(proxy->proxy_io);
		proxy->proxy_io = NULL;
		return;
	}

	ret = net_receive(proxy->proxy_fd, buf, sizeof(buf));
	if (ret > 0)
		(void)o_stream_send(proxy->client_output, buf, ret);
	else if (ret < 0)
                login_proxy_free(proxy);
}

static void proxy_client_input(void *context)
{
	struct login_proxy *proxy = context;
	unsigned char buf[OUTBUF_THRESHOLD];
	ssize_t ret;

	if (o_stream_get_buffer_used_size(proxy->proxy_output) >
	    OUTBUF_THRESHOLD) {
		/* proxy's output buffer is already quite full.
		   don't send more until we're below threshold. */
		io_remove(proxy->client_io);
		proxy->client_io = NULL;
		return;
	}

	ret = net_receive(proxy->client_fd, buf, sizeof(buf));
	if (ret > 0)
		(void)o_stream_send(proxy->proxy_output, buf, ret);
	else if (ret < 0)
                login_proxy_free(proxy);
}

static void proxy_output(void *context)
{
	struct login_proxy *proxy = context;

	if (o_stream_flush(proxy->proxy_output) < 0) {
                login_proxy_free(proxy);
		return;
	}

	if (proxy->client_io == NULL &&
	    o_stream_get_buffer_used_size(proxy->proxy_output) <
	    OUTBUF_THRESHOLD) {
		/* there's again space in proxy's output buffer, so we can
		   read more from client. */
		proxy->client_io = io_add(proxy->client_fd, IO_READ,
					  proxy_client_input, proxy);
	}
}

static void proxy_client_output(void *context)
{
	struct login_proxy *proxy = context;

	if (o_stream_flush(proxy->client_output) < 0) {
                login_proxy_free(proxy);
		return;
	}

	if (proxy->proxy_io == NULL &&
	    o_stream_get_buffer_used_size(proxy->client_output) <
	    OUTBUF_THRESHOLD) {
		/* there's again space in client's output buffer, so we can
		   read more from proxy. */
		proxy->proxy_io =
			io_add(proxy->proxy_fd, IO_READ, proxy_input, proxy);
	}
}

static void proxy_prelogin_input(void *context)
{
	struct login_proxy *proxy = context;
	unsigned char buf[1024];
	ssize_t ret;

	ret = net_receive(proxy->proxy_fd, buf, sizeof(buf));
	if (ret < 0) {
		/* disconnected */
		login_proxy_free(proxy);
		return;
	}

	/* we just want to eat away the first banner line. be dummy and don't
	   check any errors, so we don't need any IMAP/POP3-specific things
	   here (except for assuming the banner line..) */
	if (buf[ret-1] != '\n')
		return;

	/* send LOGIN command */
	(void)o_stream_send_str(proxy->proxy_output, proxy->login_cmd);

	safe_memset(proxy->login_cmd, 0, strlen(proxy->login_cmd));
	i_free(proxy->login_cmd);
        proxy->login_cmd = NULL;

	/* from now on, just do dummy proxying */
	io_remove(proxy->proxy_io);
	proxy->proxy_io = io_add(proxy->proxy_fd, IO_READ, proxy_input, proxy);
	proxy->client_io = io_add(proxy->client_fd, IO_READ,
				  proxy_client_input, proxy);

	proxy->client_output =
		o_stream_create_file(proxy->client_fd, default_pool,
				     (size_t)-1, FALSE);

	o_stream_set_flush_callback(proxy->client_output,
				    proxy_client_output, proxy);
	o_stream_set_flush_callback(proxy->proxy_output, proxy_output, proxy);
}

static void proxy_wait_connect(void *context)
{
	struct login_proxy *proxy = context;
	int err;

	err = net_geterror(proxy->proxy_fd);
	if (err != 0) {
		i_error("proxy: connect(%s, %u) failed: %s",
			proxy->host, proxy->port, strerror(err));
                login_proxy_free(proxy);
		return;
	}

	/* initialize proxy's streams */
	proxy->proxy_output =
		o_stream_create_file(proxy->proxy_fd, default_pool,
				     (size_t)-1, FALSE);

	io_remove(proxy->proxy_io);
	proxy->proxy_io =
		io_add(proxy->proxy_fd, IO_READ, proxy_prelogin_input, proxy);
}

int login_proxy_new(struct client *client, const char *host,
		    unsigned int port, const char *login_cmd)
{
	struct login_proxy *proxy;
	struct ip_addr ip;
	int fd;

	if (host == NULL) {
		i_error("proxy(%s): host not given", client->virtual_user);
		return -1;
	}

	if (net_addr2ip(host, &ip) < 0) {
		i_error("proxy(%s): %s is not a valid IP",
			client->virtual_user, host);
		return -1;
	}

	fd = net_connect_ip(&ip, port, NULL);
	if (fd < 0) {
		i_error("proxy(%s): connect(%s, %u) failed: %m",
			client->virtual_user, host, port);
		return -1;
	}

	proxy = i_new(struct login_proxy, 1);
	proxy->host = i_strdup(host);
	proxy->login_cmd = i_strdup(login_cmd);
	proxy->port = port;

	proxy->proxy_fd = fd;
	proxy->proxy_io = io_add(fd, IO_WRITE, proxy_wait_connect, proxy);

	/* move client fd */
	proxy->client_fd = client->fd;
	client->fd = -1;

	if (login_proxies == NULL) {
		login_proxies = hash_create(default_pool, default_pool,
					    0, NULL, NULL);
	}
	hash_insert(login_proxies, proxy, proxy);

	proxy->client = client;
	main_ref();
	return 0;
}

static void login_proxy_free(struct login_proxy *proxy)
{
	main_unref();

	hash_remove(login_proxies, proxy);

	if (proxy->proxy_io != NULL)
		io_remove(proxy->proxy_io);
	if (proxy->proxy_output != NULL)
		o_stream_unref(proxy->proxy_output);

	if (proxy->client_io != NULL)
		io_remove(proxy->client_io);
	if (proxy->client_output != NULL)
		o_stream_unref(proxy->client_output);

	net_disconnect(proxy->proxy_fd);
	net_disconnect(proxy->client_fd);

	if (proxy->login_cmd != NULL) {
		safe_memset(proxy->login_cmd, 0, strlen(proxy->login_cmd));
		i_free(proxy->login_cmd);
	}

	i_free(proxy->host);
	i_free(proxy->user);
	i_free(proxy);
}

void login_proxy_deinit(void)
{
	struct hash_iterate_context *iter;
	void *key, *value;

	if (login_proxies == NULL)
		return;

	iter = hash_iterate_init(login_proxies);
	while (hash_iterate(iter, &key, &value))
		login_proxy_free(value);
	hash_iterate_deinit(iter);
	hash_destroy(login_proxies);
}
