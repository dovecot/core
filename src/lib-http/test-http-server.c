/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "llist.h"
#include "str.h"
#include "ioloop.h"
#include "ostream.h"
#include "connection.h"
#include "http-url.h"
#include "http-server.h"

#include <unistd.h>

static int fd_listen;
static struct ioloop *ioloop;
static struct io *io_listen;
static struct http_server *http_server;
static bool shut_down = FALSE;
static struct client *clients_head = NULL, *clients_tail = NULL;

struct client {
	struct client *prev, *next;

	struct ip_addr server_ip, ip;
	in_port_t server_port, port;
	struct http_server_connection *http_conn;
};

static void
client_destroy(struct client **_client, const char *reason)
{
	struct client *client = *_client;

	if (client->http_conn != NULL) {
		/* We're not in the lib-http/server's connection destroy callback.
		   If at all possible, avoid destroying client objects directly.
	   */
		http_server_connection_close(&client->http_conn, reason);
	}
	DLLIST2_REMOVE(&clients_head, &clients_tail, client);
	i_free(client);

	if (clients_head == NULL)
		io_loop_stop(ioloop);
}

/* This function just serves as an illustration of what to do when client
   objects are destroyed by some actor other than lib-http/server. The best way
   to close all clients is to drop the whole http-server, which will close all
   connections, which in turn calls the connection_destroy() callbacks. Using a
   function like this just complicates matters. */
static void
clients_destroy_all(void)
{
	while (clients_head != NULL) {
		struct client *client = clients_head;
		client_destroy(&client, "Shutting down server");
	}
}

static void
client_http_handle_request(void *context,
	struct http_server_request *req)
{
	struct client *client = (struct client *)context;
	const struct http_request *http_req = http_server_request_get(req);
	struct http_server_response *http_resp;
	const char *ipport;
	string_t *content;

	if (strcmp(http_req->method, "GET") != 0) {
		/* Unsupported method */
		http_resp = http_server_response_create(req, 501, "Not Implemented");
		http_server_response_add_header(http_resp, "Allow", "GET");
		http_server_response_submit(http_resp);
		return;
	}

	/* Compose response payload */
	content = t_str_new(1024);
	(void)net_ipport2str(&client->server_ip, client->server_port, &ipport);
	str_printfa(content, "Server: %s\r\n", ipport);
	(void)net_ipport2str(&client->ip, client->port, &ipport);
	str_printfa(content, "Client: %s\r\n", ipport);
	str_printfa(content, "Host: %s", http_req->target.url->host.name);
	if (http_req->target.url->port != 0)
		str_printfa(content, ":%u", http_req->target.url->port);
	str_append(content, "\r\n");
	switch (http_req->target.format) {
	case HTTP_REQUEST_TARGET_FORMAT_ORIGIN:
	case HTTP_REQUEST_TARGET_FORMAT_ABSOLUTE:
		str_printfa(content, "Target: %s\r\n",
			http_url_create(http_req->target.url));
		break;
	case HTTP_REQUEST_TARGET_FORMAT_AUTHORITY:
		str_printfa(content, "Target: %s\r\n",
			http_url_create_authority(http_req->target.url));
		break;
	case HTTP_REQUEST_TARGET_FORMAT_ASTERISK:
		str_append(content, "Target: *\r\n");
		break;
	}

	/* Just respond with the request target */
	http_resp = http_server_response_create(req, 200, "OK");
	http_server_response_add_header(http_resp, "Content-Type", "text/plain");
	http_server_response_set_payload_data(http_resp,
		str_data(content), str_len(content));
	http_server_response_submit(http_resp);
}

static void
client_http_connection_destroy(void *context, const char *reason)
{
	struct client *client = (struct client *)context;

	if (client->http_conn == NULL) {
		/* already destroying client directly */
		return;
	}

	/* HTTP connection is destroyed already now */
	client->http_conn = NULL;

	/* destroy the client itself */
	client_destroy(&client, reason);
}

static const struct http_server_callbacks server_callbacks = {
	.handle_request = client_http_handle_request,
	.connection_destroy = client_http_connection_destroy
};

static void
client_init(int fd, const struct ip_addr *ip, in_port_t port)
{
	struct client *client;
	struct http_request_limits req_limits;

	i_zero(&req_limits);
	req_limits.max_target_length = 4096;

	client = i_new(struct client, 1);
	client->ip = *ip;
	client->port = port;
	(void)net_getsockname(fd, &client->server_ip, &client->server_port);
	client->http_conn = http_server_connection_create(http_server,
		fd, fd, FALSE, &server_callbacks, client);

	DLLIST2_APPEND(&clients_head, &clients_tail, client);
}

static void client_accept(void *context ATTR_UNUSED)
{
	struct ip_addr client_ip;
	in_port_t client_port;
	int fd;

	fd = net_accept(fd_listen, &client_ip, &client_port);
	if (fd == -1)
		return;
	if (fd == -2)
		i_fatal("accept() failed: %m");

	client_init(fd, &client_ip, client_port);
}

static void
sig_die(const siginfo_t *si ATTR_UNUSED, void *context ATTR_UNUSED)
{
	if (shut_down) {
		i_info("Received SIGINT again - stopping immediately");
		io_loop_stop(current_ioloop);
		return;
	}

	i_info("Received SIGINT - shutting down gracefully");
	shut_down = TRUE;
	http_server_shut_down(http_server);
	if (clients_head == NULL)
		io_loop_stop(ioloop);
}

int main(int argc, char *argv[])
{
	struct http_server_settings http_set;
	bool debug = FALSE;
	struct ip_addr my_ip;
	in_port_t port;
	int c;

	lib_init();

  while ((c = getopt(argc, argv, "D")) > 0) {
		switch (c) {
		case 'D':
			debug = TRUE;
			break;
		default:
			i_fatal("Usage: %s [-D] <port> [<IP>]", argv[0]);
		}
  }
	argc -= optind;
	argv += optind;

	if (argc < 1 || net_str2port(argv[0], &port) < 0)
		i_fatal("Port parameter missing");
	if (argc < 2)
		my_ip = net_ip4_any;
	else if (net_addr2ip(argv[1], &my_ip) < 0)
		i_fatal("Invalid IP parameter");

	i_zero(&http_set);
	http_set.max_client_idle_time_msecs = 20*1000; /* defaults to indefinite! */
	http_set.max_pipelined_requests = 4;
	http_set.debug = debug;

	ioloop = io_loop_create();

	http_server = http_server_init(&http_set);

	lib_signals_init();
	lib_signals_ignore(SIGPIPE, TRUE);
	lib_signals_set_handler(SIGTERM, LIBSIG_FLAG_DELAYED, sig_die, NULL);
	lib_signals_set_handler(SIGINT, LIBSIG_FLAG_DELAYED, sig_die, NULL);

	fd_listen = net_listen(&my_ip, &port, 128);
	if (fd_listen == -1)
		i_fatal("listen(port=%u) failed: %m", port);

	io_listen = io_add(fd_listen, IO_READ, client_accept, NULL);

	io_loop_run(ioloop);

	io_remove(&io_listen);
	i_close_fd(&fd_listen);

	clients_destroy_all(); /* just an example; avoid doing this */

	http_server_deinit(&http_server);
	lib_signals_deinit();
	io_loop_destroy(&ioloop);
	lib_deinit();
}
