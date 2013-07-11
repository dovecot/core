/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "ioloop.h"
#include "ostream.h"
#include "connection.h"
#include "http-date.h"
#include "http-request-parser.h"

static struct connection_list *clients;
static int fd_listen;
struct io *io_listen;

struct client {
	struct connection conn;
	struct http_request_parser *parser;
};

static void client_destroy(struct connection *conn)
{
	struct client *client = (struct client *)conn;

	http_request_parser_deinit(&client->parser);
	connection_deinit(&client->conn);
	i_free(client);
}

static int
client_handle_request(struct client *client, struct http_request *request)
{
	string_t *str = t_str_new(128);

	if (strcmp(request->method, "GET") != 0) {
		o_stream_send_str(client->conn.output, "HTTP/1.1 501 Not Implemented\r\nAllow: GET\r\n\r\n");
		return 0;
	}
	str_append(str, "HTTP/1.1 200 OK\r\n");
	str_printfa(str, "Date: %s\r\n", http_date_create(ioloop_time));
	str_printfa(str, "Content-Length: %d\r\n", (int)strlen(request->target));
	str_append(str, "Content-Type: text/plain\r\n");
	str_append(str, "\r\n");
	str_append(str, request->target);
	o_stream_send(client->conn.output, str_data(str), str_len(str));
	return 0;
}

static void client_input(struct connection *conn)
{
	struct client *client = (struct client *)conn;
	struct http_request *request;
	const char *error;
	int ret;

	while ((ret = http_request_parse_next(client->parser, &request, &error)) > 0) {
		if (client_handle_request(client, request) < 0 ||
		    request->connection_close) {
			client_destroy(conn);
			return;
		}
	}
	if (ret < 0) {
		i_error("Client sent invalid request: %s", error);
		client_destroy(conn);
	}
}

static struct connection_settings client_set = {
	.input_max_size = (size_t)-1,
	.output_max_size = (size_t)-1,
	.client = FALSE
};

static const struct connection_vfuncs client_vfuncs = {
	.destroy = client_destroy,
	.input = client_input
};

static void client_init(int fd)
{
	struct client *client;

	client = i_new(struct client, 1);
	connection_init_server(clients, &client->conn,
			       "(http client)", fd, fd);
	client->parser = http_request_parser_init(client->conn.input);
}

static void client_accept(void *context ATTR_UNUSED)
{
	int fd;

	fd = net_accept(fd_listen, NULL, NULL);
	if (fd == -1)
		return;
	if (fd == -2)
		i_fatal("accept() failed: %m");

	client_init(fd);
}

int main(int argc, char *argv[])
{
	struct ip_addr my_ip;
	struct ioloop *ioloop;
	unsigned int port;

	lib_init();
	if (argc < 2 || str_to_uint(argv[1], &port) < 0)
		i_fatal("Port parameter missing");
	if (argc < 3)
		net_get_ip_any4(&my_ip);
	else if (net_addr2ip(argv[2], &my_ip) < 0)
		i_fatal("Invalid IP parameter");

	ioloop = io_loop_create();
	clients = connection_list_init(&client_set, &client_vfuncs);

	fd_listen = net_listen(&my_ip, &port, 128);
	if (fd_listen == -1)
		i_fatal("listen(port=%u) failed: %m", port);
	io_listen = io_add(fd_listen, IO_READ, client_accept, NULL);

	io_loop_run(ioloop);

	io_remove(&io_listen);
	i_close_fd(&fd_listen);
	connection_list_deinit(&clients);
	io_loop_destroy(&ioloop);
	lib_deinit();
}
