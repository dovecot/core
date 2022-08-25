/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "istream-zlib.h"
#include "ostream-zlib.h"
#include "module-dir.h"
#include "master-service.h"
#include "compression.h"
#include "doveadm-dump.h"

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

static bool test_dump_imap_compress(struct doveadm_cmd_context *cctx ATTR_UNUSED,
				    const char *path)
{
	const char *p;
	char buf[4096];
	int fd, ret;
	bool match = FALSE;

	p = strrchr(path, '.');
	if (p == NULL || (strcmp(p, ".in") != 0 && strcmp(p, ".out") != 0))
		return FALSE;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return FALSE;

	ret = read(fd, buf, sizeof(buf)-1);
	if (ret > 0) {
		buf[ret] = '\0';
		(void)str_lcase(buf);
		match = strstr(buf, " ok begin compression.") != NULL ||
			strstr(buf, " compress deflate") != NULL;
	}
	i_close_fd(&fd);
	return match;
}

static void
cmd_dump_imap_compress(struct doveadm_cmd_context *cctx,
		       const char *path, const char *const *args ATTR_UNUSED)
{
	struct istream *input, *input2;
	const unsigned char *data;
	size_t size;
	const char *line;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		i_fatal("open(%s) failed: %m", path);
	input = i_stream_create_fd_autoclose(&fd, 1024*32);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		/* skip tag */
		printf("%s\r\n", line);
		while (*line != ' ' && *line != '\0') line++;
		if (*line == '\0')
			continue;
		line++;

		if (str_begins_with(line, "OK Begin compression") ||
		    strcasecmp(line, "COMPRESS DEFLATE") == 0)
			break;
	}

	input2 = i_stream_create_deflate(input);
	i_stream_unref(&input);

	while (i_stream_read_more(input2, &data, &size) != -1) {
		if (fwrite(data, 1, size, stdout) != size)
			break;
		i_stream_skip(input2, size);
	}
	if (input2->stream_errno != 0)
		e_error(cctx->event,
			"read(%s) failed: %s", path, i_stream_get_error(input2));
	i_stream_unref(&input2);
	fflush(stdout);
}

struct client {
	int fd;
	struct event *event;
	struct io *io_client, *io_server;
	struct istream *input, *stdin_input;
	struct ostream *output;
	const struct compression_handler *handler;
	char *algorithm;
	bool compressed;
	bool compress_waiting;
};

static bool
client_input_get_compress_algorithm(struct client *client, const char *line)
{
	const char *algorithm;

	/* skip tag */
	while (*line != ' ' && *line != '\0')
		line++;
	if (!str_begins_icase(line, " COMPRESS ", &algorithm))
		return FALSE;

	if (compression_lookup_handler(t_str_lcase(algorithm),
				       &client->handler) <= 0)
		i_fatal("Unsupported compression mechanism: %s", algorithm);
	return TRUE;
}

static bool client_input_uncompressed(struct client *client)
{
	const char *line;

	if (client->compress_waiting) {
		/* just read all the pipelined input for now */
		(void)i_stream_read(client->stdin_input);
		return TRUE;
	}

	while ((line = i_stream_read_next_line(client->stdin_input)) != NULL) {
		o_stream_nsend_str(client->output, line);
		o_stream_nsend(client->output, "\n", 1);
		if (client_input_get_compress_algorithm(client, line))
			return TRUE;
	}
	return FALSE;
}

static void client_input(struct client *client)
{
	const unsigned char *data;
	size_t size;

	if (!client->compressed &&
	    client_input_uncompressed(client)) {
		/* stop until server has sent reply to COMPRESS command. */
		client->compress_waiting = TRUE;
		return;
	}
	if (client->compressed) {
		if (i_stream_read_more(client->stdin_input, &data, &size) > 0) {
			o_stream_nsend(client->output, data, size);
			i_stream_skip(client->stdin_input, size);
		}
		if (o_stream_flush(client->output) < 0) {
			i_fatal("write() failed: %s",
				o_stream_get_error(client->output));
		}
	}
	if (client->stdin_input->eof) {
		if (client->stdin_input->stream_errno != 0) {
			i_fatal("read(stdin) failed: %s",
				i_stream_get_error(client->stdin_input));
		}
		master_service_stop(master_service);
	}
}

static bool server_input_is_compress_reply(const char *line)
{
	/* skip tag */
	while (*line != ' ' && *line != '\0')
		line++;
	return str_begins_with(line, " OK Begin compression");
}

static bool server_input_uncompressed(struct client *client)
{
	const char *line;

	while ((line = i_stream_read_next_line(client->input)) != NULL) {
		if (write(STDOUT_FILENO, line, strlen(line)) < 0)
			i_fatal("write(stdout) failed: %m");
		if (write(STDOUT_FILENO, "\n", 1) < 0)
			i_fatal("write(stdout) failed: %m");
		if (server_input_is_compress_reply(line))
			return TRUE;
	}
	return FALSE;
}

static void server_input(struct client *client)
{
	const unsigned char *data;
	size_t size;

	if (i_stream_read(client->input) == -1) {
		if (client->input->stream_errno != 0) {
			i_fatal("read(server) failed: %s",
				i_stream_get_error(client->input));
		}

		e_info(client->event, "Server disconnected");
		master_service_stop(master_service);
		return;
	}

	if (!client->compressed && server_input_uncompressed(client)) {
		/* start compression */
		struct istream *input;
		struct ostream *output;

		e_info(client->event, "<Compression started>");
		input = client->handler->create_istream(client->input);
		output = client->handler->create_ostream(client->output, 6);
		i_stream_unref(&client->input);
		o_stream_unref(&client->output);
		client->input = input;
		client->output = output;
		client->compressed = TRUE;
		client->compress_waiting = FALSE;
		i_stream_set_input_pending(client->stdin_input, TRUE);
	}

	data = i_stream_get_data(client->input, &size);
	if (write(STDOUT_FILENO, data, size) < 0)
		i_fatal("write(stdout) failed: %m");
	i_stream_skip(client->input, size);
}

static void cmd_compress_connect(struct doveadm_cmd_context *cctx)
{
	struct client client;
	const char *host;
	struct ip_addr *ips;
	unsigned int ips_count;
	int64_t port_int64;
	in_port_t port = 143;
	int fd, ret;

	if (!doveadm_cmd_param_str(cctx, "host", &host))
		help_ver2(&doveadm_cmd_compress_connect);
	if (doveadm_cmd_param_int64(cctx, "port", &port_int64)) {
		if (port_int64 == 0 || port_int64 > 65535)
			i_fatal("Invalid port: %"PRId64, port_int64);
		port = (in_port_t)port_int64;
	}

	ret = net_gethostbyname(host, &ips, &ips_count);
	if (ret != 0) {
		i_fatal("Host %s lookup failed: %s", host,
			net_gethosterror(ret));
	}

	if ((fd = net_connect_ip(&ips[0], port, NULL)) == -1)
		i_fatal("connect(%s, %u) failed: %m", host, port);

	e_info(cctx->event, "Connected to %s port %u.", net_ip2addr(&ips[0]), port);

	i_zero(&client);
	client.event = event_create(cctx->event);
	client.fd = fd;
	fd_set_nonblock(STDIN_FILENO, TRUE);
	client.stdin_input = i_stream_create_fd(STDIN_FILENO, SIZE_MAX);
	client.input = i_stream_create_fd(fd, SIZE_MAX);
	client.output = o_stream_create_fd(fd, 0);
	o_stream_set_no_error_handling(client.output, TRUE);
	client.io_client = io_add_istream(client.stdin_input, client_input, &client);
	client.io_server = io_add_istream(client.input, server_input, &client);
	master_service_run(master_service, NULL);
	io_remove(&client.io_client);
	io_remove(&client.io_server);
	i_stream_unref(&client.stdin_input);
	i_stream_unref(&client.input);
	o_stream_unref(&client.output);
	event_unref(&client.event);
	if (close(fd) < 0)
		i_fatal("close() failed: %m");
}

struct doveadm_cmd_dump doveadm_cmd_dump_imap_compress = {
	"imap-compress",
	test_dump_imap_compress,
	cmd_dump_imap_compress
};

struct doveadm_cmd_ver2 doveadm_cmd_compress_connect = {
	.name = "compress-connect",
	.cmd = cmd_compress_connect,
	.usage = "<host> [<port>]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('\0', "host", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "port", CMD_PARAM_INT64, CMD_PARAM_FLAG_POSITIONAL|CMD_PARAM_FLAG_UNSIGNED)
DOVEADM_CMD_PARAMS_END
};
