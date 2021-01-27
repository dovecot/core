/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "istream-zlib.h"
#include "ostream-zlib.h"
#include "module-dir.h"
#include "master-service.h"
#include "doveadm-dump.h"

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

static bool test_dump_imapzlib(const char *path)
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

#ifdef HAVE_ZLIB
static void cmd_dump_imapzlib(int argc ATTR_UNUSED, char *argv[])
{
	struct istream *input, *input2;
	const unsigned char *data;
	size_t size;
	const char *line;
	int fd;

	fd = open(argv[1], O_RDONLY);
	if (fd < 0)
		i_fatal("open(%s) failed: %m", argv[1]);
	input = i_stream_create_fd_autoclose(&fd, 1024*32);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		/* skip tag */
		printf("%s\r\n", line);
		while (*line != ' ' && *line != '\0') line++;
		if (*line == '\0')
			continue;
		line++;

		if (str_begins(line, "OK Begin compression") ||
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
	if (input2->stream_errno != 0) {
		i_error("read(%s) failed: %s",
			argv[1], i_stream_get_error(input));
	}
	i_stream_unref(&input2);
	fflush(stdout);
}

struct client {
	int fd;
	struct io *io_client, *io_server;
	struct istream *input, *stdin_input;
	struct ostream *output;
	bool compressed;
	bool compress_waiting;
};

static bool client_input_is_compress_command(const char *line)
{
	/* skip tag */
	while (*line != ' ' && *line != '\0')
		line++;
	return strcasecmp(line, " COMPRESS DEFLATE") == 0;
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
		if (client_input_is_compress_command(line))
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
	return str_begins(line, " OK Begin compression");
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

		i_info("Server disconnected");
		master_service_stop(master_service);
		return;
	}

	if (!client->compressed && server_input_uncompressed(client)) {
		/* start compression */
		struct istream *input;
		struct ostream *output;

		i_info("<Compression started>");
		input = i_stream_create_deflate(client->input);
		output = o_stream_create_deflate(client->output, 6);
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

static void cmd_zlibconnect(int argc ATTR_UNUSED, char *argv[])
{
	struct client client;
	struct ip_addr *ips;
	unsigned int ips_count;
	in_port_t port = 143;
	int fd, ret;

	if (argv[1] == NULL ||
	    (argv[2] != NULL && net_str2port(argv[2], &port) < 0))
		help(&doveadm_cmd_zlibconnect);

	ret = net_gethostbyname(argv[1], &ips, &ips_count);
	if (ret != 0) {
		i_fatal("Host %s lookup failed: %s", argv[1],
			net_gethosterror(ret));
	}

	if ((fd = net_connect_ip(&ips[0], port, NULL)) == -1)
		i_fatal("connect(%s, %u) failed: %m", argv[1], port);

	i_info("Connected to %s port %u.", net_ip2addr(&ips[0]), port);

	i_zero(&client);
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
	if (close(fd) < 0)
		i_fatal("close() failed: %m");
}
#else
static void cmd_dump_imapzlib(int argc ATTR_UNUSED, char *argv[] ATTR_UNUSED)
{
	i_fatal("Dovecot compiled without zlib support");
}

static void cmd_zlibconnect(int argc ATTR_UNUSED, char *argv[] ATTR_UNUSED)
{
	i_fatal("Dovecot compiled without zlib support");
}
#endif

struct doveadm_cmd_dump doveadm_cmd_dump_zlib = {
	"imapzlib",
	test_dump_imapzlib,
	cmd_dump_imapzlib
};

struct doveadm_cmd doveadm_cmd_zlibconnect = {
	cmd_zlibconnect,
	"zlibconnect",
	"<host> [<port>]"
};
