/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "network.h"
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

const char *doveadm_zlib_plugin_version = DOVECOT_VERSION;

extern struct doveadm_cmd doveadm_cmd_zlibconnect;

void doveadm_zlib_plugin_init(struct module *module);
void doveadm_zlib_plugin_deinit(void);

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
	input = i_stream_create_fd(fd, 1024*32, TRUE);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		/* skip tag */
		printf("%s\r\n", line);
		while (*line != ' ' && *line != '\0') line++;
		if (*line == '\0')
			continue;
		line++;

		if (strcmp(line, "OK Begin compression.") == 0 ||
		    strcasecmp(line, "COMPRESS DEFLATE") == 0)
			break;
	}

	input2 = i_stream_create_deflate(input, TRUE);
	i_stream_unref(&input);

	while (i_stream_read_data(input2, &data, &size, 0) != -1) {
		fwrite(data, 1, size, stdout);
		i_stream_skip(input2, size);
	}
	i_stream_unref(&input2);
	fflush(stdout);
}

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
		str_lcase(buf);
		match = strstr(buf, " ok begin compression.") != NULL ||
			strstr(buf, " compress deflate") != NULL;
	}
	(void)close(fd);
	return match;
}

struct client {
	int fd;
	struct io *io_client, *io_server;
	struct istream *input;
	struct ostream *output;
	bool compressed;
};

static void client_input(struct client *client)
{
	struct istream *input;
	struct ostream *output;
	unsigned char buf[1024];
	ssize_t ret;

	ret = read(STDIN_FILENO, buf, sizeof(buf));
	if (ret == 0) {
		if (client->compressed) {
			master_service_stop(master_service);
			return;
		}
		/* start compression */
		i_info("<Compression started>");
		input = i_stream_create_deflate(client->input, TRUE);
		output = o_stream_create_deflate(client->output, 6);
		i_stream_unref(&client->input);
		o_stream_unref(&client->output);
		client->input = input;
		client->output = output;
		client->compressed = TRUE;
		return;
	}
	if (ret < 0)
		i_fatal("read(stdin) failed: %m");

	o_stream_send(client->output, buf, ret);
}

static void server_input(struct client *client)
{
	const unsigned char *data;
	size_t size;

	if (i_stream_read(client->input) == -1) {
		if (client->input->stream_errno != 0) {
			errno = client->input->stream_errno;
			i_fatal("read(server) failed: %m");
		}

		i_info("Server disconnected");
		master_service_stop(master_service);
		return;
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
	unsigned int ips_count, port;
	int fd, ret;

	if (argv[1] == NULL || argv[2] == NULL ||
	    str_to_uint(argv[2], &port) < 0)
		help(&doveadm_cmd_zlibconnect);

	ret = net_gethostbyname(argv[1], &ips, &ips_count);
	if (ret != 0) {
		i_fatal("Host %s lookup failed: %s", argv[1],
			net_gethosterror(ret));
	}

	if ((fd = net_connect_ip(&ips[0], port, NULL)) == -1)
		i_fatal("connect(%s, %u) failed: %m", argv[1], port);

	i_info("Connected to %s port %u. Ctrl-D starts compression",
	       net_ip2addr(&ips[0]), port);

	memset(&client, 0, sizeof(client));
	client.fd = fd;
	client.input = i_stream_create_fd(fd, (size_t)-1, FALSE);
	client.output = o_stream_create_fd(fd, 0, FALSE);
	client.io_client = io_add(STDIN_FILENO, IO_READ, client_input, &client);
	client.io_server = io_add(fd, IO_READ, server_input, &client);
	master_service_run(master_service, NULL);
	io_remove(&client.io_client);
	io_remove(&client.io_server);
	i_stream_unref(&client.input);
	o_stream_unref(&client.output);
	if (close(fd) < 0)
		i_fatal("close() failed: %m");
}

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

void doveadm_zlib_plugin_init(struct module *module ATTR_UNUSED)
{
	doveadm_dump_register(&doveadm_cmd_dump_zlib);
	doveadm_register_cmd(&doveadm_cmd_zlibconnect);
}

void doveadm_zlib_plugin_deinit(void)
{
}
