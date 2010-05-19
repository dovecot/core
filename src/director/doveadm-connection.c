/* Copyright (c) 2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "array.h"
#include "str.h"
#include "llist.h"
#include "user-directory.h"
#include "mail-host.h"
#include "director.h"
#include "director-host.h"
#include "director-request.h"
#include "doveadm-connection.h"

#include <unistd.h>

#define DOVEADM_HANDSHAKE_EXPECTED "VERSION\tdirector-doveadm\t1\t"
#define DOVEADM_HANDSHAKE DOVEADM_HANDSHAKE_EXPECTED"0\n"

#define MAX_VALID_VHOST_COUNT 1000

struct doveadm_connection {
	struct doveadm_connection *prev, *next;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;
	struct director *dir;

	unsigned int handshaked:1;
};

static struct doveadm_connection *doveadm_connections;

static void doveadm_connection_deinit(struct doveadm_connection **_conn);

static void doveadm_cmd_host_list(struct doveadm_connection *conn)
{
	struct mail_host *const *hostp;
	string_t *str = t_str_new(1024);

	array_foreach(mail_hosts_get(), hostp) {
		str_printfa(str, "%s\t%u\t%u\n",
			    net_ip2addr(&(*hostp)->ip), (*hostp)->vhost_count,
			    (*hostp)->user_count);
	}
	str_append_c(str, '\n');
	o_stream_send(conn->output, str_data(str), str_len(str));
}

static void doveadm_cmd_director_list(struct doveadm_connection *conn)
{
	struct director_host *const *hostp;
	string_t *str = t_str_new(1024);

	array_foreach(&conn->dir->dir_hosts, hostp) {
		str_printfa(str, "%s\t%u\n",
			    net_ip2addr(&(*hostp)->ip), (*hostp)->port);
	}
	str_append_c(str, '\n');
	o_stream_send(conn->output, str_data(str), str_len(str));
}

static bool
doveadm_cmd_host_set(struct doveadm_connection *conn, const char *line)
{
	const char *const *args;
	struct mail_host *host;
	struct ip_addr ip;
	unsigned int vhost_count = -1U;

	args = t_strsplit(line, "\t");
	if (args[0] == NULL ||
	    net_addr2ip(args[0], &ip) < 0 ||
	    (args[1] != NULL && str_to_uint(args[1], &vhost_count) < 0)) {
		i_error("doveadm sent invalid HOST-SET parameters");
		return FALSE;
	}
	if (vhost_count > MAX_VALID_VHOST_COUNT && vhost_count != -1U) {
		o_stream_send_str(conn->output, "vhost count too large\n");
		return TRUE;
	}
	host = mail_host_lookup(&ip);
	if (host == NULL)
		host = mail_host_add_ip(&ip);
	if (vhost_count != -1U)
		mail_host_set_vhost_count(host, vhost_count);
	director_update_host(conn->dir, conn->dir->self_host, host);

	o_stream_send(conn->output, "OK\n", 3);
	return TRUE;
}

static bool
doveadm_cmd_host_remove(struct doveadm_connection *conn, const char *line)
{
	struct mail_host *host;
	struct ip_addr ip;

	if (net_addr2ip(line, &ip) < 0) {
		i_error("doveadm sent invalid HOST-SET parameters");
		return FALSE;
	}
	host = mail_host_lookup(&ip);
	if (host == NULL)
		o_stream_send_str(conn->output, "NOTFOUND\n");
	else {
		director_remove_host(conn->dir, conn->dir->self_host, host);
		o_stream_send(conn->output, "OK\n", 3);
	}
	return TRUE;
}

static void doveadm_connection_input(struct doveadm_connection *conn)
{
	const char *line;
	bool ret = TRUE;

	if (!conn->handshaked) {
		if ((line = i_stream_read_next_line(conn->input)) == NULL)
			return;

		if (strncmp(line, DOVEADM_HANDSHAKE_EXPECTED,
			    strlen(DOVEADM_HANDSHAKE_EXPECTED)) != 0) {
			i_error("doveadm not compatible with this server "
				"(mixed old and new binaries?)");
			doveadm_connection_deinit(&conn);
			return;
		}
		conn->handshaked = TRUE;
	}

	while ((line = i_stream_read_next_line(conn->input)) != NULL && ret) {
		if (strcmp(line, "HOST-LIST") == 0)
			doveadm_cmd_host_list(conn);
		else if (strcmp(line, "DIRECTOR-LIST") == 0)
			doveadm_cmd_director_list(conn);
		else if (strncmp(line, "HOST-SET\t", 9) == 0)
			ret = doveadm_cmd_host_set(conn, line + 9);
		else if (strncmp(line, "HOST-REMOVE\t", 12) == 0)
			ret = doveadm_cmd_host_remove(conn, line + 12);
		else {
			i_error("doveadm sent unknown command: %s", line);
			ret = FALSE;
		}
	}
	if (conn->input->eof || conn->input->stream_errno != 0 || !ret)
		doveadm_connection_deinit(&conn);
}

struct doveadm_connection *
doveadm_connection_init(struct director *dir, int fd)
{
	struct doveadm_connection *conn;

	conn = i_new(struct doveadm_connection, 1);
	conn->fd = fd;
	conn->dir = dir;
	conn->input = i_stream_create_fd(conn->fd, 1024, FALSE);
	conn->output = o_stream_create_fd(conn->fd, (size_t)-1, FALSE);
	conn->io = io_add(conn->fd, IO_READ, doveadm_connection_input, conn);
	o_stream_send_str(conn->output, DOVEADM_HANDSHAKE);

	DLLIST_PREPEND(&doveadm_connections, conn);
	return conn;
}

static void doveadm_connection_deinit(struct doveadm_connection **_conn)
{
	struct doveadm_connection *conn = *_conn;

	*_conn = NULL;

	DLLIST_REMOVE(&doveadm_connections, conn);
	io_remove(&conn->io);
	o_stream_unref(&conn->output);
	if (close(conn->fd) < 0)
		i_error("close(doveadm connection) failed: %m");
	i_free(conn);
}

void doveadm_connections_deinit(void)
{
	while (doveadm_connections != NULL) {
		struct doveadm_connection *conn = doveadm_connections;

		doveadm_connection_deinit(&conn);
	}
}
