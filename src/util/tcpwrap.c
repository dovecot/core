/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "fdpass.h"
#include "write-full.h"
#include "restrict-access.h"
#include "master-service.h"

#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <tcpd.h>

struct tcpwrap_client {
	int fd;
	struct io *io;
	struct timeout *to;
};

#define INPUT_TIMEOUT_MSECS (1000*10)

/* for tcpwrap library */
int allow_severity = LOG_INFO;
int deny_severity = LOG_WARNING;

static struct tcpwrap_client *tcpwrap_client = NULL;

static void tcpwrap_client_destroy(struct tcpwrap_client **client);

static void tcpwrap_client_handle(struct tcpwrap_client *client, int check_fd,
				  const char *daemon_name)
{
	struct request_info request;

	request_init(&request, RQ_DAEMON, daemon_name,
		     RQ_FILE, check_fd, 0);
	fromhost(&request);

	if (!hosts_access(&request))
		(void)write_full(client->fd, "0\n", 2);
	else
		(void)write_full(client->fd, "1\n", 2);
	exit(0);
}

static void tcpwrap_client_input(struct tcpwrap_client *client)
{
	unsigned char buf[1024];
	ssize_t ret;
	int check_fd = -1;

	ret = fd_read(client->fd, buf, sizeof(buf), &check_fd);
	if (ret <= 0) {
		i_error("fd_read() failed: %m");
	} else if (ret > 1 && (size_t)ret < sizeof(buf) && buf[ret-1] == '\n') {
		tcpwrap_client_handle(client, check_fd, t_strndup(buf, ret-1));
	} else {
		i_error("Invalid input from client");
	}

	if (check_fd != -1) {
		if (close(check_fd) < 0)
			i_error("close(fdread fd) failed: %m");
	}
	tcpwrap_client_destroy(&client);
}

static void tcpwrap_client_timeout(struct tcpwrap_client *client)
{
	tcpwrap_client_destroy(&client);
}

static struct tcpwrap_client *tcpwrap_client_create(int fd)
{
	struct tcpwrap_client *client;

	client = i_new(struct tcpwrap_client, 1);
	client->fd = fd;
	client->io = io_add(fd, IO_READ, tcpwrap_client_input, client);
	client->to = timeout_add(INPUT_TIMEOUT_MSECS, tcpwrap_client_timeout,
				 client);
	return client;
}

static void tcpwrap_client_destroy(struct tcpwrap_client **_client)
{
	struct tcpwrap_client *client = *_client;

	*_client = NULL;

	timeout_remove(&client->to);
	io_remove(&client->io);
	if (close(client->fd) < 0)
		i_error("close() failed: %m");
	i_free(client);

	tcpwrap_client = NULL;
	master_service_client_connection_destroyed(master_service);
}

static void client_connected(struct master_service_connection *conn)
{
	if (tcpwrap_client != NULL) {
		i_error("tcpwrap must be configured with client_limit=1");
		return;
	}

	master_service_client_connection_accept(conn);
	tcpwrap_client = tcpwrap_client_create(conn->fd);
}

int main(int argc, char *argv[])
{
	master_service = master_service_init("tcpwrap", 0,
					     &argc, &argv, NULL);
	if (master_getopt(master_service) > 0)
		return FATAL_DEFAULT;

	master_service_init_log(master_service, "tcpwrap: ");
	restrict_access_by_env(NULL, FALSE);
	restrict_access_allow_coredumps(TRUE);

	master_service_init_finish(master_service);

	master_service_run(master_service, client_connected);
	if (tcpwrap_client != NULL)
		tcpwrap_client_destroy(&tcpwrap_client);

	master_service_deinit(&master_service);
        return 0;
}
