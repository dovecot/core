/* Copyright (c) 2024 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "auth-common.h"
#include "auth-master-connection.h"
#include "test-auth-master.h"

#include <sys/stat.h>

void auth_master_server_connected(int *server_fd, const char *socket)
{
	struct stat st;
	i_zero(&st);
	struct auth *auth = auth_default_protocol();
	int fd = net_accept(*server_fd, NULL, NULL);
	i_assert(fd > 0);
	auth_master_connection_create(auth, fd, socket, &st, FALSE);
}

void auth_master_server_deinit(void)
{
	auth_master_connections_destroy_all();
}
