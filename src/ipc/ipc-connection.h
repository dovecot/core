#ifndef IPC_CONNECTION_H
#define IPC_CONNECTION_H

#include "ipc-group.h"

struct ipc_connection_cmd {
	unsigned int tag;
	struct ipc_connection *conn;

	ipc_cmd_callback_t *callback;
	void *context;
};

struct ipc_connection {
	struct ipc_group *group;
	/* prev/next within group */
	struct ipc_connection *prev, *next;

	unsigned int id;
	pid_t pid;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	unsigned int cmd_tag_counter;

	/* running commands */
	ARRAY_DEFINE(cmds, struct ipc_connection_cmd *);

	unsigned int version_received:1;
	unsigned int handshake_received:1;
};

struct ipc_connection *ipc_connection_create(int listen_fd, int fd);
void ipc_connection_destroy(struct ipc_connection **conn);

struct ipc_connection *
ipc_connection_lookup_id(struct ipc_group *group, unsigned int id);

void ipc_connection_cmd(struct ipc_connection *conn, const char *cmd,
			ipc_cmd_callback_t *callback, void *context);

#endif
