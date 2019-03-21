#ifndef IPC_GROUP_H
#define IPC_GROUP_H

enum ipc_cmd_status {
	/* Command received a reply line */
	IPC_CMD_STATUS_REPLY,
	/* Command finished successfully */
	IPC_CMD_STATUS_OK,
	/* Command finished with errors */
	IPC_CMD_STATUS_ERROR
};

struct ipc_group {
	int listen_fd;
	char *name;

	/* connections list also acts as a refcount */
	struct ipc_connection *connections;
};

/* line is non-NULL only with IPC_CMD_STATUS_REPLY.
   Each line begins with the connection ID and TAB. */
typedef void ipc_cmd_callback_t(enum ipc_cmd_status status,
				const char *line, void *context);

struct ipc_group *ipc_group_alloc(int listen_fd);
void ipc_group_free(struct ipc_group **group);

struct ipc_group *ipc_group_lookup_listen_fd(int listen_fd);
struct ipc_group *ipc_group_lookup_name(const char *name);

/* Returns 0 if name is ok, -1 if name doesn't match the existing one. */
int ipc_group_update_name(struct ipc_group *group, const char *name);

/* Send a command to all connections in a group. All connections are expected
   to answer something. If there are no connections, callback() is called
   immediately and FALSE is returned. */
bool ipc_group_cmd(struct ipc_group *group, const char *cmd,
		   ipc_cmd_callback_t *callback, void *context);

void ipc_groups_init(void);
void ipc_groups_deinit(void);
void ipc_groups_disconnect_all(void);

#endif
