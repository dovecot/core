#ifndef IPC_CLIENT_H
#define IPC_CLIENT_H

enum ipc_client_cmd_state {
	IPC_CLIENT_CMD_STATE_REPLY,
	IPC_CLIENT_CMD_STATE_OK,
	IPC_CLIENT_CMD_STATE_ERROR
};

typedef void ipc_client_callback_t(enum ipc_client_cmd_state state,
				   const char *data, void *context);

struct ipc_client *
ipc_client_init(const char *ipc_socket_path);
void ipc_client_deinit(struct ipc_client **client);

struct ipc_client_cmd *
ipc_client_cmd(struct ipc_client *client, const char *cmd,
	       ipc_client_callback_t *callback, void *context)
	ATTR_NULL(4);
void ipc_client_cmd_abort(struct ipc_client *client,
			  struct ipc_client_cmd **cmd);

#endif
