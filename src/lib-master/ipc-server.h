#ifndef IPC_SERVER_H
#define IPC_SERVER_H

struct ipc_cmd;

/* The callback must eventually free the cmd by calling ip_cmd_success/fail().
   line is guaranteed to be non-empty. */
typedef void ipc_command_callback_t(struct ipc_cmd *cmd, const char *line);

struct ipc_server *
ipc_server_init(const char *ipc_socket_path, const char *name,
		ipc_command_callback_t *callback);
void ipc_server_deinit(struct ipc_server **server);

void ipc_cmd_send(struct ipc_cmd *cmd, const char *data);
void ipc_cmd_success(struct ipc_cmd **cmd);
void ipc_cmd_success_reply(struct ipc_cmd **cmd, const char *data);
void ipc_cmd_fail(struct ipc_cmd **cmd, const char *errormsg);

#endif
