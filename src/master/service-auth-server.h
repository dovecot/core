#ifndef SERVICE_AUTH_SERVER_H
#define SERVICE_AUTH_SERVER_H

struct service_process;

void service_process_auth_server_init(struct service_process *process, int fd);
void service_process_auth_server_deinit(struct service_process *process);

#endif
