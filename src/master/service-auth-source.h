#ifndef SERVICE_AUTH_SOURCE_H
#define SERVICE_AUTH_SOURCE_H

struct service_process;
struct service_process_auth_source;

void service_process_auth_source_init(struct service_process *process, int fd);
void service_process_auth_source_deinit(struct service_process *process);

void service_process_auth_source_send_reply(struct service_process_auth_source *process,
					    unsigned int tag,
					    enum master_auth_status status);

void service_processes_auth_source_notify(struct service *service,
					  bool all_processes_created);

#endif
