#ifndef SERVICE_PROCESS_NOTIFY_H
#define SERVICE_PROCESS_NOTIFY_H

typedef int
service_process_notify_callback_t(int fd, struct service_process *process);

struct service_process_notify *
service_process_notify_init(int fd,
			    service_process_notify_callback_t *write_callback);
void service_process_notify_deinit(struct service_process_notify **notify);

void service_process_notify_add(struct service_process_notify *notify,
				struct service_process *process);

#endif
