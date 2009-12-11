#ifndef SERVICE_ANVIL_H
#define SERVICE_ANVIL_H

struct service_anvil_global {
	pid_t pid;
	unsigned int uid;

	int status_fd[2];
	/* passed to child processes */
	int blocking_fd[2];
	/* used by master process to notify about dying processes */
	int nonblocking_fd[2];
	/* master process sends new log fds to anvil via this unix socket */
	int log_fdpass_fd[2];

	struct service_process_notify *kills;
	struct io *io_blocking, *io_nonblocking;

	unsigned int process_count;
};

extern struct service_anvil_global *service_anvil_global;

void service_anvil_monitor_start(struct service_list *service_list);

void service_anvil_process_created(struct service_process *process);
void service_anvil_process_destroyed(struct service_process *process);

void service_anvil_send_log_fd(void);

void service_anvil_global_init(void);
void service_anvil_global_deinit(void);

#endif
