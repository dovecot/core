#ifndef SERVICE_PROCESS_H
#define SERVICE_PROCESS_H

struct service_process {
	struct service_process *prev, *next;
	struct service *service;
	int refcount;

	pid_t pid;
        /* uid is used to check for old/invalid status messages */
	unsigned int uid;

	/* number of new connections process is currently accepting */
	unsigned int available_count;
	/* number of connections process has ever accepted */
	unsigned int total_count;

	/* time when process started idling, or 0 if we're not idling */
	time_t idle_start;
	/* kill process if it hits idle timeout */
	struct timeout *to_idle;

	/* time when we last received a status update */
	time_t last_status_update;
	/* time when we last sent SIGINT to process */
	time_t last_kill_sent;

	/* kill the process if it doesn't send initial status notification */
	struct timeout *to_status;

	unsigned int destroyed:1;
};

#define SERVICE_PROCESS_IS_INITIALIZED(process) \
	((process)->to_status == NULL)

struct service_process *service_process_create(struct service *service);
void service_process_destroy(struct service_process *process);

void service_process_ref(struct service_process *process);
int service_process_unref(struct service_process *process);

void service_process_log_status_error(struct service_process *process,
				      int status);

#endif
