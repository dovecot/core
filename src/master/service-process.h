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

	/* kill the process if it doesn't send initial status notification */
	struct timeout *to_status;

	unsigned int destroyed:1;
};

struct service_process_auth_server {
	struct service_process process;

	int auth_fd;
	struct io *io_auth;
	struct ostream *auth_output;
	struct istream *auth_input;

	/* pending authentication requests that are being verified from
	   auth server. */
	struct hash_table *auth_requests;
	/* Last time we wrote "authentication server is too busy" to log */
	time_t auth_busy_stamp;
	/* Tag counter for outgoing requests */
	unsigned int auth_tag_counter;

	unsigned int auth_version_sent:1;
	unsigned int auth_version_received:1;
};

struct service_process_auth_source {
	struct service_process process;

	int last_notify_status;

	int auth_fd;
	struct io *io_auth;
	struct ostream *auth_output;
};

struct service_process_auth_request {
	struct service_process_auth_source *process;

	unsigned int process_tag;
	int fd;

	struct ip_addr local_ip, remote_ip;
	unsigned int data_size;
	unsigned char data[FLEXIBLE_ARRAY_MEMBER];
};

struct service_process *
service_process_create(struct service *service, const char *const *auth_args,
		       const struct service_process_auth_request *request);
void service_process_destroy(struct service_process *process);

void service_process_ref(struct service_process *process);
int service_process_unref(struct service_process *process);

void service_process_log_status_error(struct service_process *process,
				      int status);

#endif
