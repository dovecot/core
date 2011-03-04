#ifndef SERVICE_H
#define SERVICE_H

#include "network.h"
#include "master-settings.h"

/* If a service process doesn't send its first status notification in
   this many seconds, kill the process */
#define SERVICE_FIRST_STATUS_TIMEOUT_SECS 30

enum service_listener_type {
	SERVICE_LISTENER_UNIX,
	SERVICE_LISTENER_FIFO,
	SERVICE_LISTENER_INET
};

struct service_listener {
	struct service *service;

	enum service_listener_type type;
	int fd; /* may be -1 */
	struct io *io;

	const char *inet_address;

	union {
		struct {
			const struct file_listener_settings *set;
			uid_t uid;
			gid_t gid;
		} fileset;
		struct {
			const struct inet_listener_settings *set;
			struct ip_addr ip;
		} inetset;
	} set;
};

struct service {
	struct service_list *list;

	enum service_type type;

	const struct service_settings *set;
	const char *config_file_path;

	const char *executable;
	uid_t uid;
	gid_t gid;
	gid_t privileged_gid;
	const char *extra_gids; /* comma-separated list */

	/* all listeners, even those that aren't currently listening */
	ARRAY_DEFINE(listeners, struct service_listener *);
	/* linked list of all processes belonging to this service */
	struct service_process *processes;

	/* number of processes currently created for this service */
	unsigned int process_count;
	/* number of processes currently accepting new clients */
	unsigned int process_avail;
	/* max number of processes allowed */
	unsigned int process_limit;

	/* Maximum number of client connections a process can handle. */
	unsigned int client_limit;
	/* Kill idling processes after this many seconds. */
	unsigned int idle_kill;
	/* set->vsz_limit or set->master_set->default_client_limit */
	uoff_t vsz_limit;

	/* log process pipe file descriptors. */
	int log_fd[2];
	/* fd that log process sees log_fd[0] as. can be used to identify
	   service name when sending commands via master_log_fd. */
	int log_process_internal_fd;

	/* status report pipe file descriptors */
	int status_fd[2];
	struct io *io_status;

	/* Login process's notify fd. We change its seek position to
	   communicate state to login processes. */
	int login_notify_fd;
	time_t last_login_notify_time;
	struct timeout *to_login_notify;

	/* if a process fails before servicing its first request, assume it's
	   broken and start throtting new process creations */
	struct timeout *to_throttle;

	/* Last time a "dropping client connections" warning was logged */
	time_t last_drop_warning;

	/* all processes are in use and new connections are coming */
	unsigned int listen_pending:1;
	/* service is currently listening for new connections */
	unsigned int listening:1;
	/* TRUE if service has at least one inet_listener */
	unsigned int have_inet_listeners:1;
	/* service_login_notify()'s last notification state */
	unsigned int last_login_full_notify:1;
};

struct service_list {
	pool_t pool;
	pool_t set_pool;
	int refcount;
	struct timeout *to_kill;

	const struct master_settings *set;
	const struct master_service_settings *service_set;

	struct service *config;
	struct service *log;
	struct service *anvil;

	/* nonblocking log fds usd by master */
	int master_log_fd[2];
	struct service_process_notify *log_byes;

	int master_dead_pipe_fd[2];

	ARRAY_DEFINE(services, struct service *);

	unsigned int destroyed:1;
	unsigned int sigterm_sent:1;
	unsigned int sigterm_sent_to_log:1;
};

extern struct hash_table *service_pids;

/* Create all services from settings */
int services_create(const struct master_settings *set,
		    struct service_list **services_r, const char **error_r);

/* Destroy services */
void services_destroy(struct service_list *service_list);

void service_list_ref(struct service_list *service_list);
void service_list_unref(struct service_list *service_list);

/* Return path to configuration process socket. */
const char *services_get_config_socket_path(struct service_list *service_list);

/* Send a signal to all processes in a given service */
void service_signal(struct service *service, int signo);
/* Notify all processes (if necessary) that no more connections can be handled
   by the service without killing existing connections (TRUE) or that they
   can be (FALSE). */
void service_login_notify(struct service *service, bool all_processes_full);

/* Prevent service from launching new processes for a while. */
void service_throttle(struct service *service, unsigned int secs);
/* Time moved backwards. Throttle services that care about time. */
void services_throttle_time_sensitives(struct service_list *list,
				       unsigned int secs);

/* Find service by name. */
struct service *
service_lookup(struct service_list *service_list, const char *name);
/* Find service by type */
struct service *
service_lookup_type(struct service_list *service_list, enum service_type type);

void service_error(struct service *service, const char *format, ...)
	ATTR_FORMAT(2, 3);

void service_pids_init(void);
void service_pids_deinit(void);

#endif
