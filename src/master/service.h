#ifndef SERVICE_H
#define SERVICE_H

#include "network.h"

struct master_settings;

/* If a service process doesn't send its first status notification in
   this many seconds, kill the process */
#define SERVICE_FIRST_STATUS_TIMEOUT_SECS 30

enum service_type {
	SERVICE_TYPE_UNKNOWN,
	SERVICE_TYPE_LOG,
	SERVICE_TYPE_ANVIL,
	SERVICE_TYPE_CONFIG,
	SERVICE_TYPE_AUTH_SERVER,
	SERVICE_TYPE_AUTH_SOURCE
};

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

	/* number of processes currently created for this service */
	unsigned int process_count;
	/* number of processes currently accepting new clients */
	unsigned int process_avail;
	/* max number of processes allowed */
	unsigned int process_limit;

	/* Maximum number of client connections a process can handle. */
	unsigned int client_limit;
	/* set->vsz_limit or set->master_set->default_client_limit */
	unsigned int vsz_limit;

	/* log process pipe file descriptors. */
	int log_fd[2];
	/* fd that log process sees log_fd[0] as. can be used to identify
	   service name when sending commands via master_log_fd. */
	int log_process_internal_fd;

	/* status report pipe file descriptors */
	int status_fd[2];
	struct io *io_status;

	/* if a process fails before servicing its first request, assume it's
	   broken and start throtting new process creations */
	struct timeout *to_throttle;

	/* SERVICE_TYPE_AUTH_SOURCE: Destination service to run after
	   successful authentication. */
	struct service *auth_dest_service;

	/* Last time a "dropping client connections" warning was logged */
	time_t last_drop_warning;

	/* all processes are in use and new connections are coming */
	unsigned int listen_pending:1;
	/* service is currently listening for new connections */
	unsigned int listening:1;
	/* TRUE if service has at least one inet_listener */
	unsigned int have_inet_listeners:1;
};

struct service_list {
	pool_t pool;
	pool_t set_pool;
	int refcount;
	struct timeout *to_kill;

	const struct master_service_settings *service_set;

	struct service *config;
	struct service *log;
	const char *const *child_process_env;

	/* nonblocking log fds usd by master */
	int master_log_fd[2];
	struct service_process_notify *log_byes;

	/* passed to auth destination processes */
	int blocking_anvil_fd[2];
	/* used by master process to notify about dying processes */
	int nonblocking_anvil_fd[2];
	struct service_process_notify *anvil_kills;
	struct io *anvil_io_blocking, *anvil_io_nonblocking;

	ARRAY_DEFINE(services, struct service *);

	unsigned int destroyed:1;
	unsigned int sigterm_sent:1;
	unsigned int sigterm_sent_to_log:1;
};

extern struct hash_table *service_pids;

/* Create all services from settings */
int services_create(const struct master_settings *set,
		    const char *const *child_process_env,
		    struct service_list **services_r, const char **error_r);

/* Destroy services */
void services_destroy(struct service_list *service_list);

void service_list_ref(struct service_list *service_list);
void service_list_unref(struct service_list *service_list);

/* Return path to configuration process socket. */
const char *services_get_config_socket_path(struct service_list *service_list);

/* Send a signal to all processes in a given service */
void service_signal(struct service *service, int signo);

/* Prevent service from launching new processes for a while. */
void service_throttle(struct service *service, unsigned int secs);
/* Time moved backwards. Throttle services that care about time. */
void services_throttle_time_sensitives(struct service_list *list,
				       unsigned int secs);

/* Find a service by name. */
struct service *
service_lookup(struct service_list *service_list, const char *name);

void service_error(struct service *service, const char *format, ...)
	ATTR_FORMAT(2, 3);

void service_pids_init(void);
void service_pids_deinit(void);

#endif
