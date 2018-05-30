#ifndef SERVICE_H
#define SERVICE_H

#include "net.h"
#include "master-settings.h"

/* If a service process doesn't send its first status notification in
   this many seconds, kill the process */
#define SERVICE_FIRST_STATUS_TIMEOUT_SECS 30

#define SERVICE_STARTUP_FAILURE_THROTTLE_MIN_SECS 2
#define SERVICE_STARTUP_FAILURE_THROTTLE_MAX_SECS 60

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

	const char *name;
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

	bool reuse_port;
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
	ARRAY(struct service_listener *) listeners;
	/* linked list of all processes belonging to this service */
	struct service_process *processes;

	/* number of processes currently created for this service */
	unsigned int process_count;
	/* number of processes currently accepting new clients */
	unsigned int process_avail;
	/* max number of processes allowed */
	unsigned int process_limit;
	/* Total number of processes ever created */
	uint64_t process_count_total;

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

	int master_dead_pipe_fd[2];

	unsigned int throttle_secs;
	time_t exit_failure_last;
	unsigned int exit_failures_in_sec;

	/* Login process's notify fd. We change its seek position to
	   communicate state to login processes. */
	int login_notify_fd;
	time_t last_login_notify_time;
	struct timeout *to_login_notify;

	/* if a process fails before servicing its first request, assume it's
	   broken and start throttling new process creations */
	struct timeout *to_throttle;
	/* when process_limit is reached, wait for a while until we actually
	   start dropping pending connections */
	struct timeout *to_drop;

	/* prefork processes up to process_min_avail if there's time */
	struct timeout *to_prefork;
	unsigned int prefork_counter;

	/* Last time a "dropping client connections" warning was logged */
	time_t last_drop_warning;

	/* all processes are in use and new connections are coming */
	bool listen_pending:1;
	/* service is currently listening for new connections */
	bool listening:1;
	/* TRUE if service has at least one inet_listener */
	bool have_inet_listeners:1;
	/* service_login_notify()'s last notification state */
	bool last_login_full_notify:1;
	/* service has exited at least once with exit code 0 */
	bool have_successful_exits:1;
	/* service was stopped via doveadm */
	bool doveadm_stop:1;
};

struct service_list {
	pool_t pool;
	pool_t set_pool;
	int refcount;
	struct timeout *to_kill;
	unsigned int fork_counter;

	const struct master_settings *set;
	const struct master_service_settings *service_set;

	struct service *config;
	struct service *log;
	struct service *anvil;

	struct file_listener_settings master_listener_set;
	struct io *io_master;
	int master_fd;

	/* nonblocking log fds usd by master */
	int master_log_fd[2];
	struct service_process_notify *log_byes;

	ARRAY(struct service *) services;

	bool destroying:1;
	bool destroyed:1;
	bool sigterm_sent:1;
	bool sigterm_sent_to_log:1;
};

HASH_TABLE_DEFINE_TYPE(pid_process, void *, struct service_process *);
extern HASH_TABLE_TYPE(pid_process) service_pids;

/* Create all services from settings */
int services_create(const struct master_settings *set,
		    struct service_list **services_r, const char **error_r);

/* Destroy services */
void services_destroy(struct service_list *service_list, bool wait);

void service_list_ref(struct service_list *service_list);
void service_list_unref(struct service_list *service_list);

/* Return path to configuration process socket. */
const char *services_get_config_socket_path(struct service_list *service_list);

/* Send a signal to all processes in a given service. However, if we're sending
   a SIGTERM and a process hasn't yet sent the initial status notification,
   that process is skipped. The number of such skipped processes are stored in
   uninitialized_count_r. Returns the number of processes that a signal was
   successfully sent to. */
unsigned int service_signal(struct service *service, int signo,
			    unsigned int *uninitialized_count_r);
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
