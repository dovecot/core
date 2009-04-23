#ifndef SERVICE_H
#define SERVICE_H

#include "network.h"

/* If a service process doesn't send its first status notification in
   this many seconds, kill the process */
#define SERVICE_FIRST_STATUS_TIMEOUT_SECS 30

enum service_type {
	SERVICE_TYPE_UNKNOWN,
	SERVICE_TYPE_LOG,
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
	const char *name;

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
	/* number of processes currently accepting new connections */
	unsigned int process_avail;
	/* max number of processes allowed */
	unsigned int process_limit;

	/* log process pipe file descriptors */
	int log_fd[2];

	/* status report pipe file descriptors */
	int status_fd[2];
	struct io *io_status;

	/* if a process fails before servicing its first request, assume it's
	   broken and start throtting new process creations */
	struct timeout *to_throttle;

	/* SERVICE_TYPE_AUTH_SOURCE: Destination service to run after
	   successful authentication. */
	struct service *auth_dest_service;

	/* all processes are in use and new connections are coming */
	unsigned int listen_pending:1;
};

struct service_list {
	pool_t pool;

	struct service *config;
	struct service *log;
	struct hash_table *pids;
	const char *const *child_process_env;

	ARRAY_DEFINE(services, struct service *);
};

/* Create all services from settings */
struct service_list *
services_create(const struct master_settings *set,
		const char *const *child_process_env, const char **error_r);

/* Destroy services */
void services_destroy(struct service_list *service_list);

/* Send a signal to all processes in a given service */
void service_signal(struct service *service, int signo);

#endif
