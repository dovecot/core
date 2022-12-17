#ifndef MASTER_SERVICE_PRIVATE_H
#define MASTER_SERVICE_PRIVATE_H

#include "master-interface.h"
#include "master-service.h"

#include <signal.h>

struct master_service_haproxy_conn;

struct master_service_listener {
	struct master_service *service;
	char *name;
	char *type;

	/* settings */
	bool ssl;
	bool haproxy;

	/* state */
	bool closed;
	int fd;
	struct io *io;
};

struct master_service {
	struct ioloop *ioloop;
	struct event *event;

	char *name;
	char *configured_name;
	char *getopt_str;
	enum master_service_flags flags;

	int argc;
	char **argv;

	const char *version_string;
	char *config_path;
	ARRAY_TYPE(const_string) config_overrides;
	void *config_mmap_base;
	size_t config_mmap_size;
	int syslog_facility;
	data_stack_frame_t datastack_frame_id;

	struct master_service_listener *listeners;
	unsigned int socket_count;

	struct io *io_status_write, *io_status_error;
	unsigned int service_count_left;
	unsigned int total_available_count;
	unsigned int process_limit;
	unsigned int process_min_avail;
	unsigned int idle_kill_secs;

	struct master_status master_status;
	unsigned int last_sent_status_avail_count;
	time_t last_sent_status_time;
	struct timeout *to_status;

	bool (*idle_die_callback)(void);
	void (*die_callback)(void);
	struct timeout *to_die;

	master_service_avail_overflow_callback_t *avail_overflow_callback;
	struct timeout *to_overflow_state, *to_overflow_call;

	void (*stop_new_connections_callback)(void *context);
	void *stop_new_connections_context;

	master_service_connection_callback_t *callback;

	pool_t set_pool;
	const struct master_service_settings *set;
	struct setting_parser_context *set_parser;

	struct ssl_iostream_context *ssl_ctx;
	time_t ssl_params_last_refresh;

	char *current_user;
	char *last_kick_signal_user;
	siginfo_t killed_signal_info;
	volatile sig_atomic_t last_kick_signal_user_accessed;
	volatile sig_atomic_t killed_signal;
	volatile struct timeval killed_time;

	struct stats_client *stats_client;
	struct master_service_haproxy_conn *haproxy_conns;
	struct event_filter *process_shutdown_filter;

	bool stopping:1;
	bool keep_environment:1;
	bool log_directly:1;
	bool initial_status_sent:1;
	bool die_with_master:1;
	bool call_avail_overflow:1;
	bool config_path_changed_with_param:1;
	bool have_admin_sockets:1;
	bool want_ssl_server:1;
	bool ssl_ctx_initialized:1;
	bool config_path_from_master:1;
	bool log_initialized:1;
	bool init_finished:1;
	bool killed_signal_logged:1;
	bool io_status_waiting:1;
};

void master_service_io_listeners_add(struct master_service *service);
void master_status_update(struct master_service *service);

void master_service_io_listeners_remove(struct master_service *service);
void master_service_ssl_io_listeners_remove(struct master_service *service);

void master_service_client_connection_handled(struct master_service *service,
					      struct master_service_connection *conn);
void master_service_client_connection_callback(struct master_service *service,
					       struct master_service_connection *conn);

void master_service_add_stop_new_connections_callback(
	struct master_service *service,
	void (*callback)(void *context), void *context);
void master_service_remove_stop_new_connections_callback(
	struct master_service *service,
	void (*callback)(void *context), void *context);

void master_service_haproxy_new(struct master_service *service,
				struct master_service_connection *conn);
void master_service_haproxy_abort(struct master_service *service);

void master_admin_clients_deinit(void);

#endif
