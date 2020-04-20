#ifndef MASTER_SERVICE_PRIVATE_H
#define MASTER_SERVICE_PRIVATE_H

#include "master-interface.h"
#include "master-service.h"

struct master_service_haproxy_conn;

struct master_service_listener {
	struct master_service *service;
	char *name;

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

	char *name;
	char *getopt_str;
	enum master_service_flags flags;

	int argc;
	char **argv;

	const char *version_string;
	char *config_path;
	ARRAY_TYPE(const_string) config_overrides;
	int config_fd;
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

	void (*avail_overflow_callback)(void);
	struct timeout *to_overflow_state;

	struct master_login *login;

	master_service_connection_callback_t *callback;

	pool_t set_pool;
	const struct master_service_settings *set;
	struct setting_parser_context *set_parser;

	struct ssl_iostream_context *ssl_ctx;
	time_t ssl_params_last_refresh;

	struct stats_client *stats_client;
	struct master_service_haproxy_conn *haproxy_conns;

	bool killed:1;
	bool stopping:1;
	bool keep_environment:1;
	bool log_directly:1;
	bool initial_status_sent:1;
	bool die_with_master:1;
	bool call_avail_overflow:1;
	bool config_path_changed_with_param:1;
	bool want_ssl_settings:1;
	bool want_ssl_server:1;
	bool ssl_ctx_initialized:1;
	bool config_path_from_master:1;
	bool log_initialized:1;
	bool ssl_module_loaded:1;
	bool init_finished:1;
};

void master_service_io_listeners_add(struct master_service *service);
void master_status_update(struct master_service *service);
void master_service_close_config_fd(struct master_service *service);

void master_service_io_listeners_remove(struct master_service *service);
void master_service_ssl_io_listeners_remove(struct master_service *service);

void master_service_client_connection_handled(struct master_service *service,
					      struct master_service_connection *conn);
void master_service_client_connection_callback(struct master_service *service,
					       struct master_service_connection *conn);

void master_service_haproxy_new(struct master_service *service,
				struct master_service_connection *conn);
void master_service_haproxy_abort(struct master_service *service);

#endif
