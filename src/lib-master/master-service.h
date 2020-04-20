#ifndef MASTER_SERVICE_H
#define MASTER_SERVICE_H

#include "net.h"

#include <unistd.h> /* for getopt() opt* variables */
#include <stdio.h> /* for getopt() opt* variables in Solaris */

enum master_service_flags {
	/* stdin/stdout already contains a client which we want to serve */
	MASTER_SERVICE_FLAG_STD_CLIENT		= 0x01,
	/* this process is currently running standalone without a master */
	MASTER_SERVICE_FLAG_STANDALONE		= 0x02,
	/* Log to configured log file instead of stderr. By default when
	   _FLAG_STANDALONE is set, logging is done to stderr. */
	MASTER_SERVICE_FLAG_DONT_LOG_TO_STDERR	= 0x04,
	/* Service is going to do multiple configuration lookups,
	   keep the connection to config service open. Also opens the config
	   socket before dropping privileges. */
	MASTER_SERVICE_FLAG_KEEP_CONFIG_OPEN	= 0x08,
	/* Don't read settings, but use whatever is in environment */
	MASTER_SERVICE_FLAG_NO_CONFIG_SETTINGS	= 0x10,
	/* Use MASTER_LOGIN_NOTIFY_FD to track login overflow state */
	MASTER_SERVICE_FLAG_TRACK_LOGIN_STATE	= 0x40,
	/* If master sends SIGINT, don't die even if we don't have clients */
	MASTER_SERVICE_FLAG_NO_IDLE_DIE		= 0x80,
	/* Show number of connections in process title
	   (only if verbose_proctitle setting is enabled) */
	MASTER_SERVICE_FLAG_UPDATE_PROCTITLE	= 0x100,
	/* Always read SSL settings into memory, even if there are no ssl
	   listeners or _HAVE_STARTTLS flag hasn't been set. This is mainly
	   intended to be used when SSL client settings are wanted to be
	   accessed via lib-master. */
	MASTER_SERVICE_FLAG_USE_SSL_SETTINGS	= 0x200,
	/* Don't initialize SSL context automatically. */
	MASTER_SERVICE_FLAG_NO_SSL_INIT		= 0x400,
	/* Don't create a data stack frame between master_service_init() and
	   master_service_init_finish(). By default this is done to make sure
	   initialization doesn't unnecessarily use up memory in data stack. */
	MASTER_SERVICE_FLAG_NO_INIT_DATASTACK_FRAME = 0x800,
	/* Don't connect at startup to the stats process. */
	MASTER_SERVICE_FLAG_DONT_SEND_STATS	= 0x1000,
	/* Service supports STARTTLS-like feature. SSL server must be
	   initialized even if there are no ssl=yes listeners. */
	MASTER_SERVICE_FLAG_HAVE_STARTTLS	= 0x2000,
};

struct master_service_connection_proxy {
        /* only set if ssl is TRUE */
        const char *hostname;
        const char *cert_common_name;
        const unsigned char *alpn;
        unsigned int alpn_size;

	bool ssl:1;
	bool ssl_client_cert:1;
};

struct master_service_connection {
	/* fd of the new connection. */
	int fd;
	/* fd of the socket listener. Same as fd for a FIFO. */
	int listen_fd;
	/* listener name as in configuration file, or "" if unnamed. */
	const char *name;

	/* Original client/server IP/port. Both of these may have been changed
	   by the haproxy protocol. */
	struct ip_addr remote_ip, local_ip;
	in_port_t remote_port, local_port;

	/* The real client/server IP/port, unchanged by haproxy protocol. */
	struct ip_addr real_remote_ip, real_local_ip;
	in_port_t real_remote_port, real_local_port;

	/* filled if connection is proxied */
	struct master_service_connection_proxy proxy;

	/* This is a connection proxied wit HAproxy (or similar) */
	bool proxied:1;

	/* This is a FIFO fd. Only a single "connection" is ever received from
	   a FIFO after the first writer sends something to it. */
	bool fifo:1;
	/* Perform immediate SSL handshake for this connection. Currently this
	   needs to be performed explicitly by each service. */
	bool ssl:1;

	/* Internal: master_service_client_connection_accept() has been
	   called for this connection. */
	bool accepted:1;
};

typedef void
master_service_connection_callback_t(struct master_service_connection *conn);

extern struct master_service *master_service;

const char *master_service_getopt_string(void);

/* Start service initialization. */
struct master_service *
master_service_init(const char *name, enum master_service_flags flags,
		    int *argc, char **argv[], const char *getopt_str);
/* Call getopt() and handle internal parameters. Return values are the same as
   getopt()'s. */
int master_getopt(struct master_service *service);
/* Returns TRUE if str is a valid getopt_str. Currently this only checks for
   duplicate args so they aren't accidentally added. */
bool master_getopt_str_is_valid(const char *str);
/* Parser command line option. Returns TRUE if processed. */
bool master_service_parse_option(struct master_service *service,
				 int opt, const char *arg);
/* Finish service initialization. The caller should drop privileges
   before calling this. This also notifies the master that the service was
   successfully started and there shouldn't be any service throttling even if
   it crashes afterwards, so this should be called after all of the
   initialization code is finished. */
void master_service_init_finish(struct master_service *service);

/* import_environment is a space-separated list of environment keys or
   key=values. The key=values are immediately added to the environment.
   All the keys are added to DOVECOT_PRESERVE_ENVS environment so they're
   preserved by master_service_env_clean(). */
void master_service_import_environment(const char *import_environment);
/* Clean environment from everything except the ones listed in
   DOVECOT_PRESERVE_ENVS environment. */
void master_service_env_clean(void);

/* Initialize logging. Only the first call changes the actual logging
   functions. The following calls change the log prefix. */
void master_service_init_log(struct master_service *service,
			     const char *prefix);
/* Initialize/change log prefix to the given log prefix. */
void master_service_init_log_with_prefix(struct master_service *service,
					 const char *prefix);
/* Initialize/change log prefix to "configured_name(my_pid): " */
void master_service_init_log_with_pid(struct master_service *service);
/* Initialize stats client (if it's not already initialized). This is called
   automatically if MASTER_SERVICE_FLAG_SEND_STATS is enabled. If
   silent_notfound_errors is set, connect() errors aren't logged if they're
   happening because the stats service isn't running. */
void master_service_init_stats_client(struct master_service *service,
				      bool silent_notfound_errors);

/* If set, die immediately when connection to master is lost.
   Normally all existing clients are handled first. */
void master_service_set_die_with_master(struct master_service *service,
					bool set);
/* Call the given when master connection dies and die_with_master is TRUE.
   The callback is expected to shut down the service somewhat soon or it's
   done forcibly. If NULL, the service is stopped immediately. */
void master_service_set_die_callback(struct master_service *service,
				     void (*callback)(void));
/* "idle callback" is called when master thinks we're idling and asks us to
   die. We'll do it only if the idle callback returns TRUE. This callback isn't
   even called if the master service code knows that we're handling clients. */
void master_service_set_idle_die_callback(struct master_service *service,
					  bool (*callback)(void));
/* Call the given callback when there are no available connections and master
   has indicated that it can't create any more processes to handle requests.
   The callback could decide to kill one of the existing connections. */
void master_service_set_avail_overflow_callback(struct master_service *service,
						void (*callback)(void));

/* Set maximum number of clients we can handle. Default is given by master. */
void master_service_set_client_limit(struct master_service *service,
				     unsigned int client_limit);
/* Returns the maximum number of clients we can handle. */
unsigned int master_service_get_client_limit(struct master_service *service);
/* Returns how many processes of this type can be created before reaching the
   limit. */
unsigned int master_service_get_process_limit(struct master_service *service);
/* Returns service { process_min_avail } */
unsigned int master_service_get_process_min_avail(struct master_service *service);
/* Returns the service's idle_kill timeout in seconds. Normally master handles
   sending the kill request when the process has no clients, but some services
   with permanent client connections may need to handle this themselves. */
unsigned int master_service_get_idle_kill_secs(struct master_service *service);

/* Set maximum number of client connections we will handle before shutting
   down. */
void master_service_set_service_count(struct master_service *service,
				      unsigned int count);
/* Returns the number of client connections we will handle before shutting
   down. The value is decreased only after connection has been closed. */
unsigned int master_service_get_service_count(struct master_service *service);
/* Return the number of listener sockets. */
unsigned int master_service_get_socket_count(struct master_service *service);
/* Returns the name of the listener socket, or "" if none is specified. */
const char *master_service_get_socket_name(struct master_service *service,
					   int listen_fd);

/* Returns configuration file path. */
const char *master_service_get_config_path(struct master_service *service);
/* Returns PACKAGE_VERSION or NULL if version_ignore=yes. This function is
   useful mostly as parameter to module_dir_load(). */
const char *master_service_get_version_string(struct master_service *service);
/* Returns name of the service, as given in name parameter to _init(). */
const char *master_service_get_name(struct master_service *service);
/* Returns name of the service, as given in the configuration file. For example
   service name=auth, but configured_name=auth-worker. This is preferred in
   e.g. log prefixes. */
const char *master_service_get_configured_name(struct master_service *service);

/* Start the service. Blocks until finished */
void master_service_run(struct master_service *service,
			master_service_connection_callback_t *callback)
	ATTR_NULL(2);
/* Stop a running service. */
void master_service_stop(struct master_service *service);
/* Stop once we're done serving existing new connections, but don't accept
   any new ones. */
void master_service_stop_new_connections(struct master_service *service);
/* Returns TRUE if we've received a SIGINT/SIGTERM and we've decided to stop. */
bool master_service_is_killed(struct master_service *service);
/* Returns TRUE if our master process is already stopped. This process may or
   may not be dying itself. Returns FALSE always if the process was started
   standalone. */
bool master_service_is_master_stopped(struct master_service *service);

/* Send command to anvil process, if we have fd to it. */
void master_service_anvil_send(struct master_service *service, const char *cmd);
/* Call to accept the client connection. Otherwise the connection is closed. */
void master_service_client_connection_accept(struct master_service_connection *conn);
/* Used to create "extra client connections" outside the common accept()
   method. */
void master_service_client_connection_created(struct master_service *service);
/* Call whenever a client connection is destroyed. */
void master_service_client_connection_destroyed(struct master_service *service);

/* Deinitialize the service. */
void master_service_deinit(struct master_service **service);

/* Returns TRUE if line contains compatible service name and major version.
   The line is expected to be in format:
   VERSION <tab> service_name <tab> major version <tab> minor version */
bool version_string_verify(const char *line, const char *service_name,
			   unsigned major_version);
/* Same as version_string_verify(), but return the minor version. */
bool version_string_verify_full(const char *line, const char *service_name,
				unsigned major_version,
				unsigned int *minor_version_r);

/* Returns TRUE if ssl module has been loaded */
bool master_service_is_ssl_module_loaded(struct master_service *service);

#endif
