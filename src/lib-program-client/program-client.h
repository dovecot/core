#ifndef PROGRAM_CLIENT_H
#define PROGRAM_CLIENT_H

#include "restrict-access.h"
#include "net.h"

struct program_client;

enum program_client_exit_status {
	PROGRAM_CLIENT_EXIT_STATUS_INTERNAL_FAILURE = -1,
	PROGRAM_CLIENT_EXIT_STATUS_FAILURE = 0,
	PROGRAM_CLIENT_EXIT_STATUS_SUCCESS = 1,
};

struct program_client_parameters {
	unsigned int client_connect_timeout_msecs;
	unsigned int input_idle_timeout_msecs;
	const char *dns_client_socket_path;
	/* Append extra args to execute_args */
	const char *const *append_args;

	/* use o_stream_dot, which is mainly useful to make sure that an
	   unexpectedly closed connection doesn't cause the partial input to
	   be accepted as valid and complete program input. This is always
	   enabled for 'net' program clients, which may likely encounter
	   unexpected connection termination. */
	bool use_dotstream:1;
	bool no_reply:1;
};

struct program_client_settings {
	pool_t pool;
	/* Currently only a single execution is allowed */
	ARRAY_TYPE(const_string) execute;
	const char *execute_name;
	const char *execute_driver;
	const char *execute_args;

	/* driver-specific: */
	const char *execute_fork_path;
	const char *execute_unix_socket_path;
	const char *execute_tcp_host;
	in_port_t execute_tcp_port;

	const char *base_dir;
};
extern const struct setting_parser_info program_client_setting_parser_info;

typedef void program_client_fd_callback_t(void *context, struct istream *input);
typedef void program_client_callback_t(enum program_client_exit_status status,
				       void *context);

struct program_client *
program_client_local_create(struct event *event,
			    const char *bin_path, const char *const *args,
			    const struct program_client_parameters *params)
			    ATTR_NULL(3);
struct program_client *
program_client_unix_create(struct event *event,
			   const char *socket_path, const char *const *args,
			   const struct program_client_parameters *params);
struct program_client *
program_client_net_create(struct event *event,
			  const char *host, in_port_t port,
			  const char *const *args,
			  const struct program_client_parameters *params);
struct program_client *
program_client_net_create_ips(struct event *event,
			      const struct ip_addr *ips, size_t ips_count,
			      in_port_t port, const char *const *args,
			      const struct program_client_parameters *params);
int program_client_create(struct event *event, const char *uri,
			  const char *const *args,
			  const struct program_client_parameters *params,
			  struct program_client **pc_r, const char **error_r);
int program_client_create_auto(struct event *event,
			       const struct program_client_parameters *params,
			       struct program_client **pc_r, const char **error_r);

void program_client_destroy(struct program_client **_pclient);

void program_client_set_input(struct program_client *pclient,
	struct istream *input);
void program_client_set_output(struct program_client *pclient,
	struct ostream *output);

void program_client_set_output_seekable(struct program_client *pclient,
	const char *temp_prefix);
struct istream *
program_client_get_output_seekable(struct program_client *pclient);

void program_client_switch_ioloop(struct program_client *pclient);

/* Program provides side-channel output through an extra fd */
void program_client_set_extra_fd(struct program_client *pclient, int fd,
	 program_client_fd_callback_t * callback, void *context);
#define program_client_set_extra_fd(pclient, fd, callback, context) \
	program_client_set_extra_fd(pclient, fd - \
		CALLBACK_TYPECHECK(callback, \
			void (*)(typeof(context), struct istream *input)), \
		(program_client_fd_callback_t *)callback, context)

void program_client_set_env(struct program_client *pclient,
	const char *name, const char *value);

enum program_client_exit_status
program_client_run(struct program_client *pclient);
void program_client_run_async(struct program_client *pclient,
			      program_client_callback_t *, void*);
#define program_client_run_async(pclient, callback, context) \
	program_client_run_async(pclient, (program_client_callback_t*)callback, \
		1 ? context : CALLBACK_TYPECHECK(callback, \
			void (*)(enum program_client_exit_status, typeof(context))))

/* wait on program client by running an internal ioloop
   make sure pclient is not free'd in the program client callback when
   using this function */
void program_client_wait(struct program_client *pclient);
#endif
