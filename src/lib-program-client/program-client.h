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

struct program_client_settings {
	unsigned int client_connect_timeout_msecs;
	unsigned int input_idle_timeout_msecs;
	/* initialize with
	   restrict_access_init(&set.restrict_set);
	*/
	struct restrict_access_settings restrict_set;
	const char *dns_client_socket_path;
	const char *home;

	/* Event to use for the program client. */
	struct event *event;

	bool allow_root:1;
	bool debug:1;
	bool drop_stderr:1;
	/* use o_stream_dot, which is mainly useful to make sure that an
	   unexpectedly closed connection doesn't cause the partial input to
	   be accepted as valid and complete program input. This is always
	   enabled for 'net' program clients, which may likely encounter
	   unexpected connection termination. */
	bool use_dotstream:1;
};

typedef void program_client_fd_callback_t(void *context, struct istream *input);
typedef void program_client_callback_t(enum program_client_exit_status status,
				       void *context);

struct program_client *
program_client_local_create(const char *bin_path, const char *const *args,
			    const struct program_client_settings *set)
			    ATTR_NULL(3);
struct program_client *
program_client_unix_create(const char *socket_path, const char *const *args,
			   const struct program_client_settings *set,
			   bool noreply) ATTR_NULL(3);
struct program_client *
program_client_net_create(const char *host, in_port_t port,
			  const char *const *args,
			  const struct program_client_settings *set,
			  bool noreply) ATTR_NULL(4);
struct program_client *
program_client_net_create_ips(const struct ip_addr *ips, size_t ips_count,
			      in_port_t port, const char *const *args,
			      const struct program_client_settings *set,
			      bool noreply) ATTR_NULL(5);
int program_client_create(const char *uri, const char *const *args,
			  const struct program_client_settings *set,
			  bool noreply, struct program_client **pc_r,
			  const char **error_r) ATTR_NULL(3);

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
