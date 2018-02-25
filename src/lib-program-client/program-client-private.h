#ifndef PROGRAM_CLIENT_PRIVATE_H
#define PROGRAM_CLIENT_PRIVATE_H

#include "program-client.h"

enum program_client_error {
	PROGRAM_CLIENT_ERROR_NONE,
	PROGRAM_CLIENT_ERROR_CONNECT_TIMEOUT,
	PROGRAM_CLIENT_ERROR_RUN_TIMEOUT,
	PROGRAM_CLIENT_ERROR_IO,
	PROGRAM_CLIENT_ERROR_OTHER
};

enum program_client_exit_code {
	PROGRAM_CLIENT_EXIT_INTERNAL_FAILURE = -1,
	PROGRAM_CLIENT_EXIT_FAILURE = 0,
	PROGRAM_CLIENT_EXIT_SUCCESS = 1,
};

struct program_client_extra_fd {
	struct program_client *pclient;

	int child_fd, parent_fd;
	struct istream *input;
	struct io *io;

	program_client_fd_callback_t *callback;
	void *context;
};

struct program_client {
	pool_t pool;
	struct program_client_settings set;

	char *path;
	const char **args;
	ARRAY_TYPE(const_string) envs;

	int fd_in, fd_out;
	struct io *io;
	struct timeout *to;
	struct timeval start_time;

	struct istream *input, *program_input, *raw_program_input;
	struct ostream *output, *program_output, *raw_program_output;

	struct iostream_pump *pump_in, *pump_out;

	ARRAY(struct program_client_extra_fd) extra_fds;

	program_client_callback_t *callback;
	void *context;

	bool other_error;
	enum program_client_error error;
	enum program_client_exit_code exit_code;

	int (*connect) (struct program_client * pclient);
	int (*close_output) (struct program_client * pclient);
	void (*switch_ioloop) (struct program_client * pclient);
	void (*disconnect) (struct program_client * pclient, bool force);
	void (*destroy) (struct program_client * pclient);

	bool debug:1;
	bool disconnected:1;
	bool output_seekable:1;
	bool destroying:1;
};

void program_client_init(struct program_client *pclient, pool_t pool,
			 const char *path,
			 const char *const *args,
			 const struct program_client_settings *set);

void program_client_init_streams(struct program_client *pclient);

void program_client_connected(struct program_client *pclient);

void program_client_fail(struct program_client *pclient,
			 enum program_client_error error);

void program_client_program_input(struct program_client *pclient);

void program_client_disconnected(struct program_client *pclient);

#endif
