/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "env-util.h"
#include "execv-const.h"
#include "restrict-access.h"
#include "master-interface.h"
#include "master-service.h"

#include <stdlib.h>
#include <unistd.h>

#define SCRIPT_MAJOR_VERSION 1
#define SCRIPT_READ_TIMEOUT_SECS 10

static ARRAY_TYPE(const_string) exec_args;

static void script_verify_version(const char *line)
{
	if (line == NULL ||
	    !version_string_verify(line, "script", SCRIPT_MAJOR_VERSION)) {
		i_fatal("Client not compatible with this binary "
			"(connecting to wrong socket?)");
	}
}

static void client_connected(struct master_service_connection *conn)
{
	const unsigned char *end;
	const char *const *args;
	buffer_t *input;
	void *buf;
	unsigned int i, socket_count;
	size_t prev_size;
	ssize_t ret;

	net_set_nonblock(conn->fd, FALSE);
	input = buffer_create_dynamic(pool_datastack_create(), IO_BLOCK_SIZE);

	/* Input contains:

	   VERSION .. <lf>
	   arg 1 <lf>
	   arg 2 <lf>
	   ...
	   <lf> */
	alarm(SCRIPT_READ_TIMEOUT_SECS);
	do {
		prev_size = input->used;
		buf = buffer_append_space_unsafe(input, IO_BLOCK_SIZE);
		ret = read(conn->fd, buf, IO_BLOCK_SIZE);
		if (ret <= 0) {
			buffer_set_used_size(input, prev_size);
			if (strchr(str_c(input), '\n') != NULL)
				script_verify_version(t_strcut(str_c(input), '\t'));

			if (ret < 0)
				i_fatal("read() failed: %m");
			else
				i_fatal("read() failed: disconnected");
		}
		buffer_set_used_size(input, prev_size + ret);
		end = CONST_PTR_OFFSET(input->data, input->used);
	} while (!(end[-1] == '\n' && (input->used == 1 || end[-2] == '\n')));

	/* drop the last LF */
	buffer_set_used_size(input, input->used - 1);

	args = t_strsplit(str_c(input), "\n");
	script_verify_version(*args);

	for (args++; *args != NULL; args++)
		array_append(&exec_args, args, 1);
	(void)array_append_space(&exec_args);

	/* close all fds */
	socket_count = master_service_get_socket_count(master_service);
	for (i = 0; i < socket_count; i++) {
		if (close(MASTER_LISTEN_FD_FIRST + i) < 0)
			i_error("close(listener) failed: %m");
	}
	if (close(MASTER_STATUS_FD) < 0)
		i_error("close(status) failed: %m");
	if (close(conn->fd) < 0)
		i_error("close() failed: %m");

	env_clean();
	args = array_idx(&exec_args, 0);
	execvp_const(args[0], args);
}

int main(int argc, char *argv[])
{
	const char *binary;
	int i;

	master_service = master_service_init("script", 0, &argc, &argv, "+");
	if (master_getopt(master_service) > 0)
		return FATAL_DEFAULT;
	argc -= optind;
	argv += optind;

	master_service_init_log(master_service, "script: ");
	restrict_access_by_env(NULL, FALSE);
	restrict_access_allow_coredumps(TRUE);

	master_service_init_finish(master_service);
	master_service_set_service_count(master_service, 1);

	if (argv[0] == NULL)
		i_fatal("Missing script path");

	if (argv[0][0] == '/')
		binary = argv[0];
	else
		binary = t_strconcat(PKG_LIBEXECDIR"/", argv[0], NULL);

	i_array_init(&exec_args, argc + 16);
	array_append(&exec_args, &binary, 1);
	for (i = 1; i < argc; i++) {
		const char *arg = argv[i];

		array_append(&exec_args, &arg, 1);
	}

	master_service_run(master_service, client_connected);
	master_service_deinit(&master_service);
        return 0;
}
