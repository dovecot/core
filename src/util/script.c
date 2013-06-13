/* Copyright (c) 2010-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "env-util.h"
#include "execv-const.h"
#include "write-full.h"
#include "restrict-access.h"
#include "master-interface.h"
#include "master-service.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>

#define SCRIPT_MAJOR_VERSION 3
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


static void
exec_child(struct master_service_connection *conn, const char *const *args)
{
	unsigned int i, socket_count;

	if (dup2(conn->fd, STDIN_FILENO) < 0)
		i_fatal("dup2() failed: %m");
	if (dup2(conn->fd, STDOUT_FILENO) < 0)
		i_fatal("dup2() failed: %m");

	/* close all fds */
	socket_count = master_service_get_socket_count(master_service);
	for (i = 0; i < socket_count; i++) {
		if (close(MASTER_LISTEN_FD_FIRST + i) < 0)
			i_error("close(listener) failed: %m");
	}
	if (close(MASTER_STATUS_FD) < 0)
		i_error("close(status) failed: %m");
	if (close(conn->fd) < 0)
		i_error("close(conn->fd) failed: %m");

	for (; *args != NULL; args++)
		array_append(&exec_args, args, 1);
	array_append_zero(&exec_args);

	env_clean();
	args = array_idx(&exec_args, 0);
	execvp_const(args[0], args);
}

static bool client_exec_script(struct master_service_connection *conn)
{
	const char *const *args;
	string_t *input;
	void *buf;
	size_t prev_size, scanpos;
	bool header_complete = FALSE;
	ssize_t ret;
	int status;
	pid_t pid;

	net_set_nonblock(conn->fd, FALSE);
	input = buffer_create_dynamic(pool_datastack_create(), IO_BLOCK_SIZE);

	/* Input contains:

	   VERSION .. <lf>
	   [timeout=<timeout>]
	   <noreply> | "-" <lf>

	   arg 1 <lf>
	   arg 2 <lf>
	   ...
	   <lf>
	   DATA
	*/		
	alarm(SCRIPT_READ_TIMEOUT_SECS);
	scanpos = 1;
	while (!header_complete) {
		const unsigned char *pos, *end;

		prev_size = input->used;
		buf = buffer_append_space_unsafe(input, IO_BLOCK_SIZE);

		/* peek in socket input buffer */
		ret = recv(conn->fd, buf, IO_BLOCK_SIZE, MSG_PEEK);
		if (ret <= 0) {
			buffer_set_used_size(input, prev_size);
			if (strchr(str_c(input), '\n') != NULL)
				script_verify_version(t_strcut(str_c(input), '\n'));

			if (ret < 0)
				i_fatal("recv(MSG_PEEK) failed: %m");

			i_fatal("recv(MSG_PEEK) failed: disconnected");
		}

		/* scan for final \n\n */
		pos = CONST_PTR_OFFSET(input->data, scanpos);
		end = CONST_PTR_OFFSET(input->data, prev_size + ret);
		for (; pos < end; pos++) {
			if (pos[-1] == '\n' && pos[0] == '\n') {
				header_complete = TRUE;
				pos++;
				break;
			}
		}
		scanpos = pos - (const unsigned char *)input->data;

		/* read data for real (up to and including \n\n) */
		ret = recv(conn->fd, buf, scanpos-prev_size, 0);
		if (prev_size+ret != scanpos) {
			if (ret < 0)
				i_fatal("recv() failed: %m");
			if (ret == 0)
				i_fatal("recv() failed: disconnected");
			i_fatal("recv() failed: size of definitive recv() differs from peek");
		}
		buffer_set_used_size(input, scanpos);
	}
	alarm(0);

	/* drop the last two LFs */
	buffer_set_used_size(input, scanpos-2);

	args = t_strsplit(str_c(input), "\n");
	script_verify_version(*args); args++;
	if (*args != NULL) {
		if (strncmp(*args, "alarm=", 6) == 0) {
			alarm(atoi(*args + 6));
			args++;
		}
		if (strcmp(*args, "noreply") == 0) {
			/* no need to fork and check exit status */
			exec_child(conn, args + 1);
			i_unreached();
		}
		if (**args == '\0')
			i_fatal("empty options");
		args++;
	}

	if ((pid = fork()) == (pid_t)-1) {
		i_error("fork() failed: %m");
		return FALSE;
	}

	if (pid == 0) {
		/* child */
		exec_child(conn, args);
		i_unreached();
	}

	/* parent */

	/* check script exit status */
	if (waitpid(pid, &status, 0) < 0) {
		i_error("waitpid() failed: %m");
		return FALSE;
	} else if (WIFEXITED(status)) {
		ret = WEXITSTATUS(status);
		if (ret != 0) {
			i_error("Script terminated abnormally, exit status %d", (int)ret);
			return FALSE;
		}
	} else if (WIFSIGNALED(status)) {
		i_error("Script terminated abnormally, signal %d", WTERMSIG(status));
		return FALSE;
	} else if (WIFSTOPPED(status)) {
		i_fatal("Script stopped, signal %d", WSTOPSIG(status));
		return FALSE;
	} else {
		i_fatal("Script terminated abnormally, return status %d", status);
		return FALSE;
	}
	return TRUE;
}

static void client_connected(struct master_service_connection *conn)
{
	char response[2];

	response[0] = client_exec_script(conn) ? '+' : '-';
	response[1] = '\n';
	if (write_full(conn->fd, &response, 2) < 0)
		i_error("write(response) failed: %m");
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
	if (argv[0] == NULL)
		i_fatal("Missing script path");
	restrict_access_by_env(NULL, FALSE);
	restrict_access_allow_coredumps(TRUE);

	master_service_init_finish(master_service);
	master_service_set_service_count(master_service, 1);

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
