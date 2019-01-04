/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "env-util.h"
#include "execv-const.h"
#include "write-full.h"
#include "restrict-access.h"
#include "master-interface.h"
#include "master-service.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>

#define SCRIPT_MAJOR_VERSION 4
#define SCRIPT_READ_TIMEOUT_SECS 10

static ARRAY_TYPE(const_string) exec_args;
static const char **accepted_envs;

static void script_verify_version(const char *line)
{
	if (line == NULL ||
	    !version_string_verify(line, "script", SCRIPT_MAJOR_VERSION)) {
		i_fatal("Client not compatible with this binary "
			"(connecting to wrong socket?)");
	}
}


static void
exec_child(struct master_service_connection *conn,
	const char *const *args, const char *const *envs)
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

	for (; *args != NULL; args++) {
		const char *arg = t_str_tabunescape(*args);
		array_append(&exec_args, &arg, 1);
	}
	array_append_zero(&exec_args);

	env_clean();
	if (envs != NULL) {
		for(; *envs != NULL; envs++)
			env_put(*envs);
        }

	args = array_first(&exec_args);
	execvp_const(args[0], args);
}

static bool client_exec_script(struct master_service_connection *conn)
{
	ARRAY_TYPE(const_string) envs;
	const char *const *args;
	string_t *input;
	void *buf;
	size_t prev_size, scanpos;
	bool header_complete = FALSE, noreply = FALSE;
	ssize_t ret;
	int status;
	pid_t pid;

	net_set_nonblock(conn->fd, FALSE);
	input = t_buffer_create(IO_BLOCK_SIZE);

	/* Input contains:

	   VERSION .. <lf>
	   [alarm=<secs> <lf>]
	   "noreply" | "-" (or anything really) <lf>

	   arg 1 <lf>
	   arg 2 <lf>
	   ...
	   <lf>
	   DATA

	   This is quite a horrible protocol. If alarm is specified, it MUST be
	   before "noreply". If "noreply" isn't given, something other string
	   (typically "-") must be given which is eaten away.
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
	t_array_init(&envs, 16);
	if (*args != NULL) {
		const char *p;

		if (str_begins(*args, "alarm=")) {
			unsigned int seconds;
			if (str_to_uint(*args + 6, &seconds) < 0)
				i_fatal("invalid alarm option");
			alarm(seconds);
			args++;
		}
		while (str_begins(*args, "env_")) {
			const char *envname, *env;

			env = t_str_tabunescape(*args+4);
			p = strchr(env, '=');
			if (p == NULL)
				i_fatal("invalid environment variable");
			envname = t_strdup_until(*args+4, p);

			if (str_array_find(accepted_envs, envname))
				array_append(&envs, &env, 1);
			args++;
		}
		if (strcmp(*args, "noreply") == 0) {
			noreply = TRUE;
		}
		if (**args == '\0')
			i_fatal("empty options");
		args++;
	}
	array_append_zero(&envs);

	if (noreply) {
		/* no need to fork and check exit status */
		exec_child(conn, args, array_idx(&envs, 0));
		i_unreached();
	}

	if ((pid = fork()) == (pid_t)-1) {
		i_error("fork() failed: %m");
		return FALSE;
	}

	if (pid == 0) {
		/* child */
		exec_child(conn, args, array_idx(&envs, 0));
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
	const enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_DONT_SEND_STATS;
	ARRAY_TYPE(const_string) aenvs;
	const char *binary;
	const char *const *envs;
	int c, i;

	master_service = master_service_init("script", service_flags,
					     &argc, &argv, "+e:");

	t_array_init(&aenvs, 16);
	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'e':
			envs = t_strsplit_spaces(optarg,", \t");
			while (*envs != NULL) {
				array_append(&aenvs, envs, 1);
				envs++;
			}
			break;
		default:
			return FATAL_DEFAULT;
		}
	}
	argc -= optind;
	argv += optind;

	array_append_zero(&aenvs);
	accepted_envs = p_strarray_dup(default_pool, array_idx(&aenvs, 0));

	master_service_init_log(master_service, "script: ");
	if (argv[0] == NULL)
		i_fatal("Missing script path");
	restrict_access_by_env(RESTRICT_ACCESS_FLAG_ALLOW_ROOT, NULL);
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
	array_free(&exec_args);
	i_free(accepted_envs);
	master_service_deinit(&master_service);
	return 0;
}
