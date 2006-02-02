/* Copyright (C) 2006 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "network.h"
#include "fd-close-on-exec.h"
#include "env-util.h"
#include "log.h"
#include "dict-process.h"

#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>

#define DICT_SERVER_SOCKET_NAME "dict-server"

struct dict_process {
	char *path;
	int fd;
	struct io *io;
};

static struct dict_process *process;

static void dict_process_unlisten(struct dict_process *process);

static int dict_process_start(struct dict_process *process)
{
	struct log_io *log;
	const char *executable;
	int i, log_fd;
	pid_t pid;

	log_fd = log_create_pipe(&log, 0);
	if (log_fd < 0)
		pid = -1;
	else {
		pid = fork();
		if (pid < 0)
			i_error("fork() failed: %m");
	}

	if (pid < 0) {
		(void)close(log_fd);
		return -1;
	}

	if (pid != 0) {
		/* master */
		PID_ADD_PROCESS_TYPE(pid, PROCESS_TYPE_DICT);
		log_set_prefix(log, "dict: ");
		(void)close(log_fd);

                dict_process_unlisten(process);
		return 0;
	}
	log_set_prefix(log, "master-dict: ");

	/* set stdin and stdout to /dev/null, so anything written into it
	   gets ignored. */
	if (dup2(null_fd, 0) < 0)
		i_fatal("dup2(stdin) failed: %m");
	if (dup2(null_fd, 1) < 0)
		i_fatal("dup2(stdout) failed: %m");

	/* stderr = log, 3 = listener */
	if (dup2(log_fd, 2) < 0)
		i_fatal("dup2(stderr) failed: %m");
	if (dup2(process->fd, 3) < 0)
		i_fatal("dup2(3) failed: %m");

	for (i = 0; i <= 3; i++)
		fd_close_on_exec(i, FALSE);

	child_process_init_env();
	env_put(t_strconcat("DICT_LISTEN_FROM_FD=", process->path, NULL));

	/* make sure we don't leak syslog fd, but do it last so that
	   any errors above will be logged */
	closelog();

	executable = PKG_LIBEXECDIR"/dict";
	client_process_exec(executable, "");
	i_fatal_status(FATAL_EXEC, "execv(%s) failed: %m", executable);
	return -1;
}

static void dict_process_listen_input(void *context)
{
	struct dict_process *process = context;

	dict_process_start(process);
}

static int dict_process_listen(struct dict_process *process)
{
	mode_t old_umask;
	int fd, i = 0;

	for (;;) {
		old_umask = umask(0);
		process->fd = net_listen_unix(process->path, 64);
		umask(old_umask);

		if (process->fd != -1)
			break;

		if (errno != EADDRINUSE || ++i == 2) {
			i_error("net_listen_unix(%s) failed: %m",
				process->path);
			return -1;
		}

		/* see if it really exists */
		fd = net_connect_unix(process->path);
		if (fd != -1 || errno != ECONNREFUSED) {
			if (fd != -1) (void)close(fd);
			i_error("Socket already exists: %s", process->path);
			return -1;
		}

		/* delete and try again */
		if (unlink(process->path) < 0 && errno != ENOENT) {
			i_error("unlink(%s) failed: %m", process->path);
			return -1;
		}
	}

	fd_close_on_exec(process->fd, TRUE);
	process->io = io_add(process->fd, IO_READ,
			     dict_process_listen_input, process);

	return process->fd != -1 ? 0 : -1;
}

static void dict_process_unlisten(struct dict_process *process)
{
	if (process->fd == -1)
		return;

	io_remove(&process->io);

	if (close(process->fd) < 0)
		i_error("close(dict) failed: %m");
	process->fd = -1;
}

void dict_process_init(void)
{
	process = i_new(struct dict_process, 1);
	process->fd = -1;
	process->path = i_strconcat(settings_root->defaults->base_dir,
				    "/"DICT_SERVER_SOCKET_NAME, NULL);
	(void)dict_process_listen(process);
}

void dict_process_deinit(void)
{
	dict_process_unlisten(process);
	i_free(process->path);
	i_free(process);
}

void dict_process_restart(void)
{
	dict_process_deinit();
	dict_process_init();
}
