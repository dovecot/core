/* Copyright (c) 2006-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "ioloop.h"
#include "network.h"
#include "fd-close-on-exec.h"
#include "env-util.h"
#include "log.h"
#include "child-process.h"
#include "dict-process.h"

#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>

#define DICT_SERVER_SOCKET_NAME "dict-server"

struct dict_listener {
	char *path;
	int fd;
	struct io *io;

	struct dict_process *processes;
};

struct dict_process {
	struct child_process process;
	struct dict_process *next;

	struct dict_listener *listener;
	struct log_io *log;
};

static struct dict_listener *dict_listener;

static int dict_process_create(struct dict_listener *listener)
{
	struct dict_process *process;
	struct log_io *log;
	const char *executable, *const *dicts;
	unsigned int i, count;
	int log_fd;
	pid_t pid;

	process = i_new(struct dict_process, 1);
	process->process.type = PROCESS_TYPE_DICT;
	process->listener = listener;

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
		i_free(process);
		return -1;
	}

	if (pid != 0) {
		/* master */
		process->next = process->listener->processes;
		process->listener->processes = process;

		child_process_add(pid, &process->process);
		log_set_prefix(log, "dict: ");
		log_set_pid(log, pid);
		(void)close(log_fd);

		process->log = log;
		log_ref(process->log);
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
	if (dup2(process->listener->fd, 3) < 0)
		i_fatal("dup2(3) failed: %m");

	for (i = 0; i <= 3; i++)
		fd_close_on_exec(i, FALSE);

	child_process_init_env(master_set->defaults);
	env_put(t_strconcat("DICT_LISTEN_FROM_FD=",
			    process->listener->path, NULL));

	if (master_set->defaults->dict_db_config != NULL) {
		env_put(t_strconcat("DB_CONFIG=",
				    master_set->defaults->dict_db_config,
				    NULL));
	}

	dicts = array_get(&master_set->defaults->dicts, &count);
	i_assert((count % 2) == 0);
	for (i = 0; i < count; i += 2)
		env_put(t_strdup_printf("DICT_%s=%s", dicts[i], dicts[i+1]));

	/* make sure we don't leak syslog fd, but do it last so that
	   any errors above will be logged */
	closelog();

	executable = PKG_LIBEXECDIR"/dict";
	client_process_exec(executable, "");
	i_fatal_status(FATAL_EXEC, "execv(%s) failed: %m", executable);
	return -1;
}

static void dict_listener_unref(struct dict_listener *listener)
{
	if (listener->processes == NULL)
		i_free(listener);
}

static void dict_process_deinit(struct dict_process *process)
{
	struct dict_listener *listener = process->listener;
	struct dict_process **p;

	for (p = &listener->processes; *p != NULL; p = &(*p)->next) {
		if (*p == process) {
			*p = process->next;
			break;
		}
	}

	if (process->log != NULL)
		log_unref(process->log);
	i_free(process);

	dict_listener_unref(listener);
}

static void dict_listener_input(struct dict_listener *listener)
{
	unsigned int i = 0;
	int fd;

	i_assert(listener->processes == NULL);

	if (array_is_created(&master_set->defaults->dicts)) {
		for (i = 0; i < master_set->defaults->dict_process_count; i++) {
			if (dict_process_create(listener) < 0)
				break;
		}
	}
	if (i > 0)
		io_remove(&listener->io);
	else {
		/* failed to create dict process, so just reject this
		   connection and try again later */
		fd = net_accept(listener->fd, NULL, NULL);
		if (fd >= 0)
			(void)close(fd);
	}
}

static struct dict_listener *dict_listener_init(const char *path)
{
	struct dict_listener *listener;
	mode_t old_umask;

	listener = i_new(struct dict_listener, 1);
	listener->path = i_strdup(path);
	old_umask = umask(0);
	listener->fd = net_listen_unix_unlink_stale(path, 128);
	umask(old_umask);
	if (listener->fd == -1) {
		if (errno == EADDRINUSE)
			i_fatal("Socket already exists: %s", path);
		else
			i_fatal("net_listen_unix(%s) failed: %m", path);
	}
	fd_close_on_exec(listener->fd, TRUE);
	listener->io = io_add(listener->fd, IO_READ,
			      dict_listener_input, listener);
	return listener;
}

static void dict_listener_deinit(struct dict_listener *listener)
{
	if (listener->io != NULL)
		io_remove(&listener->io);
	if (close(listener->fd) < 0)
		i_error("close(dict listener) failed: %m");

	/* don't try to free the dict processes here,
	   let dict_process_destroyed() do it to avoid "unknown child exited"
	   errors. */
	dict_listener_unref(listener);
}

static void
dict_process_destroyed(struct child_process *_process,
		       pid_t pid ATTR_UNUSED, bool abnormal_exit ATTR_UNUSED)
{
	struct dict_process *process = (struct dict_process *)_process;
	struct dict_listener *listener = process->listener;

	dict_process_deinit(process);
	if (listener->processes == NULL) {
		/* last listener died, create new ones */
		listener->io = io_add(listener->fd, IO_READ,
				      dict_listener_input, listener);
	}
}

void dict_processes_init(void)
{
	const char *path;

	path = t_strconcat(master_set->defaults->base_dir,
			   "/"DICT_SERVER_SOCKET_NAME, NULL);
	dict_listener = dict_listener_init(path);

	child_process_set_destroy_callback(PROCESS_TYPE_DICT,
					   dict_process_destroyed);
}

void dict_processes_deinit(void)
{
	dict_listener_deinit(dict_listener);
}

void dict_processes_kill(void)
{
	struct dict_process *process;

	process = dict_listener->processes;
	for (; process != NULL; process = process->next) {
		if (process->log != NULL) {
			log_unref(process->log);
			process->log = NULL;
		}
	}
}
