/* Copyright (C) 2002-2006 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "env-util.h"
#include "file-copy.h"
#include "log.h"
#include "child-process.h"
#include "ssl-init.h"

#ifdef HAVE_SSL

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <utime.h>
#include <sys/stat.h>

static struct child_process ssl_param_child_process =
	{ PROCESS_TYPE_SSL_PARAM };

static struct timeout *to;
static char *generating_path = NULL;

#define SSL_PARAMETERS_PERM_PATH PKG_STATEDIR"/"SSL_PARAMETERS_FILENAME

static void start_generate_process(const char *fname)
{
	const char *binpath = PKG_LIBEXECDIR"/ssl-build-param";
	struct log_io *log;
	pid_t pid;
	int log_fd;

	log_fd = log_create_pipe(&log, 10);
	if (log_fd == -1)
		pid = -1;
	else {
		pid = fork();
		if (pid < 0)
			i_error("fork() failed: %m");
	}
	if (pid == -1) {
		(void)close(log_fd);
		return;
	}

	log_set_prefix(log, "ssl-build-param: ");
	if (pid != 0) {
		/* parent */
		i_assert(generating_path == NULL);
		generating_path = i_strdup(fname);
		child_process_add(pid, &ssl_param_child_process);
		(void)close(log_fd);
		return;
	}

	/* child. */
	if (dup2(log_fd, 2) < 0)
		i_fatal("dup2(stderr) failed: %m");

	child_process_init_env();
	client_process_exec(t_strconcat(binpath, " "SSL_PARAMETERS_PERM_PATH,
					NULL), "");
	i_fatal_status(FATAL_EXEC, "execv(%s) failed: %m", binpath);
}

static void
ssl_parameter_process_destroyed(struct child_process *process ATTR_UNUSED,
				pid_t pid ATTR_UNUSED, bool abnormal_exit)
{
	if (!abnormal_exit) {
		if (file_copy(SSL_PARAMETERS_PERM_PATH,
			      generating_path, TRUE) <= 0) {
			i_error("file_copy(%s, %s) failed: %m",
				SSL_PARAMETERS_PERM_PATH, generating_path);
		}
	}
	i_free_and_null(generating_path);
}

static bool check_parameters_file_set(struct settings *set)
{
	const char *path;
	struct stat st, st2;
	time_t regen_time;

	if (set->ssl_disable)
		return TRUE;

	path = t_strconcat(set->login_dir, "/"SSL_PARAMETERS_FILENAME, NULL);
	if (stat(path, &st) < 0) {
		if (errno != ENOENT) {
			i_error("stat() failed for SSL parameters file %s: %m",
				path);
			return TRUE;
		}

		st.st_mtime = 0;
	} else if (st.st_size == 0) {
		/* broken, delete it (mostly for backwards compatibility) */
		st.st_mtime = 0;
		(void)unlink(path);
	}

	if (stat(SSL_PARAMETERS_PERM_PATH, &st2) == 0 &&
	    st.st_mtime < st2.st_mtime) {
		/* permanent parameters file has changed. use it. */
		if (file_copy(SSL_PARAMETERS_PERM_PATH, path, TRUE) > 0) {
			if (st.st_ino != st2.st_ino) {
				/* preserve the mtime */
				struct utimbuf ut;

				ut.actime = ut.modtime = st2.st_mtime;
				if (utime(path, &ut) < 0)
					i_error("utime(%s) failed: %m", path);
			}
			if (stat(path, &st) < 0)
				st.st_mtime = 0;
		}
	}

	/* make sure it's new enough, it's not 0 sized, and the permissions
	   are correct */
	regen_time = set->ssl_parameters_regenerate == 0 ? ioloop_time :
		(st.st_mtime + (time_t)(set->ssl_parameters_regenerate*3600));
	if (regen_time < ioloop_time || st.st_size == 0 ||
	    st.st_uid != master_uid) {
		if (st.st_mtime == 0) {
			i_info("Generating Diffie-Hellman parameters "
			       "for the first time. This may take "
			       "a while..");
		}
		start_generate_process(path);
		return FALSE;
	}

	return TRUE;
}

void ssl_check_parameters_file(void)
{
	struct server_settings *server;

	if (generating_path != NULL)
		return;

	for (server = settings_root; server != NULL; server = server->next) {
		if (server->defaults != NULL &&
		    !check_parameters_file_set(server->defaults))
			break;
	}
}

static void check_parameters_file_timeout(void *context ATTR_UNUSED)
{
	ssl_check_parameters_file();
}

void ssl_init(void)
{
	generating_path = NULL;

	child_process_set_destroy_callback(PROCESS_TYPE_SSL_PARAM,
					   ssl_parameter_process_destroyed);

	/* check every 10 mins */
	to = timeout_add(600 * 1000, check_parameters_file_timeout, NULL);

        ssl_check_parameters_file();
}

void ssl_deinit(void)
{
	timeout_remove(&to);
}

#else

void ssl_parameter_process_destroyed(bool abnormal_exit ATTR_UNUSED) {}
void ssl_check_parameters_file(void) {}
void ssl_init(void) {}
void ssl_deinit(void) {}

#endif
