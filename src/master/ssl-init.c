/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "ssl-init.h"

#ifdef HAVE_SSL

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static struct timeout *to;
static bool generating;

static void generate_parameters_file(const char *fname)
{
	const char *temp_fname;
	int fd;

	temp_fname = t_strconcat(fname, ".tmp", NULL);
	(void)unlink(temp_fname);

	fd = open(temp_fname, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd == -1) {
		i_fatal("Can't create temporary SSL parameters file %s: %m",
			temp_fname);
	}

	_ssl_generate_parameters(fd, temp_fname);

	if (close(fd) < 0)
		i_fatal("close(%s) failed: %m", temp_fname);

	if (rename(temp_fname, fname) < 0)
		i_fatal("rename(%s, %s) failed: %m", temp_fname, fname);
}

static void start_generate_process(struct settings *set)
{
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		i_error("fork() failed: %m");
		return;
	}

	if (pid == 0) {
		/* child */
		generate_parameters_file(set->ssl_parameters_file);
		exit(0);
	} else {
		/* parent */
		generating = TRUE;
		PID_ADD_PROCESS_TYPE(pid, PROCESS_TYPE_SSL_PARAM);
	}
}

void ssl_parameter_process_destroyed(pid_t pid __attr_unused__)
{
	generating = FALSE;
}

static bool check_parameters_file_set(struct settings *set)
{
	struct stat st;
	time_t regen_time;

	if (set->ssl_parameters_file == NULL || set->ssl_disable)
		return TRUE;

	if (lstat(set->ssl_parameters_file, &st) < 0) {
		if (errno != ENOENT) {
			i_error("lstat() failed for SSL parameters file %s: %m",
				set->ssl_parameters_file);
			return TRUE;
		}

		st.st_mtime = 0;
	}

	/* make sure it's new enough and the permissions are correct */
	regen_time = st.st_mtime +
		(time_t)(set->ssl_parameters_regenerate*3600);
	if (regen_time < ioloop_time || (st.st_mode & 077) != 0 ||
	    st.st_uid != master_uid || st.st_gid != getegid()) {
		start_generate_process(set);
		return FALSE;
	}

	return TRUE;
}

static void check_parameters_file(void *context __attr_unused__)
{
	struct server_settings *server;

	if (generating)
		return;

	for (server = settings_root; server != NULL; server = server->next) {
		if (server->imap != NULL &&
		    !check_parameters_file_set(server->imap))
			break;
		if (server->pop3 != NULL &&
		    !check_parameters_file_set(server->pop3))
			break;
	}
}

void ssl_init(void)
{
	generating = FALSE;

	/* check every 10 mins */
	to = timeout_add(600 * 1000, check_parameters_file, NULL);

	check_parameters_file(NULL);
}

void ssl_deinit(void)
{
	timeout_remove(to);
}

#else

void ssl_parameter_process_destroyed(pid_t pid __attr_unused__) {}
void ssl_init(void) {}
void ssl_deinit(void) {}

#endif
