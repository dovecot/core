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
	mode_t old_mask;
	int fd;

	temp_fname = t_strconcat(fname, ".tmp", NULL);
	(void)unlink(temp_fname);

	old_mask = umask(0);
	fd = open(temp_fname, O_WRONLY | O_CREAT | O_EXCL, 0644);
	umask(old_mask);

	if (fd == -1) {
		i_fatal("Can't create temporary SSL parameters file %s: %m",
			temp_fname);
	}

	_ssl_generate_parameters(fd, temp_fname);

	if (close(fd) < 0)
		i_fatal("close(%s) failed: %m", temp_fname);

	if (rename(temp_fname, fname) < 0)
		i_fatal("rename(%s, %s) failed: %m", temp_fname, fname);

	i_info("SSL parameters regeneration completed");
}

static void start_generate_process(const char *fname)
{
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		i_error("fork() failed: %m");
		return;
	}

	if (pid == 0) {
		/* child */
		generate_parameters_file(fname);
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

static bool check_parameters_file_set(struct settings *set, bool foreground)
{
	const char *path;
	struct stat st;
	time_t regen_time;

	if (set->ssl_disable)
		return TRUE;

	path = t_strconcat(set->login_dir, "/"SSL_PARAMETERS_FILENAME, NULL);
	if (lstat(path, &st) < 0) {
		if (errno != ENOENT) {
			i_error("lstat() failed for SSL parameters file %s: %m",
				path);
			return TRUE;
		}

		st.st_mtime = 0;
	} else if (st.st_size == 0) {
		/* broken, delete it (mostly for backwards compatibility) */
		st.st_mtime = 0;
		(void)unlink(path);
	}

	/* make sure it's new enough, it's not 0 sized, and the permissions
	   are correct */
	regen_time = set->ssl_parameters_regenerate == 0 ? ioloop_time :
		st.st_mtime + (time_t)(set->ssl_parameters_regenerate*3600);
	if (regen_time < ioloop_time || st.st_size == 0 ||
	    st.st_uid != master_uid || st.st_gid != getegid()) {
		if (foreground) {
			i_info("Generating Diffie-Hellman parameters. "
			       "This may take a while..");
			generate_parameters_file(path);
		} else {
			if (st.st_mtime == 0) {
				i_info("Generating Diffie-Hellman parameters "
				       "for the first time. This may take "
				       "a while..");
			}
			start_generate_process(path);
		}
		return FALSE;
	} else if (foreground) {
		i_info("Diffie-Hellman parameter file already exists.");
	}

	return TRUE;
}

void ssl_check_parameters_file(bool foreground)
{
	struct server_settings *server;

	if (generating)
		return;

	for (server = settings_root; server != NULL; server = server->next) {
		if (server->defaults != NULL &&
		    !check_parameters_file_set(server->defaults, foreground))
			break;
	}
}

static void check_parameters_file_timeout(void *context __attr_unused__)
{
	ssl_check_parameters_file(FALSE);
}

void ssl_init(void)
{
	generating = FALSE;

	/* check every 10 mins */
	to = timeout_add(600 * 1000, check_parameters_file_timeout, NULL);

        ssl_check_parameters_file(FALSE);
}

void ssl_deinit(void)
{
	timeout_remove(&to);
}

#else

void ssl_parameter_process_destroyed(pid_t pid __attr_unused__) {}
void ssl_init(void) {}
void ssl_deinit(void) {}

#endif
