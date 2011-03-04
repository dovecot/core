/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "doveadm.h"

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#define MASTER_PID_FILE_NAME "master.pid"

static bool pid_file_read(const char *path, pid_t *pid_r)
{
	char buf[32];
	int fd;
	ssize_t ret;
	bool found;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		if (errno == ENOENT)
			return FALSE;
		i_fatal("open(%s) failed: %m", path);
	}

	ret = read(fd, buf, sizeof(buf));
	if (ret <= 0) {
		if (ret == 0)
			i_error("Empty PID file in %s", path);
		else
			i_fatal("read(%s) failed: %m", path);
		found = FALSE;
	} else {
		if (buf[ret-1] == '\n')
			ret--;
		buf[ret] = '\0';
		if (str_to_pid(buf, pid_r) < 0)
			found = FALSE;
		else {
			found = !(*pid_r == getpid() ||
				  (kill(*pid_r, 0) < 0 && errno == ESRCH));
		}
	}
	(void)close(fd);
	return found;
}

void doveadm_master_send_signal(int signo)
{
	const char *pidfile_path;
	unsigned int i;
	pid_t pid;

	pidfile_path = t_strconcat(doveadm_settings->base_dir,
				   "/"MASTER_PID_FILE_NAME, NULL);

	if (!pid_file_read(pidfile_path, &pid))
		i_fatal("Dovecot is not running (read from %s)", pidfile_path);

	if (kill(pid, signo) < 0)
		i_fatal("kill(%s, %d) failed: %m", dec2str(pid), signo);

	if (signo == SIGTERM) {
		/* wait for a while for the process to die */
		usleep(1000);
		for (i = 0; i < 30; i++) {
			if (kill(pid, 0) < 0) {
				if (errno != ESRCH)
					i_error("kill() failed: %m");
				break;
			}
			usleep(100000);
		}
	}
}

static void cmd_stop(int argc ATTR_UNUSED, char *argv[] ATTR_UNUSED)
{
	doveadm_master_send_signal(SIGTERM);
}

static void cmd_reload(int argc ATTR_UNUSED, char *argv[] ATTR_UNUSED)
{
	doveadm_master_send_signal(SIGHUP);
}

struct doveadm_cmd doveadm_cmd_stop = {
	cmd_stop, "stop", ""
};

struct doveadm_cmd doveadm_cmd_reload = {
	cmd_reload, "reload", ""
};
