/* Copyright (c) 2006-2012 Dovecot authors, see the included COPYING file */

#include "lib.h"

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>

int main(int argc, char *argv[])
{
	pid_t pid = fork();
	const char *path, *cmd;
	int fd_in[2], fd_out[2], fd_log, status;

	if (argc < 2)
		i_fatal("Usage: gdbhelper <program> [<args>]");

	switch (pid) {
	case 1:
		i_fatal("fork() failed: %m");
	case 0:
		/* child */
		(void)execvp(argv[1], argv+1);
		i_fatal("execvp(%s) failed: %m", argv[1]);
	default:
		if (pipe(fd_in) < 0 || pipe(fd_out) < 0)
			i_fatal("pipe() failed: %m");
		cmd = "handle SIGPIPE nostop\n"
			"handle SIGALRM nostop\n"
			"handle SIG32 nostop\n"
			"cont\n"
			"bt full\n"
			"quit\n";
		if (write(fd_in[1], cmd, strlen(cmd)) < 0)
			i_fatal("write() failed: %m");

		if (dup2(fd_in[0], 0) < 0 ||
		    dup2(fd_out[1], 1) < 0 ||
		    dup2(fd_out[1], 2) < 0)
			i_fatal("dup2() failed: %m");

		cmd = t_strdup_printf("gdb %s %s", argv[1], dec2str(pid));
		if (system(cmd) < 0)
			i_fatal("system() failed: %m");

		if (wait(&status) < 0)
			i_fatal("wait() failed: %m");
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			char buf[1024];
			ssize_t ret;

			path = t_strdup_printf("/tmp/gdbhelper.%s.%s",
					       dec2str(time(NULL)),
					       dec2str(pid));
			fd_log = open(path, O_CREAT | O_WRONLY, 0600);
			if (fd_log < 0)
				i_fatal("open(%s) failed: %m", path);

			while ((ret = read(fd_out[0], buf, sizeof(buf))) > 0) {
				if (write(fd_log, buf, ret) < 0)
					i_fatal("write(%s) failed: %m", path);
			}
			if (ret < 0)
				i_fatal("read(pipe) failed: %m");
			i_close_fd(&fd_log);
		}
	}
	return 0;
}
