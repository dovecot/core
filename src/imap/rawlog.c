/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"

#ifdef BUILD_RAWLOG

#include "ioloop.h"
#include "rawlog.h"
#include "write-full.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>

static IOLoop ioloop;
static int client_in, client_out, imap_in, imap_out;
static int log_in, log_out;

static void copy(int in, int out, int log)
{
	char buf[1024];
	ssize_t r_ret, s_ret;

	r_ret = read(in, buf, sizeof(buf));
	if (r_ret <= 0) {
		if (r_ret < 0)
			i_error("imap_in: read() failed: %m");

		/* disconnected */
		io_loop_stop(ioloop);
		return;
	}

	if (write_full(log, buf, r_ret) < 0)
		i_fatal("Can't write to log file: %m");

	do {
		s_ret = write(out, buf, r_ret);
		if (s_ret <= 0) {
			if (r_ret < 0)
				i_error("imap_in: write() failed: %m");

			/* disconnected */
			io_loop_stop(ioloop);
			return;
		}
		r_ret -= s_ret;
	} while (r_ret > 0);
}

static void imap_input(void *context __attr_unused__, int fd __attr_unused__,
		       IO io __attr_unused__)
{
	copy(imap_in, client_out, log_out);
}

static void client_input(void *context __attr_unused__, int fd __attr_unused__,
			 IO io __attr_unused__)
{
	copy(client_in, imap_out, log_in);
}

void rawlog_open(int *hin, int *hout)
{
	IO io_imap, io_client;
	const char *home, *path, *fname;
	char timestamp[50];
	struct tm *tm;
	struct stat st;
	int sfd[2];
	pid_t pid;

	home = getenv("HOME");
	if (home == NULL)
		home = ".";

	/* see if we want rawlog */
	path = t_strconcat(home, "/rawlog", NULL);
	if (stat(path, &st) < 0) {
		if (errno != ENOENT)
			i_warning("stat() failed for %s: %m", path);
		return;
	}

	/* yes, open the files. Do it before forking to make sure we don't
	   unneededly do it. */
	tm = localtime(&ioloop_time);
	if (strftime(timestamp, sizeof(timestamp), "%Y%m%d-%H%M%S", tm) <= 0)
		i_fatal("strftime() failed");

	fname = t_strdup_printf("%s/%s-%d.in", path, timestamp, getpid());
	log_in = open(fname, O_CREAT|O_EXCL|O_WRONLY, 0600);
	if (log_in == -1) {
		i_warning("rawlog_open: open() failed for %s: %m", fname);
		return;
	}

	fname = t_strdup_printf("%s/%s-%d.out", path, timestamp, getpid());
	log_out = open(fname, O_CREAT|O_EXCL|O_WRONLY, 0600);
	if (log_out == -1) {
		i_warning("rawlog_open: open() failed for %s: %m", fname);
		close(log_in);
		return;
	}

	/* we need to fork the rawlog writer to separate process since
	   imap process does blocking writes. */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sfd) < 0)
		i_fatal("socketpair() failed: %m");

	pid = fork();
	if (pid < 0)
		i_fatal("fork() failed: %m");

	if (pid > 0) {
		/* parent */
		close(log_in); close(log_out);
		close(*hin); close(*hout);
		close(sfd[0]);
		*hin = *hout = sfd[1];
		return;
	}
	close(sfd[1]);

	/* child */
	client_in = *hin;
	client_out = *hout;
	imap_in = sfd[0];
	imap_out = sfd[0];

	ioloop = io_loop_create(system_pool);
	io_imap = io_add(imap_in, IO_READ, imap_input, NULL);
	io_client = io_add(client_in, IO_READ, client_input, NULL);

	io_loop_run(ioloop);

	io_remove(io_imap);
	io_remove(io_client);
	io_loop_destroy(ioloop);

	lib_deinit();
	exit(0);
}

#else
void rawlog_open(int *hin __attr_unused__, int *hout __attr_unused__)
{
}
#endif
