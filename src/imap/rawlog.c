/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "rawlog.h"

#ifdef BUILD_RAWLOG

#include "ioloop.h"
#include "network.h"
#include "write-full.h"
#include "process-title.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>

#define TIMESTAMP_WAIT_TIME 5
#define TIMESTAMP_FORMAT " * OK [RAWLOG TIMESTAMP] %Y-%m-%d %H:%M:%S\n"

static IOLoop ioloop;
static int client_in, client_out, imap_in, imap_out;
static int log_in, log_out;

static time_t last_write = 0;
static int last_lf = TRUE;

static void copy(int in, int out, int log)
{
	struct tm *tm;
	char buf[1024];
	ssize_t r_ret, s_ret;

	if (last_lf && ioloop_time - last_write > TIMESTAMP_WAIT_TIME) {
		tm = localtime(&ioloop_time);

		if (strftime(buf, sizeof(buf), TIMESTAMP_FORMAT, tm) <= 0)
			i_fatal("strftime() failed");
		if (write_full(log, buf, strlen(buf)) < 0)
			i_fatal("Can't write to log file: %m");
	}

	net_set_nonblock(in, TRUE);
	do {
		r_ret = net_receive(in, buf, sizeof(buf));
	} while (r_ret == 0);

	if (r_ret < 0) {
		if (r_ret == -1)
			i_error("imap_in: net_receive() failed: %m");

		/* disconnected */
		io_loop_stop(ioloop);
		return;
	}

	last_lf = buf[r_ret-1] == '\n';
	if (write_full(log, buf, r_ret) < 0)
		i_fatal("Can't write to log file: %m");

	net_set_nonblock(out, FALSE);
	do {
		s_ret = net_transmit(out, buf, r_ret);
		if (s_ret < 0) {
			if (s_ret == -1)
				i_error("imap_in: net_transmit() failed: %m");

			/* disconnected */
			io_loop_stop(ioloop);
			return;
		}
		r_ret -= s_ret;
	} while (r_ret > 0);

	last_write = time(NULL);
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
	pid_t pid, parent_pid;

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

	fname = t_strdup_printf("%s/%s-%s.in", path, timestamp,
				dec2str(getpid()));
	log_in = open(fname, O_CREAT|O_EXCL|O_WRONLY, 0600);
	if (log_in == -1) {
		i_warning("rawlog_open: open() failed for %s: %m", fname);
		return;
	}

	fname = t_strdup_printf("%s/%s-%s.out", path, timestamp,
				dec2str(getpid()));
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

	parent_pid = getpid();

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

	process_title_set(t_strdup_printf("[%s:%s rawlog]", getenv("USER"),
					  dec2str(parent_pid)));

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
