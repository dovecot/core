/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"

#include "ioloop.h"
#include "fd-set-nonblock.h"
#include "network.h"
#include "str.h"
#include "write-full.h"
#include "istream.h"
#include "ostream.h"
#include "process-title.h"
#include "restrict-access.h"
#include "master-service.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>

#define OUTBUF_THRESHOLD IO_BLOCK_SIZE

static struct ioloop *ioloop;

enum rawlog_flags {
	RAWLOG_FLAG_LOG_INPUT		= 0x01,
	RAWLOG_FLAG_LOG_OUTPUT		= 0x02,
	RAWLOG_FLAG_LOG_TIMESTAMPS	= 0x04,
	RAWLOG_FLAG_LOG_BOUNDARIES	= 0X10
};

struct rawlog_proxy {
	int client_in_fd, client_out_fd, server_fd;
	struct io *client_io, *server_io;
	struct ostream *client_output, *server_output;

	int fd_in, fd_out;
	enum rawlog_flags flags;
	bool prev_lf_in, prev_lf_out;
};

static void rawlog_proxy_destroy(struct rawlog_proxy *proxy)
{
	if (proxy->fd_in != -1) {
		if (close(proxy->fd_in) < 0)
			i_error("close(in) failed: %m");
	}
	if (proxy->fd_out != -1) {
		if (close(proxy->fd_out) < 0)
			i_error("close(out) failed: %m");
	}
	if (proxy->client_io != NULL)
		io_remove(&proxy->client_io);
	if (proxy->server_io != NULL)
		io_remove(&proxy->server_io);

	o_stream_destroy(&proxy->client_output);
	o_stream_destroy(&proxy->server_output);

	if (close(proxy->client_in_fd) < 0)
		i_error("close(client_in_fd) failed: %m");
	if (close(proxy->client_out_fd) < 0)
		i_error("close(client_out_fd) failed: %m");
	if (close(proxy->server_fd) < 0)
		i_error("close(server_fd) failed: %m");
	i_free(proxy);

	io_loop_stop(ioloop);
}

static int
write_with_timestamps(int fd, bool *prev_lf,
		      const unsigned char *data, size_t size)
{
	int ret;

	T_BEGIN {
		const char *timestamp = t_strdup_printf("%ld.%06lu ",
			(long)ioloop_timeval.tv_sec,
			(unsigned long)ioloop_timeval.tv_usec);
		string_t *str = t_str_new(size + 128);
		size_t i;

		if (*prev_lf)
			str_append(str, timestamp);

		for (i = 0; i < size; i++) {
			str_append_c(str, data[i]);
			if (data[i] == '\n' && i+1 != size)
				str_append(str, timestamp);
		}
		*prev_lf = data[i-1] == '\n';
		ret = write_full(fd, str_data(str), str_len(str));
	} T_END;
	return ret;
}

static int proxy_write_data(struct rawlog_proxy *proxy, int fd,
			    bool *prev_lf, const void *data, size_t size)
{
	if (fd == -1 || size == 0)
		return 0;

	if ((proxy->flags & RAWLOG_FLAG_LOG_BOUNDARIES) != 0) {
		if (write_full(fd, "<<<\n", 4) < 0)
			return -1;
	}

	if ((proxy->flags & RAWLOG_FLAG_LOG_TIMESTAMPS) != 0) {
		if (write_with_timestamps(fd, prev_lf, data, size) < 0)
			return -1;
	} else {
		if (write_full(fd, data, size) < 0)
			return -1;
	}

	if ((proxy->flags & RAWLOG_FLAG_LOG_BOUNDARIES) != 0) {
		if (write_full(fd, ">>>\n", 4) < 0)
			return -1;
	}
	return 0;
}

static void proxy_write_in(struct rawlog_proxy *proxy,
			   const void *data, size_t size)
{
	if (proxy_write_data(proxy, proxy->fd_in, &proxy->prev_lf_in,
			     data, size) < 0) {
		/* failed, disable logging */
		i_error("write(in) failed: %m");
		(void)close(proxy->fd_in);
		proxy->fd_in = -1;
	}
}

static void proxy_write_out(struct rawlog_proxy *proxy,
			    const void *data, size_t size)
{
	if (proxy_write_data(proxy, proxy->fd_out, &proxy->prev_lf_out,
			     data, size) < 0) {
		/* failed, disable logging */
		i_error("write(out) failed: %m");
		(void)close(proxy->fd_out);
		proxy->fd_out = -1;
	}
}

static void server_input(struct rawlog_proxy *proxy)
{
	unsigned char buf[OUTBUF_THRESHOLD];
	ssize_t ret;

	if (o_stream_get_buffer_used_size(proxy->client_output) >
	    OUTBUF_THRESHOLD) {
		/* client's output buffer is already quite full.
		   don't send more until we're below threshold. */
		io_remove(&proxy->server_io);
		return;
	}

	ret = net_receive(proxy->server_fd, buf, sizeof(buf));
	if (ret > 0) {
		(void)o_stream_send(proxy->client_output, buf, ret);
		proxy_write_out(proxy, buf, ret);
	} else if (ret <= 0)
		rawlog_proxy_destroy(proxy);
}

static void client_input(struct rawlog_proxy *proxy)
{
	unsigned char buf[OUTBUF_THRESHOLD];
	ssize_t ret;

	if (o_stream_get_buffer_used_size(proxy->server_output) >
	    OUTBUF_THRESHOLD) {
		/* proxy's output buffer is already quite full.
		   don't send more until we're below threshold. */
		io_remove(&proxy->client_io);
		return;
	}

	ret = net_receive(proxy->client_in_fd, buf, sizeof(buf));
	if (ret > 0) {
		(void)o_stream_send(proxy->server_output, buf, ret);
		proxy_write_in(proxy, buf, ret);
	} else if (ret < 0)
		rawlog_proxy_destroy(proxy);
}

static int server_output(struct rawlog_proxy *proxy)
{
	if (o_stream_flush(proxy->server_output) < 0) {
                rawlog_proxy_destroy(proxy);
		return 1;
	}

	if (proxy->client_io == NULL &&
	    o_stream_get_buffer_used_size(proxy->server_output) <
	    OUTBUF_THRESHOLD) {
		/* there's again space in proxy's output buffer, so we can
		   read more from client. */
		proxy->client_io = io_add(proxy->client_in_fd, IO_READ,
					  client_input, proxy);
	}
	return 1;
}

static int client_output(struct rawlog_proxy *proxy)
{
	if (o_stream_flush(proxy->client_output) < 0) {
                rawlog_proxy_destroy(proxy);
		return 1;
	}

	if (proxy->server_io == NULL &&
	    o_stream_get_buffer_used_size(proxy->client_output) <
	    OUTBUF_THRESHOLD) {
		/* there's again space in client's output buffer, so we can
		   read more from proxy. */
		proxy->server_io =
			io_add(proxy->server_fd, IO_READ, server_input, proxy);
	}
	return 1;
}

static void proxy_open_logs(struct rawlog_proxy *proxy, const char *path)
{
	time_t now;
	struct tm *tm;
	const char *fname;
	char timestamp[50];

	now = time(NULL);
	tm = localtime(&now);
	if (strftime(timestamp, sizeof(timestamp), "%Y%m%d-%H%M%S", tm) <= 0)
		i_fatal("strftime() failed");

	if ((proxy->flags & RAWLOG_FLAG_LOG_INPUT) != 0) {
		fname = t_strdup_printf("%s/%s-%s.in", path, timestamp,
					dec2str(getpid()));
		proxy->fd_in = open(fname, O_CREAT|O_EXCL|O_WRONLY, 0600);
		if (proxy->fd_in == -1) {
			i_error("rawlog_open: open() failed for %s: %m", fname);
			return;
		}
	}

	if ((proxy->flags & RAWLOG_FLAG_LOG_OUTPUT) != 0) {
		fname = t_strdup_printf("%s/%s-%s.out", path, timestamp,
					dec2str(getpid()));
		proxy->fd_out = open(fname, O_CREAT|O_EXCL|O_WRONLY, 0600);
		if (proxy->fd_out == -1) {
			i_error("rawlog_open: open() failed for %s: %m", fname);
			(void)close(proxy->fd_in);
			proxy->fd_in = -1;
			return;
		}
	}
}

static struct rawlog_proxy *
rawlog_proxy_create(int client_in_fd, int client_out_fd, int server_fd,
		    const char *path, enum rawlog_flags flags)
{
	struct rawlog_proxy *proxy;

	proxy = i_new(struct rawlog_proxy, 1);
	proxy->server_fd = server_fd;
	proxy->server_output = o_stream_create_fd(server_fd, (size_t)-1, FALSE);
	proxy->server_io = io_add(server_fd, IO_READ, server_input, proxy);
	o_stream_set_flush_callback(proxy->server_output, server_output, proxy);

	proxy->client_in_fd = client_in_fd;
	proxy->client_out_fd = client_out_fd;
	proxy->client_output =
		o_stream_create_fd(client_out_fd, (size_t)-1, FALSE);
	proxy->client_io = io_add(proxy->client_in_fd, IO_READ,
				  client_input, proxy);
	o_stream_set_flush_callback(proxy->client_output, client_output, proxy);

	fd_set_nonblock(client_in_fd, TRUE);
	fd_set_nonblock(client_out_fd, TRUE);

	proxy->flags = flags;

	proxy->prev_lf_in = proxy->prev_lf_out = TRUE;
	proxy->fd_in = proxy->fd_out = -1;
	proxy_open_logs(proxy, path);
	return proxy;
}

static void rawlog_open(enum rawlog_flags flags)
{
	const char *chroot_dir, *home, *path;
	struct stat st;
	int sfd[2];
	pid_t pid;

	chroot_dir = getenv("RESTRICT_CHROOT");
	home = getenv("HOME");
	if (chroot_dir != NULL)
		home = t_strconcat(chroot_dir, home, NULL);
	else if (home == NULL)
		home = ".";

	/* see if we want rawlog */
	path = t_strconcat(home, "/dovecot.rawlog", NULL);
	if (lstat(path, &st) < 0) {
		if (errno != ENOENT)
			i_warning("lstat() failed for %s: %m", path);
		else if (getenv("DEBUG") != NULL)
			i_info("rawlog: %s doesn't exist", path);
		return;
	}
	if (!S_ISDIR(st.st_mode)) {
		if (getenv("DEBUG") != NULL)
			i_info("rawlog: %s is not a directory", path);
		return;
	}

	if (chroot_dir != NULL) {
		/* we'll chroot soon. skip over the chroot in the path. */
		path += strlen(chroot_dir);
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sfd) < 0)
		i_fatal("socketpair() failed: %m");
	fd_set_nonblock(sfd[0], TRUE);
	fd_set_nonblock(sfd[1], TRUE);

	pid = fork();
	if (pid < 0)
		i_fatal("fork() failed: %m");

	if (pid > 0) {
		/* parent */
		if (dup2(sfd[1], 0) < 0)
			i_fatal("dup2(sfd, 0)");
		if (dup2(sfd[1], 1) < 0)
			i_fatal("dup2(sfd, 1)");
		(void)close(sfd[0]);
		(void)close(sfd[1]);
		return;
	}
	(void)close(sfd[1]);

	restrict_access_by_env(getenv("HOME"), TRUE);

	process_title_set(t_strdup_printf("[%s:%s rawlog]", getenv("USER"),
					  dec2str(getppid())));

	ioloop = io_loop_create();
	rawlog_proxy_create(0, 1, sfd[0], path, flags);
	io_loop_run(ioloop);
	io_loop_destroy(&ioloop);

	lib_deinit();
	exit(0);
}

int main(int argc, char *argv[])
{
	char *executable, *p;
	enum rawlog_flags flags =
		RAWLOG_FLAG_LOG_INPUT | RAWLOG_FLAG_LOG_OUTPUT;
	int c;

	master_service = master_service_init("rawlog", 0,
					     &argc, &argv, "+iobt");
	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'i':
			flags &= ~RAWLOG_FLAG_LOG_OUTPUT;
			break;
		case 'o':
			flags &= ~RAWLOG_FLAG_LOG_INPUT;
			break;
		case 'b':
			flags |= RAWLOG_FLAG_LOG_BOUNDARIES;
			break;
		case 't':
			flags |= RAWLOG_FLAG_LOG_TIMESTAMPS;
			break;
		default:
			return FATAL_DEFAULT;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1)
		i_fatal("Usage: rawlog [-i | -o] [-b] [-t] <binary> <arguments>");

	master_service_init_log(master_service, "rawlog: ");
	master_service_init_finish(master_service);

	executable = argv[0];
	rawlog_open(flags);

	/* hide the executable path, it's ugly */
	p = strrchr(argv[0], '/');
	if (p != NULL) argv[0] = p+1;
	execv(executable, argv);

	i_fatal_status(FATAL_EXEC, "execv(%s) failed: %m", executable);

	/* not reached */
	return FATAL_EXEC;
}
