/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "network.h"
#include "fdpass.h"
#include "access-lookup.h"

#include <unistd.h>

#define ACCESS_LOOKUP_TIMEOUT_MSECS (1000*60)

struct access_lookup {
	int refcount;

	int fd;
	char *path;

	struct io *io;
	struct timeout *to;

	access_lookup_callback_t *callback;
	void *context;
};

static void access_lookup_input(struct access_lookup *lookup)
{
	unsigned char buf[3];
	ssize_t ret;
	bool success = FALSE;

	ret = read(lookup->fd, buf, sizeof(buf));
	if (ret < 0) {
		i_error("read(%s) failed: %m", lookup->path);
	} else if (ret == 0) {
		/* connection close -> no success */
	} else if (ret == 2 && buf[0] == '0' && buf[1] == '\n') {
		/* no success */
	} else if (ret == 2 && buf[0] == '1' && buf[1] == '\n') {
		success = TRUE;
	} else {
		i_error("access(%s): Invalid input", lookup->path);
	}

	lookup->refcount++;
	lookup->callback(success, lookup->context);
	if (lookup->refcount > 1)
		access_lookup_destroy(&lookup);
	access_lookup_destroy(&lookup);
}

static void access_lookup_timeout(struct access_lookup *lookup)
{
	i_error("access(%s): Timed out while waiting for reply", lookup->path);

	lookup->refcount++;
	lookup->callback(FALSE, lookup->context);
	if (lookup->refcount > 1)
		access_lookup_destroy(&lookup);
	access_lookup_destroy(&lookup);
}

struct access_lookup *
access_lookup(const char *path, int client_fd, const char *daemon_name,
	      access_lookup_callback_t *callback, void *context)
{
	struct access_lookup *lookup;
	const char *cmd;
	ssize_t ret;
	int fd;

	fd = net_connect_unix(path);
	if (fd == -1) {
		i_error("connect(%s) failed: %m", path);
		return NULL;
	}

	cmd = t_strconcat(daemon_name, "\n", NULL);
	ret = fd_send(fd, client_fd, cmd, strlen(cmd));
	if (ret != (ssize_t)strlen(cmd)) {
		if (ret < 0)
			i_error("fd_send(%s) failed: %m", path);
		else
			i_error("fd_send(%s) didn't write enough bytes", path);
		(void)close(fd);
		return NULL;
	}

	lookup = i_new(struct access_lookup, 1);
	lookup->refcount = 1;
	lookup->fd = fd;
	lookup->path = i_strdup(path);
	lookup->io = io_add(fd, IO_READ, access_lookup_input, lookup);
	lookup->to = timeout_add(ACCESS_LOOKUP_TIMEOUT_MSECS,
				 access_lookup_timeout, lookup);
	lookup->callback = callback;
	lookup->context = context;
	return lookup;
}

void access_lookup_destroy(struct access_lookup **_lookup)
{
	struct access_lookup *lookup = *_lookup;

	i_assert(lookup->refcount > 0);
	if (--lookup->refcount > 0)
		return;

	*_lookup = NULL;

	if (lookup->to != NULL)
		timeout_remove(&lookup->to);
	io_remove(&lookup->io);
	if (close(lookup->fd) < 0)
		i_error("close(%s) failed: %m", lookup->path);

	i_free(lookup->path);
	i_free(lookup);
}
