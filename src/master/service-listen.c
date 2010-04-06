/* Copyright (c) 2005-2010 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "fd-set-nonblock.h"
#include "fd-close-on-exec.h"
#include "network.h"
#include "service.h"
#include "service-listen.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define MIN_BACKLOG 4
#define MAX_BACKLOG 128

static unsigned int service_get_backlog(struct service *service)
{
	unsigned int backlog;

	i_assert(service->process_limit > 0);
	i_assert(service->client_limit > 0);

	/* as unlikely as it is, avoid overflows */
	if (service->process_limit > MAX_BACKLOG ||
	    service->client_limit > MAX_BACKLOG)
		backlog = MAX_BACKLOG;
	else {
		backlog = service->process_limit * service->client_limit;
		if (backlog > MAX_BACKLOG)
			backlog = MAX_BACKLOG;
	}
	return I_MAX(backlog, MIN_BACKLOG);
}

static int service_unix_listener_listen(struct service_listener *l)
{
        struct service *service = l->service;
	const struct file_listener_settings *set = l->set.fileset.set;
	mode_t old_umask;
	int fd, i;

	old_umask = umask((set->mode ^ 0777) & 0777);
	for (i = 0;; i++) {
		fd = net_listen_unix(set->path, service_get_backlog(service));
		if (fd != -1)
			break;

		if (errno == EISDIR || errno == ENOENT) {
			/* looks like the path doesn't exist. */
			return 0;
		}

		if (errno != EADDRINUSE) {
			service_error(service, "net_listen_unix(%s) failed: %m",
				      set->path);
			return -1;
		}

		/* already in use - see if it really exists.
		   after 3 times just fail here. */
		fd = net_connect_unix(set->path);
		if (fd != -1 || errno != ECONNREFUSED || i >= 3) {
			if (fd != -1)
				(void)close(fd);
			service_error(service, "Socket already exists: %s",
				      set->path);
			return 0;
		}

		/* delete and try again */
		if (unlink(set->path) < 0 && errno != ENOENT) {
			service_error(service, "unlink(%s) failed: %m",
				      set->path);
			return -1;
		}
	}
	umask(old_umask);

	i_assert(fd != -1);

	/* see if we need to change its owner/group */
	if ((l->set.fileset.uid != (uid_t)-1 &&
	     l->set.fileset.uid != master_uid) ||
	    (l->set.fileset.gid != (gid_t)-1 &&
	     l->set.fileset.gid != master_gid)) {
		if (chown(set->path, l->set.fileset.uid, l->set.fileset.gid) < 0) {
			i_error("chown(%s, %lld, %lld) failed: %m", set->path,
				(long long)l->set.fileset.uid,
				(long long)l->set.fileset.gid);
			(void)close(fd);
			return -1;
		}
	}

	net_set_nonblock(fd, TRUE);
	fd_close_on_exec(fd, TRUE);

	l->fd = fd;
	return 1;
}

static int service_fifo_listener_listen(struct service_listener *l)
{
        struct service *service = l->service;
	const struct file_listener_settings *set = l->set.fileset.set;
	mode_t old_umask;
	int fd, ret;

	old_umask = umask((set->mode ^ 0777) & 0777);
	ret = mkfifo(set->path, set->mode);
	umask(old_umask);

	if (ret < 0 && errno != EEXIST) {
		service_error(service, "mkfifo(%s) failed: %m", set->path);
		return -1;
	}

	fd = open(set->path, O_RDONLY);
	if (fd == -1) {
		service_error(service, "open(%s) failed: %m", set->path);
		return -1;
	}

	/* see if we need to change its owner/group */
	if ((service->uid != (uid_t)-1 && service->uid != master_uid) ||
	    (service->gid != (gid_t)-1 && service->gid != master_gid)) {
		if (chown(set->path, service->uid, service->gid) < 0) {
			i_error("chown(%s, %lld, %lld) failed: %m", set->path,
				(long long)service->uid,
				(long long)service->gid);
			(void)close(fd);
			return -1;
		}
	}

	fd_set_nonblock(fd, TRUE);
	fd_close_on_exec(fd, TRUE);

	l->fd = fd;
	return 1;
}

static int service_inet_listener_listen(struct service_listener *l)
{
        struct service *service = l->service;
	const struct inet_listener_settings *set = l->set.inetset.set;
	unsigned int port = set->port;
	int fd;

	fd = net_listen(&l->set.inetset.ip, &port,
			service_get_backlog(service));
	if (fd < 0) {
		service_error(service, "listen(%s, %u) failed: %m",
			      l->inet_address, set->port);
		return errno == EADDRINUSE ? 0 : -1;
	}
	net_set_nonblock(fd, TRUE);
	fd_close_on_exec(fd, TRUE);

	l->fd = fd;
	return 1;
}

static int service_listen(struct service *service)
{
	struct service_listener *const *listeners;
	int ret = 1, ret2 = 0;

	array_foreach(&service->listeners, listeners) {
		struct service_listener *l = *listeners;

		if (l->fd != -1)
			continue;

		switch (l->type) {
		case SERVICE_LISTENER_UNIX:
			ret2 = service_unix_listener_listen(l);
			break;
		case SERVICE_LISTENER_FIFO:
			ret2 = service_fifo_listener_listen(l);
			break;
		case SERVICE_LISTENER_INET:
			ret2 = service_inet_listener_listen(l);
			break;
		}

		if (ret2 < ret)
			ret = ret2;
	}
	return ret;
}

int services_listen(struct service_list *service_list)
{
	struct service *const *services;
	int ret = 1, ret2;

	array_foreach(&service_list->services, services) {
		ret2 = service_listen(*services);
		if (ret2 < ret)
			ret = ret2;
	}
	return ret;
}

static int listener_equals(const struct service_listener *l1,
			   const struct service_listener *l2)
{
	if (l1->type != l2->type)
		return FALSE;

	switch (l1->type) {
	case SERVICE_LISTENER_UNIX:
	case SERVICE_LISTENER_FIFO:
		/* We could just keep using the same listener, but it's more
		   likely to cause problems if old process accepts a connection
		   before it knows that it should die. So just always unlink
		   and recreate unix/fifo listeners. */
		return FALSE;
	case SERVICE_LISTENER_INET:
		if (memcmp(&l1->set.inetset.ip, &l2->set.inetset.ip,
			   sizeof(l1->set.inetset.ip)) != 0)
			return FALSE;
		if (l1->set.inetset.set->port != l2->set.inetset.set->port)
			return FALSE;
		return TRUE;
	}
	return FALSE;
}

int services_listen_using(struct service_list *new_service_list,
			  struct service_list *old_service_list)
{
	struct service *const *services, *old_service, *new_service;
	ARRAY_DEFINE(new_listeners_arr, struct service_listener *);
	ARRAY_DEFINE(old_listeners_arr, struct service_listener *);
	struct service_listener *const *new_listeners, *const *old_listeners;
	unsigned int i, j, count, new_count, old_count;

	/* rescue anvil's UNIX socket listener */
	new_service = service_lookup_type(new_service_list, SERVICE_TYPE_ANVIL);
	old_service = service_lookup_type(old_service_list, SERVICE_TYPE_ANVIL);
	if (old_service != NULL && new_service != NULL) {
		new_listeners = array_get(&new_service->listeners, &new_count);
		old_listeners = array_get(&old_service->listeners, &old_count);
		for (i = 0; i < old_count && i < new_count; i++) {
			if (new_listeners[i]->type != old_listeners[i]->type)
				break;
		}
		if (i != new_count && i != old_count) {
			i_error("Can't change anvil's listeners on the fly");
			return -1;
		}
		for (i = 0; i < new_count; i++) {
			new_listeners[i]->fd = old_listeners[i]->fd;
			old_listeners[i]->fd = -1;
		}
	}

	/* first create an arrays of all listeners to make things easier */
	t_array_init(&new_listeners_arr, 64);
	services = array_get(&new_service_list->services, &count);
	for (i = 0; i < count; i++)
		array_append_array(&new_listeners_arr, &services[i]->listeners);

	t_array_init(&old_listeners_arr, 64);
	services = array_get(&old_service_list->services, &count);
	for (i = 0; i < count; i++)
		array_append_array(&old_listeners_arr, &services[i]->listeners);

	/* then start moving fds */
	new_listeners = array_get(&new_listeners_arr, &new_count);
	old_listeners = array_get(&old_listeners_arr, &old_count);

	for (i = 0; i < new_count; i++) {
		for (j = 0; j < old_count; j++) {
			if (old_listeners[j]->fd != -1 &&
			    listener_equals(new_listeners[i],
					    old_listeners[j])) {
				new_listeners[i]->fd = old_listeners[j]->fd;
                                old_listeners[j]->fd = -1;
				break;
			}
		}
	}

	/* close what's left */
	for (j = 0; j < old_count; j++) {
		if (old_listeners[j]->fd == -1)
			continue;

		if (close(old_listeners[j]->fd) < 0)
			i_error("close(listener) failed: %m");
		switch (old_listeners[j]->type) {
		case SERVICE_LISTENER_UNIX:
		case SERVICE_LISTENER_FIFO: {
			const char *path =
				old_listeners[j]->set.fileset.set->path;
			if (unlink(path) < 0)
				i_error("unlink(%s) failed: %m", path);
			break;
		}
		case SERVICE_LISTENER_INET:
			break;
		}
	}

	/* and let services_listen() deal with the remaining fds */
	return services_listen(new_service_list);
}
