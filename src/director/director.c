/* Copyright (c) 2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "user-directory.h"
#include "mail-host.h"
#include "director-host.h"
#include "director-connection.h"
#include "director.h"

#define DIRECTOR_RECONNECT_RETRY_SECS 60

static bool director_is_self_ip_set(struct director *dir)
{
	struct ip_addr ip;

	net_get_ip_any4(&ip);
	if (net_ip_compare(&dir->self_ip, &ip))
		return FALSE;

	net_get_ip_any6(&ip);
	if (net_ip_compare(&dir->self_ip, &ip))
		return FALSE;

	return TRUE;
}

static void director_find_self_ip(struct director *dir)
{
	struct director_host *const *hosts;
	unsigned int i, count;

	hosts = array_get(&dir->dir_hosts, &count);
	for (i = 0; i < count; i++) {
		if (net_try_bind(&hosts[i]->ip) == 0) {
			dir->self_ip = hosts[i]->ip;
			return;
		}
	}
	i_fatal("director_servers doesn't list ourself");
}

static void director_find_self(struct director *dir)
{
	if (dir->self_host != NULL)
		return;

	if (!director_is_self_ip_set(dir))
		director_find_self_ip(dir);

	dir->self_host = director_host_lookup(dir, &dir->self_ip,
					      dir->self_port);
	if (dir->self_host == NULL) {
		i_fatal("director_servers doesn't list ourself (%s:%u)",
			net_ip2addr(&dir->self_ip), dir->self_port);
	}
	dir->self_host->self = TRUE;
}

static unsigned int director_find_self_idx(struct director *dir)
{
	struct director_host *const *hosts;
	unsigned int i, count;

	i_assert(dir->self_host != NULL);

	hosts = array_get(&dir->dir_hosts, &count);
	for (i = 0; i < count; i++) {
		if (hosts[i] == dir->self_host)
			return i;
	}
	i_unreached();
}

int director_connect_host(struct director *dir, struct director_host *host)
{
	int fd;

	i_assert(dir->right == NULL);

	if (host->last_failed + DIRECTOR_RECONNECT_RETRY_SECS > ioloop_time) {
		/* failed recently, don't try retrying here */
		return -1;
	}

	fd = net_connect_ip(&host->ip, host->port, &dir->self_ip);
	if (fd == -1) {
		host->last_failed = ioloop_time;
		i_error("connect(%s) failed: %m", host->name);
		return -1;
	}

	dir->right = director_connection_init_out(dir, fd, host);
	return 0;
}

void director_connect(struct director *dir)
{
	struct director_host *const *hosts;
	unsigned int i, count, self_idx;

	director_find_self(dir);
	self_idx = director_find_self_idx(dir);

	/* try to connect to first working server on our right side.
	   the left side is supposed to connect to us. */
	hosts = array_get(&dir->dir_hosts, &count);
	for (i = 1; i < count; i++) {
		unsigned int idx = (self_idx + i) % count;

		if (director_connect_host(dir, hosts[idx]) == 0)
			break;
	}
	if (i == count) {
		/* we're the only one */
		dir->ring_handshaked = TRUE;
		director_set_state_changed(dir);
	}
}

void director_update_host(struct director *dir, struct director_host *src,
			  struct mail_host *host)
{
	director_set_state_changed(dir);

	director_update_send(dir, src, t_strdup_printf(
		"HOST\t%s\t%u\n", net_ip2addr(&host->ip), host->vhost_count));
}

void director_remove_host(struct director *dir, struct director_host *src,
			  struct mail_host *host)
{
	director_update_send(dir, src, t_strdup_printf(
		"HOST-REMOVE\t%s\n", net_ip2addr(&host->ip)));
	user_directory_remove_host(dir->users, host);
	mail_host_remove(host);
}

void director_update_user(struct director *dir, struct director_host *src,
			  struct user *user)
{
	director_update_send(dir, src, t_strdup_printf(
		"USER\t%u\t%s\n", user->username_hash,
		net_ip2addr(&user->host->ip)));
}

void director_set_state_changed(struct director *dir)
{
	dir->state_change_callback(dir);
}

void director_update_send(struct director *dir, struct director_host *src,
			  const char *cmd)
{
	i_assert(src != NULL);

	if (dir->left != NULL)
		director_connection_send_except(dir->left, src, cmd);
	if (dir->right != NULL && dir->right != dir->left)
		director_connection_send_except(dir->right, src, cmd);
}

struct director *
director_init(const struct director_settings *set,
	      const struct ip_addr *listen_ip, unsigned int listen_port,
	      director_state_change_callback_t *callback)
{
	struct director *dir;

	dir = i_new(struct director, 1);
	dir->set = set;
	dir->self_port = listen_port;
	dir->self_ip = *listen_ip;
	dir->state_change_callback = callback;
	i_array_init(&dir->dir_hosts, 16);
	i_array_init(&dir->pending_requests, 16);
	i_array_init(&dir->desynced_host_changes, 16);
	dir->users = user_directory_init(set->director_user_expire);
	return dir;
}

void director_deinit(struct director **_dir)
{
	struct director *dir = *_dir;
	struct director_host *const *hostp;

	*_dir = NULL;

	if (dir->left != NULL)
		director_connection_deinit(&dir->left);
	if (dir->right != NULL)
		director_connection_deinit(&dir->right);

	user_directory_deinit(&dir->users);
	if (dir->to_request != NULL)
		timeout_remove(&dir->to_request);
	array_foreach(&dir->dir_hosts, hostp)
		director_host_free(*hostp);
	array_free(&dir->desynced_host_changes);
	array_free(&dir->pending_requests);
	array_free(&dir->dir_hosts);
	i_free(dir);
}
