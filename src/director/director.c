/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

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
#define DIRECTOR_RECONNECT_TIMEOUT_MSECS (30*1000)

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
	unsigned int port;
	int fd;

	if (director_connection_find_outgoing(dir, host) != NULL)
		return 0;

	if (dir->debug) {
		i_debug("Connecting to %s:%u",
			net_ip2addr(&host->ip), host->port);
	}
	port = dir->test_port != 0 ? dir->test_port : host->port;
	fd = net_connect_ip(&host->ip, port, &dir->self_ip);
	if (fd == -1) {
		host->last_failed = ioloop_time;
		i_error("connect(%s) failed: %m", host->name);
		return -1;
	}
	/* Reset timestamp so that director_connect() won't skip this host
	   while we're still trying to connect to it */
	host->last_failed = 0;

	director_connection_init_out(dir, fd, host);
	return 0;
}

static struct director_host *
director_get_preferred_right_host(struct director *dir)
{
	struct director_host *const *hosts;
	unsigned int count, self_idx;

	hosts = array_get(&dir->dir_hosts, &count);
	if (count == 1)
		return NULL;

	self_idx = director_find_self_idx(dir);
	return hosts[(self_idx + 1) % count];
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

		if (hosts[idx]->last_failed +
		    DIRECTOR_RECONNECT_RETRY_SECS > ioloop_time) {
			/* failed recently, don't try retrying here */
			continue;
		}

		if (director_connect_host(dir, hosts[idx]) == 0)
			break;
	}
	if (i == count) {
		/* we're the only one */
		if (dir->debug) {
			i_debug("director: Couldn't connect to right side, "
				"we must be the only director left");
		}
		if (dir->left != NULL) {
			/* since we couldn't connect to it,
			   it must have failed recently */
			director_connection_deinit(&dir->left);
		}
		if (!dir->ring_handshaked)
			director_set_ring_handshaked(dir);
		else
			director_set_ring_synced(dir);
	}
}

void director_set_ring_handshaked(struct director *dir)
{
	i_assert(!dir->ring_handshaked);

	if (dir->to_handshake_warning != NULL)
		timeout_remove(&dir->to_handshake_warning);
	if (dir->ring_handshake_warning_sent) {
		i_warning("Directors have been connected, "
			  "continuing delayed requests");
		dir->ring_handshake_warning_sent = FALSE;
	}
	if (dir->debug)
		i_debug("Director ring handshaked");

	dir->ring_handshaked = TRUE;
	director_set_ring_synced(dir);
}

static void director_reconnect_timeout(struct director *dir)
{
	struct director_host *cur_host, *preferred_host =
		director_get_preferred_right_host(dir);

	cur_host = dir->right == NULL ? NULL :
		director_connection_get_host(dir->right);

	if (cur_host != preferred_host)
		(void)director_connect_host(dir, preferred_host);
	else {
		/* the connection hasn't finished sync yet.
		   keep this timeout for now. */
	}
}

void director_set_ring_synced(struct director *dir)
{
	struct director_host *host;

	i_assert(!dir->ring_synced);
	i_assert((dir->left != NULL && dir->right != NULL) ||
		 (dir->left == NULL && dir->right == NULL));

	if (dir->to_handshake_warning != NULL)
		timeout_remove(&dir->to_handshake_warning);
	if (dir->ring_handshake_warning_sent) {
		i_warning("Ring is synced, continuing delayed requests");
		dir->ring_handshake_warning_sent = FALSE;
	}

	host = dir->right == NULL ? NULL :
		director_connection_get_host(dir->right);
	if (host != director_get_preferred_right_host(dir)) {
		/* try to reconnect to preferred host later */
		if (dir->to_reconnect == NULL) {
			dir->to_reconnect =
				timeout_add(DIRECTOR_RECONNECT_TIMEOUT_MSECS,
					    director_reconnect_timeout, dir);
		}
	} else {
		if (dir->to_reconnect != NULL)
			timeout_remove(&dir->to_reconnect);
	}

	dir->ring_synced = TRUE;
	director_set_state_changed(dir);
}

static void director_sync(struct director *dir)
{
	if (dir->sync_frozen) {
		dir->sync_pending = TRUE;
		return;
	}
	if (dir->right == NULL) {
		i_assert(!dir->ring_synced ||
			 (dir->left == NULL && dir->right == NULL));
		return;
	}

	/* we're synced again when we receive this SYNC back */
	dir->sync_seq++;
	dir->ring_synced = FALSE;

	if (dir->debug) {
		i_debug("Ring is desynced (seq=%u, sending SYNC to %s)",
			dir->sync_seq, dir->right == NULL ? "(nowhere)" :
			director_connection_get_name(dir->right));
	}

	if (dir->left != NULL)
		director_connection_wait_sync(dir->left);
	director_connection_wait_sync(dir->right);
	director_connection_send(dir->right, t_strdup_printf(
		"SYNC\t%s\t%u\t%u\n", net_ip2addr(&dir->self_ip),
		dir->self_port, dir->sync_seq));
}

void director_sync_freeze(struct director *dir)
{
	i_assert(!dir->sync_frozen);
	i_assert(!dir->sync_pending);

	if (dir->left != NULL)
		director_connection_cork(dir->left);
	if (dir->right != NULL)
		director_connection_cork(dir->right);
	dir->sync_frozen = TRUE;
}

void director_sync_thaw(struct director *dir)
{
	i_assert(dir->sync_frozen);

	dir->sync_frozen = FALSE;
	if (dir->sync_pending) {
		dir->sync_pending = FALSE;
		director_sync(dir);
	}
	if (dir->left != NULL)
		director_connection_uncork(dir->left);
	if (dir->right != NULL)
		director_connection_uncork(dir->right);
}

void director_update_host(struct director *dir, struct director_host *src,
			  struct director_host *orig_src,
			  struct mail_host *host)
{
	/* update state in case this is the first mail host being added */
	director_set_state_changed(dir);

	if (orig_src == NULL) {
		orig_src = dir->self_host;
		orig_src->last_seq++;
	}

	director_update_send(dir, src, t_strdup_printf(
		"HOST\t%s\t%u\t%u\t%s\t%u\n",
		net_ip2addr(&orig_src->ip), orig_src->port, orig_src->last_seq,
		net_ip2addr(&host->ip), host->vhost_count));
	director_sync(dir);
}

void director_remove_host(struct director *dir, struct director_host *src,
			  struct director_host *orig_src,
			  struct mail_host *host)
{
	if (src != NULL) {
		if (orig_src == NULL) {
			orig_src = dir->self_host;
			orig_src->last_seq++;
		}

		director_update_send(dir, src, t_strdup_printf(
			"HOST-REMOVE\t%s\t%u\t%u\t%s\n",
			net_ip2addr(&orig_src->ip), orig_src->port,
			orig_src->last_seq, net_ip2addr(&host->ip)));
	}

	user_directory_remove_host(dir->users, host);
	mail_host_remove(dir->mail_hosts, host);
	director_sync(dir);
}

void director_flush_host(struct director *dir, struct director_host *src,
			 struct director_host *orig_src,
			 struct mail_host *host)
{
	if (orig_src == NULL) {
		orig_src = dir->self_host;
		orig_src->last_seq++;
	}

	director_update_send(dir, src, t_strdup_printf(
		"HOST-FLUSH\t%s\t%u\t%u\t%s\n",
		net_ip2addr(&orig_src->ip), orig_src->port, orig_src->last_seq,
		net_ip2addr(&host->ip)));
	user_directory_remove_host(dir->users, host);
	director_sync(dir);
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
	dir->users = user_directory_init(set->director_user_expire);
	dir->mail_hosts = mail_hosts_init();
	return dir;
}

void director_deinit(struct director **_dir)
{
	struct director *dir = *_dir;
	struct director_host *const *hostp;

	*_dir = NULL;

	director_connections_deinit(dir);
	user_directory_deinit(&dir->users);
	mail_hosts_deinit(&dir->mail_hosts);
	mail_hosts_deinit(&dir->orig_config_hosts);
	if (dir->to_reconnect != NULL)
		timeout_remove(&dir->to_reconnect);
	if (dir->to_handshake_warning != NULL)
		timeout_remove(&dir->to_handshake_warning);
	if (dir->to_request != NULL)
		timeout_remove(&dir->to_request);
	array_foreach(&dir->dir_hosts, hostp)
		director_host_free(*hostp);
	array_free(&dir->pending_requests);
	array_free(&dir->dir_hosts);
	i_free(dir);
}
