/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "ipc-client.h"
#include "user-directory.h"
#include "mail-host.h"
#include "director-host.h"
#include "director-connection.h"
#include "director.h"

#define DIRECTOR_IPC_PROXY_PATH "ipc"

#define DIRECTOR_RECONNECT_RETRY_SECS 60
#define DIRECTOR_RECONNECT_TIMEOUT_MSECS (30*1000)
#define DIRECTOR_USER_MOVE_TIMEOUT_MSECS (30*1000)
#define DIRECTOR_USER_MOVE_FINISH_DELAY_MSECS (2*1000)

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

struct director_user_kill_finish_ctx {
	struct director *dir;
	struct user *user;
};

static void
director_user_kill_finish_delayed_to(struct director_user_kill_finish_ctx *ctx)
{
	i_assert(ctx->user->kill_state == USER_KILL_STATE_DELAY);

	ctx->user->kill_state = USER_KILL_STATE_NONE;
	timeout_remove(&ctx->user->to_move);

	ctx->dir->state_change_callback(ctx->dir);
	i_free(ctx);
}

static void
director_user_kill_finish_delayed(struct director *dir, struct user *user)
{
	struct director_user_kill_finish_ctx *ctx;

	ctx = i_new(struct director_user_kill_finish_ctx, 1);
	ctx->dir = dir;
	ctx->user = user;

	user->kill_state = USER_KILL_STATE_DELAY;
	timeout_remove(&user->to_move);

	user->to_move = timeout_add(DIRECTOR_USER_MOVE_FINISH_DELAY_MSECS,
				    director_user_kill_finish_delayed_to, ctx);
}

struct director_kill_context {
	struct director *dir;
	unsigned int username_hash;
	bool self;
};

static void
director_finish_user_kill(struct director *dir, struct user *user, bool self)
{
	if (dir->right == NULL || dir->right == dir->left) {
		/* we're alone */
		director_user_kill_finish_delayed(dir, user);
	} else if (self ||
		   user->kill_state == USER_KILL_STATE_KILLING_NOTIFY_RECEIVED) {
		director_connection_send(dir->right, t_strdup_printf(
			"USER-KILLED\t%u\n", user->username_hash));
		user->kill_state = USER_KILL_STATE_KILLED_WAITING_FOR_EVERYONE;
	} else {
		i_assert(user->kill_state == USER_KILL_STATE_KILLING);
		user->kill_state = USER_KILL_STATE_KILLED_WAITING_FOR_NOTIFY;
	}
}

static void director_kill_user_callback(enum ipc_client_cmd_state state,
					const char *data, void *context)
{
	struct director_kill_context *ctx = context;
	struct user *user;

	switch (state) {
	case IPC_CLIENT_CMD_STATE_REPLY:
		return;
	case IPC_CLIENT_CMD_STATE_OK:
		break;
	case IPC_CLIENT_CMD_STATE_ERROR:
		i_error("Failed to kill user %u connections: %s",
			ctx->username_hash, data);
		/* we can't really do anything but continue anyway */
		break;
	}

	user = user_directory_lookup(ctx->dir->users, ctx->username_hash);
	if (user == NULL || user->kill_state == USER_KILL_STATE_NONE)
		return;

	director_finish_user_kill(ctx->dir, user, ctx->self);
}

static void director_user_move_timeout(struct user *user)
{
	i_error("Finishing user %u move timed out, "
		"its state may now be inconsistent", user->username_hash);

	user->kill_state = USER_KILL_STATE_NONE;
	timeout_remove(&user->to_move);
}

void director_move_user(struct director *dir, struct director_host *src,
			struct director_host *orig_src,
			unsigned int username_hash, struct mail_host *host)
{
	struct user *user;
	const char *cmd;
	struct director_kill_context *ctx;

	/* 1. move this user's host, and set its "killing" flag to delay all of
	   its future connections until all directors have killed the
	   connections and notified us about it.

	   2. tell the other directors about the move

	   3. once user kill callback is called, tell the other directors
	   with USER-KILLED that we're done killing the user.

	   4. when some director gets a duplicate USER-KILLED, it's
	   responsible for notifying all directors that user is completely
	   killed.

	   5. after receiving USER-KILLED-EVERYWHERE notification,
	   new connections are again allowed for the user.
	*/
	user = user_directory_lookup(dir->users, username_hash);
	if (user == NULL) {
		user = user_directory_add(dir->users, username_hash,
					  host, ioloop_time);
	} else {
		if (user->host == host) {
			/* user is already in this host */
			return;
		}
		user->host->user_count--;
		user->host = host;
		user->host->user_count++;
		user->timestamp = ioloop_time;
	}
	if (user->kill_state == USER_KILL_STATE_NONE) {
		ctx = i_new(struct director_kill_context, 1);
		ctx->dir = dir;
		ctx->username_hash = username_hash;
		ctx->self = src->self;

		user->to_move = timeout_add(DIRECTOR_USER_MOVE_TIMEOUT_MSECS,
					    director_user_move_timeout, user);
		user->kill_state = USER_KILL_STATE_KILLING;
		cmd = t_strdup_printf("proxy\t*\tKICK-DIRECTOR-HASH\t%u",
				      username_hash);
		ipc_client_cmd(dir->ipc_proxy, cmd,
			       director_kill_user_callback, ctx);
	}

	if (orig_src == NULL) {
		orig_src = dir->self_host;
		orig_src->last_seq++;
	}
	director_update_send(dir, src, t_strdup_printf(
		"USER-MOVE\t%s\t%u\t%u\t%u\t%s\n",
		net_ip2addr(&orig_src->ip), orig_src->port, orig_src->last_seq,
		user->username_hash, net_ip2addr(&user->host->ip)));
}

void director_user_killed(struct director *dir, unsigned int username_hash)
{
	struct user *user;

	user = user_directory_lookup(dir->users, username_hash);
	if (user == NULL)
		return;

	switch (user->kill_state) {
	case USER_KILL_STATE_KILLING:
		user->kill_state = USER_KILL_STATE_KILLING_NOTIFY_RECEIVED;
		break;
	case USER_KILL_STATE_KILLED_WAITING_FOR_NOTIFY:
		director_finish_user_kill(dir, user, TRUE);
		break;
	case USER_KILL_STATE_NONE:
	case USER_KILL_STATE_DELAY:
	case USER_KILL_STATE_KILLING_NOTIFY_RECEIVED:
		break;
	case USER_KILL_STATE_KILLED_WAITING_FOR_EVERYONE:
		director_user_killed_everywhere(dir, dir->self_host,
						NULL, username_hash);
		break;
	}
}

void director_user_killed_everywhere(struct director *dir,
				     struct director_host *src,
				     struct director_host *orig_src,
				     unsigned int username_hash)
{
	struct user *user;

	user = user_directory_lookup(dir->users, username_hash);
	if (user == NULL ||
	    user->kill_state != USER_KILL_STATE_KILLED_WAITING_FOR_EVERYONE)
		return;

	director_user_kill_finish_delayed(dir, user);

	if (orig_src == NULL) {
		orig_src = dir->self_host;
		orig_src->last_seq++;
	}
	director_update_send(dir, src, t_strdup_printf(
		"USER-KILLED-EVERYWHERE\t%s\t%u\t%u\t%u\n",
		net_ip2addr(&orig_src->ip), orig_src->port, orig_src->last_seq,
		user->username_hash));
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
	const char *path;

	dir = i_new(struct director, 1);
	dir->set = set;
	dir->self_port = listen_port;
	dir->self_ip = *listen_ip;
	dir->state_change_callback = callback;
	i_array_init(&dir->dir_hosts, 16);
	i_array_init(&dir->pending_requests, 16);
	dir->users = user_directory_init(set->director_user_expire);
	dir->mail_hosts = mail_hosts_init();

	path = t_strconcat(set->base_dir, "/" DIRECTOR_IPC_PROXY_PATH, NULL);
	dir->ipc_proxy = ipc_client_init(path);
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

	ipc_client_deinit(&dir->ipc_proxy);
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
