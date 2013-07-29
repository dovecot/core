/* Copyright (c) 2010-2013 Dovecot authors, see the included COPYING file */

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
#define DIRECTOR_SYNC_TIMEOUT_MSECS (5*1000)
#define DIRECTOR_RING_MIN_WAIT_SECS 20
#define DIRECTOR_QUICK_RECONNECT_TIMEOUT_MSECS 1000
#define DIRECTOR_DELAYED_DIR_REMOVE_MSECS (1000*30)

bool director_debug;

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

void director_find_self(struct director *dir)
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

static bool
director_has_outgoing_connection(struct director *dir,
				 struct director_host *host)
{
	struct director_connection *const *connp;

	array_foreach(&dir->connections, connp) {
		if (director_connection_get_host(*connp) == host &&
		    !director_connection_is_incoming(*connp))
			return TRUE;
	}
	return FALSE;
}

int director_connect_host(struct director *dir, struct director_host *host)
{
	unsigned int port;
	int fd;

	if (director_has_outgoing_connection(dir, host))
		return 0;

	dir_debug("Connecting to %s:%u",
		  net_ip2addr(&host->ip), host->port);
	port = dir->test_port != 0 ? dir->test_port : host->port;
	fd = net_connect_ip(&host->ip, port, &dir->self_ip);
	if (fd == -1) {
		host->last_network_failure = ioloop_time;
		i_error("connect(%s) failed: %m", host->name);
		return -1;
	}
	/* Reset timestamp so that director_connect() won't skip this host
	   while we're still trying to connect to it */
	host->last_network_failure = 0;

	(void)director_connection_init_out(dir, fd, host);
	return 0;
}

static struct director_host *
director_get_preferred_right_host(struct director *dir)
{
	struct director_host *const *hosts, *host;
	unsigned int i, count, self_idx;

	hosts = array_get(&dir->dir_hosts, &count);
	if (count == 1) {
		/* self */
		return NULL;
	}

	self_idx = director_find_self_idx(dir);
	for (i = 0; i < count; i++) {
		host = hosts[(self_idx + i + 1) % count];
		if (!host->removed)
			return host;
	}
	/* self, with some removed hosts */
	return NULL;
}

static bool director_wait_for_others(struct director *dir)
{
	struct director_host *const *hostp;

	/* don't assume we're alone until we've attempted to connect
	   to others for a while */
	if (dir->ring_first_alone != 0 &&
	    ioloop_time - dir->ring_first_alone > DIRECTOR_RING_MIN_WAIT_SECS)
		return FALSE;

	if (dir->ring_first_alone == 0)
		dir->ring_first_alone = ioloop_time;
	/* reset all failures and try again */
	array_foreach(&dir->dir_hosts, hostp) {
		(*hostp)->last_network_failure = 0;
		(*hostp)->last_protocol_failure = 0;
	}
	if (dir->to_reconnect != NULL)
		timeout_remove(&dir->to_reconnect);
	dir->to_reconnect = timeout_add(DIRECTOR_QUICK_RECONNECT_TIMEOUT_MSECS,
					director_connect, dir);
	return TRUE;
}

void director_connect(struct director *dir)
{
	struct director_host *const *hosts;
	unsigned int i, count, self_idx;

	self_idx = director_find_self_idx(dir);

	/* try to connect to first working server on our right side.
	   the left side is supposed to connect to us. */
	hosts = array_get(&dir->dir_hosts, &count);
	for (i = 1; i < count; i++) {
		unsigned int idx = (self_idx + i) % count;

		if (hosts[idx]->removed)
			continue;

		if (hosts[idx]->last_network_failure +
		    DIRECTOR_RECONNECT_RETRY_SECS > ioloop_time) {
			/* connection failed recently, don't try retrying here */
			continue;
		}
		if (hosts[idx]->last_protocol_failure +
		    DIRECTOR_PROTOCOL_FAILURE_RETRY_SECS > ioloop_time) {
			/* the director recently sent invalid protocol data,
			   don't try retrying yet */
			continue;
		}

		if (director_connect_host(dir, hosts[idx]) == 0) {
			/* success */
			return;
		}
	}

	if (count > 1 && director_wait_for_others(dir))
		return;

	/* we're the only one */
	if (count > 1) {
		i_warning("director: Couldn't connect to right side, "
			  "we must be the only director left");
	}
	if (dir->left != NULL) {
		/* since we couldn't connect to it,
		   it must have failed recently */
		i_warning("director: Assuming %s is dead, disconnecting",
			  director_connection_get_name(dir->left));
		director_connection_deinit(&dir->left,
					   "This connection is dead?");
	}
	dir->ring_min_version = DIRECTOR_VERSION_MINOR;
	if (!dir->ring_handshaked)
		director_set_ring_handshaked(dir);
	else
		director_set_ring_synced(dir);
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
	dir_debug("Director ring handshaked");

	dir->ring_handshaked = TRUE;
	director_set_ring_synced(dir);
}

static void director_reconnect_timeout(struct director *dir)
{
	struct director_host *cur_host, *preferred_host =
		director_get_preferred_right_host(dir);

	cur_host = dir->right == NULL ? NULL :
		director_connection_get_host(dir->right);

	if (preferred_host == NULL) {
		/* all directors have been removed, try again later */
	} else if (cur_host != preferred_host)
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

	if (dir->to_reconnect != NULL)
		timeout_remove(&dir->to_reconnect);
	if (host != director_get_preferred_right_host(dir)) {
		/* try to reconnect to preferred host later */
		dir->to_reconnect =
			timeout_add(DIRECTOR_RECONNECT_TIMEOUT_MSECS,
				    director_reconnect_timeout, dir);
	}

	if (dir->left != NULL)
		director_connection_set_synced(dir->left, TRUE);
	if (dir->right != NULL)
		director_connection_set_synced(dir->right, TRUE);
	if (dir->to_sync != NULL)
		timeout_remove(&dir->to_sync);
	dir->ring_synced = TRUE;
	dir->ring_last_sync_time = ioloop_time;
	director_set_state_changed(dir);
}

void director_sync_send(struct director *dir, struct director_host *host,
			uint32_t seq, unsigned int minor_version,
			unsigned int timestamp)
{
	string_t *str;

	str = t_str_new(128);
	str_printfa(str, "SYNC\t%s\t%u\t%u",
		    net_ip2addr(&host->ip), host->port, seq);
	if (minor_version > 0 &&
	    director_connection_get_minor_version(dir->right) > 0) {
		/* only minor_version>0 supports extra parameters */
		str_printfa(str, "\t%u\t%u", minor_version, timestamp);
	}
	str_append_c(str, '\n');
	director_connection_send(dir->right, str_c(str));

	/* ping our connections in case either of them are hanging.
	   if they are, we want to know it fast. */
	if (dir->left != NULL)
		director_connection_ping(dir->left);
	if (dir->right != NULL)
		director_connection_ping(dir->right);
}

bool director_resend_sync(struct director *dir)
{
	if (!dir->ring_synced && dir->left != NULL && dir->right != NULL) {
		/* send a new SYNC in case the previous one got dropped */
		dir->self_host->last_sync_timestamp = ioloop_time;
		director_sync_send(dir, dir->self_host, dir->sync_seq,
				   DIRECTOR_VERSION_MINOR, ioloop_time);
		if (dir->to_sync != NULL)
			timeout_reset(dir->to_sync);
		return TRUE;
	}
	return FALSE;
}

static void director_sync_timeout(struct director *dir)
{
	i_assert(!dir->ring_synced);

	if (director_resend_sync(dir))
		i_error("Ring SYNC appears to have got lost, resending");
}

void director_set_ring_unsynced(struct director *dir)
{
	if (dir->ring_synced) {
		dir->ring_synced = FALSE;
		dir->ring_last_sync_time = ioloop_time;
	}

	if (dir->to_sync == NULL) {
		dir->to_sync = timeout_add(DIRECTOR_SYNC_TIMEOUT_MSECS,
					   director_sync_timeout, dir);
	} else {
		timeout_reset(dir->to_sync);
	}
}

static void director_sync(struct director *dir)
{
	/* we're synced again when we receive this SYNC back */
	dir->sync_seq++;
	if (dir->right == NULL && dir->left == NULL) {
		/* we're alone. if we're already synced,
		   don't become unsynced. */
		return;
	}
	director_set_ring_unsynced(dir);

	if (dir->sync_frozen) {
		dir->sync_pending = TRUE;
		return;
	}
	if (dir->right == NULL) {
		i_assert(!dir->ring_synced ||
			 (dir->left == NULL && dir->right == NULL));
		return;
	}

	dir_debug("Ring is desynced (seq=%u, sending SYNC to %s)",
		  dir->sync_seq, dir->right == NULL ? "(nowhere)" :
		  director_connection_get_name(dir->right));

	/* send PINGs to our connections more rapidly until we've synced again.
	   if the connection has actually died, we don't need to wait (and
	   delay requests) for as long to detect it */
	if (dir->left != NULL)
		director_connection_set_synced(dir->left, FALSE);
	director_connection_set_synced(dir->right, FALSE);
	director_sync_send(dir, dir->self_host, dir->sync_seq,
			   DIRECTOR_VERSION_MINOR, ioloop_time);
}

void director_sync_freeze(struct director *dir)
{
	struct director_connection *const *connp;

	i_assert(!dir->sync_frozen);
	i_assert(!dir->sync_pending);

	array_foreach(&dir->connections, connp)
		director_connection_cork(*connp);
	dir->sync_frozen = TRUE;
}

void director_sync_thaw(struct director *dir)
{
	struct director_connection *const *connp;

	i_assert(dir->sync_frozen);

	dir->sync_frozen = FALSE;
	if (dir->sync_pending) {
		dir->sync_pending = FALSE;
		director_sync(dir);
	}
	array_foreach(&dir->connections, connp)
		director_connection_uncork(*connp);
}

void director_notify_ring_added(struct director_host *added_host,
				struct director_host *src)
{
	const char *cmd;

	cmd = t_strdup_printf("DIRECTOR\t%s\t%u\n",
			      net_ip2addr(&added_host->ip), added_host->port);
	director_update_send(added_host->dir, src, cmd);
}

static void director_delayed_dir_remove_timeout(struct director *dir)
{
	struct director_host *const *hosts, *host;
	unsigned int i, count;

	timeout_remove(&dir->to_remove_dirs);

	hosts = array_get(&dir->dir_hosts, &count);
	for (i = 0; i < count; ) {
		if (hosts[i]->removed) {
			host = hosts[i];
			director_host_free(&host);
			hosts = array_get(&dir->dir_hosts, &count);
		} else {
			i++;
		}
	}
}

void director_ring_remove(struct director_host *removed_host,
			  struct director_host *src)
{
	struct director *dir = removed_host->dir;
	struct director_connection *const *conns, *conn;
	unsigned int i, count;
	const char *cmd;

	if (removed_host->self) {
		/* others will just disconnect us */
		return;
	}

	/* mark the host as removed and fully remove it later. this delay is
	   needed, because the removal may trigger director reconnections,
	   which may send the director back and we don't want to re-add it */
	removed_host->removed = TRUE;
	if (dir->to_remove_dirs == NULL) {
		dir->to_remove_dirs =
			timeout_add(DIRECTOR_DELAYED_DIR_REMOVE_MSECS,
				    director_delayed_dir_remove_timeout, dir);
	}

	/* disconnect any connections to the host */
	conns = array_get(&dir->connections, &count);
	for (i = 0; i < count; ) {
		conn = conns[i];
		if (director_connection_get_host(conn) != removed_host)
			i++;
		else {
			director_connection_deinit(&conn, "Removing from ring");
			conns = array_get(&dir->connections, &count);
		}
	}
	if (dir->right == NULL)
		director_connect(dir);

	cmd = t_strdup_printf("DIRECTOR-REMOVE\t%s\t%u\n",
			      net_ip2addr(&removed_host->ip),
			      removed_host->port);
	director_update_send_version(dir, src,
				     DIRECTOR_VERSION_RING_REMOVE, cmd);
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
	i_assert(src != NULL);

	i_assert(!user->weak);
	director_update_send(dir, src, t_strdup_printf("USER\t%u\t%s\n",
		user->username_hash, net_ip2addr(&user->host->ip)));
}

void director_update_user_weak(struct director *dir, struct director_host *src,
			       struct director_host *orig_src,
			       struct user *user)
{
	i_assert(src != NULL);
	i_assert(user->weak);

	if (orig_src == NULL) {
		orig_src = dir->self_host;
		orig_src->last_seq++;
	}

	director_update_send(dir, src, t_strdup_printf(
		"USER-WEAK\t%s\t%u\t%u\t%u\t%s\n",
		net_ip2addr(&orig_src->ip), orig_src->port, orig_src->last_seq,
		user->username_hash, net_ip2addr(&user->host->ip)));
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
	if (dir->right == NULL) {
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

static void director_state_callback_timeout(struct director *dir)
{
	timeout_remove(&dir->to_callback);
	dir->state_change_callback(dir);
}

void director_set_state_changed(struct director *dir)
{
	/* we may get called to here from various places. use a timeout to
	   make sure the state callback is called with a clean state. */
	if (dir->to_callback == NULL) {
		dir->to_callback =
			timeout_add(0, director_state_callback_timeout, dir);
	}
}

void director_update_send(struct director *dir, struct director_host *src,
			  const char *cmd)
{
	director_update_send_version(dir, src, 0, cmd);
}

void director_update_send_version(struct director *dir,
				  struct director_host *src,
				  unsigned int min_version, const char *cmd)
{
	struct director_connection *const *connp;

	i_assert(src != NULL);

	array_foreach(&dir->connections, connp) {
		if (director_connection_get_host(*connp) != src &&
		    director_connection_get_minor_version(*connp) >= min_version)
			director_connection_send(*connp, cmd);
	}
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
	i_array_init(&dir->connections, 8);
	dir->users = user_directory_init(set->director_user_expire,
					 set->director_username_hash);
	dir->mail_hosts = mail_hosts_init();

	dir->ipc_proxy = ipc_client_init(DIRECTOR_IPC_PROXY_PATH);
	dir->ring_min_version = DIRECTOR_VERSION_MINOR;
	return dir;
}

void director_deinit(struct director **_dir)
{
	struct director *dir = *_dir;
	struct director_host *const *hostp, *host;
	struct director_connection *conn, *const *connp;

	*_dir = NULL;

	while (array_count(&dir->connections) > 0) {
		connp = array_idx(&dir->connections, 0);
		conn = *connp;
		director_connection_deinit(&conn, "Shutting down");
	}

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
	if (dir->to_sync != NULL)
		timeout_remove(&dir->to_sync);
	if (dir->to_remove_dirs != NULL)
		timeout_remove(&dir->to_remove_dirs);
	if (dir->to_callback != NULL)
		timeout_remove(&dir->to_callback);
	while (array_count(&dir->dir_hosts) > 0) {
		hostp = array_idx(&dir->dir_hosts, 0);
		host = *hostp;
		director_host_free(&host);
	}
	array_free(&dir->pending_requests);
	array_free(&dir->dir_hosts);
	array_free(&dir->connections);
	i_free(dir);
}

void dir_debug(const char *fmt, ...)
{
	va_list args;

	if (!director_debug)
		return;

	va_start(args, fmt);
	T_BEGIN {
		i_debug("%s", t_strdup_vprintf(fmt, args));
	} T_END;
	va_end(args);
}
