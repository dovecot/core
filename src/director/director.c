/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "log-throttle.h"
#include "ipc-client.h"
#include "program-client.h"
#include "var-expand.h"
#include "istream.h"
#include "ostream.h"
#include "iostream-temp.h"
#include "mail-user-hash.h"
#include "user-directory.h"
#include "mail-host.h"
#include "director-host.h"
#include "director-connection.h"
#include "director.h"

#define DIRECTOR_IPC_PROXY_PATH "ipc"
#define DIRECTOR_RECONNECT_RETRY_SECS 60
#define DIRECTOR_RECONNECT_TIMEOUT_MSECS (30*1000)
#define DIRECTOR_USER_MOVE_TIMEOUT_MSECS (30*1000)
#define DIRECTOR_SYNC_TIMEOUT_MSECS (5*1000)
#define DIRECTOR_RING_MIN_WAIT_SECS 20
#define DIRECTOR_QUICK_RECONNECT_TIMEOUT_MSECS 1000
#define DIRECTOR_DELAYED_DIR_REMOVE_MSECS (1000*30)

bool director_debug;

const char *user_kill_state_names[USER_KILL_STATE_DELAY+1] = {
	"none",
	"killing",
	"notify-received",
	"waiting-for-notify",
	"waiting-for-everyone",
	"flushing",
	"delay",
};

static struct log_throttle *user_move_throttle;
static struct log_throttle *user_kill_fail_throttle;

static void director_hosts_purge_removed(struct director *dir);

static const struct log_throttle_settings director_log_throttle_settings = {
	.throttle_at_max_per_interval = 100,
	.unthrottle_at_max_per_interval = 2,
};

static void
director_user_kill_finish_delayed(struct director *dir, struct user *user,
				  bool skip_delay);

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

static void
director_log_connect(struct director *dir, struct director_host *host,
		     const char *reason)
{
	string_t *str = t_str_new(128);

	if (host->last_network_failure > 0) {
		str_printfa(str, ", last network failure %ds ago",
			    (int)(ioloop_time - host->last_network_failure));
	}
	if (host->last_protocol_failure > 0) {
		str_printfa(str, ", last protocol failure %ds ago",
			    (int)(ioloop_time - host->last_protocol_failure));
	}
	i_info("Connecting to %s:%u (as %s%s): %s",
	       host->ip_str, host->port,
	       net_ip2addr(&dir->self_ip), str_c(str), reason);
}

int director_connect_host(struct director *dir, struct director_host *host,
			  const char *reason)
{
	in_port_t port;
	int fd;

	if (director_has_outgoing_connection(dir, host))
		return 0;

	director_log_connect(dir, host, reason);
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

static void director_quick_reconnect_retry(struct director *dir)
{
	director_connect(dir, "Alone in director ring - trying to connect to others");
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
					director_quick_reconnect_retry, dir);
	return TRUE;
}

void director_connect(struct director *dir, const char *reason)
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

		if (director_connect_host(dir, hosts[idx], reason) == 0) {
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
	else if (!dir->ring_synced)
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
	} else if (cur_host != preferred_host) {
		(void)director_connect_host(dir, preferred_host,
			"Reconnect attempt to preferred director");
	} else {
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
		i_warning("Ring is synced, continuing delayed requests "
			  "(syncing took %d secs, hosts_hash=%u)",
			  (int)(ioloop_time - dir->ring_last_sync_time),
			  mail_hosts_hash(dir->mail_hosts));
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
	/* If there are any director hosts still marked as "removed", we can
	   safely remove those now. The entire director cluster knows about the
	   removal now. */
	director_hosts_purge_removed(dir);
	mail_hosts_set_synced(dir->mail_hosts);
	director_set_state_changed(dir);
}

void director_sync_send(struct director *dir, struct director_host *host,
			uint32_t seq, unsigned int minor_version,
			unsigned int timestamp, unsigned int hosts_hash)
{
	string_t *str;

	if (host == dir->self_host) {
		dir->last_sync_sent_ring_change_counter = dir->ring_change_counter;
		dir->last_sync_start_time = ioloop_timeval;
	}

	str = t_str_new(128);
	str_printfa(str, "SYNC\t%s\t%u\t%u",
		    host->ip_str, host->port, seq);
	if (minor_version > 0 &&
	    director_connection_get_minor_version(dir->right) > 0) {
		/* only minor_version>0 supports extra parameters */
		str_printfa(str, "\t%u\t%u\t%u", minor_version,
			    timestamp, hosts_hash);
	}
	str_append_c(str, '\n');
	director_connection_send(dir->right, str_c(str));

	/* ping our connections in case either of them are hanging.
	   if they are, we want to know it fast. */
	if (dir->left != NULL)
		director_connection_ping(dir->left);
	director_connection_ping(dir->right);
}

static bool
director_has_any_outgoing_connections(struct director *dir)
{
	struct director_connection *const *connp;

	array_foreach(&dir->connections, connp) {
		if (!director_connection_is_incoming(*connp))
			return TRUE;
	}
	return FALSE;
}

bool director_resend_sync(struct director *dir)
{
	if (dir->ring_synced) {
		/* everything ok, no need to do anything */
		return FALSE;
	}

	if (dir->right == NULL) {
		/* right side connection is missing. make sure we're not
		   hanging due to some bug. */
		if (dir->to_reconnect == NULL &&
		    !director_has_any_outgoing_connections(dir)) {
			i_warning("Right side connection is unexpectedly lost, reconnecting");
			director_connect(dir, "Right side connection lost");
		}
	} else if (dir->left != NULL) {
		/* send a new SYNC in case the previous one got dropped */
		dir->self_host->last_sync_timestamp = ioloop_time;
		director_sync_send(dir, dir->self_host, dir->sync_seq,
				   DIRECTOR_VERSION_MINOR, ioloop_time,
				   mail_hosts_hash(dir->mail_hosts));
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
		i_error("Ring SYNC seq=%u appears to have got lost, resending", dir->sync_seq);
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
		dir_debug("Ring is desynced (seq=%u, no right connection)",
			  dir->sync_seq);
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
			   DIRECTOR_VERSION_MINOR, ioloop_time,
			   mail_hosts_hash(dir->mail_hosts));
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
				struct director_host *src, bool log)
{
	const char *cmd;

	if (log) {
		i_info("Adding director %s to ring (requested by %s)",
		       added_host->name, src->name);
	}

	added_host->dir->ring_change_counter++;
	cmd = t_strdup_printf("DIRECTOR\t%s\t%u\n",
			      added_host->ip_str, added_host->port);
	director_update_send(added_host->dir, src, cmd);
}

static void director_hosts_purge_removed(struct director *dir)
{
	struct director_host *const *hosts, *host;
	unsigned int i, count;

	if (dir->to_remove_dirs != NULL)
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

	i_info("Removing director %s from ring (requested by %s)",
	       removed_host->name, src->name);

	if (removed_host->self && !src->self) {
		/* others will just disconnect us */
		return;
	}

	if (!removed_host->self) {
		/* mark the host as removed and fully remove it later. this
		   delay is needed, because the removal may trigger director
		   reconnections, which may send the director back and we don't
		   want to re-add it */
		removed_host->removed = TRUE;
		if (dir->to_remove_dirs == NULL) {
			dir->to_remove_dirs =
				timeout_add(DIRECTOR_DELAYED_DIR_REMOVE_MSECS,
					    director_hosts_purge_removed, dir);
		}
	}

	/* if our left or ride side gets removed, notify them first
	   before disconnecting. */
	cmd = t_strdup_printf("DIRECTOR-REMOVE\t%s\t%u\n",
			      removed_host->ip_str, removed_host->port);
	director_update_send_version(dir, src,
				     DIRECTOR_VERSION_RING_REMOVE, cmd);

	/* disconnect any connections to the host */
	conns = array_get(&dir->connections, &count);
	for (i = 0; i < count; ) {
		conn = conns[i];
		if (director_connection_get_host(conn) != removed_host ||
		    removed_host->self)
			i++;
		else {
			director_connection_deinit(&conn, "Removing from ring");
			conns = array_get(&dir->connections, &count);
		}
	}
	if (dir->right == NULL)
		director_connect(dir, "Reconnecting after director was removed");
	director_sync(dir);
}

static void
director_send_host(struct director *dir, struct director_host *src,
		   struct director_host *orig_src,
		   struct mail_host *host)
{
	const char *host_tag = mail_host_get_tag(host);
	string_t *str;

	if (orig_src == NULL) {
		orig_src = dir->self_host;
		orig_src->last_seq++;
	}

	str = t_str_new(128);
	str_printfa(str, "HOST\t%s\t%u\t%u\t%s\t%u",
		    orig_src->ip_str, orig_src->port, orig_src->last_seq,
		    host->ip_str, host->vhost_count);
	if (dir->ring_min_version >= DIRECTOR_VERSION_TAGS_V2) {
		str_append_c(str, '\t');
		str_append_tabescaped(str, host_tag);
	} else if (host_tag[0] != '\0' &&
		   dir->ring_min_version < DIRECTOR_VERSION_TAGS_V2) {
		if (dir->ring_min_version < DIRECTOR_VERSION_TAGS) {
			i_error("Ring has directors that don't support tags - removing host %s with tag '%s'",
				host->ip_str, host_tag);
		} else {
			i_error("Ring has directors that support mixed versions of tags - removing host %s with tag '%s'",
				host->ip_str, host_tag);
		}
		director_remove_host(dir, NULL, NULL, host);
		return;
	}
	if (dir->ring_min_version >= DIRECTOR_VERSION_UPDOWN) {
		str_printfa(str, "\t%c%ld\t", host->down ? 'D' : 'U',
			    (long)host->last_updown_change);
		/* add any further version checks here - these directors ignore
		   any extra unknown arguments */
		if (host->hostname != NULL)
			str_append_tabescaped(str, host->hostname);
	}
	str_append_c(str, '\n');
	director_update_send(dir, src, str_c(str));
}

void director_resend_hosts(struct director *dir)
{
	struct mail_host *const *hostp;

	array_foreach(mail_hosts_get(dir->mail_hosts), hostp)
		director_send_host(dir, dir->self_host, NULL, *hostp);
}

void director_update_host(struct director *dir, struct director_host *src,
			  struct director_host *orig_src,
			  struct mail_host *host)
{
	/* update state in case this is the first mail host being added */
	director_set_state_changed(dir);

	dir_debug("Updating host %s vhost_count=%u "
		  "down=%d last_updown_change=%ld (hosts_hash=%u)",
		  host->ip_str, host->vhost_count, host->down,
		  (long)host->last_updown_change,
		  mail_hosts_hash(dir->mail_hosts));

	director_send_host(dir, src, orig_src, host);

	/* mark the host desynced until ring is synced again. except if we're
	   alone in the ring that never happens. */
	if (dir->right != NULL || dir->left != NULL)
		host->desynced = TRUE;
	director_sync(dir);
}

void director_remove_host(struct director *dir, struct director_host *src,
			  struct director_host *orig_src,
			  struct mail_host *host)
{
	struct user_directory *users = host->tag->users;

	if (src != NULL) {
		if (orig_src == NULL) {
			orig_src = dir->self_host;
			orig_src->last_seq++;
		}

		director_update_send(dir, src, t_strdup_printf(
			"HOST-REMOVE\t%s\t%u\t%u\t%s\n",
			orig_src->ip_str, orig_src->port,
			orig_src->last_seq, host->ip_str));
	}

	user_directory_remove_host(users, host);
	mail_host_remove(host);
	director_sync(dir);
}

void director_flush_host(struct director *dir, struct director_host *src,
			 struct director_host *orig_src,
			 struct mail_host *host)
{
	struct user_directory *users = host->tag->users;

	if (orig_src == NULL) {
		orig_src = dir->self_host;
		orig_src->last_seq++;
	}

	director_update_send(dir, src, t_strdup_printf(
		"HOST-FLUSH\t%s\t%u\t%u\t%s\n",
		orig_src->ip_str, orig_src->port, orig_src->last_seq,
		host->ip_str));
	user_directory_remove_host(users, host);
	director_sync(dir);
}

void director_update_user(struct director *dir, struct director_host *src,
			  struct user *user)
{
	struct director_connection *const *connp;

	i_assert(src != NULL);
	i_assert(!user->weak);

	array_foreach(&dir->connections, connp) {
		if (director_connection_get_host(*connp) == src)
			continue;

		if (director_connection_get_minor_version(*connp) >= DIRECTOR_VERSION_USER_TIMESTAMP) {
			director_connection_send(*connp, t_strdup_printf(
				"USER\t%u\t%s\t%u\n", user->username_hash, user->host->ip_str,
				user->timestamp));
		} else {
			director_connection_send(*connp, t_strdup_printf(
				"USER\t%u\t%s\n", user->username_hash, user->host->ip_str));
		}
	}
}

void director_update_user_weak(struct director *dir, struct director_host *src,
			       struct director_connection *src_conn,
			       struct director_host *orig_src,
			       struct user *user)
{
	const char *cmd;

	i_assert(src != NULL);
	i_assert(user->weak);

	if (orig_src == NULL) {
		orig_src = dir->self_host;
		orig_src->last_seq++;
	}

	cmd = t_strdup_printf("USER-WEAK\t%s\t%u\t%u\t%u\t%s\n",
		orig_src->ip_str, orig_src->port, orig_src->last_seq,
		user->username_hash, user->host->ip_str);

	if (src != dir->self_host && dir->left != NULL && dir->right != NULL &&
	    director_connection_get_host(dir->left) ==
	    director_connection_get_host(dir->right)) {
		/* only two directors in this ring and we're forwarding
		   USER-WEAK from one director back to itself via another
		   so it sees we've received it. we can't use
		   director_update_send() for this, because it doesn't send
		   data back to the source. */
		if (dir->right == src_conn)
			director_connection_send(dir->left, cmd);
		else if (dir->left == src_conn)
			director_connection_send(dir->right, cmd);
		else
			i_unreached();
	} else {
		director_update_send(dir, src, cmd);
	}
}

static void
director_flush_user_continue(int result, struct director_kill_context *ctx)
{
	struct director *dir = ctx->dir;
	ctx->callback_pending = FALSE;

	struct user *user = user_directory_lookup(ctx->tag->users,
						  ctx->username_hash);

	if (result == 0) {
		struct istream *is = iostream_temp_finish(&ctx->reply, (size_t)-1);
		char *data;
		i_stream_set_return_partial_line(is, TRUE);
		data = i_stream_read_next_line(is);
		i_error("%s: Failed to flush user hash %u in host %s: %s",
			ctx->socket_path,
			ctx->username_hash,
			net_ip2addr(&ctx->host_ip),
			data == NULL ? "(no output to stdout)" : data);
		while((data = i_stream_read_next_line(is)) != NULL) {
			i_error("%s: Failed to flush user hash %u in host %s: %s",
				ctx->socket_path,
				ctx->username_hash,
				net_ip2addr(&ctx->host_ip), data);
		}
		i_stream_unref(&is);
	} else {
		o_stream_unref(&ctx->reply);
	}
	program_client_destroy(&ctx->pclient);

	if (!DIRECTOR_KILL_CONTEXT_IS_VALID(user, ctx)) {
		/* user was already freed - ignore */
		dir_debug("User %u freed while flushing, result=%d",
			  ctx->username_hash, result);
		i_assert(ctx->to_move == NULL);
		i_free(ctx);
	} else {
		/* ctx is freed later via user->kill_ctx */
		dir_debug("Flushing user %u finished, result=%d",
			  ctx->username_hash, result);
		director_user_kill_finish_delayed(dir, user, result == 1);
	}
}

static void
director_flush_user(struct director *dir, struct user *user)
{
	struct director_kill_context *ctx = user->kill_ctx;
	struct var_expand_table tab[] = {
		{ 'i', user->host->ip_str, "ip" },
		{ 'h', user->host->hostname, "host" },
		{ '\0', NULL, NULL }
	};

	/* Execute flush script, if set. Only the director that started the
	   user moving will call the flush script. Having each director do it
	   would be redundant since they're all supposed to be performing the
	   same flush task to the same backend.

	   Flushing is also not triggered if we're moving a user that we just
	   created due to the user move. This means that the user doesn't have
	   an old host, so we couldn't really even perform any flushing on the
	   backend. */
	if (*dir->set->director_flush_socket == '\0' ||
	    ctx->old_host_ip.family == 0 ||
	    !ctx->kill_is_self_initiated) {
		director_user_kill_finish_delayed(dir, user, FALSE);
		return;
	}

	ctx->host_ip = user->host->ip;

	string_t *s_sock = str_new(default_pool, 32);
	var_expand(s_sock, dir->set->director_flush_socket, tab);
	ctx->socket_path = str_free_without_data(&s_sock);

	const char *error;
	struct program_client_settings set = {
		.client_connect_timeout_msecs = 10000,
	};

	restrict_access_init(&set.restrict_set);

	const char *const args[] = {
		"FLUSH",
		t_strdup_printf("%u", user->username_hash),
		net_ip2addr(&ctx->old_host_ip),
		user->host->ip_str,
		ctx->old_host_down ? "down" : "up",
		dec2str(ctx->old_host_vhost_count),
		NULL
	};

	ctx->kill_state = USER_KILL_STATE_FLUSHING;
	dir_debug("Flushing user %u via %s", user->username_hash,
		  ctx->socket_path);

	if ((program_client_create(ctx->socket_path, args, &set, FALSE,
				   &ctx->pclient, &error)) != 0) {
		i_error("%s: Failed to flush user hash %u in host %s: %s",
			ctx->socket_path,
			user->username_hash,
			user->host->ip_str,
			error);
		director_flush_user_continue(0, ctx);
		return;
	}

	ctx->reply =
		iostream_temp_create_named("/tmp", 0,
					   t_strdup_printf("flush response from %s",
							   user->host->ip_str));
	o_stream_set_no_error_handling(ctx->reply, TRUE);
	program_client_set_output(ctx->pclient, ctx->reply);
	ctx->callback_pending = TRUE;
	program_client_run_async(ctx->pclient, director_flush_user_continue, ctx);
}

static void director_user_move_finished(struct director *dir)
{
	i_assert(dir->users_moving_count > 0);
	dir->users_moving_count--;

	director_set_state_changed(dir);
}

static void director_user_move_free(struct user *user)
{
	struct director *dir = user->kill_ctx->dir;
	struct director_kill_context *kill_ctx = user->kill_ctx;

	i_assert(kill_ctx != NULL);

	dir_debug("User %u move finished at state=%s", user->username_hash,
		  user_kill_state_names[kill_ctx->kill_state]);

	if (kill_ctx->ipc_cmd != NULL)
		ipc_client_cmd_abort(dir->ipc_proxy, &kill_ctx->ipc_cmd);
	if (kill_ctx->to_move != NULL)
		timeout_remove(&kill_ctx->to_move);
	i_free(kill_ctx->socket_path);
	i_free(kill_ctx);
	user->kill_ctx = NULL;

	director_user_move_finished(dir);
}

static void
director_user_kill_finish_delayed_to(struct user *user)
{
	i_assert(user->kill_ctx != NULL);
	i_assert(user->kill_ctx->kill_state == USER_KILL_STATE_DELAY);

	director_user_move_free(user);
}

static void
director_user_kill_finish_delayed(struct director *dir, struct user *user,
				  bool skip_delay)
{
	if (skip_delay) {
		user->kill_ctx->kill_state = USER_KILL_STATE_NONE;
		director_user_move_free(user);
		return;
	}

	user->kill_ctx->kill_state = USER_KILL_STATE_DELAY;

	/* wait for a while for the kills to finish in the backend server,
	   so there are no longer any processes running for the user before we
	   start letting new in connections to the new server. */
	timeout_remove(&user->kill_ctx->to_move);
	user->kill_ctx->to_move =
		timeout_add(dir->set->director_user_kick_delay * 1000,
			    director_user_kill_finish_delayed_to, user);
}

static void
director_finish_user_kill(struct director *dir, struct user *user, bool self)
{
	struct director_kill_context *kill_ctx = user->kill_ctx;

	i_assert(kill_ctx != NULL);
	i_assert(kill_ctx->kill_state != USER_KILL_STATE_FLUSHING);
	i_assert(kill_ctx->kill_state != USER_KILL_STATE_DELAY);

	dir_debug("User %u kill finished - %sstate=%s", user->username_hash,
		  self ? "we started it " : "",
		  user_kill_state_names[kill_ctx->kill_state]);

	if (dir->right == NULL) {
		/* we're alone */
		director_flush_user(dir, user);
	} else if (self ||
		   kill_ctx->kill_state == USER_KILL_STATE_KILLING_NOTIFY_RECEIVED) {
		director_connection_send(dir->right, t_strdup_printf(
			"USER-KILLED\t%u\n", user->username_hash));
		kill_ctx->kill_state = USER_KILL_STATE_KILLED_WAITING_FOR_EVERYONE;
	} else {
		i_assert(kill_ctx->kill_state == USER_KILL_STATE_KILLING);
		kill_ctx->kill_state = USER_KILL_STATE_KILLED_WAITING_FOR_NOTIFY;
	}
}

static void director_user_kill_fail_throttled(unsigned int new_events_count,
					      void *context ATTR_UNUSED)
{
	i_error("Failed to kill %u users' connections", new_events_count);
}

static void director_kill_user_callback(enum ipc_client_cmd_state state,
					const char *data, void *context)
{
	struct director_kill_context *ctx = context;
	struct user *user;

	/* don't try to abort the IPC command anymore */
	ctx->ipc_cmd = NULL;

	/* this is an asynchronous notification about user being killed.
	   there are no guarantees about what might have happened to the user
	   in the mean time. */
	switch (state) {
	case IPC_CLIENT_CMD_STATE_REPLY:
		/* shouldn't get here. the command reply isn't finished yet. */
		i_error("login process sent unexpected reply to kick: %s", data);
		return;
	case IPC_CLIENT_CMD_STATE_OK:
		break;
	case IPC_CLIENT_CMD_STATE_ERROR:
		if (log_throttle_accept(user_kill_fail_throttle)) {
			i_error("Failed to kill user %u connections: %s",
				ctx->username_hash, data);
		}
		/* we can't really do anything but continue anyway */
		break;
	}

	i_assert(ctx->dir->users_kicking_count > 0);
	ctx->dir->users_kicking_count--;
	if (ctx->dir->kick_callback != NULL)
		ctx->dir->kick_callback(ctx->dir);

	user = user_directory_lookup(ctx->tag->users, ctx->username_hash);
	if (!DIRECTOR_KILL_CONTEXT_IS_VALID(user, ctx)) {
		/* user was already freed - ignore */
		i_assert(ctx->to_move == NULL);
		director_user_move_finished(ctx->dir);
		i_free(ctx);
	} else {
		i_assert(ctx->kill_state == USER_KILL_STATE_KILLING ||
			 ctx->kill_state == USER_KILL_STATE_KILLING_NOTIFY_RECEIVED);
		/* we were still waiting for the kill notification */
		director_finish_user_kill(ctx->dir, user, ctx->kill_is_self_initiated);
	}
}

static void director_user_move_throttled(unsigned int new_events_count,
					 void *context ATTR_UNUSED)
{
	i_error("%u users' move timed out, their state may now be inconsistent",
		new_events_count);
}

static void director_user_move_timeout(struct user *user)
{
	i_assert(user->kill_ctx != NULL);
	i_assert(user->kill_ctx->kill_state != USER_KILL_STATE_DELAY);

	if (log_throttle_accept(user_move_throttle)) {
		i_error("Finishing user %u move timed out, "
			"its state may now be inconsistent (state=%s)",
			user->username_hash,
			user_kill_state_names[user->kill_ctx->kill_state]);
	}
	if (user->kill_ctx->kill_state == USER_KILL_STATE_FLUSHING) {
		o_stream_unref(&user->kill_ctx->reply);
		program_client_destroy(&user->kill_ctx->pclient);
	}
	director_user_move_free(user);
}

void director_kill_user(struct director *dir, struct director_host *src,
			struct user *user, struct mail_tag *tag,
			struct mail_host *old_host, bool forced_kick)
{
	struct director_kill_context *ctx;
	const char *cmd;

	if (USER_IS_BEING_KILLED(user)) {
		/* User is being moved again before the previous move
		   finished. We'll just continue wherever we left off
		   earlier. */
		dir_debug("User %u move restarted - previous kill_state=%s",
			  user->username_hash,
			  user_kill_state_names[user->kill_ctx->kill_state]);
		return;
	}

	user->kill_ctx = ctx = i_new(struct director_kill_context, 1);
	ctx->dir = dir;
	ctx->tag = tag;
	ctx->username_hash = user->username_hash;
	ctx->kill_is_self_initiated = src->self;
	if (old_host != NULL) {
		ctx->old_host_ip = old_host->ip;
		ctx->old_host_down = old_host->down;
		ctx->old_host_vhost_count = old_host->vhost_count;
	}

	dir->users_moving_count++;
	ctx->to_move = timeout_add(DIRECTOR_USER_MOVE_TIMEOUT_MSECS,
				   director_user_move_timeout, user);
	ctx->kill_state = USER_KILL_STATE_KILLING;

	if ((old_host != NULL && old_host != user->host) || forced_kick) {
		cmd = t_strdup_printf("proxy\t*\tKICK-DIRECTOR-HASH\t%u",
				      user->username_hash);
		dir->users_kicking_count++;
		ctx->ipc_cmd = ipc_client_cmd(dir->ipc_proxy, cmd,
					      director_kill_user_callback, ctx);
	} else {
		/* a) we didn't even know about the user before now.
		   don't bother performing a local kick, since it wouldn't
		   kick anything.
		   b) our host was already correct. notify others that we have
		   killed the user, but don't really do it. */
		director_finish_user_kill(ctx->dir, user,
					  ctx->kill_is_self_initiated);
	}
}

void director_move_user(struct director *dir, struct director_host *src,
			struct director_host *orig_src,
			unsigned int username_hash, struct mail_host *host)
{
	struct user_directory *users = host->tag->users;
	struct mail_host *old_host = NULL;
	struct user *user;

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
	user = user_directory_lookup(users, username_hash);
	if (user == NULL) {
		dir_debug("User %u move started: User was nonexistent",
			  username_hash);
		user = user_directory_add(users, username_hash,
					  host, ioloop_time);
	} else if (user->host == host) {
		/* User is already in the wanted host, but another director
		   didn't think so. We'll need to finish the move without
		   killing any of our connections. */
		old_host = user->host;
		user->timestamp = ioloop_time;
		dir_debug("User %u move forwarded: host is already %s",
			  username_hash, host->ip_str);
	} else {
		/* user is looked up via the new host's tag, so if it's found
		   the old tag has to be the same. */
		i_assert(user->host->tag == host->tag);

		old_host = user->host;
		user->host->user_count--;
		user->host = host;
		user->host->user_count++;
		user->timestamp = ioloop_time;
		dir_debug("User %u move started: host %s -> %s",
			  username_hash, old_host->ip_str,
			  host->ip_str);
	}

	if (orig_src == NULL) {
		orig_src = dir->self_host;
		orig_src->last_seq++;
	}
	director_update_send(dir, src, t_strdup_printf(
		"USER-MOVE\t%s\t%u\t%u\t%u\t%s\n",
		orig_src->ip_str, orig_src->port, orig_src->last_seq,
		user->username_hash, user->host->ip_str));
	/* kill the user only after sending the USER-MOVE, because the kill
	   may finish instantly. */
	director_kill_user(dir, src, user, host->tag, old_host, FALSE);
}

static void
director_kick_user_callback(enum ipc_client_cmd_state state,
			    const char *data, void *context)
{
	struct director *dir = context;

	if (state == IPC_CLIENT_CMD_STATE_REPLY) {
		/* shouldn't get here. the command reply isn't finished yet. */
		i_error("login process sent unexpected reply to kick: %s", data);
		return;
	}

	i_assert(dir->users_kicking_count > 0);
	dir->users_kicking_count--;
	if (dir->kick_callback != NULL)
		dir->kick_callback(dir);
}

void director_kick_user(struct director *dir, struct director_host *src,
			struct director_host *orig_src, const char *username)
{
	string_t *cmd = t_str_new(64);

	str_append(cmd, "proxy\t*\tKICK\t");
	str_append_tabescaped(cmd, username);
	dir->users_kicking_count++;
	ipc_client_cmd(dir->ipc_proxy, str_c(cmd),
		       director_kick_user_callback, dir);

	if (orig_src == NULL) {
		orig_src = dir->self_host;
		orig_src->last_seq++;
	}
	str_truncate(cmd, 0);
	str_printfa(cmd, "USER-KICK\t%s\t%u\t%u\t",
		orig_src->ip_str, orig_src->port, orig_src->last_seq);
	str_append_tabescaped(cmd, username);
	str_append_c(cmd, '\n');
	director_update_send_version(dir, src, DIRECTOR_VERSION_USER_KICK, str_c(cmd));
}

void director_kick_user_alt(struct director *dir, struct director_host *src,
			    struct director_host *orig_src,
			    const char *field, const char *value)
{
	string_t *cmd = t_str_new(64);

	str_append(cmd, "proxy\t*\tKICK-ALT\t");
	str_append_tabescaped(cmd, field);
	str_append_c(cmd, '\t');
	str_append_tabescaped(cmd, value);
	dir->users_kicking_count++;
	ipc_client_cmd(dir->ipc_proxy, str_c(cmd),
		       director_kick_user_callback, dir);

	if (orig_src == NULL) {
		orig_src = dir->self_host;
		orig_src->last_seq++;
	}
	str_truncate(cmd, 0);
	str_printfa(cmd, "USER-KICK-ALT\t%s\t%u\t%u\t",
		orig_src->ip_str, orig_src->port, orig_src->last_seq);
	str_append_tabescaped(cmd, field);
	str_append_c(cmd, '\t');
	str_append_tabescaped(cmd, value);
	str_append_c(cmd, '\n');
	director_update_send_version(dir, src, DIRECTOR_VERSION_USER_KICK_ALT, str_c(cmd));
}

void director_kick_user_hash(struct director *dir, struct director_host *src,
			     struct director_host *orig_src,
			     unsigned int username_hash,
			     const struct ip_addr *except_ip)
{
	const char *cmd;

	cmd = t_strdup_printf("proxy\t*\tKICK-DIRECTOR-HASH\t%u\t%s",
			      username_hash, net_ip2addr(except_ip));
	dir->users_kicking_count++;
	ipc_client_cmd(dir->ipc_proxy, cmd,
		       director_kick_user_callback, dir);

	if (orig_src == NULL) {
		orig_src = dir->self_host;
		orig_src->last_seq++;
	}
	cmd = t_strdup_printf("USER-KICK-HASH\t%s\t%u\t%u\t%u\t%s\n",
		orig_src->ip_str, orig_src->port, orig_src->last_seq,
		username_hash, net_ip2addr(except_ip));
	director_update_send_version(dir, src, DIRECTOR_VERSION_USER_KICK, cmd);
}

static void
director_send_user_killed_everywhere(struct director *dir,
				     struct director_host *src,
				     struct director_host *orig_src,
				     unsigned int username_hash)
{
	if (orig_src == NULL) {
		orig_src = dir->self_host;
		orig_src->last_seq++;
	}
	director_update_send(dir, src, t_strdup_printf(
		"USER-KILLED-EVERYWHERE\t%s\t%u\t%u\t%u\n",
		orig_src->ip_str, orig_src->port, orig_src->last_seq,
		username_hash));
}

static void
director_user_tag_killed(struct director *dir, struct mail_tag *tag,
			 unsigned int username_hash)
{
	struct user *user;

	user = user_directory_lookup(tag->users, username_hash);
	if (user == NULL || !USER_IS_BEING_KILLED(user))
		return;

	switch (user->kill_ctx->kill_state) {
	case USER_KILL_STATE_KILLING:
		user->kill_ctx->kill_state = USER_KILL_STATE_KILLING_NOTIFY_RECEIVED;
		break;
	case USER_KILL_STATE_KILLED_WAITING_FOR_NOTIFY:
		director_finish_user_kill(dir, user, TRUE);
		break;
	case USER_KILL_STATE_KILLING_NOTIFY_RECEIVED:
		dir_debug("User %u kill_state=%s - ignoring USER-KILLED",
			  username_hash, user_kill_state_names[user->kill_ctx->kill_state]);
		break;
	case USER_KILL_STATE_NONE:
	case USER_KILL_STATE_FLUSHING:
	case USER_KILL_STATE_DELAY:
		/* move restarted. state=none can also happen if USER-MOVE was
		   sent while we were still moving. send back
		   USER-KILLED-EVERYWHERE to avoid hangs. */
		director_send_user_killed_everywhere(dir, dir->self_host, NULL,
						     username_hash);
		break;
	case USER_KILL_STATE_KILLED_WAITING_FOR_EVERYONE:
		director_user_killed_everywhere(dir, dir->self_host,
						NULL, username_hash);
		break;
	}
}

void director_user_killed(struct director *dir, unsigned int username_hash)
{
	struct mail_tag *const *tagp;

	array_foreach(mail_hosts_get_tags(dir->mail_hosts), tagp)
		director_user_tag_killed(dir, *tagp, username_hash);
}

static void
director_user_tag_killed_everywhere(struct director *dir,
				    struct mail_tag *tag,
				    struct director_host *src,
				    struct director_host *orig_src,
				    unsigned int username_hash)
{
	struct user *user;

	user = user_directory_lookup(tag->users, username_hash);
	if (user == NULL) {
		dir_debug("User %u no longer exists - ignoring USER-KILLED-EVERYWHERE",
			  username_hash);
		return;
	}
	if (!USER_IS_BEING_KILLED(user)) {
		dir_debug("User %u is no longer being killed - ignoring USER-KILLED-EVERYWHERE",
			  username_hash);
		return;
	}
	if (user->kill_ctx->kill_state != USER_KILL_STATE_KILLED_WAITING_FOR_EVERYONE) {
		dir_debug("User %u kill_state=%s - ignoring USER-KILLED-EVERYWHERE",
			  username_hash, user_kill_state_names[user->kill_ctx->kill_state]);
		return;
	}

	director_flush_user(dir, user);
	director_send_user_killed_everywhere(dir, src, orig_src, username_hash);
}

void director_user_killed_everywhere(struct director *dir,
				     struct director_host *src,
				     struct director_host *orig_src,
				     unsigned int username_hash)
{
	struct mail_tag *const *tagp;

	array_foreach(mail_hosts_get_tags(dir->mail_hosts), tagp) {
		director_user_tag_killed_everywhere(dir, *tagp, src, orig_src,
						    username_hash);
	}
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

static void director_user_freed(struct user *user)
{
	if (user->kill_ctx != NULL) {
		/* director_user_expire is very short. user expired before
		   moving the user finished or timed out. */
		if (user->kill_ctx->callback_pending) {
			/* kill_ctx is used as a callback parameter.
			   only remove the timeout and finish the free later. */
			if (user->kill_ctx->to_move != NULL)
				timeout_remove(&user->kill_ctx->to_move);
		} else {
			director_user_move_free(user);
		}
	}
}

struct director *
director_init(const struct director_settings *set,
	      const struct ip_addr *listen_ip, in_port_t listen_port,
	      director_state_change_callback_t *callback,
	      director_kick_callback_t *kick_callback)
{
	struct director *dir;

	dir = i_new(struct director, 1);
	dir->set = set;
	dir->self_port = listen_port;
	dir->self_ip = *listen_ip;
	dir->state_change_callback = callback;
	dir->kick_callback = kick_callback;
	i_array_init(&dir->dir_hosts, 16);
	i_array_init(&dir->pending_requests, 16);
	i_array_init(&dir->connections, 8);
	dir->mail_hosts = mail_hosts_init(set->director_user_expire,
					  set->director_consistent_hashing,
					  director_user_freed);

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

struct director_user_iter {
	struct director *dir;
	unsigned int tag_idx;
	struct user_directory_iter *user_iter;
	bool iter_until_current_tail;
};

struct director_user_iter *
director_iterate_users_init(struct director *dir, bool iter_until_current_tail)
{
	struct director_user_iter *iter = i_new(struct director_user_iter, 1);
	iter->dir = dir;
	iter->iter_until_current_tail = iter_until_current_tail;
	return iter;
}

struct user *director_iterate_users_next(struct director_user_iter *iter)
{
	const ARRAY_TYPE(mail_tag) *tags;
	struct user *user;

	i_assert(iter != NULL);

	if (iter->user_iter == NULL) {
		tags = mail_hosts_get_tags(iter->dir->mail_hosts);
		if (iter->tag_idx >= array_count(tags))
			return NULL;
		struct mail_tag *const *tagp = array_idx(tags, iter->tag_idx);
		iter->user_iter = user_directory_iter_init((*tagp)->users,
			iter->iter_until_current_tail);
	}
	user = user_directory_iter_next(iter->user_iter);
	if (user == NULL) {
		user_directory_iter_deinit(&iter->user_iter);
		iter->tag_idx++;
		return director_iterate_users_next(iter);
	} else
		return user;
}

void director_iterate_users_deinit(struct director_user_iter **_iter)
{
	i_assert(_iter != NULL && *_iter != NULL);
	struct director_user_iter *iter = *_iter;
	*_iter = NULL;
	if (iter->user_iter != NULL)
		user_directory_iter_deinit(&iter->user_iter);
	i_free(iter);
}

unsigned int
director_get_username_hash(struct director *dir, const char *username)
{
	return mail_user_hash(username, dir->set->director_username_hash);
}

void directors_init(void)
{
	user_move_throttle =
		log_throttle_init(&director_log_throttle_settings,
				  director_user_move_throttled, NULL);
	user_kill_fail_throttle =
		log_throttle_init(&director_log_throttle_settings,
				  director_user_kill_fail_throttled, NULL);
}

void directors_deinit(void)
{
	log_throttle_deinit(&user_move_throttle);
	log_throttle_deinit(&user_kill_fail_throttle);
}
