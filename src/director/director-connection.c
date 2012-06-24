/* Copyright (c) 2010-2012 Dovecot authors, see the included COPYING file */

/*
   Handshaking:

   Incoming director connections send:

   VERSION
   ME
   <wait for DONE from remote handshake>
   DONE
   <make this connection our "left" connection, potentially disconnecting
   another one>

   Outgoing director connections send:

   VERSION
   ME
   [0..n] DIRECTOR
   HOST-HAND-START
   [0..n] HOST
   HOST-HAND-END
   [0..n] USER
   <possibly other non-handshake commands between USERs>
   DONE
   <wait for DONE from remote>
   <make this connection our "right" connection, potentially disconnecting
   another one>
*/

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "master-service.h"
#include "mail-host.h"
#include "director.h"
#include "director-host.h"
#include "director-request.h"
#include "user-directory.h"
#include "director-connection.h"

#include <stdlib.h>
#include <unistd.h>

#define MAX_INBUF_SIZE 1024
#define MAX_OUTBUF_SIZE (1024*1024*10)
#define OUTBUF_FLUSH_THRESHOLD (1024*128)
/* Max idling time before "ME" command must have been received,
   or we'll disconnect. */
#define DIRECTOR_CONNECTION_ME_TIMEOUT_MSECS (10*1000)
/* Max time to wait for USERs in handshake to be sent. With a lot of users the
   kernel may quickly eat up everything we send, while the receiver is busy
   parsing the data. */
#define DIRECTOR_CONNECTION_SEND_USERS_TIMEOUT_MSECS (30*1000)
/* Max idling time before "DONE" command must have been received,
   or we'll disconnect. */
#define DIRECTOR_CONNECTION_DONE_TIMEOUT_MSECS (30*1000)
/* How long to wait for PONG for an idling connection */
#define DIRECTOR_CONNECTION_PING_IDLE_TIMEOUT_MSECS (10*1000)
/* Maximum time to wait for PONG reply */
#define DIRECTOR_CONNECTION_PONG_TIMEOUT_MSECS (60*1000)
/* How long to wait to send PING when connection is idle */
#define DIRECTOR_CONNECTION_PING_INTERVAL_MSECS (15*1000)
/* How long to wait before sending PING while waiting for SYNC reply */
#define DIRECTOR_CONNECTION_PING_SYNC_INTERVAL_MSECS 1000
/* If outgoing director connection exists for less than this many seconds,
   mark the host as failed so we won't try to reconnect to it immediately */
#define DIRECTOR_SUCCESS_MIN_CONNECT_SECS 40
#define DIRECTOR_WAIT_DISCONNECT_SECS 10

#if DIRECTOR_CONNECTION_DONE_TIMEOUT_MSECS <= DIRECTOR_CONNECTION_PING_TIMEOUT_MSECS
#  error DIRECTOR_CONNECTION_DONE_TIMEOUT_MSECS is too low
#endif

#if DIRECTOR_CONNECTION_PONG_TIMEOUT_MSECS <= DIRECTOR_CONNECTION_PING_IDLE_TIMEOUT_MSECS
#  error DIRECTOR_CONNECTION_PONG_TIMEOUT_MSECS is too low
#endif

#define CMD_IS_USER_HANDHAKE(args) \
	(str_array_length(args) > 2)

struct director_connection {
	struct director *dir;
	char *name;
	time_t created;
	unsigned int minor_version;

	/* for incoming connections the director host isn't known until
	   ME-line is received */
	struct director_host *host;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;
	struct timeout *to_disconnect, *to_ping, *to_pong;

	struct user_directory_iter *user_iter;

	/* set during command execution */
	const char *cur_cmd, *cur_line;

	unsigned int in:1;
	unsigned int connected:1;
	unsigned int version_received:1;
	unsigned int me_received:1;
	unsigned int handshake_received:1;
	unsigned int ignore_host_events:1;
	unsigned int handshake_sending_hosts:1;
	unsigned int ping_waiting:1;
	unsigned int synced:1;
	unsigned int wrong_host:1;
	unsigned int verifying_left:1;
};

static void director_connection_disconnected(struct director_connection **conn);
static void director_connection_reconnect(struct director_connection **conn);

static void ATTR_FORMAT(2, 3)
director_cmd_error(struct director_connection *conn, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	i_error("director(%s): Command %s: %s (input: %s)", conn->name,
		conn->cur_cmd, t_strdup_vprintf(fmt, args), conn->cur_line);
	va_end(args);

	conn->host->last_protocol_failure = ioloop_time;
}

static void
director_connection_init_timeout(struct director_connection *conn)
{
	unsigned int secs = ioloop_time - conn->created;

	if (!conn->connected) {
		i_error("director(%s): Connect timed out (%u secs)",
			conn->name, secs);
	} else if (conn->io == NULL) {
		i_error("director(%s): Sending handshake (%u secs)",
			conn->name, secs);
	} else if (!conn->me_received) {
		i_error("director(%s): Handshaking ME timed out (%u secs)",
			conn->name, secs);
	} else {
		i_error("director(%s): Handshaking DONE timed out (%u secs)",
			conn->name, secs);
	}
	director_connection_disconnected(&conn);
}

static void
director_connection_set_ping_timeout(struct director_connection *conn)
{
	unsigned int msecs;

	msecs = conn->synced || !conn->handshake_received ?
		DIRECTOR_CONNECTION_PING_INTERVAL_MSECS :
		DIRECTOR_CONNECTION_PING_SYNC_INTERVAL_MSECS;

	timeout_remove(&conn->to_ping);
	conn->to_ping = timeout_add(msecs, director_connection_ping, conn);
}

static void director_connection_wait_timeout(struct director_connection *conn)
{
	director_connection_deinit(&conn);
}

static void director_connection_send_connect(struct director_connection *conn,
					     struct director_host *host)
{
	const char *connect_str;

	if (conn->to_disconnect != NULL)
		return;

	connect_str = t_strdup_printf("CONNECT\t%s\t%u\n",
				      net_ip2addr(&host->ip), host->port);
	director_connection_send(conn, connect_str);
	(void)o_stream_flush(conn->output);
	o_stream_uncork(conn->output);

	conn->to_disconnect =
		timeout_add(DIRECTOR_WAIT_DISCONNECT_SECS*1000,
			    director_connection_wait_timeout, conn);
}

static void director_connection_assigned(struct director_connection *conn)
{
	struct director *dir = conn->dir;

	if (dir->left != NULL && dir->right != NULL) {
		/* we're connected to both directors. see if the ring is
		   finished by sending a SYNC. if we get it back, it's done. */
		dir->sync_seq++;
		director_set_ring_unsynced(dir);
		director_sync_send(dir, dir->self_host, dir->sync_seq,
				   DIRECTOR_VERSION_MINOR);
	}
	director_connection_set_ping_timeout(conn);
}

static bool director_connection_assign_left(struct director_connection *conn)
{
	struct director *dir = conn->dir;

	i_assert(conn->in);
	i_assert(dir->left != conn);

	/* make sure this is the correct incoming connection */
	if (conn->host->self) {
		i_error("Connection from self, dropping");
		return FALSE;
	} else if (dir->left == NULL) {
		/* no conflicts yet */
	} else if (dir->left->host == conn->host) {
		i_info("Dropping existing connection %s "
		       "in favor of its new connection %s",
		       dir->left->host->name, conn->host->name);
		director_connection_deinit(&dir->left);
	} else if (dir->left->verifying_left) {
		/* we're waiting to verify if our current left is still
		   working. if we don't receive a PONG, the current left
		   gets disconnected and a new left gets assigned. if we do
		   receive a PONG, we'll wait until the current left
		   disconnects us and then reassign the new left. */
		return TRUE;
	} else if (director_host_cmp_to_self(dir->left->host, conn->host,
					     dir->self_host) < 0) {
		/* the old connection is the correct one.
		   refer the client there (FIXME: do we ever get here?) */
		i_warning("Director connection %s tried to connect to "
			  "us, should use %s instead",
			  conn->name, dir->left->host->name);
		director_connection_send_connect(conn, dir->left->host);
		return TRUE;
	} else {
		/* this new connection is the correct one, but wait until the
		   old connection gets disconnected before using this one.
		   that guarantees that the director inserting itself into
		   the ring has finished handshaking its left side, so the
		   switch will be fast. */
		return TRUE;
	}
	dir->left = conn;
	i_free(conn->name);
	conn->name = i_strdup_printf("%s/left", conn->host->name);
	director_connection_assigned(conn);
	return TRUE;
}

static void director_assign_left(struct director *dir)
{
	struct director_connection *conn, *const *connp;

	array_foreach(&dir->connections, connp) {
		conn = *connp;

		if (conn->in && conn->handshake_received &&
		    conn->to_disconnect == NULL && conn != dir->left) {
			/* either use this or disconnect it */
			if (!director_connection_assign_left(conn)) {
				/* we don't want this */
				director_connection_deinit(&conn);
				director_assign_left(dir);
				break;
			}
		}
	}
}

static bool director_has_outgoing_connections(struct director *dir)
{
	struct director_connection *const *connp;

	array_foreach(&dir->connections, connp) {
		if (!(*connp)->in && (*connp)->to_disconnect == NULL)
			return TRUE;
	}
	return FALSE;
}

static bool director_connection_assign_right(struct director_connection *conn)
{
	struct director *dir = conn->dir;

	i_assert(!conn->in);

	if (dir->right != NULL) {
		/* see if we should disconnect or keep the existing
		   connection. */
		if (director_host_cmp_to_self(conn->host, dir->right->host,
					      dir->self_host) <= 0) {
			/* the old connection is the correct one */
			i_warning("Aborting incorrect outgoing connection to %s "
				  "(already connected to correct one: %s)",
				  conn->host->name, dir->right->host->name);
			conn->wrong_host = TRUE;
			return FALSE;
		}
		i_info("Replacing right director connection %s with %s",
		       dir->right->host->name, conn->host->name);
		director_connection_deinit(&dir->right);
	}
	dir->right = conn;
	i_free(conn->name);
	conn->name = i_strdup_printf("%s/right", conn->host->name);
	director_connection_assigned(conn);
	return TRUE;
}

static bool
director_args_parse_ip_port(struct director_connection *conn,
			    const char *const *args,
			    struct ip_addr *ip_r, unsigned int *port_r)
{
	if (args[0] == NULL || args[1] == NULL) {
		director_cmd_error(conn, "Missing IP+port parameters");
		return FALSE;
	}
	if (net_addr2ip(args[0], ip_r) < 0) {
		director_cmd_error(conn, "Invalid IP address: %s", args[0]);
		return FALSE;
	}
	if (str_to_uint(args[1], port_r) < 0) {
		director_cmd_error(conn, "Invalid port: %s", args[1]);
		return FALSE;
	}
	return TRUE;
}

static bool director_cmd_me(struct director_connection *conn,
			    const char *const *args)
{
	struct director *dir = conn->dir;
	const char *connect_str;
	struct ip_addr ip;
	unsigned int port;
	time_t next_comm_attempt;

	if (!director_args_parse_ip_port(conn, args, &ip, &port))
		return FALSE;
	if (conn->me_received) {
		director_cmd_error(conn, "Duplicate ME");
		return FALSE;
	}

	if (!conn->in && (!net_ip_compare(&conn->host->ip, &ip) ||
			  conn->host->port != port)) {
		i_error("Remote director thinks it's someone else "
			"(connected to %s:%u, remote says it's %s:%u)",
			net_ip2addr(&conn->host->ip), conn->host->port,
			net_ip2addr(&ip), port);
		return FALSE;
	}
	conn->me_received = TRUE;

	timeout_remove(&conn->to_ping);
	conn->to_ping = timeout_add(DIRECTOR_CONNECTION_DONE_TIMEOUT_MSECS,
				    director_connection_init_timeout, conn);

	if (!conn->in)
		return TRUE;

	/* Incoming connection:

	   a) we don't have an established ring yet. make sure we're connecting
	   to our right side (which might become our left side).

	   b) it's our current "left" connection. the previous connection
	   is most likely dead.

	   c) we have an existing ring. tell our current "left" to connect to
	   it with CONNECT command.

	   d) the incoming connection doesn't belong to us at all, refer it
	   elsewhere with CONNECT. however, before disconnecting it verify
	   first that our left side is actually still functional.
	*/
	i_assert(conn->host == NULL);
	conn->host = director_host_get(dir, &ip, port);
	/* the host shouldn't be removed at this point, but if for some
	   reason it is we don't want to crash */
	conn->host->removed = FALSE;
	director_host_ref(conn->host);
	/* make sure we don't keep old sequence values across restarts */
	conn->host->last_seq = 0;

	next_comm_attempt = conn->host->last_protocol_failure +
		DIRECTOR_PROTOCOL_FAILURE_RETRY_SECS;
	if (next_comm_attempt > ioloop_time) {
		/* the director recently sent invalid protocol data,
		   don't try retrying yet */
		i_error("director(%s): Remote sent invalid protocol data recently, "
			"waiting %u secs before allowing further communication",
			conn->name, (unsigned int)(next_comm_attempt-ioloop_time));
		return FALSE;
	} else if (dir->left == NULL) {
		/* a) - just in case the left is also our right side reset
		   its failed state, so we can connect to it */
		conn->host->last_network_failure = 0;
		if (!director_has_outgoing_connections(dir))
			director_connect(dir);
	} else if (dir->left->host == conn->host) {
		/* b) */
		i_assert(dir->left != conn);
		director_connection_deinit(&dir->left);
	} else if (director_host_cmp_to_self(conn->host, dir->left->host,
					     dir->self_host) < 0) {
		/* c) */
		connect_str = t_strdup_printf("CONNECT\t%s\t%u\n",
					      net_ip2addr(&conn->host->ip),
					      conn->host->port);
		director_connection_send(dir->left, connect_str);
	} else {
		/* d) */
		dir->left->verifying_left = TRUE;
		director_connection_ping(dir->left);
	}
	return TRUE;
}

static bool
director_user_refresh(struct director_connection *conn,
		      unsigned int username_hash, struct mail_host *host,
		      time_t timestamp, bool weak, struct user **user_r)
{
	struct director *dir = conn->dir;
	struct user *user;
	bool ret = FALSE, unset_weak_user = FALSE;

	user = user_directory_lookup(dir->users, username_hash);
	if (user == NULL) {
		*user_r = user_directory_add(dir->users, username_hash,
					     host, timestamp);
		(*user_r)->weak = weak;
		return TRUE;
	}

	if (user->weak) {
		if (!weak) {
			/* removing user's weakness */
			unset_weak_user = TRUE;
			user->weak = FALSE;
			ret = TRUE;
		} else {
			/* weak user marked again as weak */
		}
	} else if (weak &&
		   !user_directory_user_is_recently_updated(dir->users, user)) {
		/* mark the user as weak */
		user->weak = TRUE;
		ret = TRUE;
	} else if (user->host != host) {
		/* non-weak user received a non-weak update with
		   conflicting host. this shouldn't happen. */
		string_t *str = t_str_new(128);

		str_printfa(str, "User hash %u "
			    "is being redirected to two hosts: %s and %s",
			    username_hash, net_ip2addr(&user->host->ip),
			    net_ip2addr(&host->ip));
		str_printfa(str, " (old_ts=%ld", (long)user->timestamp);

		if (!conn->handshake_received) {
			str_printfa(str, ",handshaking,recv_ts=%ld",
				    (long)timestamp);
		}
		if (user->to_move != NULL)
			str_append(str, ",moving");
		if (user->kill_state != USER_KILL_STATE_NONE)
			str_printfa(str, ",kill_state=%d", user->kill_state);
		str_append_c(str, ')');
		i_error("%s", str_c(str));

		/* we want all the directors to redirect the user to same
		   server, but we don't want two directors fighting over which
		   server it belongs to, so always use the lower IP address */
		if (net_ip_cmp(&user->host->ip, &host->ip) > 0) {
			/* change the host. we'll also need to remove the user
			   from the old host's user_count, because we can't
			   keep track of the user for more than one host */
		} else {
			/* keep the host */
			host = user->host;
		}
		ret = TRUE;
	}
	if (user->host != host) {
		user->host->user_count--;
		user->host = host;
		user->host->user_count++;
		ret = TRUE;
	}
	if (timestamp == ioloop_time && (time_t)user->timestamp != timestamp) {
		user_directory_refresh(dir->users, user);
		ret = TRUE;
	}

	if (unset_weak_user) {
		/* user is no longer weak. handle pending requests for
		   this user if there are any */
		director_set_state_changed(conn->dir);
	}

	*user_r = user;
	return ret;
}

static bool
director_handshake_cmd_user(struct director_connection *conn,
			    const char *const *args)
{
	unsigned int username_hash, timestamp;
	struct ip_addr ip;
	struct mail_host *host;
	struct user *user;
	bool weak;

	if (str_array_length(args) < 3 ||
	    str_to_uint(args[0], &username_hash) < 0 ||
	    net_addr2ip(args[1], &ip) < 0 ||
	    str_to_uint(args[2], &timestamp) < 0) {
		director_cmd_error(conn, "Invalid parameters");
		return FALSE;
	}
	weak = args[3] != NULL && args[3][0] == 'w';

	host = mail_host_lookup(conn->dir->mail_hosts, &ip);
	if (host == NULL) {
		i_error("director(%s): USER used unknown host %s in handshake",
			conn->name, args[1]);
		return FALSE;
	}

	director_user_refresh(conn, username_hash, host, timestamp, weak, &user);
	return TRUE;
}

static bool
director_cmd_user(struct director_connection *conn,
		  const char *const *args)
{
	unsigned int username_hash;
	struct ip_addr ip;
	struct mail_host *host;
	struct user *user;

	/* NOTE: if more parameters are added, update also
	   CMD_IS_USER_HANDHAKE() macro */
	if (str_array_length(args) != 2 ||
	    str_to_uint(args[0], &username_hash) < 0 ||
	    net_addr2ip(args[1], &ip) < 0) {
		director_cmd_error(conn, "Invalid parameters");
		return FALSE;
	}

	host = mail_host_lookup(conn->dir->mail_hosts, &ip);
	if (host == NULL) {
		/* we probably just removed this host. */
		return TRUE;
	}

	if (director_user_refresh(conn, username_hash,
				  host, ioloop_time, FALSE, &user)) {
		i_assert(!user->weak);
		director_update_user(conn->dir, conn->host, user);
	}
	return TRUE;
}

static bool director_cmd_director(struct director_connection *conn,
				  const char *const *args)
{
	struct director_host *host;
	struct ip_addr ip;
	unsigned int port;
	bool forward = FALSE;

	if (!director_args_parse_ip_port(conn, args, &ip, &port))
		return FALSE;

	host = director_host_lookup(conn->dir, &ip, port);
	if (host != NULL) {
		if (host == conn->dir->self_host) {
			/* ignore updates to ourself */
			return TRUE;
		}
		if (host->removed) {
			/* ignore re-adds of removed directors */
			return TRUE;
		}

		/* already have this. just reset its last_network_failure
		   timestamp, since it might be up now. */
		host->last_network_failure = 0;
		if (host->last_seq != 0) {
			/* it also may have been restarted, reset last_seq */
			host->last_seq = 0;
			forward = TRUE;
		}
	} else {
		/* save the director and forward it */
		host = director_host_add(conn->dir, &ip, port);
		forward = TRUE;
	}
	if (forward) {
		director_notify_ring_added(host,
			director_connection_get_host(conn));
	}
	return TRUE;
}

static bool director_cmd_director_remove(struct director_connection *conn,
					 const char *const *args)
{
	struct director_host *host;
	struct ip_addr ip;
	unsigned int port;

	if (!director_args_parse_ip_port(conn, args, &ip, &port))
		return FALSE;

	host = director_host_lookup(conn->dir, &ip, port);
	if (host != NULL && !host->removed)
		director_ring_remove(host, director_connection_get_host(conn));
	return TRUE;
}

static bool
director_cmd_host_hand_start(struct director_connection *conn,
			     const char *const *args)
{
	const ARRAY_TYPE(mail_host) *hosts;
	struct mail_host *const *hostp;
	unsigned int remote_ring_completed;

	if (args[0] == NULL ||
	    str_to_uint(args[0], &remote_ring_completed) < 0) {
		director_cmd_error(conn, "Invalid parameters");
		return FALSE;
	}

	if (remote_ring_completed && !conn->dir->ring_handshaked) {
		/* clear everything we have and use only what remote sends us */
		hosts = mail_hosts_get(conn->dir->mail_hosts);
		while (array_count(hosts) > 0) {
			hostp = array_idx(hosts, 0);
			director_remove_host(conn->dir, NULL, NULL, *hostp);
		}
	} else if (!remote_ring_completed && conn->dir->ring_handshaked) {
		/* ignore whatever remote sends */
		conn->ignore_host_events = TRUE;
	}
	conn->handshake_sending_hosts = TRUE;
	return TRUE;
}

static int
director_cmd_is_seen(struct director_connection *conn,
		     const char *const **_args,
		     struct director_host **host_r)
{
	const char *const *args = *_args;
	struct ip_addr ip;
	unsigned int port, seq;
	struct director_host *host;

	if (str_array_length(args) < 3 ||
	    net_addr2ip(args[0], &ip) < 0 ||
	    str_to_uint(args[1], &port) < 0 ||
	    str_to_uint(args[2], &seq) < 0) {
		director_cmd_error(conn, "Invalid parameters");
		return -1;
	}
	*_args = args + 3;

	host = director_host_lookup(conn->dir, &ip, port);
	if (host == NULL || host->removed) {
		/* director is already gone, but we can't be sure if this
		   command was sent everywhere. re-send it as if it was from
		   ourself. */
		*host_r = NULL;
	} else {
		if (seq <= host->last_seq) {
			/* already seen this */
			return 1;
		}
		*host_r = host;
		host->last_seq = seq;
	}
	return 0;
}

static bool
director_cmd_user_weak(struct director_connection *conn,
		       const char *const *args)
{
	struct director_host *dir_host;
	struct ip_addr ip;
	unsigned int username_hash;
	struct mail_host *host;
	struct user *user;
	struct director_host *src_host = conn->host;
	bool weak = TRUE;
	int ret;

	if ((ret = director_cmd_is_seen(conn, &args, &dir_host)) != 0)
		return FALSE;

	if (str_array_length(args) != 2 ||
	    str_to_uint(args[0], &username_hash) < 0 ||
	    net_addr2ip(args[1], &ip) < 0) {
		director_cmd_error(conn, "Invalid parameters");
		return FALSE;
	}

	host = mail_host_lookup(conn->dir->mail_hosts, &ip);
	if (host == NULL) {
		/* we probably just removed this host. */
		return TRUE;
	}

	if (ret > 0) {
		/* The entire ring has seen this USER-WEAK.
		   make it non-weak now. */
		weak = FALSE;
		src_host = conn->dir->self_host;
	}

	if (director_user_refresh(conn, username_hash,
				  host, ioloop_time, weak, &user)) {
		if (!user->weak)
			director_update_user(conn->dir, src_host, user);
		else {
			director_update_user_weak(conn->dir, src_host,
						  dir_host, user);
		}
	}
	return TRUE;
}

static bool ATTR_NULL(3)
director_cmd_host_int(struct director_connection *conn, const char *const *args,
		      struct director_host *dir_host)
{
	struct mail_host *host;
	struct ip_addr ip;
	unsigned int vhost_count;
	bool update;

	if (str_array_length(args) != 2 ||
	    net_addr2ip(args[0], &ip) < 0 ||
	    str_to_uint(args[1], &vhost_count) < 0) {
		director_cmd_error(conn, "Invalid parameters");
		return FALSE;
	}
	if (conn->ignore_host_events) {
		/* remote is sending hosts in a handshake, but it doesn't have
		   a completed ring and we do. */
		i_assert(conn->handshake_sending_hosts);
		return TRUE;
	}

	host = mail_host_lookup(conn->dir->mail_hosts, &ip);
	if (host == NULL) {
		host = mail_host_add_ip(conn->dir->mail_hosts, &ip);
		update = TRUE;
	} else {
		update = host->vhost_count != vhost_count;
	}

	if (update) {
		mail_host_set_vhost_count(conn->dir->mail_hosts,
					  host, vhost_count);
		director_update_host(conn->dir, conn->host, dir_host, host);
	}
	return TRUE;
}

static bool
director_cmd_host_handshake(struct director_connection *conn,
			    const char *const *args)
{
	return director_cmd_host_int(conn, args, NULL);
}

static bool
director_cmd_host(struct director_connection *conn, const char *const *args)
{
	struct director_host *dir_host;
	int ret;

	if ((ret = director_cmd_is_seen(conn, &args, &dir_host)) != 0)
		return ret > 0;
	return director_cmd_host_int(conn, args, dir_host);
}

static bool
director_cmd_host_remove(struct director_connection *conn,
			 const char *const *args)
{
	struct director_host *dir_host;
	struct mail_host *host;
	struct ip_addr ip;
	int ret;

	if ((ret = director_cmd_is_seen(conn, &args, &dir_host)) != 0)
		return ret > 0;

	if (str_array_length(args) != 1 ||
	    net_addr2ip(args[0], &ip) < 0) {
		director_cmd_error(conn, "Invalid parameters");
		return FALSE;
	}

	host = mail_host_lookup(conn->dir->mail_hosts, &ip);
	if (host != NULL)
		director_remove_host(conn->dir, conn->host, dir_host, host);
	return TRUE;
}

static bool
director_cmd_host_flush(struct director_connection *conn,
			 const char *const *args)
{
	struct director_host *dir_host;
	struct mail_host *host;
	struct ip_addr ip;
	int ret;

	if ((ret = director_cmd_is_seen(conn, &args, &dir_host)) != 0)
		return ret > 0;

	if (str_array_length(args) != 1 ||
	    net_addr2ip(args[0], &ip) < 0) {
		director_cmd_error(conn, "Invalid parameters");
		return FALSE;
	}

	host = mail_host_lookup(conn->dir->mail_hosts, &ip);
	if (host != NULL)
		director_flush_host(conn->dir, conn->host, dir_host, host);
	return TRUE;
}

static bool
director_cmd_user_move(struct director_connection *conn,
		       const char *const *args)
{
	struct director_host *dir_host;
	struct mail_host *host;
	struct ip_addr ip;
	unsigned int username_hash;
	int ret;

	if ((ret = director_cmd_is_seen(conn, &args, &dir_host)) != 0)
		return ret > 0;

	if (str_array_length(args) != 2 ||
	    str_to_uint(args[0], &username_hash) < 0 ||
	    net_addr2ip(args[1], &ip) < 0) {
		director_cmd_error(conn, "Invalid parameters");
		return FALSE;
	}

	host = mail_host_lookup(conn->dir->mail_hosts, &ip);
	if (host != NULL) {
		director_move_user(conn->dir, conn->host, dir_host,
				   username_hash, host);
	}
	return TRUE;
}

static bool
director_cmd_user_killed(struct director_connection *conn,
			 const char *const *args)
{
	unsigned int username_hash;

	if (str_array_length(args) != 1 ||
	    str_to_uint(args[0], &username_hash) < 0) {
		director_cmd_error(conn, "Invalid parameters");
		return FALSE;
	}

	director_user_killed(conn->dir, username_hash);
	return TRUE;
}

static bool
director_cmd_user_killed_everywhere(struct director_connection *conn,
				    const char *const *args)
{
	struct director_host *dir_host;
	unsigned int username_hash;
	int ret;

	if ((ret = director_cmd_is_seen(conn, &args, &dir_host)) != 0)
		return ret > 0;

	if (str_array_length(args) != 1 ||
	    str_to_uint(args[0], &username_hash) < 0) {
		director_cmd_error(conn, "Invalid parameters");
		return FALSE;
	}

	director_user_killed_everywhere(conn->dir, conn->host,
					dir_host, username_hash);
	return TRUE;
}

static bool director_handshake_cmd_done(struct director_connection *conn)
{
	struct director *dir = conn->dir;

	if (dir->debug) {
		unsigned int secs = time(NULL)-conn->created;

		i_debug("director(%s): Handshake took %u secs, "
			"bytes in=%"PRIuUOFF_T" out=%"PRIuUOFF_T,
			conn->name, secs, conn->input->v_offset,
			conn->output->offset);
	}

	/* the host is up now, make sure we can connect to it immediately
	   if needed */
	conn->host->last_network_failure = 0;

	conn->handshake_received = TRUE;
	if (conn->in) {
		/* handshaked to left side. tell it we've received the
		   whole handshake. */
		director_connection_send(conn, "DONE\n");

		/* tell the "right" director about the "left" one */
		director_update_send(dir, director_connection_get_host(conn),
			t_strdup_printf("DIRECTOR\t%s\t%u\n",
					net_ip2addr(&conn->host->ip),
					conn->host->port));
		/* this is our "left" side. */
		return director_connection_assign_left(conn);
	} else {
		/* handshaked to "right" side. */
		return director_connection_assign_right(conn);
	}
}

static int
director_connection_handle_handshake(struct director_connection *conn,
				     const char *cmd, const char *const *args)
{
	/* both incoming and outgoing connections get VERSION and ME */
	if (strcmp(cmd, "VERSION") == 0 && str_array_length(args) >= 3) {
		if (strcmp(args[0], DIRECTOR_VERSION_NAME) != 0) {
			i_error("director(%s): Wrong protocol in socket "
				"(%s vs %s)",
				conn->name, args[0], DIRECTOR_VERSION_NAME);
			return -1;
		} else if (atoi(args[1]) != DIRECTOR_VERSION_MAJOR) {
			i_error("director(%s): Incompatible protocol version: "
				"%u vs %u", conn->name, atoi(args[1]),
				DIRECTOR_VERSION_MAJOR);
			return -1;
		}
		conn->minor_version = atoi(args[2]);
		conn->version_received = TRUE;
		return 1;
	}
	if (!conn->version_received) {
		director_cmd_error(conn, "Incompatible protocol");
		return -1;
	}

	if (strcmp(cmd, "ME") == 0)
		return director_cmd_me(conn, args) ? 1 : -1;
	if (!conn->me_received) {
		director_cmd_error(conn, "Expecting ME command first");
		return -1;
	}

	/* incoming connections get a HOST list */
	if (conn->handshake_sending_hosts) {
		if (strcmp(cmd, "HOST") == 0)
			return director_cmd_host_handshake(conn, args) ? 1 : -1;
		if (strcmp(cmd, "HOST-HAND-END") == 0) {
			conn->ignore_host_events = FALSE;
			conn->handshake_sending_hosts = FALSE;
			return 1;
		}
		director_cmd_error(conn, "Unexpected command during host list");
		return -1;
	}
	if (strcmp(cmd, "HOST-HAND-START") == 0) {
		if (!conn->in) {
			director_cmd_error(conn,
				"Host list is only for incoming connections");
			return -1;
		}
		return director_cmd_host_hand_start(conn, args) ? 1 : -1;
	}

	if (conn->in && strcmp(cmd, "USER") == 0 && CMD_IS_USER_HANDHAKE(args))
		return director_handshake_cmd_user(conn, args) ? 1 : -1;

	/* both get DONE */
	if (strcmp(cmd, "DONE") == 0)
		return director_handshake_cmd_done(conn) ? 1 : -1;
	return 0;
}

static void
director_connection_sync_host(struct director_connection *conn,
			      struct director_host *host,
			      uint32_t seq, unsigned int minor_version)
{
	struct director *dir = conn->dir;

	if (minor_version > DIRECTOR_VERSION_MINOR) {
		/* we're not up to date */
		minor_version = DIRECTOR_VERSION_MINOR;
	}

	if (host->self) {
		if (dir->sync_seq != seq) {
			/* stale SYNC event */
			return;
		}
		/* sync_seq increases when we get disconnected, so we must be
		   successfully connected to both directions */
		i_assert(dir->left != NULL && dir->right != NULL);

		dir->ring_min_version = minor_version;
		if (!dir->ring_handshaked) {
			/* the ring is handshaked */
			director_set_ring_handshaked(dir);
		} else if (dir->ring_synced) {
			/* duplicate SYNC (which was sent just in case the
			   previous one got lost) */
		} else {
			if (dir->debug) {
				i_debug("Ring is synced (%s sent seq=%u)",
					conn->name, seq);
			}
			director_set_ring_synced(dir);
		}
	} else if (dir->right != NULL) {
		/* forward it to the connection on right */
		director_sync_send(dir, host, seq, minor_version);
	}
}

static bool director_connection_sync(struct director_connection *conn,
				     const char *const *args)
{
	struct director *dir = conn->dir;
	struct director_host *host;
	struct ip_addr ip;
	unsigned int port, seq, minor_version = 0;

	if (str_array_length(args) < 3 ||
	    !director_args_parse_ip_port(conn, args, &ip, &port) ||
	    str_to_uint(args[2], &seq) < 0) {
		director_cmd_error(conn, "Invalid parameters");
		return FALSE;
	}
	if (args[3] != NULL)
		minor_version = atoi(args[3]);

	/* find the originating director. if we don't see it, it was already
	   removed and we can ignore this sync. */
	host = director_host_lookup(dir, &ip, port);
	if (host != NULL) {
		director_connection_sync_host(conn, host, seq,
					      minor_version);
	}

	if (host == NULL || !host->self)
		director_resend_sync(dir);
	return TRUE;
}

static bool director_cmd_connect(struct director_connection *conn,
				 const char *const *args)
{
	struct director *dir = conn->dir;
	struct director_host *host;
	struct ip_addr ip;
	unsigned int port;

	if (str_array_length(args) != 2 ||
	    !director_args_parse_ip_port(conn, args, &ip, &port)) {
		director_cmd_error(conn, "Invalid parameters");
		return FALSE;
	}

	host = director_host_get(conn->dir, &ip, port);
	/* reset failure timestamp so we'll actually try to connect there. */
	host->last_network_failure = 0;

	/* remote suggests us to connect elsewhere */
	if (dir->right != NULL &&
	    director_host_cmp_to_self(host, dir->right->host,
				      dir->self_host) <= 0) {
		/* the old connection is the correct one */
		if (dir->debug) {
			i_debug("Ignoring CONNECT request to %s "
				"(current right is %s)",
				host->name, dir->right->name);
		}
		return TRUE;
	}

	if (dir->debug) {
		if (dir->right == NULL) {
			i_debug("Received CONNECT request to %s, "
				"initializing right", host->name);
		} else {
			i_debug("Received CONNECT request to %s, "
				"replacing current right %s",
				host->name, dir->right->name);
		}
	}

	/* connect here */
	(void)director_connect_host(dir, host);
	return TRUE;
}

static void director_disconnect_wrong_lefts(struct director *dir)
{
	struct director_connection *const *connp, *conn;

	array_foreach(&dir->connections, connp) {
		conn = *connp;

		if (conn->in && conn != dir->left && conn->me_received &&
		    conn->to_disconnect == NULL &&
		    director_host_cmp_to_self(dir->left->host, conn->host,
					      dir->self_host) < 0) {
			i_warning("Director connection %s tried to connect to "
				  "us, should use %s instead",
				  conn->name, dir->left->host->name);
			director_connection_send_connect(conn, dir->left->host);
		}
	}
}

static bool director_cmd_pong(struct director_connection *conn)
{
	if (!conn->ping_waiting)
		return TRUE;
	conn->ping_waiting = FALSE;
	timeout_remove(&conn->to_pong);

	if (conn->verifying_left) {
		conn->verifying_left = FALSE;
		if (conn == conn->dir->left) {
			/* our left side is functional. tell all the wrong
			   incoming connections to connect to it instead. */
			director_disconnect_wrong_lefts(conn->dir);
		}
	}

	director_connection_set_ping_timeout(conn);
	return TRUE;
}

static bool
director_connection_handle_cmd(struct director_connection *conn,
			       const char *cmd, const char *const *args)
{
	int ret;

	if (!conn->handshake_received) {
		ret = director_connection_handle_handshake(conn, cmd, args);
		if (ret > 0)
			return TRUE;
		if (ret < 0) {
			/* invalid commands during handshake,
			   we probably don't want to reconnect here */
			return FALSE;
		}
		/* allow also other commands during handshake */
	}

	if (strcmp(cmd, "PING") == 0) {
		director_connection_send(conn, "PONG\n");
		return TRUE;
	}
	if (strcmp(cmd, "PONG") == 0)
		return director_cmd_pong(conn);
	if (strcmp(cmd, "USER") == 0)
		return director_cmd_user(conn, args);
	if (strcmp(cmd, "USER-WEAK") == 0)
		return director_cmd_user_weak(conn, args);
	if (strcmp(cmd, "HOST") == 0)
		return director_cmd_host(conn, args);
	if (strcmp(cmd, "HOST-REMOVE") == 0)
		return director_cmd_host_remove(conn, args);
	if (strcmp(cmd, "HOST-FLUSH") == 0)
		return director_cmd_host_flush(conn, args);
	if (strcmp(cmd, "USER-MOVE") == 0)
		return director_cmd_user_move(conn, args);
	if (strcmp(cmd, "USER-KILLED") == 0)
		return director_cmd_user_killed(conn, args);
	if (strcmp(cmd, "USER-KILLED-EVERYWHERE") == 0)
		return director_cmd_user_killed_everywhere(conn, args);
	if (strcmp(cmd, "DIRECTOR") == 0)
		return director_cmd_director(conn, args);
	if (strcmp(cmd, "DIRECTOR-REMOVE") == 0)
		return director_cmd_director_remove(conn, args);
	if (strcmp(cmd, "SYNC") == 0)
		return director_connection_sync(conn, args);
	if (strcmp(cmd, "CONNECT") == 0)
		return director_cmd_connect(conn, args);

	director_cmd_error(conn, "Unknown command %s", cmd);
	return FALSE;
}

static bool
director_connection_handle_line(struct director_connection *conn,
				const char *line)
{
	const char *cmd, *const *args;
	bool ret;

	args = t_strsplit_tab(line);
	cmd = args[0]; args++;
	if (cmd == NULL) {
		director_cmd_error(conn, "Received empty line");
		return FALSE;
	}

	conn->cur_cmd = cmd;
	conn->cur_line = line;
	ret = director_connection_handle_cmd(conn, cmd, args);
	conn->cur_cmd = NULL;
	conn->cur_line = NULL;
	return ret;
}

static void director_connection_input(struct director_connection *conn)
{
	struct director *dir = conn->dir;
	char *line;
	bool ret;

	switch (i_stream_read(conn->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		i_error("Director %s disconnected%s", conn->name,
			conn->handshake_received ? "" :
			" before handshake finished");
		director_connection_disconnected(&conn);
		return;
	case -2:
		/* buffer full */
		director_cmd_error(conn, "Director sent us more than %d bytes",
				   MAX_INBUF_SIZE);
		director_connection_reconnect(&conn);
		return;
	}

	if (conn->to_disconnect != NULL) {
		/* just read everything the remote sends, and wait for it
		   to disconnect. we mainly just want the remote to read the
		   CONNECT we sent it. */
		size_t size;

		(void)i_stream_get_data(conn->input, &size);
		i_stream_skip(conn->input, size);
		return;
	}

	director_sync_freeze(dir);
	while ((line = i_stream_next_line(conn->input)) != NULL) {
		T_BEGIN {
			ret = director_connection_handle_line(conn, line);
		} T_END;

		if (!ret) {
			director_connection_reconnect(&conn);
			break;
		}
	}
	director_sync_thaw(dir);
	if (conn != NULL)
		timeout_reset(conn->to_ping);
}

static void director_connection_send_directors(struct director_connection *conn,
					       string_t *str)
{
	struct director_host *const *hostp;

	array_foreach(&conn->dir->dir_hosts, hostp) {
		if ((*hostp)->removed)
			continue;
		str_printfa(str, "DIRECTOR\t%s\t%u\n",
			    net_ip2addr(&(*hostp)->ip), (*hostp)->port);
	}
}

static void
director_connection_send_hosts(struct director_connection *conn, string_t *str)
{
	struct mail_host *const *hostp;

	str_printfa(str, "HOST-HAND-START\t%u\n", conn->dir->ring_handshaked);
	array_foreach(mail_hosts_get(conn->dir->mail_hosts), hostp) {
		str_printfa(str, "HOST\t%s\t%u\n",
			    net_ip2addr(&(*hostp)->ip), (*hostp)->vhost_count);
	}
	str_printfa(str, "HOST-HAND-END\t%u\n", conn->dir->ring_handshaked);
}

static int director_connection_send_users(struct director_connection *conn)
{
	struct user *user;
	int ret;

	while ((user = user_directory_iter_next(conn->user_iter)) != NULL) {
		T_BEGIN {
			string_t *str = t_str_new(128);

			str_printfa(str, "USER\t%u\t%s\t%u",
				    user->username_hash,
				    net_ip2addr(&user->host->ip),
				    user->timestamp);
			if (user->weak)
				str_append(str, "\tw");
			str_append_c(str, '\n');
			director_connection_send(conn, str_c(str));
		} T_END;

		if (o_stream_get_buffer_used_size(conn->output) >= OUTBUF_FLUSH_THRESHOLD) {
			if ((ret = o_stream_flush(conn->output)) <= 0) {
				/* continue later */
				timeout_reset(conn->to_ping);
				return ret;
			}
		}
	}
	user_directory_iter_deinit(&conn->user_iter);
	director_connection_send(conn, "DONE\n");

	ret = o_stream_flush(conn->output);
	timeout_reset(conn->to_ping);
	return ret;
}

static int director_connection_output(struct director_connection *conn)
{
	int ret;

	if (conn->user_iter != NULL) {
		/* still handshaking USER list */
		o_stream_cork(conn->output);
		ret = director_connection_send_users(conn);
		o_stream_uncork(conn->output);
		if (ret < 0)
			director_connection_disconnected(&conn);
		else
			o_stream_set_flush_pending(conn->output, TRUE);
		return ret;
	}
	return o_stream_flush(conn->output);
}

static struct director_connection *
director_connection_init_common(struct director *dir, int fd)
{
	struct director_connection *conn;

	conn = i_new(struct director_connection, 1);
	conn->created = ioloop_time;
	conn->fd = fd;
	conn->dir = dir;
	conn->input = i_stream_create_fd(conn->fd, MAX_INBUF_SIZE, FALSE);
	conn->output = o_stream_create_fd(conn->fd, MAX_OUTBUF_SIZE, FALSE);
	conn->to_ping = timeout_add(DIRECTOR_CONNECTION_ME_TIMEOUT_MSECS,
				    director_connection_init_timeout, conn);
	array_append(&dir->connections, &conn, 1);
	return conn;
}

static void director_connection_send_handshake(struct director_connection *conn)
{
	director_connection_send(conn, t_strdup_printf(
		"VERSION\t"DIRECTOR_VERSION_NAME"\t%u\t%u\n"
		"ME\t%s\t%u\n",
		DIRECTOR_VERSION_MAJOR, DIRECTOR_VERSION_MINOR,
		net_ip2addr(&conn->dir->self_ip), conn->dir->self_port));
}

struct director_connection *
director_connection_init_in(struct director *dir, int fd,
			    const struct ip_addr *ip)
{
	struct director_connection *conn;

	conn = director_connection_init_common(dir, fd);
	conn->in = TRUE;
	conn->connected = TRUE;
	conn->name = i_strdup_printf("%s/in", net_ip2addr(ip));
	conn->io = io_add(conn->fd, IO_READ, director_connection_input, conn);

	director_connection_send_handshake(conn);
	return conn;
}

static void director_connection_connected(struct director_connection *conn)
{
	struct director *dir = conn->dir;
	string_t *str = t_str_new(1024);
	int err;

	if ((err = net_geterror(conn->fd)) != 0) {
		i_error("director(%s): connect() failed: %s", conn->name,
			strerror(err));
		director_connection_disconnected(&conn);
		return;
	}
	conn->connected = TRUE;
	o_stream_set_flush_callback(conn->output,
				    director_connection_output, conn);

	io_remove(&conn->io);
	conn->io = io_add(conn->fd, IO_READ, director_connection_input, conn);

	timeout_remove(&conn->to_ping);
	conn->to_ping = timeout_add(DIRECTOR_CONNECTION_SEND_USERS_TIMEOUT_MSECS,
				    director_connection_init_timeout, conn);

	o_stream_cork(conn->output);
	director_connection_send_handshake(conn);
	director_connection_send_directors(conn, str);
	director_connection_send_hosts(conn, str);
	director_connection_send(conn, str_c(str));

	conn->user_iter = user_directory_iter_init(dir->users);
	if (director_connection_send_users(conn) == 0)
		o_stream_set_flush_pending(conn->output, TRUE);
	o_stream_uncork(conn->output);
}

struct director_connection *
director_connection_init_out(struct director *dir, int fd,
			     struct director_host *host)
{
	struct director_connection *conn;

	i_assert(!host->removed);

	/* make sure we don't keep old sequence values across restarts */
	host->last_seq = 0;

	conn = director_connection_init_common(dir, fd);
	conn->name = i_strdup_printf("%s/out", host->name);
	conn->host = host;
	director_host_ref(host);
	conn->io = io_add(conn->fd, IO_WRITE,
			  director_connection_connected, conn);
	return conn;
}

void director_connection_deinit(struct director_connection **_conn)
{
	struct director_connection *const *conns, *conn = *_conn;
	struct director *dir = conn->dir;
	unsigned int i, count;

	*_conn = NULL;

	if (dir->debug && conn->host != NULL)
		i_debug("Disconnecting from %s", conn->host->name);

	conns = array_get(&dir->connections, &count);
	for (i = 0; i < count; i++) {
		if (conns[i] == conn) {
			array_delete(&dir->connections, i, 1);
			break;
		}
	}
	i_assert(i < count);
	if (dir->left == conn) {
		dir->left = NULL;
		/* if there is already another handshaked incoming connection,
		   use it as the new "left" */
		director_assign_left(dir);
	}
	if (dir->right == conn)
		dir->right = NULL;
	if (conn->host != NULL)
		director_host_unref(conn->host);

	if (conn->user_iter != NULL)
		user_directory_iter_deinit(&conn->user_iter);
	if (conn->to_disconnect != NULL)
		timeout_remove(&conn->to_disconnect);
	if (conn->to_pong != NULL)
		timeout_remove(&conn->to_pong);
	timeout_remove(&conn->to_ping);
	if (conn->io != NULL)
		io_remove(&conn->io);
	i_stream_unref(&conn->input);
	o_stream_unref(&conn->output);
	if (close(conn->fd) < 0)
		i_error("close(director connection) failed: %m");

	if (conn->in)
		master_service_client_connection_destroyed(master_service);
	i_free(conn->name);
	i_free(conn);

	if (dir->left == NULL || dir->right == NULL) {
		/* we aren't synced until we're again connected to a ring */
		dir->sync_seq++;
		director_set_ring_unsynced(dir);
	}
}

void director_connection_disconnected(struct director_connection **_conn)
{
	struct director_connection *conn = *_conn;
	struct director *dir = conn->dir;

	if (conn->created + DIRECTOR_SUCCESS_MIN_CONNECT_SECS > ioloop_time &&
	    conn->host != NULL) {
		/* connection didn't exist for very long, assume it has a
		   network problem */
		conn->host->last_network_failure = ioloop_time;
	}

	director_connection_deinit(_conn);
	if (dir->right == NULL)
		director_connect(dir);
}

void director_connection_reconnect(struct director_connection **_conn)
{
	struct director_connection *conn = *_conn;
	struct director *dir = conn->dir;

	director_connection_deinit(_conn);
	if (dir->right == NULL)
		director_connect(dir);
}

void director_connection_send(struct director_connection *conn,
			      const char *data)
{
	unsigned int len = strlen(data);
	off_t ret;

	if (conn->output->closed || !conn->connected)
		return;

	ret = o_stream_send(conn->output, data, len);
	if (ret != (off_t)len) {
		if (ret < 0)
			i_error("director(%s): write() failed: %m", conn->name);
		else {
			i_error("director(%s): Output buffer full, "
				"disconnecting", conn->name);
		}
		o_stream_close(conn->output);
	}
}

static void
director_connection_ping_idle_timeout(struct director_connection *conn)
{
	i_error("director(%s): Ping timed out, disconnecting", conn->name);
	director_connection_disconnected(&conn);
}

static void director_connection_pong_timeout(struct director_connection *conn)
{
	i_error("director(%s): PONG reply not received although other "
		"input keeps coming, disconnecting", conn->name);
	director_connection_disconnected(&conn);
}

void director_connection_ping(struct director_connection *conn)
{
	if (conn->ping_waiting)
		return;

	timeout_remove(&conn->to_ping);
	conn->to_ping = timeout_add(DIRECTOR_CONNECTION_PING_IDLE_TIMEOUT_MSECS,
				    director_connection_ping_idle_timeout, conn);
	conn->to_pong = timeout_add(DIRECTOR_CONNECTION_PONG_TIMEOUT_MSECS,
				    director_connection_pong_timeout, conn);
	director_connection_send(conn, "PING\n");
	conn->ping_waiting = TRUE;
}

const char *director_connection_get_name(struct director_connection *conn)
{
	return conn->name;
}

struct director_host *
director_connection_get_host(struct director_connection *conn)
{
	return conn->host;
}

bool director_connection_is_handshaked(struct director_connection *conn)
{
	return conn->handshake_received;
}

bool director_connection_is_incoming(struct director_connection *conn)
{
	return conn->in;
}

unsigned int
director_connection_get_minor_version(struct director_connection *conn)
{
	return conn->minor_version;
}

void director_connection_cork(struct director_connection *conn)
{
	o_stream_cork(conn->output);
}

void director_connection_uncork(struct director_connection *conn)
{
	o_stream_uncork(conn->output);
}

void director_connection_set_synced(struct director_connection *conn,
				    bool synced)
{
	if (conn->synced == synced)
		return;
	conn->synced = synced;

	/* switch ping timeout, unless we're already waiting for PONG */
	if (conn->ping_waiting)
		return;

	director_connection_set_ping_timeout(conn);
}
