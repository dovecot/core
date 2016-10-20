/* Copyright (c) 2010-2016 Dovecot authors, see the included COPYING file */

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
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "strescape.h"
#include "time-util.h"
#include "master-service.h"
#include "mail-host.h"
#include "director.h"
#include "director-host.h"
#include "director-request.h"
#include "director-connection.h"

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
#define DIRECTOR_HANDSHAKE_WARN_SECS 29
#define DIRECTOR_HANDSHAKE_BYTES_LOG_MIN_SECS (60*30)
#define DIRECTOR_MAX_SYNC_SEQ_DUPLICATES 4
/* If we receive SYNCs with a timestamp this many seconds higher than the last
   valid received SYNC timestamp, assume that we lost the director's restart
   notification and reset the last_sync_seq */
#define DIRECTOR_SYNC_STALE_TIMESTAMP_RESET_SECS (60*2)
#define DIRECTOR_MAX_CLOCK_DIFF_WARN_SECS 1

#if DIRECTOR_CONNECTION_DONE_TIMEOUT_MSECS <= DIRECTOR_CONNECTION_PING_TIMEOUT_MSECS
#  error DIRECTOR_CONNECTION_DONE_TIMEOUT_MSECS is too low
#endif

#if DIRECTOR_CONNECTION_PONG_TIMEOUT_MSECS <= DIRECTOR_CONNECTION_PING_IDLE_TIMEOUT_MSECS
#  error DIRECTOR_CONNECTION_PONG_TIMEOUT_MSECS is too low
#endif

#define CMD_IS_USER_HANDHAKE(args) \
	(str_array_length(args) > 2)

#define DIRECTOR_OPT_CONSISTENT_HASHING "consistent-hashing"

struct director_connection {
	struct director *dir;
	char *name;
	time_t created;
	unsigned int minor_version;

	struct timeval last_input, last_output;

	/* for incoming connections the director host isn't known until
	   ME-line is received */
	struct director_host *host;
	/* this is set only for wrong connections: */
	struct director_host *connect_request_to;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;
	struct timeout *to_disconnect, *to_ping, *to_pong;

	struct director_user_iter *user_iter;

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
	unsigned int users_unsorted:1;
};

static void director_finish_sending_handshake(struct director_connection *conn);
static void director_connection_disconnected(struct director_connection **conn,
					     const char *reason);
static void director_connection_reconnect(struct director_connection **conn,
					  const char *reason);
static void
director_connection_log_disconnect(struct director_connection *conn, int err,
				   const char *errstr);
static int director_connection_send_done(struct director_connection *conn);

static void ATTR_FORMAT(2, 3)
director_cmd_error(struct director_connection *conn, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	i_error("director(%s): Command %s: %s (input: %s)", conn->name,
		conn->cur_cmd, t_strdup_vprintf(fmt, args), conn->cur_line);
	va_end(args);

	if (conn->host != NULL)
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
	director_connection_disconnected(&conn, "Handshake timeout");
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
	director_connection_log_disconnect(conn, ETIMEDOUT, "");
	director_connection_deinit(&conn,
		"Timeout waiting for disconnect after CONNECT");
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
	o_stream_uncork(conn->output);

	/* wait for a while for the remote to disconnect, so it will hopefully
	   see our CONNECT command. we'll also log the warning later to avoid
	   multiple log lines about it. */
	conn->connect_request_to = host;
	director_host_ref(conn->connect_request_to);

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
				   DIRECTOR_VERSION_MINOR, ioloop_time,
				   mail_hosts_hash(dir->mail_hosts));
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
		i_warning("Replacing left director connection %s with %s",
			  dir->left->host->name, conn->host->name);
		director_connection_deinit(&dir->left, t_strdup_printf(
			"Replacing with %s", conn->host->name));
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
				director_connection_deinit(&conn,
					"Unwanted incoming connection");
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

static void director_send_delayed_syncs(struct director *dir)
{
	struct director_host *const *hostp;

	i_assert(dir->right != NULL);

	dir_debug("director(%s): Sending delayed SYNCs", dir->right->name);
	array_foreach(&dir->dir_hosts, hostp) {
		if ((*hostp)->delayed_sync_seq == 0)
			continue;

		director_sync_send(dir, *hostp, (*hostp)->delayed_sync_seq,
				   (*hostp)->delayed_sync_minor_version,
				   (*hostp)->delayed_sync_timestamp,
				   (*hostp)->delayed_sync_hosts_hash);
		(*hostp)->delayed_sync_seq = 0;
	}
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
		i_warning("Replacing right director connection %s with %s",
			  dir->right->host->name, conn->host->name);
		director_connection_deinit(&dir->right, t_strdup_printf(
			"Replacing with %s", conn->host->name));
	}
	dir->right = conn;
	i_free(conn->name);
	conn->name = i_strdup_printf("%s/right", conn->host->name);
	director_connection_assigned(conn);
	director_send_delayed_syncs(dir);
	return TRUE;
}

static bool
director_args_parse_ip_port(struct director_connection *conn,
			    const char *const *args,
			    struct ip_addr *ip_r, in_port_t *port_r)
{
	if (args[0] == NULL || args[1] == NULL) {
		director_cmd_error(conn, "Missing IP+port parameters");
		return FALSE;
	}
	if (net_addr2ip(args[0], ip_r) < 0) {
		director_cmd_error(conn, "Invalid IP address: %s", args[0]);
		return FALSE;
	}
	if (net_str2port(args[1], port_r) < 0) {
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
	in_port_t port;
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

	if (args[2] != NULL) {
		time_t remote_time;
		int diff;

		if (str_to_time(args[2], &remote_time) < 0) {
			director_cmd_error(conn, "Invalid ME timestamp");
			return FALSE;
		}
		diff = ioloop_time - remote_time;
		if (diff > DIRECTOR_MAX_CLOCK_DIFF_WARN_SECS ||
		    (diff < 0 && -diff > DIRECTOR_MAX_CLOCK_DIFF_WARN_SECS)) {
			i_warning("Director %s clock differs from ours by %d secs",
				  conn->name, diff);
		}
	}

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
	director_host_restarted(conn->host);

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
		director_connection_deinit(&dir->left,
			"Replacing with new incoming connection");
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
		      time_t timestamp, bool weak, bool *forced_r,
		      struct user **user_r)
{
	struct director *dir = conn->dir;
	struct user *user;
	bool ret = FALSE, unset_weak_user = FALSE;
	struct user_directory *users = host->tag->users;

	*forced_r = FALSE;

	user = user_directory_lookup(users, username_hash);
	if (user == NULL) {
		*user_r = user_directory_add(users, username_hash,
					     host, timestamp);
		(*user_r)->weak = weak;
		dir_debug("user refresh: %u added", username_hash);
		return TRUE;
	}

	if (user->weak) {
		if (!weak) {
			/* removing user's weakness */
			dir_debug("user refresh: %u weakness removed",
				  username_hash);
			unset_weak_user = TRUE;
			user->weak = FALSE;
			ret = TRUE;
		} else {
			/* weak user marked again as weak */
		}
	} else if (weak &&
		   !user_directory_user_is_recently_updated(users, user)) {
		/* mark the user as weak */
		dir_debug("user refresh: %u set weak", username_hash);
		user->weak = TRUE;
		ret = TRUE;
	} else if (weak) {
		dir_debug("user refresh: %u weak update to %s ignored, "
			  "we recently changed it to %s",
			  username_hash, net_ip2addr(&host->ip),
			  net_ip2addr(&user->host->ip));
		host = user->host;
		ret = TRUE;
	} else if (user->host == host) {
		/* update to the same host */
	} else if (user_directory_user_is_near_expiring(users, user)) {
		/* host conflict for a user that is already near expiring. we can
		   assume that the other director had already dropped this user
		   and we should have as well. use the new host. */
		dir_debug("user refresh: %u is nearly expired, "
			  "replacing host %s with %s", username_hash,
			  net_ip2addr(&user->host->ip), net_ip2addr(&host->ip));
		ret = TRUE;
	} else if (USER_IS_BEING_KILLED(user)) {
		/* user is still being moved - ignore conflicting host updates
		   from other directors who don't yet know about the move. */
		dir_debug("user refresh: %u is being moved, "
			  "preserve its host %s instead of replacing with %s",
			  username_hash, net_ip2addr(&user->host->ip),
			  net_ip2addr(&host->ip));
		host = user->host;
	} else {
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
		if (USER_IS_BEING_KILLED(user)) {
			if (user->kill_ctx->to_move != NULL)
				str_append(str, ",moving");
			str_printfa(str, ",kill_state=%s",
				    user_kill_state_names[user->kill_ctx->kill_state]);
		}
		str_append_c(str, ')');
		i_error("%s", str_c(str));

		/* we want all the directors to redirect the user to same
		   server, but we don't want two directors fighting over which
		   server it belongs to, so always use the lower IP address */
		if (net_ip_cmp(&user->host->ip, &host->ip) > 0) {
			/* change the host. we'll also need to remove the user
			   from the old host's user_count, because we can't
			   keep track of the user for more than one host.

			   send the updated USER back to the sender as well. */
			*forced_r = TRUE;
		} else {
			/* keep the host */
			host = user->host;
		}
		/* especially IMAP connections can take a long time to die.
		   make sure we kill off the connections in the wrong
		   backends. */
		director_kick_user_hash(dir, dir->self_host, NULL,
					username_hash, &host->ip);
		ret = TRUE;
	}
	if (user->host != host) {
		user->host->user_count--;
		user->host = host;
		user->host->user_count++;
		ret = TRUE;
	}
	if (timestamp == ioloop_time && (time_t)user->timestamp != timestamp) {
		user_directory_refresh(users, user);
		ret = TRUE;
	}
	dir_debug("user refresh: %u refreshed timeout to %ld",
		  username_hash, (long)user->timestamp);

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
	bool weak, forced;

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

	(void)director_user_refresh(conn, username_hash, host,
				    timestamp, weak, &forced, &user);
	if (user->timestamp < timestamp) {
		conn->users_unsorted = TRUE;
		user->timestamp = timestamp;
	}
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
	bool forced;

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
				  host, ioloop_time, FALSE, &forced, &user)) {
		struct director_host *src_host =
			forced ? conn->dir->self_host : conn->host;
		i_assert(!user->weak);
		director_update_user(conn->dir, src_host, user);
	}
	return TRUE;
}

static bool director_cmd_director(struct director_connection *conn,
				  const char *const *args)
{
	struct director_host *host;
	struct ip_addr ip;
	in_port_t port;

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
		/* it also may have been restarted, reset its state */
		director_host_restarted(host);
	} else {
		/* save the director and forward it */
		host = director_host_add(conn->dir, &ip, port);
	}
	/* just forward this to the entire ring until it reaches back to
	   itself. some hosts may see this twice, but that's the only way to
	   guarantee that it gets seen by everyone. reseting the host multiple
	   times may cause us to handle its commands multiple times, but the
	   commands can handle that. however, we need to also handle a
	   situation where the added director never comes back - we don't want
	   to send the director information in a loop forever. */
	if (conn->dir->right != NULL &&
	    director_host_cmp_to_self(host, conn->dir->right->host,
				      conn->dir->self_host) > 0) {
		dir_debug("Received DIRECTOR update for a host where we should be connected to. "
			  "Not forwarding it since it's probably crashed.");
	} else {
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
	in_port_t port;

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
		dir_debug("%s: We're joining a ring - replace all hosts",
			  conn->name);
		hosts = mail_hosts_get(conn->dir->mail_hosts);
		while (array_count(hosts) > 0) {
			hostp = array_idx(hosts, 0);
			director_remove_host(conn->dir, NULL, NULL, *hostp);
		}
	} else if (!remote_ring_completed && conn->dir->ring_handshaked) {
		/* ignore whatever remote sends */
		dir_debug("%s: Remote is joining our ring - "
			  "ignore all remote HOSTs", conn->name);
		conn->ignore_host_events = TRUE;
	} else {
		dir_debug("%s: Merge rings' hosts", conn->name);
	}
	conn->handshake_sending_hosts = TRUE;
	return TRUE;
}

static int
director_cmd_is_seen_full(struct director_connection *conn,
			  const char *const **_args, unsigned int *seq_r,
			  struct director_host **host_r)
{
	const char *const *args = *_args;
	struct ip_addr ip;
	in_port_t port;
	unsigned int seq;
	struct director_host *host;

	if (str_array_length(args) < 3 ||
	    net_addr2ip(args[0], &ip) < 0 ||
	    net_str2port(args[1], &port) < 0 ||
	    str_to_uint(args[2], &seq) < 0) {
		director_cmd_error(conn, "Invalid parameters");
		return -1;
	}
	*_args = args + 3;
	*seq_r = seq;

	host = director_host_lookup(conn->dir, &ip, port);
	if (host == NULL || host->removed) {
		/* director is already gone, but we can't be sure if this
		   command was sent everywhere. re-send it as if it was from
		   ourself. */
		*host_r = NULL;
	} else {
		*host_r = host;
		if (seq <= host->last_seq) {
			/* already seen this */
			return 1;
		}
		host->last_seq = seq;
	}
	return 0;
}

static int
director_cmd_is_seen(struct director_connection *conn,
		     const char *const **_args,
		     struct director_host **host_r)
{
	unsigned int seq;

	return director_cmd_is_seen_full(conn, _args, &seq, host_r);
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
	bool weak = TRUE, weak_forward = FALSE, forced;
	int ret;

	/* note that unlike other commands we don't want to just ignore
	   duplicate commands */
	if ((ret = director_cmd_is_seen(conn, &args, &dir_host)) < 0)
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

	if (ret == 0) {
		/* First time we're seeing this - forward it to others also.
		   We'll want to do it even if the user was already marked as
		   weak, because otherwise if two directors mark the user weak
		   at the same time both the USER-WEAK notifications reach
		   only half the directors until they collide and neither one
		   finishes going through the whole ring marking the user
		   non-weak. */
		weak_forward = TRUE;
	} else if (dir_host == conn->dir->self_host) {
		/* We originated this USER-WEAK request. The entire ring has seen
		   it and there weren't any conflicts. Make the user non-weak. */
		dir_debug("user refresh: %u Our USER-WEAK seen by the entire ring",
			  username_hash);
		src_host = conn->dir->self_host;
		weak = FALSE;
	} else {
		/* The original USER-WEAK sender will send a new non-weak USER
		   update saying what really happened. We'll still need to forward
		   this around the ring to the origin so it also knows it has
		   travelled through the ring. */
		dir_debug("user refresh: %u Remote USER-WEAK from %s seen by the entire ring, ignoring",
			  username_hash, net_ip2addr(&dir_host->ip));
		weak_forward = TRUE;
	}

	if (director_user_refresh(conn, username_hash,
				  host, ioloop_time, weak, &forced, &user) ||
	    weak_forward) {
		if (forced)
			src_host = conn->dir->self_host;
		if (!user->weak)
			director_update_user(conn->dir, src_host, user);
		else {
			director_update_user_weak(conn->dir, src_host, conn,
						  dir_host, user);
		}
	}
	return TRUE;
}

static bool ATTR_NULL(3)
director_cmd_host_int(struct director_connection *conn, const char *const *args,
		      struct director_host *dir_host)
{
	struct director_host *src_host = conn->host;
	struct mail_host *host;
	struct ip_addr ip;
	const char *tag = "", *host_tag, *hostname = NULL;
	unsigned int arg_count, vhost_count;
	bool update, down = FALSE;
	time_t last_updown_change = 0;

	arg_count = str_array_length(args);
	if (arg_count < 2 ||
	    net_addr2ip(args[0], &ip) < 0 ||
	    str_to_uint(args[1], &vhost_count) < 0) {
		director_cmd_error(conn, "Invalid parameters");
		return FALSE;
	}
	if (arg_count >= 3)
		tag = args[2];
	if (arg_count >= 4) {
		if ((args[3][0] != 'D' && args[3][0] != 'U') ||
		    str_to_time(args[3]+1, &last_updown_change) < 0) {
			director_cmd_error(conn, "Invalid updown parameters");
			return FALSE;
		}
		down = args[3][0] == 'D';
	}
	if (arg_count >= 5)
		hostname = args[4];
	if (conn->ignore_host_events) {
		/* remote is sending hosts in a handshake, but it doesn't have
		   a completed ring and we do. */
		i_assert(conn->handshake_sending_hosts);
		return TRUE;
	}
	if (tag[0] != '\0' && conn->minor_version < DIRECTOR_VERSION_TAGS_V2) {
		director_cmd_error(conn, "Received a host tag from older director version with incompatible tagging support");
		return FALSE;
	}

	host = mail_host_lookup(conn->dir->mail_hosts, &ip);
	if (host == NULL) {
		host = mail_host_add_hostname(conn->dir->mail_hosts,
					      hostname, &ip, tag);
		update = TRUE;
	} else {
		update = host->vhost_count != vhost_count ||
			host->down != down;

		host_tag = mail_host_get_tag(host);
		if (strcmp(tag, host_tag) != 0) {
			i_error("director(%s): Host %s changed tag from '%s' to '%s'",
				conn->name, net_ip2addr(&host->ip),
				host_tag, tag);
			mail_host_set_tag(host, tag);
			update = TRUE;
		}
		if (update && host->desynced) {
			string_t *str = t_str_new(128);

			str_printfa(str, "director(%s): Host %s is being updated before previous update had finished (",
				  conn->name, net_ip2addr(&host->ip));
			if (host->down != down &&
			    host->last_updown_change > last_updown_change) {
				/* our host has a newer change. preserve it. */
				down = host->down;
			}
			if (host->down != down) {
				if (host->down)
					str_append(str, "down -> up");
				else
					str_append(str, "up -> down");
			}
			if (host->vhost_count != vhost_count) {
				if (host->down != down)
					str_append(str, ", ");
				str_printfa(str, "vhosts %u -> %u",
					    host->vhost_count, vhost_count);
			}
			str_append(str, ") - ");

			vhost_count = I_MIN(vhost_count, host->vhost_count);
			last_updown_change = I_MAX(last_updown_change,
						   host->last_updown_change);
			str_printfa(str, "setting to state=%s vhosts=%u",
				    down ? "down" : "up", vhost_count);
			i_warning("%s", str_c(str));
			/* make the change appear to come from us, so it
			   reaches the full ring */
			dir_host = NULL;
			src_host = conn->dir->self_host;
		}
	}

	if (update) {
		mail_host_set_down(host, down, last_updown_change);
		mail_host_set_vhost_count(host, vhost_count);
		director_update_host(conn->dir, src_host, dir_host, host);
	} else {
		dir_debug("Ignoring host %s update vhost_count=%u "
			  "down=%d last_updown_change=%ld (hosts_hash=%u)",
			  net_ip2addr(&ip), vhost_count, down,
			  (long)last_updown_change,
			  mail_hosts_hash(conn->dir->mail_hosts));
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
director_cmd_user_kick(struct director_connection *conn,
		       const char *const *args)
{
	struct director_host *dir_host;
	int ret;

	if ((ret = director_cmd_is_seen(conn, &args, &dir_host)) != 0)
		return ret > 0;

	if (str_array_length(args) != 1) {
		director_cmd_error(conn, "Invalid parameters");
		return FALSE;
	}

	director_kick_user(conn->dir, conn->host, dir_host, args[0]);
	return TRUE;
}

static bool
director_cmd_user_kick_alt(struct director_connection *conn,
			   const char *const *args)
{
	struct director_host *dir_host;
	int ret;

	if ((ret = director_cmd_is_seen(conn, &args, &dir_host)) != 0)
		return ret > 0;

	if (str_array_length(args) != 2) {
		director_cmd_error(conn, "Invalid parameters");
		return FALSE;
	}

	director_kick_user_alt(conn->dir, conn->host, dir_host, args[0], args[1]);
	return TRUE;
}

static bool
director_cmd_user_kick_hash(struct director_connection *conn,
			    const char *const *args)
{
	struct director_host *dir_host;
	unsigned int username_hash;
	struct ip_addr except_ip;
	int ret;

	if ((ret = director_cmd_is_seen(conn, &args, &dir_host)) != 0)
		return ret > 0;

	if (str_array_length(args) != 2 ||
	    str_to_uint(args[0], &username_hash) < 0 ||
	    net_addr2ip(args[1], &except_ip) < 0) {
		director_cmd_error(conn, "Invalid parameters");
		return FALSE;
	}

	director_kick_user_hash(conn->dir, conn->host, dir_host,
				username_hash, &except_ip);
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
	unsigned int seq, username_hash;
	int ret;

	if ((ret = director_cmd_is_seen_full(conn, &args, &seq, &dir_host)) < 0)
		return FALSE;

	if (str_array_length(args) != 1 ||
	    str_to_uint(args[0], &username_hash) < 0) {
		director_cmd_error(conn, "Invalid parameters");
		return FALSE;
	}

	if (ret > 0) {
		i_assert(dir_host != NULL);
		dir_debug("User %u - ignoring already seen USER-KILLED-EVERYWHERE "
			  "with seq=%u <= %s.last_seq=%u", username_hash,
			  seq, dir_host->name, dir_host->last_seq);
		return TRUE;
	}

	director_user_killed_everywhere(conn->dir, conn->host,
					dir_host, username_hash);
	return TRUE;
}

static bool director_handshake_cmd_done(struct director_connection *conn)
{
	struct director *dir = conn->dir;
	unsigned int handshake_secs = time(NULL) - conn->created;
	string_t *str;

	if (conn->users_unsorted && conn->user_iter == NULL) {
		/* we sent our user list before receiving remote's */
		conn->users_unsorted = FALSE;
		mail_hosts_sort_users(conn->dir->mail_hosts);
	}

	str = t_str_new(128);
	str_printfa(str, "director(%s): Handshake finished in %u secs "
		    "(bytes in=%"PRIuUOFF_T" out=%"PRIuUOFF_T")",
		    conn->name, handshake_secs, conn->input->v_offset,
		    conn->output->offset);
	if (handshake_secs >= DIRECTOR_HANDSHAKE_WARN_SECS)
		i_warning("%s", str_c(str));
	else
		i_info("%s", str_c(str));

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
director_handshake_cmd_options(struct director_connection *conn,
			       const char *const *args)
{
	bool consistent_hashing = FALSE;
	unsigned int i;

	for (i = 0; args[i] != NULL; i++) {
		if (strcmp(args[i], DIRECTOR_OPT_CONSISTENT_HASHING) == 0)
			consistent_hashing = TRUE;
	}
	if (consistent_hashing != conn->dir->set->director_consistent_hashing) {
		i_error("director(%s): director_consistent_hashing settings differ between directors",
			conn->name);
		return -1;
	}
	return 1;
}

static int
director_connection_handle_handshake(struct director_connection *conn,
				     const char *cmd, const char *const *args)
{
	unsigned int major_version;

	/* both incoming and outgoing connections get VERSION and ME */
	if (strcmp(cmd, "VERSION") == 0 && str_array_length(args) >= 3) {
		if (strcmp(args[0], DIRECTOR_VERSION_NAME) != 0) {
			i_error("director(%s): Wrong protocol in socket "
				"(%s vs %s)",
				conn->name, args[0], DIRECTOR_VERSION_NAME);
			return -1;
		} else if (str_to_uint(args[1], &major_version) < 0 ||
			str_to_uint(args[2], &conn->minor_version) < 0) {
			i_error("director(%s): Invalid protocol version: "
				"%s.%s", conn->name, args[1], args[2]);
			return -1;
		} else if (major_version != DIRECTOR_VERSION_MAJOR) {
			i_error("director(%s): Incompatible protocol version: "
				"%u vs %u", conn->name, major_version,
				DIRECTOR_VERSION_MAJOR);
			return -1;
		}
		if (conn->minor_version < DIRECTOR_VERSION_TAGS_V2 &&
		    mail_hosts_have_tags(conn->dir->mail_hosts)) {
			i_error("director(%s): Director version supports incompatible tags", conn->name);
			return -1;
		}
		conn->version_received = TRUE;
		director_finish_sending_handshake(conn);
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
	if (strcmp(cmd, "OPTIONS") == 0)
		return director_handshake_cmd_options(conn, args);
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

static bool
director_connection_sync_host(struct director_connection *conn,
			      struct director_host *host,
			      uint32_t seq, unsigned int minor_version,
			      unsigned int timestamp, unsigned int hosts_hash)
{
	struct director *dir = conn->dir;

	if (minor_version > DIRECTOR_VERSION_MINOR) {
		/* we're not up to date */
		minor_version = DIRECTOR_VERSION_MINOR;
	}

	if (host->self) {
		if (dir->sync_seq != seq) {
			/* stale SYNC event */
			return FALSE;
		}
		/* sync_seq increases when we get disconnected, so we must be
		   successfully connected to both directions */
		i_assert(dir->left != NULL && dir->right != NULL);

		if (hosts_hash != 0 &&
		    hosts_hash != mail_hosts_hash(conn->dir->mail_hosts)) {
			i_error("director(%s): Hosts unexpectedly changed during SYNC reply - resending"
				"(seq=%u, old hosts_hash=%u, new hosts_hash=%u)",
				conn->name, seq, hosts_hash,
				mail_hosts_hash(dir->mail_hosts));
			(void)director_resend_sync(dir);
			return FALSE;
		}

		dir->ring_min_version = minor_version;
		if (!dir->ring_handshaked) {
			/* the ring is handshaked */
			director_set_ring_handshaked(dir);
		} else if (dir->ring_synced) {
			/* duplicate SYNC (which was sent just in case the
			   previous one got lost) */
		} else {
			dir_debug("Ring is synced (%s sent seq=%u, hosts_hash=%u)",
				  conn->name, seq,
				  mail_hosts_hash(dir->mail_hosts));
			director_set_ring_synced(dir);
		}
	} else {
		if (seq < host->last_sync_seq &&
		    timestamp < host->last_sync_timestamp +
		    DIRECTOR_SYNC_STALE_TIMESTAMP_RESET_SECS) {
			/* stale SYNC event */
			dir_debug("Ignore stale SYNC event for %s "
				  "(seq %u < %u, timestamp=%u)",
				  host->name, seq, host->last_sync_seq,
				  timestamp);
			return FALSE;
		} else if (seq < host->last_sync_seq) {
			i_warning("Last SYNC seq for %s appears to be stale, reseting "
				  "(seq=%u, timestamp=%u -> seq=%u, timestamp=%u)",
				  host->name, host->last_sync_seq,
				  host->last_sync_timestamp, seq, timestamp);
			host->last_sync_seq = seq;
			host->last_sync_timestamp = timestamp;
			host->last_sync_seq_counter = 1;
		} else if (seq > host->last_sync_seq ||
			   timestamp > host->last_sync_timestamp) {
			host->last_sync_seq = seq;
			host->last_sync_timestamp = timestamp;
			host->last_sync_seq_counter = 1;
			dir_debug("Update SYNC for %s "
				  "(seq=%u, timestamp=%u -> seq=%u, timestamp=%u)",
				  host->name, host->last_sync_seq,
				  host->last_sync_timestamp, seq, timestamp);
		} else if (++host->last_sync_seq_counter >
			   DIRECTOR_MAX_SYNC_SEQ_DUPLICATES) {
			/* we've received this too many times already */
			dir_debug("Ignore duplicate #%u SYNC event for %s "
				  "(seq=%u, timestamp %u <= %u)",
				  host->last_sync_seq_counter, host->name, seq,
				  timestamp, host->last_sync_timestamp);
			return FALSE;
		}

		if (hosts_hash != 0 &&
		    hosts_hash != mail_hosts_hash(conn->dir->mail_hosts)) {
			if (host->desynced_hosts_hash != hosts_hash) {
				dir_debug("Ignore director %s stale SYNC request whose hosts don't match us "
					  "(seq=%u, remote hosts_hash=%u, my hosts_hash=%u)",
					  net_ip2addr(&host->ip), seq, hosts_hash,
					  mail_hosts_hash(dir->mail_hosts));
				host->desynced_hosts_hash = hosts_hash;
				return FALSE;
			}
			/* we'll get here only if we received a SYNC twice
			   with the same wrong hosts_hash. FIXME: this gets
			   triggered unnecessarily sometimes if hosts are
			   changing rapidly. */
			i_error("director(%s): Director %s SYNC request hosts don't match us - resending hosts "
				"(seq=%u, remote hosts_hash=%u, my hosts_hash=%u)",
				conn->name, net_ip2addr(&host->ip), seq,
				hosts_hash, mail_hosts_hash(dir->mail_hosts));
			director_resend_hosts(dir);
			return FALSE;
		}
		host->desynced_hosts_hash = 0;
		if (dir->right != NULL) {
			/* forward it to the connection on right */
			director_sync_send(dir, host, seq, minor_version,
					   timestamp, hosts_hash);
		} else {
			dir_debug("director(%s): We have no right connection - "
				  "delay replying to SYNC until finished", conn->name);
			host->delayed_sync_seq = seq;
			host->delayed_sync_minor_version = minor_version;
			host->delayed_sync_timestamp = timestamp;
			host->delayed_sync_hosts_hash = hosts_hash;
		}
	}
	return TRUE;
}

static bool director_connection_sync(struct director_connection *conn,
				     const char *const *args)
{
	struct director *dir = conn->dir;
	struct director_host *host;
	struct ip_addr ip;
	in_port_t port;
	unsigned int arg_count, seq, minor_version = 0, timestamp = ioloop_time;
	unsigned int hosts_hash = 0;

	arg_count = str_array_length(args);
	if (arg_count < 3 ||
	    !director_args_parse_ip_port(conn, args, &ip, &port) ||
	    str_to_uint(args[2], &seq) < 0) {
		director_cmd_error(conn, "Invalid parameters");
		return FALSE;
	}
	if (arg_count >= 4 && str_to_uint(args[3], &minor_version) < 0) {
		director_cmd_error(conn, "Invalid parameters");
		return FALSE;
	}
	if (arg_count >= 5 && str_to_uint(args[4], &timestamp) < 0) {
		director_cmd_error(conn, "Invalid parameters");
		return FALSE;
	}
	if (arg_count >= 6 && str_to_uint(args[5], &hosts_hash) < 0) {
		director_cmd_error(conn, "Invalid parameters");
		return FALSE;
	}

	/* find the originating director. if we don't see it, it was already
	   removed and we can ignore this sync. */
	host = director_host_lookup(dir, &ip, port);
	if (host != NULL) {
		if (!director_connection_sync_host(conn, host, seq,
						   minor_version, timestamp,
						   hosts_hash))
			return TRUE;
	}

	/* If directors got disconnected while we were waiting a SYNC reply,
	   it might have gotten lost. If we've received a DIRECTOR update since
	   the last time we sent a SYNC, retry sending it here to make sure
	   it doesn't get stuck. We don't want to do this too eagerly because
	   it may trigger desynced_hosts_hash != hosts_hash mismatch, which
	   causes unnecessary error logging and hosts-resending. */
	if ((host == NULL || !host->self) &&
	    dir->last_sync_sent_ring_change_counter != dir->ring_change_counter &&
	    (time_t)dir->self_host->last_sync_timestamp != ioloop_time)
		(void)director_resend_sync(dir);
	return TRUE;
}

static bool director_cmd_connect(struct director_connection *conn,
				 const char *const *args)
{
	struct director *dir = conn->dir;
	struct director_host *host;
	struct ip_addr ip;
	in_port_t port;

	if (str_array_length(args) != 2 ||
	    !director_args_parse_ip_port(conn, args, &ip, &port)) {
		director_cmd_error(conn, "Invalid parameters");
		return FALSE;
	}

	host = director_host_get(conn->dir, &ip, port);

	/* remote suggests us to connect elsewhere */
	if (dir->right != NULL &&
	    director_host_cmp_to_self(host, dir->right->host,
				      dir->self_host) <= 0) {
		/* the old connection is the correct one */
		dir_debug("Ignoring CONNECT request to %s (current right is %s)",
			  host->name, dir->right->name);
		return TRUE;
	}

	/* reset failure timestamp so we'll actually try to connect there. */
	host->last_network_failure = 0;
	/* reset removed-flag, so we don't crash */
	host->removed = FALSE;

	if (dir->right == NULL) {
		dir_debug("Received CONNECT request to %s, "
			  "initializing right", host->name);
	} else {
		dir_debug("Received CONNECT request to %s, "
			  "replacing current right %s",
			  host->name, dir->right->name);
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
					      dir->self_host) < 0)
			director_connection_send_connect(conn, dir->left->host);
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
	if (strcmp(cmd, "USER-KICK") == 0)
		return director_cmd_user_kick(conn, args);
	if (strcmp(cmd, "USER-KICK-ALT") == 0)
		return director_cmd_user_kick_alt(conn, args);
	if (strcmp(cmd, "USER-KICK-HASH") == 0)
		return director_cmd_user_kick_hash(conn, args);
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
	if (strcmp(cmd, "QUIT") == 0) {
		i_warning("Director %s disconnected us with reason: %s",
			  conn->name, t_strarray_join(args, " "));
		return FALSE;
	}

	director_cmd_error(conn, "Unknown command %s", cmd);
	return FALSE;
}

static bool
director_connection_handle_line(struct director_connection *conn,
				const char *line)
{
	const char *cmd, *const *args;
	bool ret;

	dir_debug("input: %s: %s", conn->name, line);

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

static void
director_connection_log_disconnect(struct director_connection *conn, int err,
				   const char *errstr)
{
	unsigned int secs = ioloop_time - conn->created;
	string_t *str = t_str_new(128);

	i_assert(conn->connected);

	if (conn->connect_request_to != NULL) {
		i_warning("Director %s tried to connect to us, "
			  "should use %s instead",
			  conn->name, conn->connect_request_to->name);
		return;
	}

	str_printfa(str, "Director %s disconnected: ", conn->name);
	str_append(str, "Connection closed");
	if (err != 0 && err != EPIPE) {
		errno = err;
		if (errstr[0] == '\0')
			str_printfa(str, ": %m");
		else
			str_printfa(str, ": %s", errstr);
	}

	str_printfa(str, " (connected %u secs, "
		    "in=%"PRIuUOFF_T" out=%"PRIuUOFF_T,
		    secs, conn->input->v_offset, conn->output->offset);

	if (!conn->me_received)
		str_append(str, ", handshake ME not received");
	else if (!conn->handshake_received)
		str_append(str, ", handshake DONE not received");
	i_error("%s", str_c(str));
}

static void director_connection_input(struct director_connection *conn)
{
	struct director *dir = conn->dir;
	char *line;
	uoff_t prev_offset;
	bool ret;

	switch (i_stream_read(conn->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		director_connection_log_disconnect(conn, conn->input->stream_errno,
						   i_stream_get_error(conn->input));
		director_connection_disconnected(&conn, i_stream_get_error(conn->input));
		return;
	case -2:
		/* buffer full */
		director_cmd_error(conn, "Director sent us more than %d bytes",
				   MAX_INBUF_SIZE);
		director_connection_reconnect(&conn, "Too long input line");
		return;
	}

	if (conn->to_disconnect != NULL) {
		/* just read everything the remote sends, and wait for it
		   to disconnect. we mainly just want the remote to read the
		   CONNECT we sent it. */
		i_stream_skip(conn->input, i_stream_get_data_size(conn->input));
		return;
	}
	conn->last_input = ioloop_timeval;

	director_sync_freeze(dir);
	prev_offset = conn->input->v_offset;
	while ((line = i_stream_next_line(conn->input)) != NULL) {
		dir->ring_traffic_input += conn->input->v_offset - prev_offset;
		prev_offset = conn->input->v_offset;

		T_BEGIN {
			ret = director_connection_handle_line(conn, line);
		} T_END;

		if (!ret) {
			director_connection_reconnect(&conn, t_strdup_printf(
				"Invalid input: %s", line));
			break;
		}
	}
	director_sync_thaw(dir);
	if (conn != NULL)
		timeout_reset(conn->to_ping);
}

static void director_connection_send_directors(struct director_connection *conn)
{
	struct director_host *const *hostp;
	string_t *str = t_str_new(64);

	array_foreach(&conn->dir->dir_hosts, hostp) {
		if ((*hostp)->removed)
			continue;

		str_truncate(str, 0);
		str_printfa(str, "DIRECTOR\t%s\t%u\n",
			    net_ip2addr(&(*hostp)->ip), (*hostp)->port);
		director_connection_send(conn, str_c(str));
	}
}

static void
director_connection_send_hosts(struct director_connection *conn)
{
	struct mail_host *const *hostp;
	bool send_updowns;
	string_t *str = t_str_new(128);

	i_assert(conn->version_received);

	send_updowns = conn->minor_version >= DIRECTOR_VERSION_UPDOWN;

	str_printfa(str, "HOST-HAND-START\t%u\n", conn->dir->ring_handshaked);
	array_foreach(mail_hosts_get(conn->dir->mail_hosts), hostp) {
		struct mail_host *host = *hostp;
		const char *host_tag = mail_host_get_tag(host);

		str_printfa(str, "HOST\t%s\t%u",
			    net_ip2addr(&host->ip), host->vhost_count);
		if (host_tag[0] != '\0' || send_updowns) {
			str_append_c(str, '\t');
			str_append_tabescaped(str, host_tag);
		}
		if (send_updowns) {
			str_printfa(str, "\t%c%ld\t", host->down ? 'D' : 'U',
				    (long)host->last_updown_change);
			if (host->hostname != NULL)
				str_append_tabescaped(str, host->hostname);
		}
		str_append_c(str, '\n');
		director_connection_send(conn, str_c(str));
		str_truncate(str, 0);
	}
	str_printfa(str, "HOST-HAND-END\t%u\n", conn->dir->ring_handshaked);
	director_connection_send(conn, str_c(str));
}

static int director_connection_send_done(struct director_connection *conn)
{
	i_assert(conn->version_received);

	if (!conn->dir->set->director_consistent_hashing)
		;
	else if (conn->minor_version >= DIRECTOR_VERSION_OPTIONS) {
		director_connection_send(conn,
			"OPTIONS\t"DIRECTOR_OPT_CONSISTENT_HASHING"\n");
	} else {
		i_error("director(%s): Director version is too old for supporting director_consistent_hashing=yes",
			conn->name);
		return -1;
	}
	director_connection_send(conn, "DONE\n");
	return 0;
}

static int director_connection_send_users(struct director_connection *conn)
{
	struct user *user;
	int ret;

	i_assert(conn->version_received);

	while ((user = director_iterate_users_next(conn->user_iter)) != NULL) {
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
	director_iterate_users_deinit(&conn->user_iter);
	if (director_connection_send_done(conn) < 0)
		return -1;

	if (conn->users_unsorted && conn->handshake_received) {
		/* we received remote's list of users before sending ours */
		conn->users_unsorted = FALSE;
		mail_hosts_sort_users(conn->dir->mail_hosts);
	}

	ret = o_stream_flush(conn->output);
	timeout_reset(conn->to_ping);
	return ret;
}

static int director_connection_output(struct director_connection *conn)
{
	int ret;

	conn->last_output = ioloop_timeval;
	if (conn->user_iter != NULL) {
		/* still handshaking USER list */
		o_stream_cork(conn->output);
		ret = director_connection_send_users(conn);
		o_stream_uncork(conn->output);
		if (ret < 0) {
			director_connection_disconnected(&conn,
				o_stream_get_error(conn->output));
		} else {
			o_stream_set_flush_pending(conn->output, TRUE);
		}
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
	o_stream_set_no_error_handling(conn->output, TRUE);
	conn->to_ping = timeout_add(DIRECTOR_CONNECTION_ME_TIMEOUT_MSECS,
				    director_connection_init_timeout, conn);
	array_append(&dir->connections, &conn, 1);
	return conn;
}

static void director_connection_send_handshake(struct director_connection *conn)
{
	director_connection_send(conn, t_strdup_printf(
		"VERSION\t"DIRECTOR_VERSION_NAME"\t%u\t%u\n"
		"ME\t%s\t%u\t%lld\n",
		DIRECTOR_VERSION_MAJOR, DIRECTOR_VERSION_MINOR,
		net_ip2addr(&conn->dir->self_ip), conn->dir->self_port,
		(long long)time(NULL)));
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
	int err;

	if ((err = net_geterror(conn->fd)) != 0) {
		i_error("director(%s): connect() failed: %s", conn->name,
			strerror(err));
		director_connection_disconnected(&conn, strerror(err));
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
	director_connection_send_directors(conn);
	o_stream_uncork(conn->output);
	/* send the rest of the handshake after we've received the remote's
	   version number */
}

static void director_finish_sending_handshake(struct director_connection *conn)
{
	if (
	    conn->in) {
		/* only outgoing connections send hosts & users */
		return;
	}
	o_stream_cork(conn->output);
	director_connection_send_hosts(conn);

	i_assert(conn->user_iter == NULL);
	conn->user_iter = director_iterate_users_init(conn->dir);

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
	director_host_restarted(host);

	conn = director_connection_init_common(dir, fd);
	conn->name = i_strdup_printf("%s/out", host->name);
	conn->host = host;
	director_host_ref(host);
	conn->io = io_add(conn->fd, IO_WRITE,
			  director_connection_connected, conn);
	return conn;
}

void director_connection_deinit(struct director_connection **_conn,
				const char *remote_reason)
{
	struct director_connection *const *conns, *conn = *_conn;
	struct director *dir = conn->dir;
	unsigned int i, count;

	*_conn = NULL;

	if (conn->host != NULL) {
		dir_debug("Disconnecting from %s: %s",
			  conn->host->name, remote_reason);
	}
	if (*remote_reason != '\0' &&
	    conn->minor_version >= DIRECTOR_VERSION_QUIT) {
		o_stream_send_str(conn->output, t_strdup_printf(
			"QUIT\t%s\n", remote_reason));
	}

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

	if (conn->connect_request_to != NULL)
		director_host_unref(conn->connect_request_to);
	if (conn->user_iter != NULL)
		director_iterate_users_deinit(&conn->user_iter);
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

static void director_connection_disconnected(struct director_connection **_conn,
					     const char *reason)
{
	struct director_connection *conn = *_conn;
	struct director *dir = conn->dir;

	if (conn->created + DIRECTOR_SUCCESS_MIN_CONNECT_SECS > ioloop_time &&
	    conn->host != NULL) {
		/* connection didn't exist for very long, assume it has a
		   network problem */
		conn->host->last_network_failure = ioloop_time;
	}

	director_connection_deinit(_conn, reason);
	if (dir->right == NULL)
		director_connect(dir);
}

static void director_connection_reconnect(struct director_connection **_conn,
					  const char *reason)
{
	struct director_connection *conn = *_conn;
	struct director *dir = conn->dir;

	director_connection_deinit(_conn, reason);
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

	if (director_debug) T_BEGIN {
		const char *const *lines = t_strsplit(data, "\n");
		for (; lines[1] != NULL; lines++)
			dir_debug("output: %s: %s", conn->name, *lines);
	} T_END;
	ret = o_stream_send(conn->output, data, len);
	if (ret != (off_t)len) {
		if (ret < 0) {
			i_error("director(%s): write() failed: %s", conn->name,
				o_stream_get_error(conn->output));
		} else {
			i_error("director(%s): Output buffer full, "
				"disconnecting", conn->name);
		}
		o_stream_close(conn->output);
	} else {
		conn->dir->ring_traffic_output += len;
	}
}

static void
director_connection_ping_idle_timeout(struct director_connection *conn)
{
	int input_diff = timeval_diff_msecs(&ioloop_timeval, &conn->last_input);
	int output_diff = timeval_diff_msecs(&ioloop_timeval, &conn->last_output);
	string_t *str = t_str_new(128);

	str_printfa(str, "Ping timed out, disconnecting "
		    "(last input %u.%03u s ago, last output %u.%03u s ago",
		    input_diff/1000, input_diff%1000,
		    output_diff/1000, output_diff%1000);
	if (conn->handshake_received)
		str_append(str, ", handshaked");
	if (conn->synced)
		str_append(str, ", synced");
	str_append_c(str, ')');
	i_error("director(%s): %s", conn->name, str_c(str));
	director_connection_disconnected(&conn, "Ping timeout");
}

static void director_connection_pong_timeout(struct director_connection *conn)
{
	i_error("director(%s): PONG reply not received although other "
		"input keeps coming, disconnecting", conn->name);
	director_connection_disconnected(&conn, "Pong timeout");
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

bool director_connection_is_synced(struct director_connection *conn)
{
	return conn->synced;
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
