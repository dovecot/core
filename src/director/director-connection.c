/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "llist.h"
#include "master-service.h"
#include "mail-host.h"
#include "director.h"
#include "director-host.h"
#include "director-request.h"
#include "user-directory.h"
#include "director-connection.h"

#include <stdlib.h>
#include <unistd.h>

#define DIRECTOR_VERSION_NAME "director"
#define DIRECTOR_VERSION_MAJOR 1
#define DIRECTOR_VERSION_MINOR 0

#define MAX_INBUF_SIZE 1024
#define MAX_OUTBUF_SIZE (1024*1024*10)
#define OUTBUF_FLUSH_THRESHOLD (1024*128)
/* Max idling time while connecting/handshaking before disconnecting */
#define DIRECTOR_CONNECTION_INIT_TIMEOUT_MSECS (2*1000)
/* How long to wait for PONG after PING request */
#define DIRECTOR_CONNECTION_PING_TIMEOUT_MSECS (2*1000)
/* How long to wait to send PING when connection is idle */
#define DIRECTOR_CONNECTION_PING_INTERVAL_MSECS (15*1000)
/* How long to wait before sending PING while waiting for SYNC reply */
#define DIRECTOR_CONNECTION_SYNC_TIMEOUT_MSECS 1000
/* If outgoing director connection exists for less than this many seconds,
   mark the host as failed so we won't try to reconnect to it immediately */
#define DIRECTOR_SUCCESS_MIN_CONNECT_SECS 10

struct director_connection {
	struct director_connection *prev, *next;

	struct director *dir;
	char *name;
	time_t created;

	/* for incoming connections the director host isn't known until
	   ME-line is received */
	struct director_host *host;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;
	struct timeout *to, *to_ping;

	struct user_directory_iter *user_iter;

	unsigned int in:1;
	unsigned int connected:1;
	unsigned int version_received:1;
	unsigned int me_received:1;
	unsigned int handshake_received:1;
	unsigned int ignore_host_events:1;
	unsigned int handshake_sending_hosts:1;
	unsigned int ping_waiting:1;
	unsigned int sync_ping:1;
};

static void director_connection_ping(struct director_connection *conn);
static void director_connection_disconnected(struct director_connection **conn);

static bool
director_args_parse_ip_port(struct director_connection *conn,
			    const char *const *args,
			    struct ip_addr *ip_r, unsigned int *port_r)
{
	if (net_addr2ip(args[0], ip_r) < 0) {
		i_error("director(%s): Command has invalid IP address: %s",
			conn->name, args[0]);
		return FALSE;
	}
	if (str_to_uint(args[1], port_r) < 0) {
		i_error("director(%s): Command has invalid port: %s",
			conn->name, args[1]);
		return FALSE;
	}
	return TRUE;
}

static bool director_cmd_me(struct director_connection *conn,
			    const char *const *args)
{
	struct director *dir = conn->dir;
	struct director_host *host;
	const char *connect_str;
	struct ip_addr ip;
	unsigned int port;

	if (!director_args_parse_ip_port(conn, args, &ip, &port))
		return FALSE;

	if (!conn->in && (!net_ip_compare(&conn->host->ip, &ip) ||
			  conn->host->port != port)) {
		i_error("Remote director thinks it's someone else "
			"(connected to %s:%u, remote says it's %s:%u)",
			net_ip2addr(&conn->host->ip), conn->host->port,
			net_ip2addr(&ip), port);
		return FALSE;
	}
	host = director_host_get(dir, &ip, port);
	/* the host is up now, make sure we can connect to it immediately
	   if needed */
	host->last_failed = 0;
	conn->me_received = TRUE;

	if (!conn->in)
		return TRUE;

	i_free(conn->name);
	conn->name = i_strdup_printf("%s/left", host->name);
	conn->host = host;
	/* make sure we don't keep old sequence values across restarts */
	host->last_seq = 0;

	connect_str = t_strdup_printf("CONNECT\t%s\t%u\n",
				      net_ip2addr(&host->ip), host->port);
	/* make sure this is the correct incoming connection */
	if (host->self) {
		/* probably we're trying to find our own ip. it's no */
		i_error("Connection from self, dropping");
		return FALSE;
	} else if (dir->left == NULL) {
		/* no conflicts yet */
	} else if (dir->left->host == host) {
		i_warning("Dropping existing connection %s "
			  "in favor of its new connection %s",
			  dir->left->host->name, host->name);
		director_connection_deinit(&dir->left);
	} else {
		if (director_host_cmp_to_self(dir->left->host, host,
					      dir->self_host) < 0) {
			/* the old connection is the correct one.
			   refer the client there. */
			i_warning("Director connection %s tried to connect to "
				  "us, should use %s instead",
				  host->name, dir->left->host->name);
			director_connection_send(conn, t_strdup_printf(
				"CONNECT\t%s\t%u\n",
				net_ip2addr(&dir->left->host->ip),
				dir->left->host->port));
			/* also make sure that the connection is alive */
			director_connection_ping(dir->left);
			return FALSE;
		}

		/* this new connection is the correct one. disconnect the old
		   one, but before that tell it to connect to the new one.
		   that message might not reach it, so also send the same
		   message to right side. */
		i_warning("Replacing director connection %s with %s",
			  dir->left->host->name, host->name);
		director_connection_send(dir->left, connect_str);
		(void)o_stream_flush(dir->left->output);
		director_connection_deinit(&dir->left);
	}
	dir->left = conn;

	/* tell the ring's right side to connect to this new director. */
	if (dir->right != NULL) {
		if (dir->left->host != dir->right->host)
			director_connection_send(dir->right, connect_str);
		else {
			/* there are only two directors, and we already have
			   a connection to this server. */
		}
	} else {
		/* there are only two directors. connect to the other one. */
		(void)director_connect_host(dir, host);
	}
	return TRUE;
}

static bool
director_user_refresh(struct director *dir, unsigned int username_hash,
		      struct mail_host *host, time_t timestamp,
		      struct user **user_r)
{
	struct user *user;
	bool ret = FALSE;

	user = user_directory_lookup(dir->users, username_hash);
	if (user == NULL) {
		*user_r = user_directory_add(dir->users, username_hash,
					     host, timestamp);
		return TRUE;
	}
	if (timestamp == ioloop_time && (time_t)user->timestamp != timestamp) {
		user_directory_refresh(dir->users, user);
		ret = TRUE;
	}

	if (user->host != host) {
		i_error("User hash %u is being redirected to two hosts: "
			"%s and %s", username_hash,
			net_ip2addr(&user->host->ip),
			net_ip2addr(&host->ip));

		/* we want all the directors to redirect the user to same
		   server, but we don't want two directors fighting over which
		   server it belongs to, so always use the lower IP address */
		if (net_ip_cmp(&user->host->ip, &host->ip) > 0) {
			/* change the host. we'll also need to remove the user
			   from the old host's user_count, because we can't
			   keep track of the user for more than one host */
			user->host->user_count--;
			user->host = host;
			user->host->user_count++;
		}
		ret = TRUE;
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

	if (str_array_length(args) != 3 ||
	    str_to_uint(args[0], &username_hash) < 0 ||
	    net_addr2ip(args[1], &ip) < 0 ||
	    str_to_uint(args[2], &timestamp) < 0) {
		i_error("director(%s): Invalid USER handshake args",
			conn->name);
		return FALSE;
	}

	host = mail_host_lookup(conn->dir->mail_hosts, &ip);
	if (host == NULL) {
		i_error("director(%s): USER used unknown host %s in handshake",
			conn->name, args[1]);
		return FALSE;
	}

	director_user_refresh(conn->dir, username_hash, host, timestamp, &user);
	return TRUE;
}

static bool
director_cmd_user(struct director_connection *conn, const char *const *args)
{
	unsigned int username_hash;
	struct ip_addr ip;
	struct mail_host *host;
	struct user *user;

	if (str_array_length(args) != 2 ||
	    str_to_uint(args[0], &username_hash) < 0 ||
	    net_addr2ip(args[1], &ip) < 0) {
		i_error("director(%s): Invalid USER args", conn->name);
		return FALSE;
	}

	host = mail_host_lookup(conn->dir->mail_hosts, &ip);
	if (host == NULL) {
		/* we probably just removed this host. */
		return TRUE;
	}

	if (director_user_refresh(conn->dir, username_hash,
				  host, ioloop_time, &user))
		director_update_user(conn->dir, conn->host, user);
	return TRUE;
}

static bool director_cmd_director(struct director_connection *conn,
				  const char *const *args)
{
	struct director_host *host;
	struct ip_addr ip;
	unsigned int port;

	if (!director_args_parse_ip_port(conn, args, &ip, &port))
		return FALSE;

	host = director_host_lookup(conn->dir, &ip, port);
	if (host != NULL) {
		/* already have this. just reset its last_failed timestamp,
		   since it might be up now. */
		host->last_failed = 0;
		return TRUE;
	}

	/* save the director and forward it */
	director_host_add(conn->dir, &ip, port);
	director_connection_send(conn->dir->right,
		t_strdup_printf("DIRECTOR\t%s\t%u\n", net_ip2addr(&ip), port));
	return TRUE;
}

static bool
director_cmd_host_hand_start(struct director_connection *conn,
			     const char *const *args)
{
	const ARRAY_TYPE(mail_host) *hosts;
	struct mail_host *const *hostp;
	unsigned int remote_ring_completed;

	if (args == NULL || str_to_uint(args[0], &remote_ring_completed) < 0) {
		i_error("director(%s): Invalid HOST-HAND-START args",
			conn->name);
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
		i_error("director(%s): Command is missing parameters: %s",
			conn->name, t_strarray_join(args, " "));
		return -1;
	}
	*_args = args + 3;

	host = director_host_lookup(conn->dir, &ip, port);
	if (host == NULL) {
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
		i_error("director(%s): Invalid HOST args", conn->name);
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
		i_error("director(%s): Invalid HOST-REMOVE args", conn->name);
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
		i_error("director(%s): Invalid HOST-FLUSH args", conn->name);
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
		i_error("director(%s): Invalid USER-MOVE args", conn->name);
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
		i_error("director(%s): Invalid USER-KILLED args", conn->name);
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
		i_error("director(%s): Invalid USER-KILLED-EVERYWHERE args",
			conn->name);
		return FALSE;
	}

	director_user_killed_everywhere(conn->dir, conn->host,
					dir_host, username_hash);
	return TRUE;
}

static void director_handshake_cmd_done(struct director_connection *conn)
{
	struct director *dir = conn->dir;

	if (dir->debug)
		i_debug("Handshaked to %s", conn->host->name);

	conn->host->last_failed = 0;
	conn->handshake_received = TRUE;
	if (conn->in) {
		/* handshaked to left side. tell it we've received the
		   whole handshake. */
		director_connection_send(conn, "DONE\n");

		/* tell the right director about the left one */
		if (dir->right != NULL) {
			director_connection_send(dir->right,
				t_strdup_printf("DIRECTOR\t%s\t%u\n",
						net_ip2addr(&conn->host->ip),
						conn->host->port));
		}
	}

	if (dir->left != NULL && dir->right != NULL &&
	    dir->left->handshake_received && dir->right->handshake_received) {
		/* we're connected to both directors. see if the ring is
		   finished by sending a SYNC. if we get it back, it's done. */
		dir->sync_seq++;
		dir->ring_synced = FALSE;
		director_connection_send(dir->right,
			t_strdup_printf("SYNC\t%s\t%u\t%u\n",
					net_ip2addr(&dir->self_ip),
					dir->self_port, dir->sync_seq));
	}
	if (conn->to_ping != NULL)
		timeout_remove(&conn->to_ping);
	conn->to_ping = timeout_add(DIRECTOR_CONNECTION_PING_INTERVAL_MSECS,
				    director_connection_ping, conn);
}

static bool
director_connection_handle_handshake(struct director_connection *conn,
				     const char *cmd, const char *const *args)
{
	struct director_host *host;
	struct ip_addr ip;
	unsigned int port;

	/* both incoming and outgoing connections get VERSION and ME */
	if (strcmp(cmd, "VERSION") == 0 && str_array_length(args) >= 3) {
		if (strcmp(args[0], DIRECTOR_VERSION_NAME) != 0) {
			i_error("director(%s): Wrong protocol in socket "
				"(%s vs %s)",
				conn->name, args[0], DIRECTOR_VERSION_NAME);
			return FALSE;
		} else if (atoi(args[1]) != DIRECTOR_VERSION_MAJOR) {
			i_error("director(%s): Incompatible protocol version: "
				"%u vs %u", conn->name, atoi(args[1]),
				DIRECTOR_VERSION_MAJOR);
			return FALSE;
		}
		conn->version_received = TRUE;
		return TRUE;
	}
	if (!conn->version_received) {
		i_error("director(%s): Incompatible protocol", conn->name);
		return FALSE;
	}

	if (strcmp(cmd, "ME") == 0 && !conn->me_received &&
	    str_array_length(args) == 2)
		return director_cmd_me(conn, args);

	/* only outgoing connections get a CONNECT reference */
	if (!conn->in && strcmp(cmd, "CONNECT") == 0 &&
	    str_array_length(args) == 2) {
		/* remote wants us to connect elsewhere */
		if (!director_args_parse_ip_port(conn, args, &ip, &port))
			return FALSE;

		conn->dir->right = NULL;
		host = director_host_get(conn->dir, &ip, port);
		/* reset failure timestamp so we'll actually try to
		   connect there. */
		host->last_failed = 0;
		if (conn->dir->debug)
			i_debug("Received CONNECT reference to %s", host->name);
		(void)director_connect_host(conn->dir, host);
		return FALSE;
	}
	/* only incoming connections get DIRECTOR and HOST lists */
	if (conn->in && strcmp(cmd, "DIRECTOR") == 0 && conn->me_received)
		return director_cmd_director(conn, args);

	if (strcmp(cmd, "HOST") == 0) {
		/* allow hosts from all connections always,
		   this could be an host update */
		if (conn->handshake_sending_hosts)
			return director_cmd_host_handshake(conn, args);
		else
			return director_cmd_host(conn, args);
	}
	if (conn->handshake_sending_hosts &&
	    strcmp(cmd, "HOST-HAND-END") == 0) {
		conn->ignore_host_events = FALSE;
		conn->handshake_sending_hosts = FALSE;
		return TRUE;
	}
	if (conn->in && strcmp(cmd, "HOST-HAND-START") == 0 &&
	    conn->me_received)
		return director_cmd_host_hand_start(conn, args);

	/* only incoming connections get a full USER list, but outgoing
	   connections can also receive USER updates during handshake and
	   it wouldn't be safe to ignore them. */
	if (strcmp(cmd, "USER") == 0 && conn->me_received) {
		if (conn->in)
			return director_handshake_cmd_user(conn, args);
		else
			return director_cmd_user(conn, args);
	}
	/* both get DONE */
	if (strcmp(cmd, "DONE") == 0 && !conn->handshake_received &&
	    !conn->handshake_sending_hosts) {
		director_handshake_cmd_done(conn);
		return TRUE;
	}
	i_error("director(%s): Invalid handshake command: %s "
		"(in=%d me_received=%d)", conn->name, cmd,
		conn->in, conn->me_received);
	return FALSE;
}

static bool director_connection_sync(struct director_connection *conn,
				     const char *const *args, const char *line)
{
	struct director *dir = conn->dir;
	struct director_host *host;
	struct ip_addr ip;
	unsigned int port, seq;

	if (str_array_length(args) != 3 ||
	    !director_args_parse_ip_port(conn, args, &ip, &port) ||
	    str_to_uint(args[2], &seq) < 0) {
		i_error("director(%s): Invalid SYNC args", conn->name);
		return FALSE;
	}

	/* find the originating director. if we don't see it, it was already
	   removed and we can ignore this sync. */
	host = director_host_lookup(dir, &ip, port);
	if (host == NULL)
		return TRUE;

	if (host->self) {
		if (dir->sync_seq != seq) {
			/* stale SYNC event */
			return TRUE;
		}

		if (!dir->ring_handshaked) {
			/* the ring is handshaked */
			director_set_ring_handshaked(dir);
		} else if (dir->ring_synced) {
			i_error("Received SYNC from %s (seq=%u) "
				"while already synced", conn->name, seq);
			return TRUE;
		} else {
			if (dir->debug) {
				i_debug("Ring is synced (%s sent seq=%u)",
					conn->name, seq);
			}
			director_set_ring_synced(dir);
		}
		return TRUE;
	}

	/* forward it to the connection on right */
	if (dir->right != NULL) {
		director_connection_send(dir->right,
					 t_strconcat(line, "\n", NULL));
	}
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
		i_error("director(%s): Invalid CONNECT args", conn->name);
		return FALSE;
	}

	host = director_host_lookup(dir, &ip, port);
	if (host == NULL) {
		i_error("Received CONNECT request to unknown host %s:%u",
			net_ip2addr(&ip), port);
		return TRUE;
	}

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

static bool director_cmd_pong(struct director_connection *conn)
{
	if (!conn->ping_waiting)
		return TRUE;

	conn->ping_waiting = FALSE;
	timeout_remove(&conn->to_ping);
	conn->to_ping = timeout_add(DIRECTOR_CONNECTION_PING_INTERVAL_MSECS,
				    director_connection_ping, conn);
	return TRUE;
}

static bool
director_connection_handle_line(struct director_connection *conn,
				const char *line)
{
	const char *cmd, *const *args;

	args = t_strsplit(line, "\t");
	cmd = args[0]; args++;
	if (cmd == NULL) {
		i_error("director(%s): Received empty line", conn->name);
		return FALSE;
	}

	/* ping/pong is always handled */
	if (strcmp(cmd, "PING") == 0) {
		director_connection_send(conn, "PONG\n");
		return TRUE;
	}
	if (strcmp(cmd, "PONG") == 0)
		return director_cmd_pong(conn);

	if (!conn->handshake_received) {
		if (!director_connection_handle_handshake(conn, cmd, args)) {
			/* invalid commands during handshake,
			   we probably don't want to reconnect here */
			if (conn->dir->debug) {
				i_debug("director(%s): Handshaking failed",
					conn->host->name);
			}
			if (conn->host != NULL)
				conn->host->last_failed = ioloop_time;
			return FALSE;
		}
		return TRUE;
	}

	if (strcmp(cmd, "USER") == 0)
		return director_cmd_user(conn, args);
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
	if (strcmp(cmd, "SYNC") == 0)
		return director_connection_sync(conn, args, line);
	if (strcmp(cmd, "CONNECT") == 0)
		return director_cmd_connect(conn, args);

	i_error("director(%s): Unknown command (in this state): %s",
		conn->name, cmd);
	return FALSE;
}

static void director_connection_input(struct director_connection *conn)
{
	struct director *dir = conn->dir;
	char *line;
	bool ret;

	if (conn->to_ping != NULL)
		timeout_reset(conn->to_ping);
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
		i_error("BUG: Director %s sent us more than %d bytes",
			conn->name, MAX_INBUF_SIZE);
		director_connection_disconnected(&conn);
		return;
	}

	director_sync_freeze(dir);
	while ((line = i_stream_next_line(conn->input)) != NULL) {
		T_BEGIN {
			ret = director_connection_handle_line(conn, line);
		} T_END;

		if (!ret) {
			if (dir->debug) {
				i_debug("director(%s): Invalid input, disconnecting",
					conn->name);
			}
			director_connection_disconnected(&conn);
			break;
		}
	}
	director_sync_thaw(dir);
}

static void director_connection_send_directors(struct director_connection *conn,
					       string_t *str)
{
	struct director_host *const *hostp;

	array_foreach(&conn->dir->dir_hosts, hostp) {
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

	o_stream_cork(conn->output);
	while ((user = user_directory_iter_next(conn->user_iter)) != NULL) {
		if (!user_directory_user_has_connections(conn->dir->users,
							 user)) {
			/* user is already expired */
			continue;
		}

		T_BEGIN {
			const char *line;

			line = t_strdup_printf("USER\t%u\t%s\t%u\n",
					       user->username_hash,
					       net_ip2addr(&user->host->ip),
					       user->timestamp);
			director_connection_send(conn, line);
		} T_END;

		if (o_stream_get_buffer_used_size(conn->output) >= OUTBUF_FLUSH_THRESHOLD) {
			if ((ret = o_stream_flush(conn->output)) <= 0) {
				/* continue later */
				return ret;
			}
		}
	}
	user_directory_iter_deinit(&conn->user_iter);
	director_connection_send(conn, "DONE\n");

	i_assert(conn->io == NULL);
	conn->io = io_add(conn->fd, IO_READ, director_connection_input, conn);

	ret = o_stream_flush(conn->output);
	o_stream_uncork(conn->output);
	return ret;
}

static int director_connection_output(struct director_connection *conn)
{
	if (conn->user_iter != NULL)
		return director_connection_send_users(conn);
	else
		return o_stream_flush(conn->output);
}

static void
director_connection_init_timeout(struct director_connection *conn)
{
	if (conn->host != NULL)
		conn->host->last_failed = ioloop_time;
	if (!conn->connected)
		i_error("director(%s): Connect timed out", conn->name);
	else
		i_error("director(%s): Handshaking timed out", conn->name);
	director_connection_disconnected(&conn);
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
	o_stream_set_flush_callback(conn->output,
				    director_connection_output, conn);
	conn->to_ping = timeout_add(DIRECTOR_CONNECTION_INIT_TIMEOUT_MSECS,
				    director_connection_init_timeout, conn);
	DLLIST_PREPEND(&dir->connections, conn);
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
		conn->host->last_failed = ioloop_time;
		i_error("director(%s): connect() failed: %s", conn->name,
			strerror(err));
		director_connection_disconnected(&conn);
		return;
	}
	conn->connected = TRUE;

	if (dir->right != NULL) {
		/* see if we should disconnect or keep the existing
		   connection. */
		if (director_host_cmp_to_self(conn->host, dir->right->host,
					      dir->self_host) <= 0) {
			/* the old connection is the correct one */
			i_warning("Aborting incorrect outgoing connection to %s "
				  "(already connected to correct one: %s)",
				  conn->host->name, dir->right->host->name);
			director_connection_deinit(&conn);
			return;
		}
		i_warning("Replacing director connection %s with %s",
			  dir->right->host->name, conn->host->name);
		director_connection_deinit(&dir->right);
	}
	dir->right = conn;
	i_free(conn->name);
	conn->name = i_strdup_printf("%s/right", conn->host->name);

	io_remove(&conn->io);

	director_connection_send_handshake(conn);
	director_connection_send_directors(conn, str);
	director_connection_send_hosts(conn, str);
	director_connection_send(conn, str_c(str));

	conn->user_iter = user_directory_iter_init(dir->users);
	(void)director_connection_send_users(conn);
}

struct director_connection *
director_connection_init_out(struct director *dir, int fd,
			     struct director_host *host)
{
	struct director_connection *conn;

	/* make sure we don't keep old sequence values across restarts */
	host->last_seq = 0;

	conn = director_connection_init_common(dir, fd);
	conn->name = i_strdup_printf("%s/out", host->name);
	conn->host = host;
	/* use IO_READ instead of IO_WRITE, so that we don't assign
	   dir->right until remote has actually sent some data */
	conn->io = io_add(conn->fd, IO_READ,
			  director_connection_connected, conn);
	return conn;
}

void director_connection_deinit(struct director_connection **_conn)
{
	struct director_connection *conn = *_conn;
	struct director *dir = conn->dir;

	*_conn = NULL;

	if (dir->debug && conn->host != NULL)
		i_debug("Disconnecting from %s", conn->host->name);

	if (conn->host != NULL && !conn->in &&
	    conn->created + DIRECTOR_SUCCESS_MIN_CONNECT_SECS > ioloop_time)
		conn->host->last_failed = ioloop_time;

	DLLIST_REMOVE(&dir->connections, conn);
	if (dir->left == conn)
		dir->left = NULL;
	if (dir->right == conn)
		dir->right = NULL;

	if (conn->user_iter != NULL)
		user_directory_iter_deinit(&conn->user_iter);
	if (conn->to != NULL)
		timeout_remove(&conn->to);
	if (conn->to_ping != NULL)
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
		dir->ring_synced = FALSE;
	}
}

void director_connection_disconnected(struct director_connection **_conn)
{
	struct director_connection *conn = *_conn;
	struct director *dir = conn->dir;

	director_connection_deinit(_conn);
	if (dir->right == NULL)
		director_connect(dir);
}

static void director_connection_timeout(struct director_connection *conn)
{
	director_connection_disconnected(&conn);
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
		conn->to = timeout_add(0, director_connection_timeout, conn);
	}
}

void director_connection_send_except(struct director_connection *conn,
				     struct director_host *skip_host,
				     const char *data)
{
	if (conn->host != skip_host)
		director_connection_send(conn, data);
}

static void director_connection_ping_timeout(struct director_connection *conn)
{
	i_error("director(%s): Ping timed out, disconnecting", conn->name);
	director_connection_disconnected(&conn);
}

static void director_connection_ping(struct director_connection *conn)
{
	conn->sync_ping = FALSE;
	if (conn->ping_waiting)
		return;

	if (conn->to_ping != NULL)
		timeout_remove(&conn->to_ping);
	conn->to_ping = timeout_add(DIRECTOR_CONNECTION_PING_TIMEOUT_MSECS,
				    director_connection_ping_timeout, conn);
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

struct director_connection *
director_connection_find_outgoing(struct director *dir,
				  struct director_host *host)
{
	struct director_connection *conn;

	for (conn = dir->connections; conn != NULL; conn = conn->next) {
		if (conn->host == host && !conn->in)
			return conn;
	}
	return NULL;
}

void director_connection_cork(struct director_connection *conn)
{
	o_stream_cork(conn->output);
}

void director_connection_uncork(struct director_connection *conn)
{
	o_stream_uncork(conn->output);
}

void director_connection_wait_sync(struct director_connection *conn)
{
	/* switch to faster ping timeout. avoid reseting the timeout if it's
	   already fast. */
	if (conn->ping_waiting || conn->sync_ping)
		return;

	if (conn->to_ping != NULL)
		timeout_remove(&conn->to_ping);
	conn->to_ping = timeout_add(DIRECTOR_CONNECTION_SYNC_TIMEOUT_MSECS,
				    director_connection_ping, conn);
	conn->sync_ping = TRUE;
}

void director_connections_deinit(struct director *dir)
{
	struct director_connection *conn;

	while (dir->connections != NULL) {
		conn = dir->connections;
		dir->connections = conn->next;
		director_connection_deinit(&conn);
	}
}
