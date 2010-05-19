/* Copyright (c) 2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
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
#define DIRECTOR_CONNECTION_PING_TIMEOUT_MSECS (2*1000)

struct director_connection {
	struct director *dir;
	const char *name;

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
};

static void director_connection_ping(struct director_connection *conn);

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
	conn->me_received = TRUE;

	if (!conn->in)
		return TRUE;

	conn->host = host;
	connect_str = t_strdup_printf("CONNECT\t%s\t%u\n",
				      net_ip2addr(&host->ip), host->port);
	/* make sure this is the correct incoming connection */
	if (host->self) {
		/* probably we're trying to find our own ip. it's no */
		i_error("director(%s): Connection from self, dropping",
			host->name);
		return FALSE;
	} else if (dir->left == NULL) {
		/* no conflicts yet */
	} else if (dir->left->host == host) {
		i_warning("director(%s): Dropping existing connection "
			  "in favor of its new connection", host->name);
		director_connection_deinit(&dir->left);
	} else {
		if (director_host_cmp_to_self(dir->left->host, host,
					      dir->self_host) > 0) {
			/* the old connection is the correct one.
			   refer the client there. */
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
			/* there are only two directors */
		}
	} else {
		/* looks like we're the right side. */
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
	if (timestamp == ioloop_time && user->timestamp != timestamp) {
		user_directory_refresh(dir->users, user);
		ret = TRUE;
	}

	if (user->host != host) {
		i_error("User hash %u is being redirected to two hosts: "
			"%s and %s", username_hash,
			net_ip2addr(&user->host->ip),
			net_ip2addr(&host->ip));
		user->host = host;
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

	host = mail_host_lookup(&ip);
	if (host == NULL) {
		i_error("director(%s): USER used unknown host %s in handshake",
			conn->name, args[1]);
		return FALSE;
	}

	director_user_refresh(conn->dir, username_hash, host, timestamp, &user);
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
		/* already have this, skip */
		return TRUE;
	}

	/* save the director and forward it */
	director_host_add(conn->dir, &ip, port);
	director_connection_send(conn->dir->right,
		t_strdup_printf("DIRECTOR\t%s\t%u\n", net_ip2addr(&ip), port));
	return TRUE;
}

static bool
director_cmd_host(struct director_connection *conn, const char *const *args)
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

	host = mail_host_lookup(&ip);
	if (host == NULL) {
		host = mail_host_add_ip(&ip);
		update = TRUE;
	} else {
		update = host->vhost_count != vhost_count;
	}

	if (update) {
		/* FIXME: 1) shouldn't be unconditional, 2) if we're not
		   handshaking, we should do SYNC before making it visible */
		host->vhost_count = vhost_count;
		director_update_host(conn->dir, conn->host, host);
	}
	return TRUE;
}

static bool
director_cmd_host_remove(struct director_connection *conn,
			 const char *const *args)
{
	struct mail_host *host;
	struct ip_addr ip;

	if (str_array_length(args) != 1 ||
	    net_addr2ip(args[0], &ip) < 0) {
		i_error("director(%s): Invalid HOST-REMOVE args", conn->name);
		return FALSE;
	}

	host = mail_host_lookup(&ip);
	if (host != NULL)
		director_remove_host(conn->dir, conn->host, host);
	return TRUE;
}

static void director_handshake_cmd_done(struct director_connection *conn)
{
	struct director *dir = conn->dir;

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

	if (dir->left != NULL && dir->right != NULL) {
		/* we're connected to both directors. see if the ring is
		   finished by sending a SYNC. if we get it back, it's done. */
		dir->sync_seq = ++dir->self_host->last_seq;
		director_connection_send(dir->right,
			t_strdup_printf("SYNC\t%s\t%u\t%u\n",
					net_ip2addr(&dir->self_ip),
					dir->self_port, dir->sync_seq));
	}
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
		(void)director_connect_host(conn->dir, host);
		return FALSE;
	}
	/* only incoming connections get DIRECTOR and HOST lists */
	if (conn->in && strcmp(cmd, "DIRECTOR") == 0 && conn->me_received)
		return director_cmd_director(conn, args);
	if (conn->in && strcmp(cmd, "HOST") == 0 && conn->me_received)
		return director_cmd_host(conn, args);
	/* only incoming connections get a USER list */
	if (conn->in && strcmp(cmd, "USER") == 0 && conn->me_received)
		return director_handshake_cmd_user(conn, args);
	/* both get DONE */
	if (strcmp(cmd, "DONE") == 0 && !conn->handshake_received) {
		director_handshake_cmd_done(conn);
		return TRUE;
	}
	i_error("director(%s): Invalid handshake command: %s",
		conn->name, cmd);
	return FALSE;
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

	host = mail_host_lookup(&ip);
	if (host == NULL) {
		/* we probably just removed this host. */
		return TRUE;
	}

	if (director_user_refresh(conn->dir, username_hash,
				  host, ioloop_time, &user))
		director_update_user(conn->dir, conn->host, user);
	return TRUE;
}

static bool director_connection_sync(struct director_connection *conn,
				     const char *const *args, const char *line)
{
	struct director_host *host;
	struct ip_addr ip;
	unsigned int port, seq;

	if (str_array_length(args) != 3 ||
	    director_args_parse_ip_port(conn, args, &ip, &port) < 0 ||
	    str_to_uint(args[2], &seq) < 0) {
		i_error("director(%s): Invalid SYNC args", conn->name);
		return FALSE;
	}

	/* find the originating director. if we don't see it, it was already
	   removed and we can ignore this sync. */
	host = director_host_lookup(conn->dir, &ip, port);
	if (host == NULL)
		return TRUE;

	if (host->self) {
		if (conn->dir->sync_seq != seq) {
			/* stale SYNC event */
			return TRUE;
		}
		if (conn->dir->ring_handshaked)
			return TRUE;

		/* the ring is handshaked */
		conn->dir->ring_handshaked = TRUE;
		director_set_state_changed(conn->dir);
		return TRUE;
	}

	/* forward it to the connection on right */
	if (conn->dir->right != NULL) {
		director_connection_send(conn->dir->right,
					 t_strconcat(line, "\n", NULL));
	}
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
	if (!conn->handshake_received) {
		if (!director_connection_handle_handshake(conn, cmd, args)) {
			/* invalid commands during handshake,
			   we probably don't want to reconnect here */
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
	if (strcmp(cmd, "DIRECTOR") == 0)
		return director_cmd_director(conn, args);
	if (strcmp(cmd, "SYNC") == 0)
		return director_connection_sync(conn, args, line);

	if (strcmp(cmd, "PING") == 0) {
		director_connection_send(conn, "PONG\n");
		return TRUE;
	}
	if (strcmp(cmd, "PONG") == 0) {
		if (conn->to_ping != NULL)
			timeout_remove(&conn->to_ping);
		return TRUE;
	}
	i_error("director(%s): Unknown command (in this state): %s",
		conn->name, cmd);
	return FALSE;
}

static void director_connection_input(struct director_connection *conn)
{
	char *line;
	bool ret;

	if (conn->to_ping != NULL)
		timeout_reset(conn->to_ping);
	switch (i_stream_read(conn->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		director_connection_deinit(&conn);
		return;
	case -2:
		/* buffer full */
		i_error("BUG: Director sent us more than %d bytes",
			MAX_INBUF_SIZE);
		director_connection_deinit(&conn);
		return;
	}

	while ((line = i_stream_next_line(conn->input)) != NULL) {
		T_BEGIN {
			ret = director_connection_handle_line(conn, line);
		} T_END;

		if (!ret) {
			director_connection_deinit(&conn);
			break;
		}
	}
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

static void director_connection_send_hosts(string_t *str)
{
	struct mail_host *const *hostp;

	array_foreach(mail_hosts_get(), hostp) {
		str_printfa(str, "HOST\t%s\t%u\n",
			    net_ip2addr(&(*hostp)->ip), (*hostp)->vhost_count);
	}
}

static int director_connection_send_users(struct director_connection *conn)
{
	struct user *user;
	int ret;

	o_stream_cork(conn->output);
	while ((user = user_directory_iter_next(conn->user_iter)) != NULL) {
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

static struct director_connection *
director_connection_init_common(struct director *dir, int fd)
{
	struct director_connection *conn;

	conn = i_new(struct director_connection, 1);
	conn->fd = fd;
	conn->dir = dir;
	conn->input = i_stream_create_fd(conn->fd, MAX_INBUF_SIZE, FALSE);
	conn->output = o_stream_create_fd(conn->fd, MAX_OUTBUF_SIZE, FALSE);
	o_stream_set_flush_callback(conn->output,
				    director_connection_output, conn);
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
director_connection_init_in(struct director *dir, int fd)
{
	struct director_connection *conn;

	conn = director_connection_init_common(dir, fd);
	conn->in = TRUE;
	conn->connected = TRUE;
	conn->name = "<incoming>";
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
		director_connection_deinit(&conn);

		/* try connecting to next server */
		director_connect(dir);
		return;
	}
	conn->connected = TRUE;

	io_remove(&conn->io);

	director_connection_send_handshake(conn);
	director_connection_send_directors(conn, str);
	director_connection_send_hosts(str);
	director_connection_send(conn, str_c(str));

	conn->user_iter = user_directory_iter_init(dir->users);
	(void)director_connection_send_users(conn);
}

struct director_connection *
director_connection_init_out(struct director *dir, int fd,
			     struct director_host *host)
{
	struct director_connection *conn;

	conn = director_connection_init_common(dir, fd);
	conn->name = host->name;
	conn->host = host;
	conn->io = io_add(conn->fd, IO_WRITE,
			  director_connection_connected, conn);
	return conn;
}

void director_connection_deinit(struct director_connection **_conn)
{
	struct director_connection *conn = *_conn;

	*_conn = NULL;

	if (conn->dir->left == conn)
		conn->dir->left = NULL;
	if (conn->dir->right == conn)
		conn->dir->right = NULL;

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
	i_free(conn);
}

static void director_connection_timeout(struct director_connection *conn)
{
	director_connection_deinit(&conn);
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
	director_connection_deinit(&conn);
}

static void director_connection_ping(struct director_connection *conn)
{
	if (conn->to_ping != NULL)
		return;

	conn->to_ping = timeout_add(DIRECTOR_CONNECTION_PING_TIMEOUT_MSECS,
				    director_connection_ping_timeout, conn);
	director_connection_send(conn, "PING\n");
}
