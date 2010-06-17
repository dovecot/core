/* Copyright (c) 2005-2010 Dovecot authors, see the included COPYING file */

/*
   This program accepts incoming unauthenticated IMAP connections from
   port 14300. If the same user is connecting to multiple different local IPs,
   it logs an error (i.e. director is not working right then).

   This program also accepts incoming director connections on port 9090 and
   forwards them to local_ip:9091. So all directors think the others are
   listening on port 9091, while in reality all of them are on 9090.
   The idea is that this test tool hooks between all director connections and
   can then add delays or break the connections.

   Finally, this program connects to director-admin socket where it adds
   and removes mail hosts.
*/

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "write-full.h"
#include "hash.h"
#include "llist.h"
#include "imap-parser.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "director-settings.h"

#define IMAP_PORT 14300
#define DIRECTOR_IN_PORT 9091
#define DIRECTOR_OUT_PORT 9090
#define USER_TIMEOUT_MSECS (1000*60)

struct user {
	char *username;
	struct ip_addr local_ip;

	time_t last_seen;
	unsigned int connections;

	struct timeout *to;
};

struct imap_client {
	struct imap_client *prev, *next;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;
	struct imap_parser *parser;
	struct user *user;

	char *username;
};

struct director_connection {
	struct director_connection *prev, *next;

	int in_fd, out_fd;
	struct io *in_io, *out_io;
	struct istream *in_input, *out_input;
	struct ostream *in_output, *out_output;
};

struct admin_connection {
	char *path;
	int fd;
	struct istream *input;
};

static struct imap_client *imap_clients;
static struct director_connection *director_connections;
static struct hash_table *users;
static struct admin_connection *admin;

static void imap_client_destroy(struct imap_client **client);
static void director_connection_destroy(struct director_connection **_conn);

static void client_username_check(struct imap_client *client)
{
	struct user *user;
	struct ip_addr local_ip;

	if (net_getsockname(client->fd, &local_ip, NULL) < 0)
		i_fatal("net_getsockname() failed: %m");

	user = hash_table_lookup(users, client->username);
	if (user == NULL) {
		user = i_new(struct user, 1);
		user->username = i_strdup(client->username);
		user->local_ip = local_ip;
		hash_table_insert(users, user->username, user);
	} else if (!net_ip_compare(&user->local_ip, &local_ip)) {
		i_error("user %s: old connection from %s, new from %s. "
			"%u old connections, last was %u secs ago",
			user->username, net_ip2addr(&user->local_ip),
			net_ip2addr(&local_ip), user->connections,
			(unsigned int)(ioloop_time - user->last_seen));
		return;
	}
	client->user = user;
	user->connections++;
	user->last_seen = ioloop_time;

	if (user->to != NULL)
		timeout_remove(&user->to);
}

static void user_free(struct user *user)
{
	if (user->to != NULL)
		timeout_remove(&user->to);
	hash_table_remove(users, user->username);
	i_free(user->username);
	i_free(user);
}

static int imap_client_parse_input(struct imap_client *client)
{
	const char *tag, *cmd, *str;
	const struct imap_arg *args;
	int ret;

	ret = imap_parser_read_args(client->parser, 0, 0, &args);
	if (ret < 0) {
		if (ret == -2)
			return 0;
		return -1;
	}

	if (!imap_arg_get_atom(args, &tag))
		return -1;
	args++;

	if (!imap_arg_get_atom(args, &cmd))
		return -1;
	args++;

	if (strcasecmp(cmd, "login") == 0) {
		if (client->username != NULL)
			return -1;

		if (!imap_arg_get_astring(args, &str))
			return -1;

		o_stream_send_str(client->output,
			t_strconcat(tag, " OK Logged in.\r\n", NULL));
		client->username = i_strdup(str);
		client_username_check(client);
	} else if (strcasecmp(cmd, "logout") == 0) {
		o_stream_send_str(client->output, t_strconcat(
			"* BYE Out.\r\n",
			tag, " OK Logged out.\r\n", NULL));
		imap_client_destroy(&client);
		return 0;
	} else if (strcasecmp(cmd, "capability") == 0) {
		o_stream_send_str(client->output,
			t_strconcat("* CAPABILITY IMAP4rev1\r\n",
				    tag, " OK Done.\r\n", NULL));
	} else {
		o_stream_send_str(client->output,
			t_strconcat(tag, " BAD Not supported.\r\n", NULL));
	}

	(void)i_stream_read_next_line(client->input); /* eat away LF */
	imap_parser_reset(client->parser);
	return 1;
}

static void imap_client_input(struct imap_client *client)
{
	int ret;

	switch (i_stream_read(client->input)) {
	case -2:
		i_error("imap: Too much input");
		imap_client_destroy(&client);
		return;
	case -1:
		imap_client_destroy(&client);
		return;
	default:
		break;
	}

	while ((ret = imap_client_parse_input(client)) > 0) ;
	if (ret < 0) {
		i_error("imap: Invalid input");
		imap_client_destroy(&client);
	}
}

static void imap_client_create(int fd)
{
	struct imap_client *client;

	client = i_new(struct imap_client, 1);
	client->fd = fd;
	client->input = i_stream_create_fd(fd, 4096, FALSE);
	client->output = o_stream_create_fd(fd, (size_t)-1, FALSE);
	client->io = io_add(fd, IO_READ, imap_client_input, client);
	client->parser =
		imap_parser_create(client->input, client->output, 4096);
	o_stream_send_str(client->output,
		"* OK [CAPABILITY IMAP4rev1] director-test ready.\r\n");
	DLLIST_PREPEND(&imap_clients, client);
}

static void imap_client_destroy(struct imap_client **_client)
{
	struct imap_client *client = *_client;
	struct user *user = client->user;

	*_client = NULL;

	if (user != NULL) {
		i_assert(user->connections > 0);
		if (--user->connections == 0) {
			i_assert(user->to == NULL);
			user->to = timeout_add(USER_TIMEOUT_MSECS, user_free,
					       user);
		}
		user->last_seen = ioloop_time;
	}

	DLLIST_REMOVE(&imap_clients, client);
	imap_parser_destroy(&client->parser);
	io_remove(&client->io);
	i_stream_unref(&client->input);
	o_stream_unref(&client->output);
	net_disconnect(client->fd);
	i_free(client->username);
	i_free(client);

	master_service_client_connection_destroyed(master_service);
}

static const char *director_line_update_port(const char *line)
{
	const char *p, *prefix, *suffix;
	unsigned int i = 0;

	/* <cmd> \t IP \t <port> [\t more] */
	for (p = line;; p++) {
		if (*p == '\0') {
			i_error("director: Invalid input: %s", line);
			return line;
		}
		if (*p == '\t') {
			if (++i == 2)
				break;
		}
	}
	prefix = t_strdup_until(line, ++p);
	suffix = strchr(p, '\t');
	return t_strdup_printf("%s%u%s", prefix, DIRECTOR_OUT_PORT,
			       suffix != NULL ? suffix : "");
}

static void
director_connection_input(struct director_connection *conn,
			  struct istream *input, struct ostream *output)
{
	const char *line;

	o_stream_cork(output);
	while ((line = i_stream_read_next_line(input)) != NULL) {
#if 0
		if (strncmp(line, "ME\t", 3) == 0 ||
		    strncmp(line, "DIRECTOR\t", 9) == 0 ||
		    strncmp(line, "SYNC\t", 5) == 0) {
			const char *orig = line;

			line = director_line_update_port(line);
		}
#endif
		o_stream_send_str(output, line);
		o_stream_send(output, "\n", 1);
	}
	o_stream_uncork(output);
	if (input->stream_errno != 0 || input->eof) {
		director_connection_destroy(&conn);
		return;
	}
}

static void director_connection_in_input(struct director_connection *conn)
{
	director_connection_input(conn, conn->in_input, conn->out_output);
}

static void director_connection_out_input(struct director_connection *conn)
{
	director_connection_input(conn, conn->out_input, conn->in_output);
}

static void
director_connection_create(int in_fd, const struct ip_addr *local_ip)
{
	struct director_connection *conn;

	conn = i_new(struct director_connection, 1);
	conn->in_fd = in_fd;
	conn->in_input = i_stream_create_fd(conn->in_fd, (size_t)-1, FALSE);
	conn->in_output = o_stream_create_fd(conn->in_fd, (size_t)-1, FALSE);
	conn->in_io = io_add(conn->in_fd, IO_READ,
			     director_connection_in_input, conn);

	conn->out_fd = net_connect_ip(local_ip, DIRECTOR_OUT_PORT, NULL);
	conn->out_input = i_stream_create_fd(conn->out_fd, (size_t)-1, FALSE);
	conn->out_output = o_stream_create_fd(conn->out_fd, (size_t)-1, FALSE);
	conn->out_io = io_add(conn->out_fd, IO_READ,
			      director_connection_out_input, conn);

	DLLIST_PREPEND(&director_connections, conn);
}

static void director_connection_destroy(struct director_connection **_conn)
{
	struct director_connection *conn = *_conn;

	DLLIST_REMOVE(&director_connections, conn);

	io_remove(&conn->in_io);
	i_stream_unref(&conn->in_input);
	o_stream_unref(&conn->in_output);
	net_disconnect(conn->in_fd);

	io_remove(&conn->out_io);
	i_stream_unref(&conn->out_input);
	o_stream_unref(&conn->out_output);
	net_disconnect(conn->out_fd);

	i_free(conn);
}

static void client_connected(struct master_service_connection *conn)
{
	struct ip_addr local_ip;
	unsigned int local_port;

	if (net_getsockname(conn->fd, &local_ip, &local_port) < 0)
		i_fatal("net_getsockname() failed: %m");

	if (local_port == IMAP_PORT)
		imap_client_create(conn->fd);
	else if (local_port == DIRECTOR_IN_PORT)
		director_connection_create(conn->fd, &local_ip);
	else {
		i_error("Connection to unknown port %u", local_port);
		return;
	}
	master_service_client_connection_accept(conn);
}

static void
admin_send(struct admin_connection *conn, const char *data)
{
	if (write_full(i_stream_get_fd(conn->input), data, strlen(data)) < 0)
		i_fatal("write(%s) failed: %m", conn->path);
}

static struct admin_connection *admin_connect(const char *path)
{
#define DIRECTOR_ADMIN_HANDSHAKE "VERSION\tdirector-doveadm\t1\t0\n"
	struct admin_connection *conn;
	const char *line;

	conn = i_new(struct admin_connection, 1);
	conn->path = i_strdup(path);
	conn->fd = net_connect_unix(path);
	if (conn->fd == -1)
		i_fatal("net_connect_unix(%s) failed: %m", path);
	net_set_nonblock(conn->fd, FALSE);

	conn->input = i_stream_create_fd(conn->fd, (size_t)-1, TRUE);
	admin_send(conn, DIRECTOR_ADMIN_HANDSHAKE);

	line = i_stream_read_next_line(conn->input);
	if (line == NULL)
		i_fatal("%s disconnected", conn->path);
	if (!version_string_verify(line, "director-doveadm", 1)) {
		i_fatal("%s not a compatible director-doveadm socket",
			conn->path);
	}
	return conn;
}

static void admin_disconnect(struct admin_connection **_conn)
{
	struct admin_connection *conn = *_conn;

	*_conn = NULL;
	i_stream_destroy(&conn->input);
	net_disconnect(conn->fd);
	i_free(conn->path);
	i_free(conn);
}

static void main_init(void)
{
	const char *admin_path;

	/*set = master_service_settings_get_others(master_service)[0];
	admin_path = t_strconcat(set->base_dir, "/director-admin", NULL);
	admin = admin_connect(admin_path);*/

	users = hash_table_create(default_pool, default_pool, 0,
				  str_hash, (hash_cmp_callback_t *)strcmp);
}

static void main_deinit(void)
{
	struct hash_iterate_context *iter;
	void *key, *value;

	while (imap_clients != NULL) {
		struct imap_client *client = imap_clients;

		imap_client_destroy(&client);
	}

	while (director_connections != NULL) {
		struct director_connection *conn = director_connections;

		director_connection_destroy(&conn);
	}

	iter = hash_table_iterate_init(users);
	while (hash_table_iterate(iter, &key, &value)) {
		struct user *user = value;
		user_free(user);
	}
	hash_table_iterate_deinit(&iter);
	hash_table_destroy(&users);
	//admin_disconnect(&admin);
}

int main(int argc, char *argv[])
{
	master_service = master_service_init("director-test", 0,
					     &argc, &argv, NULL);
	if (master_getopt(master_service) > 0)
		return FATAL_DEFAULT;

	master_service_init_log(master_service, "director-test: ");
	master_service_init_finish(master_service);

	main_init();
	master_service_run(master_service, client_connected);
	main_deinit();

	master_service_deinit(&master_service);
        return 0;
}
