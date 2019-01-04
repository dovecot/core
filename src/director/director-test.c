/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

/*
   This program accepts incoming unauthenticated IMAP connections from
   port 14300. If the same user is connecting to multiple different local IPs,
   it logs an error (i.e. director is not working right then).

   This program also accepts incoming director connections on port 9091 and
   forwards them to local_ip:9090. To make this work properly, director
   executable must be given -t 9091 parameter. The idea is that this test tool
   hooks between all director connections and can then add delays or break the
   connections.

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
#include "strescape.h"
#include "imap-parser.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "director-settings.h"

#include <unistd.h>

#define IMAP_PORT 14300
#define DIRECTOR_IN_PORT 9091
#define DIRECTOR_OUT_PORT 9090
#define USER_TIMEOUT_MSECS (1000*10) /* FIXME: this should be based on director_user_expire */
#define ADMIN_RANDOM_TIMEOUT_MSECS 500
#define DIRECTOR_CONN_MAX_DELAY_MSECS 100
#define DIRECTOR_DISCONNECT_TIMEOUT_SECS 10

struct host {
	int refcount;

	struct ip_addr ip;
	unsigned int vhost_count;
};

struct user {
	char *username;
	struct host *host;

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
	struct timeout *to_delay;
};

struct admin_connection {
	char *path;
	int fd;
	struct io *io;
	struct istream *input;
	struct timeout *to_random;
	bool pending_command;
};

static struct imap_client *imap_clients;
static struct director_connection *director_connections;
static HASH_TABLE(char *, struct user *) users;
static HASH_TABLE(struct ip_addr *, struct host *) hosts;
static ARRAY(struct host *) hosts_array;
static struct admin_connection *admin;
static struct timeout *to_disconnect;

static void imap_client_destroy(struct imap_client **client);
static void director_connection_destroy(struct director_connection **conn);
static void director_connection_timeout(struct director_connection *conn);

static void host_unref(struct host **_host)
{
	struct host *host = *_host;

	*_host = NULL;

	i_assert(host->refcount > 0);
	if (--host->refcount > 0)
		return;

	i_free(host);
}

static void client_username_check(struct imap_client *client)
{
	struct user *user;
	struct host *host;
	struct ip_addr local_ip;

	if (net_getsockname(client->fd, &local_ip, NULL) < 0)
		i_fatal("net_getsockname() failed: %m");

	host = hash_table_lookup(hosts, &local_ip);
	if (host == NULL) {
		i_error("User logging into unknown host %s",
			net_ip2addr(&local_ip));
		host = i_new(struct host, 1);
		host->refcount = 1;
		host->ip = local_ip;
		host->vhost_count = 100;
		hash_table_insert(hosts, &host->ip, host);
		array_push_back(&hosts_array, &host);
	}

	user = hash_table_lookup(users, client->username);
	if (user == NULL) {
		user = i_new(struct user, 1);
		user->username = i_strdup(client->username);
		hash_table_insert(users, user->username, user);
	} else if (user->host != host) {
		i_error("user %s: old connection from %s, new from %s. "
			"%u old connections, last was %u secs ago",
			user->username, net_ip2addr(&user->host->ip),
			net_ip2addr(&host->ip), user->connections,
			(unsigned int)(ioloop_time - user->last_seen));
		host_unref(&user->host);
	}
	client->user = user;
	user->host = host;
	user->connections++;
	user->last_seen = ioloop_time;
	user->host->refcount++;

	timeout_remove(&user->to);
}

static void user_free(struct user *user)
{
	host_unref(&user->host);
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

		o_stream_nsend_str(client->output,
			t_strconcat(tag, " OK Logged in.\r\n", NULL));
		client->username = i_strdup(str);
		client_username_check(client);
	} else if (strcasecmp(cmd, "logout") == 0) {
		o_stream_nsend_str(client->output, t_strconcat(
			"* BYE Out.\r\n",
			tag, " OK Logged out.\r\n", NULL));
		imap_client_destroy(&client);
		return 0;
	} else if (strcasecmp(cmd, "capability") == 0) {
		o_stream_nsend_str(client->output,
			t_strconcat("* CAPABILITY IMAP4rev1\r\n",
				    tag, " OK Done.\r\n", NULL));
	} else {
		o_stream_nsend_str(client->output,
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
	client->input = i_stream_create_fd(fd, 4096);
	client->output = o_stream_create_fd(fd, (size_t)-1);
	o_stream_set_no_error_handling(client->output, TRUE);
	client->io = io_add(fd, IO_READ, imap_client_input, client);
	client->parser =
		imap_parser_create(client->input, client->output, 4096);
	o_stream_nsend_str(client->output,
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
	imap_parser_unref(&client->parser);
	io_remove(&client->io);
	i_stream_destroy(&client->input);
	o_stream_destroy(&client->output);
	net_disconnect(client->fd);
	i_free(client->username);
	i_free(client);

	master_service_client_connection_destroyed(master_service);
}

static void
director_connection_input(struct director_connection *conn,
			  struct istream *input, struct ostream *output)
{
	const unsigned char *data;
	size_t size;

	if (i_stream_read_more(input, &data, &size) == -1) {
		director_connection_destroy(&conn);
		return;
	}

	o_stream_nsend(output, data, size);
	i_stream_skip(input, size);

	if (i_rand_limit(3) == 0 && conn->to_delay == NULL) {
		conn->to_delay =
			timeout_add(i_rand_limit(DIRECTOR_CONN_MAX_DELAY_MSECS),
				    director_connection_timeout, conn);
		io_remove(&conn->in_io);
		io_remove(&conn->out_io);
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

static void director_connection_timeout(struct director_connection *conn)
{
	timeout_remove(&conn->to_delay);
	conn->in_io = io_add(conn->in_fd, IO_READ,
			     director_connection_in_input, conn);
	conn->out_io = io_add(conn->out_fd, IO_READ,
			      director_connection_out_input, conn);
}

static void
director_connection_create(int in_fd, const struct ip_addr *local_ip,
			   const struct ip_addr *remote_ip)
{
	struct director_connection *conn;
	int out_fd;

	out_fd = net_connect_ip(local_ip, DIRECTOR_OUT_PORT, remote_ip);
	if (out_fd == -1) {
		i_close_fd(&in_fd);
		return;
	}

	conn = i_new(struct director_connection, 1);
	conn->in_fd = in_fd;
	conn->in_input = i_stream_create_fd(conn->in_fd, (size_t)-1);
	conn->in_output = o_stream_create_fd(conn->in_fd, (size_t)-1);
	o_stream_set_no_error_handling(conn->in_output, TRUE);
	conn->in_io = io_add(conn->in_fd, IO_READ,
			     director_connection_in_input, conn);

	conn->out_fd = out_fd;
	conn->out_input = i_stream_create_fd(conn->out_fd, (size_t)-1);
	conn->out_output = o_stream_create_fd(conn->out_fd, (size_t)-1);
	o_stream_set_no_error_handling(conn->out_output, TRUE);
	conn->out_io = io_add(conn->out_fd, IO_READ,
			      director_connection_out_input, conn);

	DLLIST_PREPEND(&director_connections, conn);
}

static void director_connection_destroy(struct director_connection **_conn)
{
	struct director_connection *conn = *_conn;

	DLLIST_REMOVE(&director_connections, conn);

	timeout_remove(&conn->to_delay);

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
	struct ip_addr local_ip, remote_ip;
	in_port_t local_port;

	if (net_getsockname(conn->fd, &local_ip, &local_port) < 0)
		i_fatal("net_getsockname() failed: %m");
	if (net_getpeername(conn->fd, &remote_ip, NULL) < 0)
		i_fatal("net_getsockname() failed: %m");

	if (local_port == IMAP_PORT)
		imap_client_create(conn->fd);
	else if (local_port == DIRECTOR_IN_PORT)
		director_connection_create(conn->fd, &local_ip, &remote_ip);
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

static void admin_input(struct admin_connection *conn)
{
	const char *line;

	while ((line = i_stream_read_next_line(conn->input)) != NULL) {
		if (strcmp(line, "OK") != 0)
			i_error("director-doveadm: Unexpected input: %s", line);
		conn->pending_command = FALSE;
	}
	if (conn->input->stream_errno != 0 || conn->input->eof)
		i_fatal("director-doveadm: Connection lost");
}

static void admin_random_action(struct admin_connection *conn)
{
	struct host *const *hosts;
	unsigned int i, count;

	if (conn->pending_command)
		return;

	hosts = array_get(&hosts_array, &count);
	i = i_rand_limit(count);

	hosts[i]->vhost_count = i_rand_limit(20) * 10;

	admin_send(conn, t_strdup_printf("HOST-SET\t%s\t%u\n",
		net_ip2addr(&hosts[i]->ip), hosts[i]->vhost_count));
	conn->pending_command = TRUE;
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
	conn->io = io_add(conn->fd, IO_READ, admin_input, conn);
	conn->to_random = timeout_add_short(ADMIN_RANDOM_TIMEOUT_MSECS,
					    admin_random_action, conn);

	net_set_nonblock(conn->fd, FALSE);
	conn->input = i_stream_create_fd(conn->fd, (size_t)-1);
	admin_send(conn, DIRECTOR_ADMIN_HANDSHAKE);

	line = i_stream_read_next_line(conn->input);
	if (line == NULL)
		i_fatal("%s disconnected", conn->path);
	if (!version_string_verify(line, "director-doveadm", 1)) {
		i_fatal("%s not a compatible director-doveadm socket",
			conn->path);
	}
	net_set_nonblock(conn->fd, TRUE);
	return conn;
}

static void admin_disconnect(struct admin_connection **_conn)
{
	struct admin_connection *conn = *_conn;

	*_conn = NULL;
	timeout_remove(&conn->to_random);
	i_stream_destroy(&conn->input);
	io_remove(&conn->io);
	net_disconnect(conn->fd);
	i_free(conn->path);
	i_free(conn);
}

static void admin_read_hosts(struct admin_connection *conn)
{
	const char *line;

	net_set_nonblock(admin->fd, FALSE);
	while ((line = i_stream_read_next_line(conn->input)) != NULL) {
		if (*line == '\0')
			break;
		/* ip vhost-count user-count */
		T_BEGIN {
			const char *const *args = t_strsplit_tabescaped(line);
			struct host *host;

			host = i_new(struct host, 1);
			host->refcount = 1;
			if (net_addr2ip(args[0], &host->ip) < 0 ||
			    str_to_uint(args[1], &host->vhost_count) < 0)
				i_fatal("host list broken");
			hash_table_insert(hosts, &host->ip, host);
			array_append(&hosts_array, &host, 1);
		} T_END;
	}
	if (line == NULL)
		i_fatal("Couldn't read hosts list");
	net_set_nonblock(admin->fd, TRUE);
}

static void ATTR_NULL(1)
director_connection_disconnect_timeout(void *context ATTR_UNUSED)
{
	struct director_connection *conn;
	unsigned int i, count = 0;

	for (conn = director_connections; conn != NULL; conn = conn->next)
		count++;

	if (count != 0) {
		i = 0; count = i_rand() % count;
		for (conn = director_connections; i < count; conn = conn->next) {
			i_assert(conn != NULL);
			i++;
		}
		i_assert(conn != NULL);
		director_connection_destroy(&conn);
	}
}

static void main_init(const char *admin_path)
{
	hash_table_create(&users, default_pool, 0, str_hash, strcmp);
	hash_table_create(&hosts, default_pool, 0, net_ip_hash, net_ip_cmp);
	i_array_init(&hosts_array, 256);

	admin = admin_connect(admin_path);
	admin_send(admin, "HOST-LIST\n");
	admin_read_hosts(admin);

	to_disconnect =
		timeout_add(1000 * i_rand_minmax(5, 5 + DIRECTOR_DISCONNECT_TIMEOUT_SECS - 1),
			    director_connection_disconnect_timeout, NULL);
}

static void main_deinit(void)
{
	struct hash_iterate_context *iter;
	char *username;
	struct ip_addr *ip;
	struct user *user;
	struct host *host;

	while (imap_clients != NULL) {
		struct imap_client *client = imap_clients;
		imap_client_destroy(&client);
	}

	timeout_remove(&to_disconnect);
	while (director_connections != NULL) {
		struct director_connection *conn = director_connections;
		director_connection_destroy(&conn);
	}

	iter = hash_table_iterate_init(users);
	while (hash_table_iterate(iter, users, &username, &user))
		user_free(user);
	hash_table_iterate_deinit(&iter);
	hash_table_destroy(&users);

	iter = hash_table_iterate_init(hosts);
	while (hash_table_iterate(iter, hosts, &ip, &host))
		host_unref(&host);
	hash_table_iterate_deinit(&iter);
	hash_table_destroy(&hosts);
	array_free(&hosts_array);

	admin_disconnect(&admin);
}

int main(int argc, char *argv[])
{
	const enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_DONT_SEND_STATS;
	const char *admin_path;

	master_service = master_service_init("director-test", service_flags,
					     &argc, &argv, "");
	if (master_getopt(master_service) > 0)
		return FATAL_DEFAULT;
	admin_path = argv[optind];
	if (admin_path == NULL)
		i_fatal("director-doveadm socket path missing");

	master_service_init_log(master_service, "director-test: ");

	main_init(admin_path);
	master_service_init_finish(master_service);
	master_service_run(master_service, client_connected);
	main_deinit();

	master_service_deinit(&master_service);
        return 0;
}
