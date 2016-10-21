/* Copyright (c) 2010-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "llist.h"
#include "master-service.h"
#include "user-directory.h"
#include "mail-host.h"
#include "director.h"
#include "director-host.h"
#include "director-request.h"
#include "director-connection.h"
#include "doveadm-connection.h"

#include <unistd.h>

#define DOVEADM_PROTOCOL_VERSION_MAJOR 1
#define DOVEADM_HANDSHAKE "VERSION\tdirector-doveadm\t1\t0\n"

#define MAX_VALID_VHOST_COUNT 1000

struct doveadm_connection {
	struct doveadm_connection *prev, *next;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;
	struct director *dir;

	bool handshaked:1;
};

static struct doveadm_connection *doveadm_connections;

static void doveadm_connection_deinit(struct doveadm_connection **_conn);

static void doveadm_cmd_host_list(struct doveadm_connection *conn)
{
	struct mail_host *const *hostp;
	string_t *str = t_str_new(1024);

	array_foreach(mail_hosts_get(conn->dir->mail_hosts), hostp) {
		str_printfa(str, "%s\t%u\t%u\t",
			    net_ip2addr(&(*hostp)->ip), (*hostp)->vhost_count,
			    (*hostp)->user_count);
		str_append_tabescaped(str, mail_host_get_tag(*hostp));
		str_printfa(str, "\t%c\t%ld", (*hostp)->down ? 'D' : 'U',
			    (long)(*hostp)->last_updown_change);
		str_append_c(str, '\n');
	}
	str_append_c(str, '\n');
	o_stream_nsend(conn->output, str_data(str), str_len(str));
}

static void doveadm_cmd_host_list_removed(struct doveadm_connection *conn)
{
	struct mail_host_list *orig_hosts_list;
	struct mail_host *const *orig_hosts, *const *cur_hosts;
	unsigned int i, j, orig_hosts_count, cur_hosts_count;
	string_t *str = t_str_new(1024);
	int ret;

	orig_hosts_list = mail_hosts_init(conn->dir->set->director_consistent_hashing);
	(void)mail_hosts_parse_and_add(orig_hosts_list,
				       conn->dir->set->director_mail_servers);

	orig_hosts = array_get(mail_hosts_get(orig_hosts_list),
			       &orig_hosts_count);
	cur_hosts = array_get(mail_hosts_get(conn->dir->mail_hosts),
			      &cur_hosts_count);

	/* the hosts are sorted by IP */
	for (i = j = 0; i < orig_hosts_count && j < cur_hosts_count; ) {
		ret = net_ip_cmp(&orig_hosts[i]->ip, &cur_hosts[j]->ip);
		if (ret == 0)
			i++, j++;
		else if (ret > 0)
			j++;
		else {
			str_printfa(str, "%s\n",
				    net_ip2addr(&orig_hosts[i]->ip));
			i++;
		}
	}
	for (; i < orig_hosts_count; i++)
		str_printfa(str, "%s\n", net_ip2addr(&orig_hosts[i]->ip));
	str_append_c(str, '\n');
	o_stream_nsend(conn->output, str_data(str), str_len(str));

	mail_hosts_deinit(&orig_hosts_list);
}

static void doveadm_director_append_status(struct director *dir, string_t *str)
{
	if (!dir->ring_handshaked)
		str_append(str, "handshaking");
	else if (dir->ring_synced)
		str_append(str, "synced");
	else {
		str_printfa(str, "syncing - last sync %d secs ago",
			    (int)(ioloop_time - dir->ring_last_sync_time));
	}
}

static void
doveadm_director_connection_append_status(struct director_connection *conn,
					  string_t *str)
{
	if (!director_connection_is_handshaked(conn))
		str_append(str, "handshaking");
	else if (director_connection_is_synced(conn))
		str_append(str, "synced");
	else
		str_append(str, "syncing");
}

static void
doveadm_director_host_append_status(struct director *dir,
				    const struct director_host *host,
				    string_t *str)
{
	struct director_connection *conn = NULL;

	if (dir->left != NULL &&
	    director_connection_get_host(dir->left) == host)
		conn = dir->left;
	else if (dir->right != NULL &&
		 director_connection_get_host(dir->right) == host)
		conn = dir->right;
	else {
		/* we might have a connection that is being connected */
		struct director_connection *const *connp;

		array_foreach(&dir->connections, connp) {
			if (director_connection_get_host(*connp) == host) {
				conn = *connp;
				break;
			}
		}
	}

	if (conn != NULL)
		doveadm_director_connection_append_status(conn, str);
}

static void doveadm_cmd_director_list(struct doveadm_connection *conn)
{
	struct director *dir = conn->dir;
	struct director_host *const *hostp;
	string_t *str = t_str_new(1024);
	const char *type;
	bool left, right;
	time_t last_failed;

	array_foreach(&dir->dir_hosts, hostp) {
		const struct director_host *host = *hostp;

		left = dir->left != NULL &&
			director_connection_get_host(dir->left) == host;
		right = dir->right != NULL &&
			 director_connection_get_host(dir->right) == host;

		if (host->removed)
			type = "removed";
		else if (dir->self_host == host)
			type = "self";
		else if (left)
			type = right ? "l+r" : "left";
		else if (right)
			type = "right";
		else
			type = "";

		last_failed = I_MAX(host->last_network_failure,
				    host->last_protocol_failure);
		str_printfa(str, "%s\t%u\t%s\t%lu\t",
			    net_ip2addr(&host->ip), host->port, type,
			    (unsigned long)last_failed);
		if (dir->self_host == host)
			doveadm_director_append_status(dir, str);
		else
			doveadm_director_host_append_status(dir, host, str);
		str_append_c(str, '\n');
	}
	str_append_c(str, '\n');
	o_stream_nsend(conn->output, str_data(str), str_len(str));
}

static int
doveadm_cmd_director_add(struct doveadm_connection *conn, const char *line)
{
	const char *const *args;
	struct director_host *host;
	struct ip_addr ip;
	in_port_t port = conn->dir->self_port;

	args = t_strsplit_tabescaped(line);
	if (args[0] == NULL ||
	    net_addr2ip(line, &ip) < 0 ||
	    (args[1] != NULL && net_str2port(args[1], &port) < 0)) {
		i_error("doveadm sent invalid DIRECTOR-ADD parameters");
		return -1;
	}

	if (director_host_lookup(conn->dir, &ip, port) == NULL) {
		host = director_host_add(conn->dir, &ip, port);
		director_notify_ring_added(host, conn->dir->self_host);
	}
	o_stream_nsend(conn->output, "OK\n", 3);
	return 1;
}

static int
doveadm_cmd_director_remove(struct doveadm_connection *conn, const char *line)
{
	const char *const *args;
	struct director_host *host;
	struct ip_addr ip;
	in_port_t port = 0;

	args = t_strsplit_tabescaped(line);
	if (args[0] == NULL ||
	    net_addr2ip(line, &ip) < 0 ||
	    (args[1] != NULL && net_str2port(args[1], &port) < 0)) {
		i_error("doveadm sent invalid DIRECTOR-REMOVE parameters");
		return -1;
	}

	host = port != 0 ?
		director_host_lookup(conn->dir, &ip, port) :
		director_host_lookup_ip(conn->dir, &ip);
	if (host == NULL)
		o_stream_nsend_str(conn->output, "NOTFOUND\n");
	else {
		director_ring_remove(host, conn->dir->self_host);
		o_stream_nsend(conn->output, "OK\n", 3);
	}
	return 1;
}

static int
doveadm_cmd_host_set_or_update(struct doveadm_connection *conn, const char *line,
			       bool update)
{
	struct director *dir = conn->dir;
	const char *const *args, *ip_str, *tag = "";
	struct mail_host *host;
	struct ip_addr ip;
	unsigned int vhost_count = UINT_MAX;

	args = t_strsplit_tabescaped(line);
	ip_str = args[0];
	if (ip_str != NULL) {
		tag = strchr(ip_str, '@');
		if (tag == NULL)
			tag = "";
		else
			ip_str = t_strdup_until(ip_str, tag++);
	}
	if (ip_str == NULL || net_addr2ip(ip_str, &ip) < 0 ||
	    (args[1] != NULL && str_to_uint(args[1], &vhost_count) < 0) ||
	    (args[1] == NULL && update)) {
		i_error("doveadm sent invalid %s parameters: %s",
			update ? "HOST-UPDATE" : "HOST-SET", line);
		return -1;
	}
	if (vhost_count > MAX_VALID_VHOST_COUNT && vhost_count != UINT_MAX) {
		o_stream_nsend_str(conn->output, "vhost count too large\n");
		return 1;
	}
	host = mail_host_lookup(dir->mail_hosts, &ip);
	if (host == NULL) {
		if (update) {
			o_stream_nsend_str(conn->output, "NOTFOUND\n");
			return 1;
		}
		host = mail_host_add_ip(dir->mail_hosts, &ip, tag);
	} else if (tag[0] != '\0' && strcmp(mail_host_get_tag(host), tag) != 0) {
		o_stream_nsend_str(conn->output, "host tag can't be changed\n");
		return 1;
	} else if (host->desynced) {
		o_stream_nsend_str(conn->output,
			"host is already being updated - try again later\n");
		return 1;
	}
	if (vhost_count != UINT_MAX)
		mail_host_set_vhost_count(host, vhost_count);
	/* NOTE: we don't support changing a tag for an existing host.
	   it needs to be removed first. otherwise it would be a bit ugly to
	   handle. */
	director_update_host(dir, dir->self_host, NULL, host);

	o_stream_nsend(conn->output, "OK\n", 3);
	return 1;
}

static int
doveadm_cmd_host_set(struct doveadm_connection *conn, const char *line)
{
	return doveadm_cmd_host_set_or_update(conn, line, FALSE);
}

static int
doveadm_cmd_host_update(struct doveadm_connection *conn, const char *line)
{
	return doveadm_cmd_host_set_or_update(conn, line, TRUE);
}

static int
doveadm_cmd_host_updown(struct doveadm_connection *conn, bool down,
			const char *line)
{
	struct mail_host *host;
	struct ip_addr ip;

	if (net_addr2ip(line, &ip) < 0) {
		i_error("doveadm sent invalid %s parameters: %s",
			down ? "HOST-DOWN" : "HOST-UP", line);
		return -1;
	}
	host = mail_host_lookup(conn->dir->mail_hosts, &ip);
	if (host == NULL) {
		o_stream_nsend_str(conn->output, "NOTFOUND\n");
		return 1;
	}
	if (host->down == down)
		;
	else if (host->desynced) {
		o_stream_nsend_str(conn->output,
			"host is already being updated - try again later\n");
		return 1;
	} else {
		mail_host_set_down(host, down, ioloop_time);
		director_update_host(conn->dir, conn->dir->self_host,
				     NULL, host);
	}
	o_stream_nsend(conn->output, "OK\n", 3);
	return 1;
}

static int
doveadm_cmd_host_remove(struct doveadm_connection *conn, const char *line)
{
	struct mail_host *host;
	struct ip_addr ip;

	if (net_addr2ip(line, &ip) < 0) {
		i_error("doveadm sent invalid HOST-REMOVE parameters");
		return -1;
	}
	host = mail_host_lookup(conn->dir->mail_hosts, &ip);
	if (host == NULL)
		o_stream_nsend_str(conn->output, "NOTFOUND\n");
	else {
		director_remove_host(conn->dir, conn->dir->self_host,
				     NULL, host);
		o_stream_nsend(conn->output, "OK\n", 3);
	}
	return 1;
}

static void
doveadm_cmd_host_flush_all(struct doveadm_connection *conn)
{
	struct mail_host *const *hostp;
	unsigned int total_user_count = 0;

	array_foreach(mail_hosts_get(conn->dir->mail_hosts), hostp) {
		total_user_count += (*hostp)->user_count;
		director_flush_host(conn->dir, conn->dir->self_host,
				    NULL, *hostp);
	}
	i_warning("Flushed all backend hosts with %u users. This is an unsafe "
		  "operation and may cause the same users to end up in multiple backends.",
		  total_user_count);
	o_stream_nsend(conn->output, "OK\n", 3);
}

static int
doveadm_cmd_host_flush(struct doveadm_connection *conn, const char *line)
{
	struct mail_host *host;
	struct ip_addr ip;

	if (*line == '\0') {
		doveadm_cmd_host_flush_all(conn);
		return 1;
	}

	if (net_addr2ip(line, &ip) < 0) {
		i_error("doveadm sent invalid HOST-FLUSH parameters");
		return -1;
	}
	host = mail_host_lookup(conn->dir->mail_hosts, &ip);
	if (host == NULL)
		o_stream_nsend_str(conn->output, "NOTFOUND\n");
	else {
		director_flush_host(conn->dir, conn->dir->self_host,
				    NULL, host);
		o_stream_nsend(conn->output, "OK\n", 3);
	}
	return 1;
}

static void
director_host_reset_users(struct director *dir, struct director_host *src,
			  struct mail_host *host)
{
	struct user_directory_iter *iter;
	struct user *user;
	struct mail_host *new_host;

	if (dir->right != NULL)
		director_connection_cork(dir->right);

	iter = user_directory_iter_init(dir->users);
	while ((user = user_directory_iter_next(iter)) != NULL) {
		if (user->host != host)
			continue;
		new_host = mail_host_get_by_hash(dir->mail_hosts,
						 user->username_hash,
						 mail_host_get_tag(host));
		if (new_host != host) T_BEGIN {
			director_move_user(dir, src, NULL,
					   user->username_hash, new_host);
		} T_END;
	}
	user_directory_iter_deinit(&iter);
	if (dir->right != NULL)
		director_connection_uncork(dir->right);
}

static void
doveadm_cmd_host_reset_users_all(struct doveadm_connection *conn)
{
	struct mail_host *const *hostp;

	array_foreach(mail_hosts_get(conn->dir->mail_hosts), hostp)
		director_host_reset_users(conn->dir, conn->dir->self_host, *hostp);
	o_stream_nsend(conn->output, "OK\n", 3);
}

static int
doveadm_cmd_host_reset_users(struct doveadm_connection *conn, const char *line)
{
	struct mail_host *host;
	struct ip_addr ip;

	if (line[0] == '\0') {
		doveadm_cmd_host_reset_users_all(conn);
		return 1;
	}

	if (net_addr2ip(line, &ip) < 0) {
		i_error("doveadm sent invalid HOST-RESET-USERS parameters");
		return -1;
	}
	host = mail_host_lookup(conn->dir->mail_hosts, &ip);
	if (host == NULL)
		o_stream_nsend_str(conn->output, "NOTFOUND\n");
	else {
		director_host_reset_users(conn->dir, conn->dir->self_host, host);
		o_stream_nsend(conn->output, "OK\n", 3);
	}
	return 1;
}

static int
doveadm_cmd_user_lookup(struct doveadm_connection *conn, const char *line)
{
	struct user *user;
	struct mail_host *host;
	const char *username, *tag, *const *args;
	unsigned int username_hash;
	string_t *str = t_str_new(256);

	args = t_strsplit_tabescaped(line);
	if (args[0] == NULL) {
		username = "";
		tag = "";
	} else {
		username = args[0];
		tag = args[1] != NULL ? args[1] : "";
	}
	if (str_to_uint(username, &username_hash) < 0)
		username_hash = user_directory_get_username_hash(conn->dir->users, username);

	/* get user's current host */
	user = user_directory_lookup(conn->dir->users, username_hash);
	if (user == NULL)
		str_append(str, "\t0");
	else {
		str_printfa(str, "%s\t%u", net_ip2addr(&user->host->ip),
			    user->timestamp +
			    conn->dir->set->director_user_expire);
	}

	/* get host if it wasn't in user directory */
	host = mail_host_get_by_hash(conn->dir->mail_hosts, username_hash, tag);
	if (host == NULL)
		str_append(str, "\t");
	else
		str_printfa(str, "\t%s", net_ip2addr(&host->ip));

	/* get host with default configuration */
	host = mail_host_get_by_hash(conn->dir->orig_config_hosts,
				     username_hash, tag);
	if (host == NULL)
		str_append(str, "\t\n");
	else
		str_printfa(str, "\t%s\n", net_ip2addr(&host->ip));
	o_stream_nsend(conn->output, str_data(str), str_len(str));
	return 1;
}

static int
doveadm_cmd_user_list(struct doveadm_connection *conn, const char *line)
{
	struct user_directory_iter *iter;
	struct user *user;
	struct ip_addr ip;

	if (*line != '\0') {
		if (net_addr2ip(line, &ip) < 0) {
			i_error("doveadm sent invalid USER-LIST parameters");
			return -1;
		}
	} else {
		ip.family = 0;
	}

	iter = user_directory_iter_init(conn->dir->users);
	while ((user = user_directory_iter_next(iter)) != NULL) {
		if (ip.family == 0 ||
		    net_ip_compare(&ip, &user->host->ip)) T_BEGIN {
			unsigned int expire_time = user->timestamp +
				conn->dir->set->director_user_expire;

			o_stream_nsend_str(conn->output, t_strdup_printf(
				"%u\t%u\t%s\n",
				user->username_hash, expire_time,
				net_ip2addr(&user->host->ip)));
		} T_END;
	}
	user_directory_iter_deinit(&iter);
	o_stream_nsend(conn->output, "\n", 1);
	return 1;
}

static int
doveadm_cmd_user_move(struct doveadm_connection *conn, const char *line)
{
	unsigned int username_hash;
	const char *const *args;
	struct user *user;
	struct mail_host *host;
	struct ip_addr ip;

	args = t_strsplit_tabescaped(line);
	if (args[0] == NULL || args[1] == NULL ||
	    net_addr2ip(args[1], &ip) < 0) {
		i_error("doveadm sent invalid USER-MOVE parameters: %s", line);
		return -1;
	}
	host = mail_host_lookup(conn->dir->mail_hosts, &ip);
	if (host == NULL) {
		o_stream_nsend_str(conn->output, "NOTFOUND\n");
		return 1;
	}

	if (str_to_uint(args[0], &username_hash) < 0)
		username_hash = user_directory_get_username_hash(conn->dir->users, line);
	user = user_directory_lookup(conn->dir->users, username_hash);
	if (user != NULL && user->kill_state != USER_KILL_STATE_NONE) {
		o_stream_nsend_str(conn->output, "TRYAGAIN\n");
		return 1;
	}

	director_move_user(conn->dir, conn->dir->self_host, NULL,
			   username_hash, host);
	o_stream_nsend(conn->output, "OK\n", 3);
	return 1;
}

static int
doveadm_cmd_user_kick(struct doveadm_connection *conn, const char *line)
{
	const char *const *args;

	args = t_strsplit_tabescaped(line);
	if (args[0] == NULL) {
		i_error("doveadm sent invalid USER-KICK parameters: %s", line);
		return -1;
	}

	director_kick_user(conn->dir, conn->dir->self_host, NULL, args[0]);
	o_stream_nsend(conn->output, "OK\n", 3);
	return 1;
}

static void doveadm_connection_input(struct doveadm_connection *conn)
{
	const char *line, *cmd, *args;
	int ret = 1;

	if (!conn->handshaked) {
		if ((line = i_stream_read_next_line(conn->input)) == NULL) {
			if (conn->input->eof || conn->input->stream_errno != 0)
				doveadm_connection_deinit(&conn);
			return;
		}

		if (!version_string_verify(line, "director-doveadm",
					   DOVEADM_PROTOCOL_VERSION_MAJOR)) {
			i_error("doveadm not compatible with this server "
				"(mixed old and new binaries?)");
			doveadm_connection_deinit(&conn);
			return;
		}
		conn->handshaked = TRUE;
	}

	while ((line = i_stream_read_next_line(conn->input)) != NULL && ret > 0) {
		args = strchr(line, '\t');
		if (args == NULL) {
			cmd = line;
			args = "";
		} else {
			cmd = t_strdup_until(line, args);
			args++;
		}

		if (strcmp(cmd, "HOST-LIST") == 0)
			doveadm_cmd_host_list(conn);
		else if (strcmp(cmd, "HOST-LIST-REMOVED") == 0)
			doveadm_cmd_host_list_removed(conn);
		else if (strcmp(cmd, "DIRECTOR-LIST") == 0)
			doveadm_cmd_director_list(conn);
		else if (strcmp(cmd, "DIRECTOR-ADD") == 0)
			ret = doveadm_cmd_director_add(conn, args);
		else if (strcmp(cmd, "DIRECTOR-REMOVE") == 0)
			ret = doveadm_cmd_director_remove(conn, args);
		else if (strcmp(cmd, "HOST-SET") == 0)
			ret = doveadm_cmd_host_set(conn, args);
		else if (strcmp(cmd, "HOST-UPDATE") == 0)
			ret = doveadm_cmd_host_update(conn, args);
		else if (strcmp(cmd, "HOST-UP") == 0)
			ret = doveadm_cmd_host_updown(conn, FALSE, args);
		else if (strcmp(cmd, "HOST-DOWN") == 0)
			ret = doveadm_cmd_host_updown(conn, TRUE, args);
		else if (strcmp(cmd, "HOST-REMOVE") == 0)
			ret = doveadm_cmd_host_remove(conn, args);
		else if (strcmp(cmd, "HOST-FLUSH") == 0)
			ret = doveadm_cmd_host_flush(conn, args);
		else if (strcmp(cmd, "HOST-RESET-USERS") == 0)
			ret = doveadm_cmd_host_reset_users(conn, args);
		else if (strcmp(cmd, "USER-LOOKUP") == 0)
			ret = doveadm_cmd_user_lookup(conn, args);
		else if (strcmp(cmd, "USER-LIST") == 0)
			ret = doveadm_cmd_user_list(conn, args);
		else if (strcmp(cmd, "USER-MOVE") == 0)
			ret = doveadm_cmd_user_move(conn, args);
		else if (strcmp(cmd, "USER-KICK") == 0)
			ret = doveadm_cmd_user_kick(conn, args);
		else {
			i_error("doveadm sent unknown command: %s", line);
			ret = -1;
		}
	}
	if (conn->input->eof || conn->input->stream_errno != 0 || ret < 0)
		doveadm_connection_deinit(&conn);
}

struct doveadm_connection *
doveadm_connection_init(struct director *dir, int fd)
{
	struct doveadm_connection *conn;

	conn = i_new(struct doveadm_connection, 1);
	conn->fd = fd;
	conn->dir = dir;
	conn->input = i_stream_create_fd(conn->fd, 1024);
	conn->output = o_stream_create_fd(conn->fd, (size_t)-1);
	o_stream_set_no_error_handling(conn->output, TRUE);
	conn->io = io_add(conn->fd, IO_READ, doveadm_connection_input, conn);
	o_stream_nsend_str(conn->output, DOVEADM_HANDSHAKE);

	DLLIST_PREPEND(&doveadm_connections, conn);
	return conn;
}

static void doveadm_connection_deinit(struct doveadm_connection **_conn)
{
	struct doveadm_connection *conn = *_conn;

	*_conn = NULL;

	DLLIST_REMOVE(&doveadm_connections, conn);
	io_remove(&conn->io);
	i_stream_unref(&conn->input);
	o_stream_unref(&conn->output);
	if (close(conn->fd) < 0)
		i_error("close(doveadm connection) failed: %m");
	i_free(conn);

	master_service_client_connection_destroyed(master_service);
}

void doveadm_connections_deinit(void)
{
	while (doveadm_connections != NULL) {
		struct doveadm_connection *conn = doveadm_connections;

		doveadm_connection_deinit(&conn);
	}
}
