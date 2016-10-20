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
#define DEFAULT_MAX_MOVING_USERS 100

struct director_reset_cmd {
	struct director_reset_cmd *prev, *next;

	struct director *dir;
	struct doveadm_connection *_conn;
	struct director_user_iter *iter;
	unsigned int host_idx, hosts_count;
	unsigned int max_moving_users;
};

struct doveadm_connection {
	struct doveadm_connection *prev, *next;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;
	struct director *dir;

	struct director_reset_cmd *reset_cmd;

	unsigned int handshaked:1;
};

static struct doveadm_connection *doveadm_connections;
static struct director_reset_cmd *reset_cmds = NULL;

static void doveadm_connection_set_io(struct doveadm_connection *conn);
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

	orig_hosts_list = mail_hosts_init(conn->dir->set->director_user_expire,
					  conn->dir->set->director_consistent_hashing,
					  NULL);
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
doveadm_cmd_director_add(struct doveadm_connection *conn,
			 const char *const *args)
{
	struct director_host *host;
	struct ip_addr ip;
	in_port_t port = conn->dir->self_port;

	if (args[0] == NULL ||
	    net_addr2ip(args[0], &ip) < 0 ||
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
doveadm_cmd_director_remove(struct doveadm_connection *conn,
			    const char *const *args)
{
	struct director_host *host;
	struct ip_addr ip;
	in_port_t port = 0;

	if (args[0] == NULL ||
	    net_addr2ip(args[0], &ip) < 0 ||
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
doveadm_cmd_host_set_or_update(struct doveadm_connection *conn,
			       const char *const *args, bool update)
{
	struct director *dir = conn->dir;
	const char *ip_str, *tag = "";
	struct mail_host *host;
	struct ip_addr ip;
	unsigned int vhost_count = UINT_MAX;

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
		i_error("doveadm sent invalid %s parameters",
			update ? "HOST-UPDATE" : "HOST-SET");
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
doveadm_cmd_host_set(struct doveadm_connection *conn, const char *const *args)
{
	return doveadm_cmd_host_set_or_update(conn, args, FALSE);
}

static int
doveadm_cmd_host_update(struct doveadm_connection *conn, const char *const *args)
{
	return doveadm_cmd_host_set_or_update(conn, args, TRUE);
}

static int
doveadm_cmd_host_updown(struct doveadm_connection *conn, bool down,
			const char *const *args)
{
	struct mail_host *host;
	struct ip_addr ip;

	if (args[0] == NULL || net_addr2ip(args[0], &ip) < 0) {
		i_error("doveadm sent invalid %s parameters: %s",
			down ? "HOST-DOWN" : "HOST-UP",
			args[0] == NULL ? "" : args[0]);
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
doveadm_cmd_host_remove(struct doveadm_connection *conn,
			const char *const *args)
{
	struct mail_host *host;
	struct ip_addr ip;

	if (args[0] == NULL || net_addr2ip(args[0], &ip) < 0) {
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
doveadm_cmd_host_flush(struct doveadm_connection *conn, const char *const *args)
{
	struct mail_host *host;
	struct ip_addr ip;

	if (args[0] == NULL || args[0][0] == '\0') {
		doveadm_cmd_host_flush_all(conn);
		return 1;
	}

	if (net_addr2ip(args[0], &ip) < 0) {
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

static void doveadm_reset_cmd_free(struct director_reset_cmd *cmd)
{
	DLLIST_REMOVE(&reset_cmds, cmd);

	if (cmd->iter != NULL)
		director_iterate_users_deinit(&cmd->iter);
	if (cmd->_conn != NULL)
		cmd->_conn->reset_cmd = NULL;
	i_free(cmd);
}

static bool
director_host_reset_users(struct director_reset_cmd *cmd,
			  struct mail_host *host)
{
	struct director *dir = cmd->dir;
	struct user *user;
	struct mail_host *new_host;

	if (dir->users_moving_count >= cmd->max_moving_users)
		return FALSE;

	if (dir->right != NULL)
		director_connection_cork(dir->right);

	if (cmd->iter == NULL)
		cmd->iter = director_iterate_users_init(dir);

	while ((user = director_iterate_users_next(cmd->iter)) != NULL) {
		if (user->host != host)
			continue;
		new_host = mail_host_get_by_hash(dir->mail_hosts,
						 user->username_hash,
						 mail_host_get_tag(host));
		if (new_host != host) T_BEGIN {
			director_move_user(dir, dir->self_host, NULL,
					   user->username_hash, new_host);
		} T_END;
		if (dir->users_moving_count >= cmd->max_moving_users)
			break;
	}
	if (user == NULL)
		director_iterate_users_deinit(&cmd->iter);
	if (dir->right != NULL)
		director_connection_uncork(dir->right);
	return user == NULL;
}

static bool
director_reset_cmd_run(struct director_reset_cmd *cmd)
{
	struct mail_host *const *hosts;
	unsigned int count;

	hosts = array_get(mail_hosts_get(cmd->dir->mail_hosts), &count);
	if (count > cmd->hosts_count)
		count = cmd->hosts_count;
	while (cmd->host_idx < count) {
		if (!director_host_reset_users(cmd, hosts[cmd->host_idx]))
			return FALSE;
		cmd->host_idx++;
	}
	if (cmd->_conn != NULL) {
		struct doveadm_connection *conn = cmd->_conn;

		o_stream_nsend(conn->output, "OK\n", 3);
		if (conn->io == NULL)
			doveadm_connection_set_io(conn);
	}
	doveadm_reset_cmd_free(cmd);
	return TRUE;
}

static int
doveadm_cmd_host_reset_users(struct doveadm_connection *conn,
			     const char *const *args)
{
	struct director_reset_cmd *cmd;
	struct ip_addr ip;
	struct mail_host *const *hosts;
	unsigned int i = 0, count;
	unsigned int max_moving_users = DEFAULT_MAX_MOVING_USERS;

	if (args[0] != NULL && args[1] != NULL &&
	    str_to_uint(args[1], &max_moving_users) < 0) {
		i_error("doveadm sent invalid HOST-RESET-USERS parameters");
		return -1;
	}

	hosts = array_get(mail_hosts_get(conn->dir->mail_hosts), &count);
	if (args[0] != NULL && args[0][0] != '\0') {
		if (net_addr2ip(args[0], &ip) < 0) {
			i_error("doveadm sent invalid HOST-RESET-USERS ip: %s",
				args[0]);
			return -1;
		}

		for (i = 0; i < count; i++) {
			if (net_ip_compare(&hosts[i]->ip, &ip))
				break;
		}
		if (i == count) {
			o_stream_nsend_str(conn->output, "NOTFOUND\n");
			return 1;
		}
		count = i+1;
	}

	conn->reset_cmd = cmd = i_new(struct director_reset_cmd, 1);
	cmd->dir = conn->dir;
	cmd->_conn = conn;
	cmd->max_moving_users = max_moving_users;
	cmd->host_idx = i;
	cmd->hosts_count = count;
	DLLIST_PREPEND(&reset_cmds, cmd);

	if (!director_reset_cmd_run(cmd)) {
		/* we still have work to do. don't handle any more doveadm
		   input until we're finished. */
		io_remove(&conn->io);
		return 0;
	}
	return 1;
}

static int
doveadm_cmd_user_lookup(struct doveadm_connection *conn,
			const char *const *args)
{
	struct user *user;
	struct mail_host *host;
	const char *username, *tag;
	unsigned int username_hash;
	struct mail_tag *mail_tag;
	string_t *str = t_str_new(256);

	if (args[0] == NULL) {
		username = "";
		tag = "";
	} else {
		username = args[0];
		tag = args[1] != NULL ? args[1] : "";
	}
	if (str_to_uint(username, &username_hash) < 0)
		username_hash = director_get_username_hash(conn->dir, username);

	/* get user's current host */
	mail_tag = mail_tag_find(conn->dir->mail_hosts, tag);
	user = mail_tag == NULL ? NULL :
		user_directory_lookup(mail_tag->users, username_hash);
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
doveadm_cmd_user_list(struct doveadm_connection *conn, const char *const *args)
{
	struct director_user_iter *iter;
	struct user *user;
	struct ip_addr ip;

	if (args[0] != NULL && args[0][0] != '\0') {
		if (net_addr2ip(args[0], &ip) < 0) {
			i_error("doveadm sent invalid USER-LIST parameters");
			return -1;
		}
	} else {
		ip.family = 0;
	}

	iter = director_iterate_users_init(conn->dir);
	while ((user = director_iterate_users_next(iter)) != NULL) {
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
	director_iterate_users_deinit(&iter);
	o_stream_nsend(conn->output, "\n", 1);
	return 1;
}

static int
doveadm_cmd_user_move(struct doveadm_connection *conn, const char *const *args)
{
	unsigned int username_hash;
	struct user *user;
	struct mail_host *host;
	struct ip_addr ip;

	if (args[0] == NULL || args[1] == NULL ||
	    net_addr2ip(args[1], &ip) < 0) {
		i_error("doveadm sent invalid USER-MOVE parameters");
		return -1;
	}
	host = mail_host_lookup(conn->dir->mail_hosts, &ip);
	if (host == NULL) {
		o_stream_nsend_str(conn->output, "NOTFOUND\n");
		return 1;
	}

	if (str_to_uint(args[0], &username_hash) < 0)
		username_hash = director_get_username_hash(conn->dir, args[0]);
	user = user_directory_lookup(host->tag->users, username_hash);
	if (user != NULL && USER_IS_BEING_KILLED(user)) {
		o_stream_nsend_str(conn->output, "TRYAGAIN\n");
		return 1;
	}

	director_move_user(conn->dir, conn->dir->self_host, NULL,
			   username_hash, host);
	o_stream_nsend(conn->output, "OK\n", 3);
	return 1;
}

static int
doveadm_cmd_user_kick(struct doveadm_connection *conn, const char *const *args)
{
	if (args[0] == NULL) {
		i_error("doveadm sent invalid USER-KICK parameters");
		return -1;
	}

	director_kick_user(conn->dir, conn->dir->self_host, NULL, args[0]);
	o_stream_nsend(conn->output, "OK\n", 3);
	return 1;
}

static int
doveadm_connection_cmd(struct doveadm_connection *conn, const char *line)
{
	const char *cmd, *const *args;
	int ret = 1;

	args = t_strsplit_tabescaped(line);
	if (args[0] == NULL) {
		i_error("doveadm sent empty command line");
		return -1;
	}
	cmd = args[0];
	args++;

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
	return ret;
}

static void doveadm_connection_input(struct doveadm_connection *conn)
{
	const char *line;
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
		T_BEGIN {
			ret = doveadm_connection_cmd(conn, line);
		} T_END;
	}
	if (conn->input->eof || conn->input->stream_errno != 0 || ret < 0)
		doveadm_connection_deinit(&conn);
}

static void doveadm_connection_set_io(struct doveadm_connection *conn)
{
	conn->io = io_add(conn->fd, IO_READ, doveadm_connection_input, conn);
}

struct doveadm_connection *
doveadm_connection_init(struct director *dir, int fd)
{
	struct doveadm_connection *conn;

	conn = i_new(struct doveadm_connection, 1);
	conn->fd = fd;
	conn->dir = dir;
	conn->input = i_stream_create_fd(conn->fd, 1024, FALSE);
	conn->output = o_stream_create_fd(conn->fd, (size_t)-1, FALSE);
	o_stream_set_no_error_handling(conn->output, TRUE);
	doveadm_connection_set_io(conn);
	o_stream_nsend_str(conn->output, DOVEADM_HANDSHAKE);

	DLLIST_PREPEND(&doveadm_connections, conn);
	return conn;
}

static void doveadm_connection_deinit(struct doveadm_connection **_conn)
{
	struct doveadm_connection *conn = *_conn;

	*_conn = NULL;

	if (conn->reset_cmd != NULL) {
		/* finish the move even if doveadm disconnected */
		conn->reset_cmd->_conn = NULL;
	}

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
	while (reset_cmds != NULL)
		doveadm_reset_cmd_free(reset_cmds);
	while (doveadm_connections != NULL) {
		struct doveadm_connection *conn = doveadm_connections;

		doveadm_connection_deinit(&conn);
	}
}

void doveadm_connections_continue_reset_cmds(void)
{
	while (reset_cmds != NULL) {
		if (!director_reset_cmd_run(reset_cmds))
			break;
	}
}
