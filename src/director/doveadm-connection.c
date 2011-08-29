/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "array.h"
#include "str.h"
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

	unsigned int handshaked:1;
};

static struct doveadm_connection *doveadm_connections;

static void doveadm_connection_deinit(struct doveadm_connection **_conn);

static void doveadm_cmd_host_list(struct doveadm_connection *conn)
{
	struct mail_host *const *hostp;
	string_t *str = t_str_new(1024);

	array_foreach(mail_hosts_get(conn->dir->mail_hosts), hostp) {
		str_printfa(str, "%s\t%u\t%u\n",
			    net_ip2addr(&(*hostp)->ip), (*hostp)->vhost_count,
			    (*hostp)->user_count);
	}
	str_append_c(str, '\n');
	o_stream_send(conn->output, str_data(str), str_len(str));
}

static void doveadm_cmd_host_list_removed(struct doveadm_connection *conn)
{
	struct mail_host_list *orig_hosts_list;
	struct mail_host *const *orig_hosts, *const *cur_hosts;
	unsigned int i, j, orig_hosts_count, cur_hosts_count;
	string_t *str = t_str_new(1024);
	int ret;

	orig_hosts_list = mail_hosts_init();
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
	o_stream_send(conn->output, str_data(str), str_len(str));

	mail_hosts_deinit(&orig_hosts_list);
}

static void doveadm_cmd_director_list(struct doveadm_connection *conn)
{
	struct director *dir = conn->dir;
	struct director_host *const *hostp;
	string_t *str = t_str_new(1024);
	const char *type;
	bool left, right;

	array_foreach(&dir->dir_hosts, hostp) {
		const struct director_host *host = *hostp;

		left = dir->left != NULL &&
			director_connection_get_host(dir->left) == host;
		right = dir->right != NULL &&
			 director_connection_get_host(dir->right) == host;

		if (dir->self_host == host)
			type = "self";
		else if (left)
			type = right ? "l+r" : "left";
		else if (right)
			type = "right";
		else
			type = "";
		str_printfa(str, "%s\t%u\t%s\t%lu\n",
			    net_ip2addr(&host->ip), host->port, type,
			    (unsigned long)host->last_failed);
	}
	str_append_c(str, '\n');
	o_stream_send(conn->output, str_data(str), str_len(str));
}

static bool
doveadm_cmd_host_set(struct doveadm_connection *conn, const char *line)
{
	struct director *dir = conn->dir;
	const char *const *args;
	struct mail_host *host;
	struct ip_addr ip;
	unsigned int vhost_count = -1U;

	args = t_strsplit(line, "\t");
	if (args[0] == NULL ||
	    net_addr2ip(args[0], &ip) < 0 ||
	    (args[1] != NULL && str_to_uint(args[1], &vhost_count) < 0)) {
		i_error("doveadm sent invalid HOST-SET parameters: %s", line);
		return FALSE;
	}
	if (vhost_count > MAX_VALID_VHOST_COUNT && vhost_count != -1U) {
		o_stream_send_str(conn->output, "vhost count too large\n");
		return TRUE;
	}
	host = mail_host_lookup(dir->mail_hosts, &ip);
	if (host == NULL)
		host = mail_host_add_ip(dir->mail_hosts, &ip);
	if (vhost_count != -1U)
		mail_host_set_vhost_count(dir->mail_hosts, host, vhost_count);
	director_update_host(dir, dir->self_host, NULL, host);

	o_stream_send(conn->output, "OK\n", 3);
	return TRUE;
}

static bool
doveadm_cmd_host_remove(struct doveadm_connection *conn, const char *line)
{
	struct mail_host *host;
	struct ip_addr ip;

	if (net_addr2ip(line, &ip) < 0) {
		i_error("doveadm sent invalid HOST-REMOVE parameters");
		return FALSE;
	}
	host = mail_host_lookup(conn->dir->mail_hosts, &ip);
	if (host == NULL)
		o_stream_send_str(conn->output, "NOTFOUND\n");
	else {
		director_remove_host(conn->dir, conn->dir->self_host,
				     NULL, host);
		o_stream_send(conn->output, "OK\n", 3);
	}
	return TRUE;
}

static void
doveadm_cmd_host_flush_all(struct doveadm_connection *conn)
{
	struct mail_host *const *hostp;

	array_foreach(mail_hosts_get(conn->dir->mail_hosts), hostp) {
		director_flush_host(conn->dir, conn->dir->self_host,
				    NULL, *hostp);
	}
	o_stream_send(conn->output, "OK\n", 3);
}

static bool
doveadm_cmd_host_flush(struct doveadm_connection *conn, const char *line)
{
	struct mail_host *host;
	struct ip_addr ip;

	if (*line == '\0') {
		doveadm_cmd_host_flush_all(conn);
		return TRUE;
	}

	if (net_addr2ip(line, &ip) < 0) {
		i_error("doveadm sent invalid HOST-FLUSH parameters");
		return FALSE;
	}
	host = mail_host_lookup(conn->dir->mail_hosts, &ip);
	if (host == NULL)
		o_stream_send_str(conn->output, "NOTFOUND\n");
	else {
		director_flush_host(conn->dir, conn->dir->self_host,
				    NULL, host);
		o_stream_send(conn->output, "OK\n", 3);
	}
	return TRUE;
}

static bool
doveadm_cmd_user_lookup(struct doveadm_connection *conn, const char *line)
{
	struct user *user;
	struct mail_host *host;
	unsigned int username_hash;
	string_t *str = t_str_new(256);

	if (str_to_uint(line, &username_hash) < 0)
		username_hash = user_directory_get_username_hash(line);

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
	host = mail_host_get_by_hash(conn->dir->mail_hosts, username_hash);
	if (host == NULL)
		str_append(str, "\t");
	else
		str_printfa(str, "\t%s", net_ip2addr(&host->ip));

	/* get host with default configuration */
	host = mail_host_get_by_hash(conn->dir->orig_config_hosts,
				     username_hash);
	if (host == NULL)
		str_append(str, "\t");
	else
		str_printfa(str, "\t%s\n", net_ip2addr(&host->ip));
	o_stream_send(conn->output, str_data(str), str_len(str));
	return TRUE;
}

static bool
doveadm_cmd_user_list(struct doveadm_connection *conn, const char *line)
{
	struct user_directory_iter *iter;
	struct user *user;
	struct ip_addr ip;

	if (*line != '\0') {
		if (net_addr2ip(line, &ip) < 0) {
			i_error("doveadm sent invalid USER-LIST parameters");
			return FALSE;
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

			o_stream_send_str(conn->output, t_strdup_printf(
				"%u\t%u\t%s\n",
				user->username_hash, expire_time,
				net_ip2addr(&user->host->ip)));
		} T_END;
	}
	user_directory_iter_deinit(&iter);
	o_stream_send(conn->output, "\n", 1);
	return TRUE;
}

static bool
doveadm_cmd_user_move(struct doveadm_connection *conn, const char *line)
{
	unsigned int username_hash;
	const char *const *args;
	struct user *user;
	struct mail_host *host;
	struct ip_addr ip;

	args = t_strsplit(line, "\t");
	if (args[0] == NULL || args[1] == NULL ||
	    net_addr2ip(args[1], &ip) < 0) {
		i_error("doveadm sent invalid USER-MOVE parameters: %s", line);
		return FALSE;
	}
	host = mail_host_lookup(conn->dir->mail_hosts, &ip);
	if (host == NULL) {
		o_stream_send_str(conn->output, "NOTFOUND\n");
		return TRUE;
	}

	if (str_to_uint(args[0], &username_hash) < 0)
		username_hash = user_directory_get_username_hash(line);
	user = user_directory_lookup(conn->dir->users, username_hash);
	if (user != NULL && user->kill_state != USER_KILL_STATE_NONE) {
		o_stream_send_str(conn->output, "TRYAGAIN\n");
		return TRUE;
	}

	director_move_user(conn->dir, conn->dir->self_host, NULL,
			   username_hash, host);
	o_stream_send(conn->output, "OK\n", 3);
	return TRUE;
}

static void doveadm_connection_input(struct doveadm_connection *conn)
{
	const char *line, *cmd, *args;
	bool ret = TRUE;

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

	while ((line = i_stream_read_next_line(conn->input)) != NULL && ret) {
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
		else if (strcmp(cmd, "HOST-SET") == 0)
			ret = doveadm_cmd_host_set(conn, args);
		else if (strcmp(cmd, "HOST-REMOVE") == 0)
			ret = doveadm_cmd_host_remove(conn, args);
		else if (strcmp(cmd, "HOST-FLUSH") == 0)
			ret = doveadm_cmd_host_flush(conn, args);
		else if (strcmp(cmd, "USER-LOOKUP") == 0)
			ret = doveadm_cmd_user_lookup(conn, args);
		else if (strcmp(cmd, "USER-LIST") == 0)
			ret = doveadm_cmd_user_list(conn, args);
		else if (strcmp(cmd, "USER-MOVE") == 0)
			ret = doveadm_cmd_user_move(conn, args);
		else {
			i_error("doveadm sent unknown command: %s", line);
			ret = FALSE;
		}
	}
	if (conn->input->eof || conn->input->stream_errno != 0 || !ret)
		doveadm_connection_deinit(&conn);
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
	conn->io = io_add(conn->fd, IO_READ, doveadm_connection_input, conn);
	o_stream_send_str(conn->output, DOVEADM_HANDSHAKE);

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
