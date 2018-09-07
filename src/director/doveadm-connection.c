/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "llist.h"
#include "time-util.h"
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

#define DOVEADM_CONNECTION_RING_SYNC_TIMEOUT_MSECS (30*1000)

enum doveadm_director_cmd_ret {
	DOVEADM_DIRECTOR_CMD_RET_FAIL = -1,
	DOVEADM_DIRECTOR_CMD_RET_UNFINISHED = 0,
	DOVEADM_DIRECTOR_CMD_RET_OK = 1,
	DOVEADM_DIRECTOR_CMD_RET_RING_SYNC_OK,
};

enum doveadm_director_cmd_flag {
	DOVEADM_DIRECTOR_CMD_FLAG_PRE_RING_SYNC = 0x01,
};

typedef void
doveadm_connection_ring_sync_callback_t(struct doveadm_connection *);

struct director_reset_cmd {
	struct director_reset_cmd *prev, *next;

	struct director *dir;
	struct doveadm_connection *_conn;
	struct timeval start_time;

	struct director_user_iter *iter;
	unsigned int host_start_idx, host_idx, hosts_count;
	unsigned int max_moving_users;
	unsigned int reset_count;
	bool users_killed;
};

struct director_kick_cmd {
	struct director_kick_cmd *prev, *next;

	struct doveadm_connection *_conn;
	struct director *dir;
	char *mask, *field, *value;
	bool alt:1;
};

struct doveadm_connection {
	struct doveadm_connection *prev, *next;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;
	struct director *dir;

	struct timeout *to_ring_sync_abort;
	struct director_reset_cmd *reset_cmd;
	struct director_kick_cmd *kick_cmd;
	doveadm_connection_ring_sync_callback_t *ring_sync_callback;

	const char **cmd_pending_args;
	unsigned int cmd_pending_idx;

	bool handshaked:1;
};

static struct doveadm_connection *doveadm_connections;
static struct doveadm_connection *doveadm_ring_sync_pending_connections;
static struct director_reset_cmd *reset_cmds = NULL;
static struct director_kick_cmd *kick_cmds = NULL;

static void doveadm_connection_set_io(struct doveadm_connection *conn);
static void doveadm_connection_deinit(struct doveadm_connection **_conn);
static void
doveadm_connection_ring_sync_list_move(struct doveadm_connection *conn);
static void doveadm_connection_cmd_run_synced(struct doveadm_connection *conn);

static enum doveadm_director_cmd_ret
doveadm_cmd_host_list(struct doveadm_connection *conn,
		      const char *const *args ATTR_UNUSED)
{
	struct mail_host *const *hostp;
	string_t *str = t_str_new(1024);

	array_foreach(mail_hosts_get(conn->dir->mail_hosts), hostp) {
		str_printfa(str, "%s\t%u\t%u\t",
			    (*hostp)->ip_str, (*hostp)->vhost_count,
			    (*hostp)->user_count);
		str_append_tabescaped(str, mail_host_get_tag(*hostp));
		str_printfa(str, "\t%c\t%ld", (*hostp)->down ? 'D' : 'U',
			    (long)(*hostp)->last_updown_change);
		str_append_c(str, '\n');
	}
	str_append_c(str, '\n');
	o_stream_nsend(conn->output, str_data(str), str_len(str));
	return DOVEADM_DIRECTOR_CMD_RET_OK;
}

static enum doveadm_director_cmd_ret
doveadm_cmd_host_list_removed(struct doveadm_connection *conn,
			      const char *const *args ATTR_UNUSED)
{
	struct mail_host_list *orig_hosts_list;
	struct mail_host *const *orig_hosts, *const *cur_hosts;
	unsigned int i, j, orig_hosts_count, cur_hosts_count;
	string_t *str = t_str_new(1024);
	int ret;

	orig_hosts_list = mail_hosts_init(conn->dir->set->director_user_expire,
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
			str_printfa(str, "%s\n", orig_hosts[i]->ip_str);
			i++;
		}
	}
	for (; i < orig_hosts_count; i++)
		str_printfa(str, "%s\n", orig_hosts[i]->ip_str);
	str_append_c(str, '\n');
	o_stream_nsend(conn->output, str_data(str), str_len(str));

	mail_hosts_deinit(&orig_hosts_list);
	return DOVEADM_DIRECTOR_CMD_RET_OK;
}

static void
doveadm_director_host_append_status(const struct director_host *host,
				    const char *type, string_t *str)
{
	time_t last_failed = I_MAX(host->last_network_failure,
				   host->last_protocol_failure);
	str_printfa(str, "%s\t%u\t%s\t%"PRIdTIME_T"\t",
		    host->ip_str, host->port, type,
		    last_failed);
}

static void doveadm_director_append_status(struct director *dir, string_t *str)
{
	if (!dir->ring_handshaked)
		str_append(str, "ring handshaking");
	else if (dir->ring_synced)
		str_append(str, "ring synced");
	else {
		str_printfa(str, "ring syncing - last sync %d secs ago",
			    (int)(ioloop_time - dir->ring_last_sync_time));
	}
	str_printfa(str, "\t%u", dir->last_sync_msecs);
}

static void
doveadm_director_connection_append_status(struct director_connection *conn,
					  string_t *str)
{
	struct director_connection_status status;

	director_connection_get_status(conn, &status);
	if (!director_connection_is_handshaked(conn)) {
		str_append(str, "handshaking - ");
		if (director_connection_is_incoming(conn))
			str_printfa(str, "%u USERs received", status.handshake_users_received);
		else
			str_printfa(str, "%u USERs sent", status.handshake_users_sent);
	} else if (director_connection_is_synced(conn))
		str_append(str, "synced");
	else
		str_append(str, "syncing");

	str_printfa(str, "\t%u\t%"PRIuUOFF_T"\t%"PRIuUOFF_T"\t%zu\t%zu\t"
		    "%"PRIdTIME_T"\t%"PRIdTIME_T, status.last_ping_msecs,
		    status.bytes_read, status.bytes_sent,
		    status.bytes_buffered, status.peak_bytes_buffered,
		    status.last_input.tv_sec, status.last_output.tv_sec);
}

static void
doveadm_director_connection_append(struct director *dir,
				   struct director_connection *conn,
				   const struct director_host *host,
				   string_t *str)
{
	const char *type;

	if (conn == dir->left)
		type = "left";
	else if (conn == dir->right)
		type = "right";
	else if (director_connection_is_incoming(conn))
		type = "in";
	else
		type = "out";

	if (host != NULL)
		doveadm_director_host_append_status(host, type, str);
	doveadm_director_connection_append_status(conn, str);
	str_append_c(str, '\n');
}

static void
doveadm_director_host_append(struct director *dir,
			     const struct director_host *host, string_t *str)
{
	const char *type;

	if (host->removed)
		type = "removed";
	else if (dir->self_host == host)
		type = "self";
	else
		type = "";

	doveadm_director_host_append_status(host, type, str);
	if (dir->self_host == host)
		doveadm_director_append_status(dir, str);
	str_append_c(str, '\n');
}

static enum doveadm_director_cmd_ret
doveadm_cmd_director_list(struct doveadm_connection *conn,
			  const char *const *args ATTR_UNUSED)
{
	struct director *dir = conn->dir;
	struct director_host *const *hostp;
	string_t *str = t_str_new(1024);
	struct director_connection *const *connp;
	ARRAY(struct director_host *) hosts;

	t_array_init(&hosts, array_count(&dir->dir_hosts));
	array_append_array(&hosts, &dir->dir_hosts);
	array_sort(&hosts, director_host_cmp_p);

	/* first show incoming connections that have no known host yet */
	array_foreach(&dir->connections, connp) {
		if (director_connection_get_host(*connp) == NULL)
			doveadm_director_connection_append(dir, *connp, NULL, str);
	}

	/* show other connections and host without connections sorted by host */
	array_foreach(&hosts, hostp) {
		const struct director_host *host = *hostp;
		bool have_connections = FALSE;

		array_foreach(&dir->connections, connp) {
			const struct director_host *conn_host =
				director_connection_get_host(*connp);
			if (conn_host != host)
				continue;
			have_connections = TRUE;
			doveadm_director_connection_append(dir, *connp, host, str);
		}
		if (!have_connections)
			doveadm_director_host_append(dir, host, str);
	}

	str_append_c(str, '\n');
	o_stream_nsend(conn->output, str_data(str), str_len(str));
	return DOVEADM_DIRECTOR_CMD_RET_OK;
}

static enum doveadm_director_cmd_ret
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
		return DOVEADM_DIRECTOR_CMD_RET_FAIL;
	}

	if (director_host_lookup(conn->dir, &ip, port) == NULL) {
		host = director_host_add(conn->dir, &ip, port);
		director_notify_ring_added(host, conn->dir->self_host, TRUE);
	}
	o_stream_nsend(conn->output, "OK\n", 3);
	return DOVEADM_DIRECTOR_CMD_RET_OK;
}

static enum doveadm_director_cmd_ret
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
		return DOVEADM_DIRECTOR_CMD_RET_FAIL;
	}

	host = port != 0 ?
		director_host_lookup(conn->dir, &ip, port) :
		director_host_lookup_ip(conn->dir, &ip);
	if (host == NULL) {
		o_stream_nsend_str(conn->output, "NOTFOUND\n");
		return DOVEADM_DIRECTOR_CMD_RET_OK;
	} else {
		director_ring_remove(host, conn->dir->self_host);
		return DOVEADM_DIRECTOR_CMD_RET_RING_SYNC_OK;
	}
}

static enum doveadm_director_cmd_ret
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
		return DOVEADM_DIRECTOR_CMD_RET_FAIL;
	}
	if (vhost_count > MAX_VALID_VHOST_COUNT && vhost_count != UINT_MAX) {
		o_stream_nsend_str(conn->output, "vhost count too large\n");
		return DOVEADM_DIRECTOR_CMD_RET_OK;
	}
	host = mail_host_lookup(dir->mail_hosts, &ip);
	if (host == NULL) {
		if (update) {
			o_stream_nsend_str(conn->output, "NOTFOUND\n");
			return DOVEADM_DIRECTOR_CMD_RET_OK;
		}
		host = mail_host_add_ip(dir->mail_hosts, &ip, tag);
	} else if (tag[0] != '\0' && strcmp(mail_host_get_tag(host), tag) != 0) {
		o_stream_nsend_str(conn->output, "host tag can't be changed\n");
		return DOVEADM_DIRECTOR_CMD_RET_OK;
	} else if (host->desynced) {
		o_stream_nsend_str(conn->output,
			"host is already being updated - try again later\n");
		return DOVEADM_DIRECTOR_CMD_RET_OK;
	}
	if (vhost_count != UINT_MAX)
		mail_host_set_vhost_count(host, vhost_count, "doveadm: ");
	/* NOTE: we don't support changing a tag for an existing host.
	   it needs to be removed first. otherwise it would be a bit ugly to
	   handle. */
	director_update_host(dir, dir->self_host, NULL, host);

	return DOVEADM_DIRECTOR_CMD_RET_RING_SYNC_OK;
}

static enum doveadm_director_cmd_ret
doveadm_cmd_host_set(struct doveadm_connection *conn, const char *const *args)
{
	return doveadm_cmd_host_set_or_update(conn, args, FALSE);
}

static enum doveadm_director_cmd_ret
doveadm_cmd_host_update(struct doveadm_connection *conn, const char *const *args)
{
	return doveadm_cmd_host_set_or_update(conn, args, TRUE);
}

static enum doveadm_director_cmd_ret
doveadm_cmd_host_updown(struct doveadm_connection *conn, bool down,
			const char *const *args)
{
	struct mail_host *host;
	struct ip_addr ip;

	if (args[0] == NULL || net_addr2ip(args[0], &ip) < 0) {
		i_error("doveadm sent invalid %s parameters: %s",
			down ? "HOST-DOWN" : "HOST-UP",
			args[0] == NULL ? "" : args[0]);
		return DOVEADM_DIRECTOR_CMD_RET_FAIL;
	}
	host = mail_host_lookup(conn->dir->mail_hosts, &ip);
	if (host == NULL) {
		o_stream_nsend_str(conn->output, "NOTFOUND\n");
		return DOVEADM_DIRECTOR_CMD_RET_OK;
	}
	if (host->down == down) {
		o_stream_nsend_str(conn->output, "OK\n");
		return DOVEADM_DIRECTOR_CMD_RET_OK;
	} else if (host->desynced) {
		o_stream_nsend_str(conn->output,
			"host is already being updated - try again later\n");
		return DOVEADM_DIRECTOR_CMD_RET_OK;
	} else {
		mail_host_set_down(host, down, ioloop_time, "doveadm: ");
		director_update_host(conn->dir, conn->dir->self_host,
				     NULL, host);
		return DOVEADM_DIRECTOR_CMD_RET_RING_SYNC_OK;
	}
}

static enum doveadm_director_cmd_ret
doveadm_cmd_host_up(struct doveadm_connection *conn,
		    const char *const *args)
{
	return doveadm_cmd_host_updown(conn, FALSE, args);
}

static enum doveadm_director_cmd_ret
doveadm_cmd_host_down(struct doveadm_connection *conn,
		      const char *const *args)
{
	return doveadm_cmd_host_updown(conn, TRUE, args);
}

static enum doveadm_director_cmd_ret
doveadm_cmd_host_remove(struct doveadm_connection *conn,
			const char *const *args)
{
	struct mail_host *host;
	struct ip_addr ip;

	if (args[0] == NULL || net_addr2ip(args[0], &ip) < 0) {
		i_error("doveadm sent invalid HOST-REMOVE parameters");
		return DOVEADM_DIRECTOR_CMD_RET_FAIL;
	}
	host = mail_host_lookup(conn->dir->mail_hosts, &ip);
	if (host == NULL) {
		o_stream_nsend_str(conn->output, "NOTFOUND\n");
		return DOVEADM_DIRECTOR_CMD_RET_OK;
	} else {
		director_remove_host(conn->dir, conn->dir->self_host,
				     NULL, host);
		return DOVEADM_DIRECTOR_CMD_RET_RING_SYNC_OK;
	}
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

static enum doveadm_director_cmd_ret
doveadm_cmd_host_flush(struct doveadm_connection *conn, const char *const *args)
{
	struct mail_host *host;
	struct ip_addr ip;

	if (args[0] == NULL || args[0][0] == '\0') {
		doveadm_cmd_host_flush_all(conn);
		return DOVEADM_DIRECTOR_CMD_RET_OK;
	}

	if (net_addr2ip(args[0], &ip) < 0) {
		i_error("doveadm sent invalid HOST-FLUSH parameters");
		return DOVEADM_DIRECTOR_CMD_RET_FAIL;
	}
	host = mail_host_lookup(conn->dir->mail_hosts, &ip);
	if (host == NULL) {
		o_stream_nsend_str(conn->output, "NOTFOUND\n");
		return DOVEADM_DIRECTOR_CMD_RET_OK;
	} else {
		director_flush_host(conn->dir, conn->dir->self_host,
				    NULL, host);
		return DOVEADM_DIRECTOR_CMD_RET_RING_SYNC_OK;
	}
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

	if (cmd->iter == NULL) {
		cmd->iter = director_iterate_users_init(dir, FALSE);
		cmd->users_killed = FALSE;
	}

	while ((user = director_iterate_users_next(cmd->iter)) != NULL) {
		if (user->host != host)
			continue;

		new_host = mail_host_get_by_hash(dir->mail_hosts,
						 user->username_hash,
						 mail_host_get_tag(host));
		if (new_host != host) T_BEGIN {
			if (new_host != NULL) {
				director_move_user(dir, dir->self_host, NULL,
					user->username_hash, new_host);
			} else {
				/* there are no more available backends.
				   kick the user instead. */
				director_kill_user(dir, dir->self_host, user,
						   user->host->tag, user->host,
						   TRUE);
				cmd->users_killed = TRUE;
			}
			cmd->reset_count++;
		} T_END;
		if (dir->users_moving_count >= cmd->max_moving_users)
			break;
	}
	if (user == NULL) {
		int msecs = timeval_diff_msecs(&ioloop_timeval, &cmd->start_time);
		i_info("Moved %u users in %u hosts in %u.%03u secs (max parallel=%u)",
		       cmd->reset_count, cmd->hosts_count - cmd->host_start_idx,
		       msecs / 1000, msecs % 1000, cmd->max_moving_users);
		director_iterate_users_deinit(&cmd->iter);
		if (cmd->users_killed) {
			/* no more backends. we already sent kills. now remove
			   the users entirely from the host. */
			director_flush_host(dir, dir->self_host, NULL, host);
		}
	}
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

static enum doveadm_director_cmd_ret
doveadm_cmd_host_reset_users(struct doveadm_connection *conn,
			     const char *const *args)
{
	struct director_reset_cmd *cmd;
	struct ip_addr ip;
	struct mail_host *const *hosts;
	unsigned int i = 0, count;
	unsigned int max_moving_users =
		conn->dir->set->director_max_parallel_moves;

	if (args[0] != NULL && args[1] != NULL &&
	    (str_to_uint(args[1], &max_moving_users) < 0 ||
	     max_moving_users == 0)) {
		i_error("doveadm sent invalid HOST-RESET-USERS parameters");
		return DOVEADM_DIRECTOR_CMD_RET_FAIL;
	}

	hosts = array_get(mail_hosts_get(conn->dir->mail_hosts), &count);
	if (args[0] != NULL && args[0][0] != '\0') {
		if (net_addr2ip(args[0], &ip) < 0) {
			i_error("doveadm sent invalid HOST-RESET-USERS ip: %s",
				args[0]);
			return DOVEADM_DIRECTOR_CMD_RET_FAIL;
		}

		for (i = 0; i < count; i++) {
			if (net_ip_compare(&hosts[i]->ip, &ip))
				break;
		}
		if (i == count) {
			o_stream_nsend_str(conn->output, "NOTFOUND\n");
			return DOVEADM_DIRECTOR_CMD_RET_OK;
		}
		count = i+1;
	}

	conn->reset_cmd = cmd = i_new(struct director_reset_cmd, 1);
	cmd->dir = conn->dir;
	cmd->_conn = conn;
	cmd->max_moving_users = max_moving_users;
	cmd->host_start_idx = i;
	cmd->host_idx = i;
	cmd->hosts_count = count;
	cmd->start_time = ioloop_timeval;
	DLLIST_PREPEND(&reset_cmds, cmd);

	if (!director_reset_cmd_run(cmd)) {
		/* we still have work to do. don't handle any more doveadm
		   input until we're finished. */
		io_remove(&conn->io);
		return DOVEADM_DIRECTOR_CMD_RET_UNFINISHED;
	}
	return DOVEADM_DIRECTOR_CMD_RET_OK;
}

static enum doveadm_director_cmd_ret
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
	if (str_to_uint(username, &username_hash) < 0) {
		if (!director_get_username_hash(conn->dir,
						username, &username_hash)) {
			o_stream_nsend_str(conn->output, "TRYAGAIN\n");
			return DOVEADM_DIRECTOR_CMD_RET_OK;
		}
	}

	/* get user's current host */
	mail_tag = mail_tag_find(conn->dir->mail_hosts, tag);
	user = mail_tag == NULL ? NULL :
		user_directory_lookup(mail_tag->users, username_hash);
	if (user == NULL)
		str_append(str, "\t0");
	else {
		str_printfa(str, "%s\t%u", user->host->ip_str,
			    user->timestamp +
			    conn->dir->set->director_user_expire);
	}

	/* get host if it wasn't in user directory */
	host = mail_host_get_by_hash(conn->dir->mail_hosts, username_hash, tag);
	if (host == NULL)
		str_append(str, "\t");
	else
		str_printfa(str, "\t%s", host->ip_str);

	/* get host with default configuration */
	host = mail_host_get_by_hash(conn->dir->orig_config_hosts,
				     username_hash, tag);
	if (host == NULL)
		str_append(str, "\t\n");
	else
		str_printfa(str, "\t%s\n", host->ip_str);
	o_stream_nsend(conn->output, str_data(str), str_len(str));
	return DOVEADM_DIRECTOR_CMD_RET_OK;
}

static enum doveadm_director_cmd_ret
doveadm_cmd_user_list(struct doveadm_connection *conn, const char *const *args)
{
	struct director_user_iter *iter;
	struct user *user;
	struct ip_addr ip;

	if (args[0] != NULL && args[0][0] != '\0') {
		if (net_addr2ip(args[0], &ip) < 0) {
			i_error("doveadm sent invalid USER-LIST parameters");
			return DOVEADM_DIRECTOR_CMD_RET_FAIL;
		}
	} else {
		ip.family = 0;
	}

	iter = director_iterate_users_init(conn->dir, FALSE);
	while ((user = director_iterate_users_next(iter)) != NULL) {
		if (ip.family == 0 ||
		    net_ip_compare(&ip, &user->host->ip)) T_BEGIN {
			unsigned int expire_time = user->timestamp +
				conn->dir->set->director_user_expire;

			o_stream_nsend_str(conn->output, t_strdup_printf(
				"%u\t%u\t%s\n",
				user->username_hash, expire_time,
				user->host->ip_str));
		} T_END;
	}
	director_iterate_users_deinit(&iter);
	o_stream_nsend(conn->output, "\n", 1);
	return DOVEADM_DIRECTOR_CMD_RET_OK;
}

static enum doveadm_director_cmd_ret
doveadm_cmd_user_move(struct doveadm_connection *conn, const char *const *args)
{
	unsigned int username_hash;
	struct user *user;
	struct mail_host *host;
	struct ip_addr ip;

	if (args[0] == NULL || args[1] == NULL ||
	    net_addr2ip(args[1], &ip) < 0) {
		i_error("doveadm sent invalid USER-MOVE parameters");
		return DOVEADM_DIRECTOR_CMD_RET_FAIL;
	}
	host = mail_host_lookup(conn->dir->mail_hosts, &ip);
	if (host == NULL) {
		o_stream_nsend_str(conn->output, "NOTFOUND\n");
		return DOVEADM_DIRECTOR_CMD_RET_OK;
	}

	if (str_to_uint(args[0], &username_hash) < 0) {
		if (!director_get_username_hash(conn->dir,
						args[0], &username_hash)) {
			o_stream_nsend_str(conn->output, "TRYAGAIN\n");
			return DOVEADM_DIRECTOR_CMD_RET_OK;
		}
	}

	user = user_directory_lookup(host->tag->users, username_hash);
	if (user != NULL && USER_IS_BEING_KILLED(user)) {
		o_stream_nsend_str(conn->output, "TRYAGAIN\n");
		return DOVEADM_DIRECTOR_CMD_RET_OK;
	}

	if (user == NULL || user->host != host) {
		director_move_user(conn->dir, conn->dir->self_host, NULL,
				   username_hash, host);
	} else {
		/* already the correct host. reset the user's timeout. */
		user_directory_refresh(host->tag->users, user);
		director_update_user(conn->dir, conn->dir->self_host, user);
	}
	o_stream_nsend(conn->output, "OK\n", 3);
	return DOVEADM_DIRECTOR_CMD_RET_OK;
}

static void doveadm_kick_cmd_free(struct director_kick_cmd **_cmd)
{
	struct director_kick_cmd *cmd = *_cmd;
	*_cmd = NULL;

	if (cmd->_conn != NULL)
		cmd->_conn->kick_cmd = NULL;

	i_free(cmd->field);
	i_free(cmd->value);
	i_free(cmd->mask);
	i_free(cmd);
}

static bool doveadm_cmd_user_kick_run(struct director_kick_cmd *cmd)
{
	if (cmd->dir->users_kicking_count >=
	    cmd->dir->set->director_max_parallel_kicks)
		return FALSE;

	if (cmd->alt)
		director_kick_user_alt(cmd->dir, cmd->dir->self_host,
				       NULL, cmd->field, cmd->value);
	else
		director_kick_user(cmd->dir, cmd->dir->self_host,
				       NULL, cmd->mask);
	if (cmd->_conn != NULL) {
		struct doveadm_connection *conn = cmd->_conn;

		o_stream_nsend(conn->output, "OK\n", 3);
		if (conn->io == NULL)
			doveadm_connection_set_io(conn);
	}
	DLLIST_REMOVE(&kick_cmds, cmd);
	doveadm_kick_cmd_free(&cmd);
	return TRUE;
}

static enum doveadm_director_cmd_ret
doveadm_cmd_user_kick(struct doveadm_connection *conn, const char *const *args)
{
	struct director_kick_cmd *cmd;
	bool wait = TRUE;

	if (args[0] == NULL) {
		i_error("doveadm sent invalid USER-KICK parameters");
		return DOVEADM_DIRECTOR_CMD_RET_FAIL;
	}

	if (null_strcmp(args[1], "nowait") == 0)
		wait = FALSE;

	cmd = conn->kick_cmd = i_new(struct director_kick_cmd, 1);
	cmd->alt = FALSE;
	cmd->mask = i_strdup(args[0]);
	cmd->dir = conn->dir;
	cmd->_conn = conn;

	DLLIST_PREPEND(&kick_cmds, cmd);

	if (!doveadm_cmd_user_kick_run(cmd)) {
		if (wait) {
			/* we have work to do, wait until it finishes */
			io_remove(&conn->io);
			return DOVEADM_DIRECTOR_CMD_RET_UNFINISHED;
		} else {
			o_stream_nsend_str(conn->output, "TRYAGAIN\n");
			/* need to remove it here */
			DLLIST_REMOVE(&kick_cmds, cmd);
			doveadm_kick_cmd_free(&cmd);
		}
	}

	return DOVEADM_DIRECTOR_CMD_RET_OK;
}

static enum doveadm_director_cmd_ret
doveadm_cmd_user_kick_alt(struct doveadm_connection *conn, const char *const *args)
{
	bool wait = TRUE;
	struct director_kick_cmd *cmd;

	if (str_array_length(args) < 2) {
		i_error("doveadm sent invalid USER-KICK-ALT parameters");
		return DOVEADM_DIRECTOR_CMD_RET_FAIL;
	}

	if (null_strcmp(args[2], "nowait") == 0)
		wait = FALSE;

	conn->kick_cmd = cmd = i_new(struct director_kick_cmd, 1);
	cmd->alt = TRUE;
	cmd->field = i_strdup(args[0]);
	cmd->value = i_strdup(args[1]);
	cmd->dir = conn->dir;
	cmd->_conn = conn;

	DLLIST_PREPEND(&kick_cmds, cmd);

	if (!doveadm_cmd_user_kick_run(cmd)) {
		if (wait) {
			/* we have work to do, wait until it finishes */
			io_remove(&conn->io);
			return DOVEADM_DIRECTOR_CMD_RET_UNFINISHED;
		} else {
			o_stream_nsend_str(conn->output, "TRYAGAIN\n");
			DLLIST_REMOVE(&kick_cmds, cmd);
			doveadm_kick_cmd_free(&cmd);
		}
	}

	return DOVEADM_DIRECTOR_CMD_RET_OK;
}

struct {
	const char *name;
	enum doveadm_director_cmd_ret (*cmd)
		(struct doveadm_connection *conn, const char *const *args);
	enum doveadm_director_cmd_flag flags;
} doveadm_director_commands[] = {
	{ "HOST-LIST", doveadm_cmd_host_list, 0 },
	{ "HOST-LIST-REMOVED", doveadm_cmd_host_list_removed, 0 },
	{ "DIRECTOR-LIST", doveadm_cmd_director_list, 0 },
	{ "DIRECTOR-ADD", doveadm_cmd_director_add, DOVEADM_DIRECTOR_CMD_FLAG_PRE_RING_SYNC },
	{ "DIRECTOR-REMOVE", doveadm_cmd_director_remove, DOVEADM_DIRECTOR_CMD_FLAG_PRE_RING_SYNC },
	{ "HOST-SET", doveadm_cmd_host_set, DOVEADM_DIRECTOR_CMD_FLAG_PRE_RING_SYNC },
	{ "HOST-UPDATE", doveadm_cmd_host_update, DOVEADM_DIRECTOR_CMD_FLAG_PRE_RING_SYNC },
	{ "HOST-UP", doveadm_cmd_host_up, DOVEADM_DIRECTOR_CMD_FLAG_PRE_RING_SYNC },
	{ "HOST-DOWN", doveadm_cmd_host_down, DOVEADM_DIRECTOR_CMD_FLAG_PRE_RING_SYNC },
	{ "HOST-REMOVE", doveadm_cmd_host_remove, DOVEADM_DIRECTOR_CMD_FLAG_PRE_RING_SYNC },
	{ "HOST-FLUSH", doveadm_cmd_host_flush, DOVEADM_DIRECTOR_CMD_FLAG_PRE_RING_SYNC },
	{ "HOST-RESET-USERS", doveadm_cmd_host_reset_users, 0 },
	{ "USER-LOOKUP", doveadm_cmd_user_lookup, 0 },
	{ "USER-LIST", doveadm_cmd_user_list, 0 },
	{ "USER-MOVE", doveadm_cmd_user_move, 0 },
	{ "USER-KICK", doveadm_cmd_user_kick, 0 },
	{ "USER-KICK-ALT", doveadm_cmd_user_kick_alt, 0 },
};

static void
doveadm_connection_ring_sync_timeout(struct doveadm_connection *conn)
{
	doveadm_connection_ring_sync_list_move(conn);
	o_stream_nsend_str(conn->output, "Ring sync timed out\n");

	doveadm_connection_set_io(conn);
	io_set_pending(conn->io);

	i_free_and_null(conn->cmd_pending_args);
}

static void
doveadm_connection_set_ring_sync_callback(struct doveadm_connection *conn,
					  doveadm_connection_ring_sync_callback_t *callback)
{
	i_assert(conn->ring_sync_callback == NULL);
	i_assert(conn->to_ring_sync_abort == NULL);

	conn->ring_sync_callback = callback;
	io_remove(&conn->io);
	DLLIST_REMOVE(&doveadm_connections, conn);
	DLLIST_PREPEND(&doveadm_ring_sync_pending_connections, conn);
	conn->to_ring_sync_abort =
		timeout_add(DOVEADM_CONNECTION_RING_SYNC_TIMEOUT_MSECS,
			    doveadm_connection_ring_sync_timeout, conn);
}

static void doveadm_connection_ret_ok(struct doveadm_connection *conn)
{
	o_stream_nsend(conn->output, "OK\n", 3);
}

static enum doveadm_director_cmd_ret
doveadm_connection_cmd_run(struct doveadm_connection *conn,
			   const char *const *args, unsigned int i)
{
	enum doveadm_director_cmd_ret ret;

	if ((doveadm_director_commands[i].flags &
	     DOVEADM_DIRECTOR_CMD_FLAG_PRE_RING_SYNC) != 0 &&
	    !conn->dir->ring_synced) {
		/* wait for ring to be synced before running the command */
		conn->cmd_pending_args = p_strarray_dup(default_pool, args);
		conn->cmd_pending_idx = i;
		doveadm_connection_set_ring_sync_callback(conn,
			doveadm_connection_cmd_run_synced);
		return DOVEADM_DIRECTOR_CMD_RET_UNFINISHED;
	}

	ret = doveadm_director_commands[i].cmd(conn, args);
	if (ret != DOVEADM_DIRECTOR_CMD_RET_RING_SYNC_OK)
		return ret;
	/* Delay sending OK until ring is synced. This way doveadm will know
	   whether the call actually succeeded or not. */
	if (conn->dir->ring_synced) {
		/* director is alone */
		i_assert(conn->dir->right == NULL && conn->dir->left == NULL);
		o_stream_nsend(conn->output, "OK\n", 3);
		return DOVEADM_DIRECTOR_CMD_RET_OK;
	}
	doveadm_connection_set_ring_sync_callback(conn, doveadm_connection_ret_ok);
	return DOVEADM_DIRECTOR_CMD_RET_RING_SYNC_OK;
}

static void doveadm_connection_cmd_run_synced(struct doveadm_connection *conn)
{
	const char **args = conn->cmd_pending_args;

	conn->cmd_pending_args = NULL;
	(void)doveadm_connection_cmd_run(conn, args, conn->cmd_pending_idx);
	i_free(args);
}

static enum doveadm_director_cmd_ret
doveadm_connection_cmd(struct doveadm_connection *conn, const char *line)
{
	const char *cmd, *const *args;

	args = t_strsplit_tabescaped(line);
	if (args[0] == NULL) {
		i_error("doveadm sent empty command line");
		return DOVEADM_DIRECTOR_CMD_RET_FAIL;
	}
	cmd = args[0];
	args++;

	for (unsigned int i = 0; i < N_ELEMENTS(doveadm_director_commands); i++) {
		if (strcmp(doveadm_director_commands[i].name, cmd) == 0)
			return doveadm_connection_cmd_run(conn, args, i);
	}
	i_error("doveadm sent unknown command: %s", line);
	return DOVEADM_DIRECTOR_CMD_RET_FAIL;
}

static void doveadm_connection_input(struct doveadm_connection *conn)
{
	const char *line;
	enum doveadm_director_cmd_ret ret = DOVEADM_DIRECTOR_CMD_RET_OK;

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

	while ((line = i_stream_read_next_line(conn->input)) != NULL &&
	       ret == DOVEADM_DIRECTOR_CMD_RET_OK) {
		T_BEGIN {
			ret = doveadm_connection_cmd(conn, line);
		} T_END;
	}
	if (conn->input->eof || conn->input->stream_errno != 0 ||
	    ret == DOVEADM_DIRECTOR_CMD_RET_FAIL)
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
	conn->input = i_stream_create_fd(conn->fd, 1024);
	conn->output = o_stream_create_fd(conn->fd, (size_t)-1);
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

	i_assert(conn->to_ring_sync_abort == NULL);

	if (conn->reset_cmd != NULL) {
		/* finish the move even if doveadm disconnected */
		conn->reset_cmd->_conn = NULL;
	}
	if (conn->kick_cmd != NULL) {
		/* finish the kick even if doveadm disconnected */
		conn->kick_cmd->_conn = NULL;
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

static void
doveadm_connection_ring_sync_list_move(struct doveadm_connection *conn)
{
	timeout_remove(&conn->to_ring_sync_abort);
	DLLIST_REMOVE(&doveadm_ring_sync_pending_connections, conn);
	DLLIST_PREPEND(&doveadm_connections, conn);
}

void doveadm_connections_deinit(void)
{
	while (reset_cmds != NULL)
		doveadm_reset_cmd_free(reset_cmds);

	unsigned int pending_count = 0;
	while (doveadm_ring_sync_pending_connections != NULL) {
		doveadm_connection_ring_sync_list_move(doveadm_ring_sync_pending_connections);
		pending_count++;
	}
	if (pending_count > 0)
		i_warning("Shutting down while %u doveadm connections were waiting for ring sync", pending_count);
	while (doveadm_connections != NULL) {
		struct doveadm_connection *conn = doveadm_connections;

		doveadm_connection_deinit(&conn);
	}
}

void doveadm_connections_kick_callback(struct director *dir ATTR_UNUSED)
{
	while(kick_cmds != NULL)
		if (!doveadm_cmd_user_kick_run(kick_cmds))
			break;
}

static void doveadm_connections_continue_reset_cmds(void)
{
	while (reset_cmds != NULL) {
		if (!director_reset_cmd_run(reset_cmds))
			break;
	}
}

void doveadm_connections_ring_synced(struct director *dir)
{
	while (doveadm_ring_sync_pending_connections != NULL &&
	       dir->ring_synced) {
		struct doveadm_connection *conn =
			doveadm_ring_sync_pending_connections;
		doveadm_connection_ring_sync_callback_t *callback =
			conn->ring_sync_callback;

		conn->ring_sync_callback = NULL;
		doveadm_connection_ring_sync_list_move(conn);
		doveadm_connection_set_io(conn);
		io_set_pending(conn->io);
		callback(conn);
	}
	if (dir->ring_synced)
		doveadm_connections_continue_reset_cmds();
}
