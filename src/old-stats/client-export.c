/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "ostream.h"
#include "str.h"
#include "strescape.h"
#include "wildcard-match.h"
#include "mail-stats.h"
#include "mail-command.h"
#include "mail-session.h"
#include "mail-user.h"
#include "mail-domain.h"
#include "mail-ip.h"
#include "client.h"
#include "client-export.h"

enum mail_export_level {
	MAIL_EXPORT_LEVEL_COMMAND,
	MAIL_EXPORT_LEVEL_SESSION,
	MAIL_EXPORT_LEVEL_USER,
	MAIL_EXPORT_LEVEL_DOMAIN,
	MAIL_EXPORT_LEVEL_IP,
	MAIL_EXPORT_LEVEL_GLOBAL
};
static const char *mail_export_level_names[] = {
	"command", "session", "user", "domain", "ip", "global"
};

struct mail_export_filter {
	const char *user, *domain, *session;
	struct ip_addr ip;
	unsigned int ip_bits;
	time_t since;
	bool connected;
};

struct client_export_cmd {
	enum mail_export_level level;
	struct mail_export_filter filter;
	string_t *str;
	int (*export_iter)(struct client *client);
	bool header_sent;
};

static int
mail_export_level_parse(const char *str, enum mail_export_level *level_r)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(mail_export_level_names); i++) {
		if (strcmp(mail_export_level_names[i], str) == 0) {
			*level_r = (enum mail_export_level)i;
			return 0;
		}
	}
	return -1;
}

static int
mail_export_parse_filter(const char *const *args, pool_t pool,
			 struct mail_export_filter *filter_r,
			 const char **error_r)
{
	unsigned long l;

	/* filters:
	   user=<wildcard> | domain=<wildcard> | session=<str>
	   ip=<ip>[/<mask>]
	   since=<timestamp>
	   connected
	*/
	i_zero(filter_r);
	for (; *args != NULL; args++) {
		if (str_begins(*args, "user="))
			filter_r->user = p_strdup(pool, *args + 5);
		else if (str_begins(*args, "domain="))
			filter_r->domain = p_strdup(pool, *args + 7);
		else if (str_begins(*args, "session="))
			filter_r->session = p_strdup(pool, *args + 8);
		else if (str_begins(*args, "ip=")) {
			if (net_parse_range(*args + 3, &filter_r->ip,
					    &filter_r->ip_bits) < 0) {
				*error_r = "Invalid ip filter";
				return -1;
			}
		} else if (str_begins(*args, "since=")) {
			if (str_to_ulong(*args + 6, &l) < 0) {
				*error_r = "Invalid since filter";
				return -1;
			}
			filter_r->since = (time_t)l;
		} else if (strcmp(*args, "connected") == 0) {
			filter_r->connected = TRUE;
		}
	}
	return 0;
}

static void
client_export_stats_headers(struct client *client)
{
	unsigned int i, count = stats_field_count();
	string_t *str = t_str_new(128);

	i_assert(count > 0);

	str_append(str, stats_field_name(0));
	for (i = 1; i < count; i++) {
		str_append_c(str, '\t');
		str_append(str, stats_field_name(i));
	}
	str_append_c(str, '\n');
	o_stream_nsend(client->output, str_data(str), str_len(str));
}

static void
client_export_stats(string_t *str, const struct stats *stats)
{
	unsigned int i, count = stats_field_count();

	i_assert(count > 0);

	stats_field_value(str, stats, 0);
	for (i = 1; i < count; i++) {
		str_append_c(str, '\t');
		stats_field_value(str, stats, i);
	}
}

static bool
mail_export_filter_match_session(const struct mail_export_filter *filter,
				 const struct mail_session *session)
{
	if (filter->connected && session->disconnected)
		return FALSE;
	if (filter->since > session->last_update.tv_sec)
		return FALSE;
	if (filter->session != NULL &&
	    strcmp(session->id, filter->session) != 0)
		return FALSE;
	if (filter->user != NULL &&
	    !wildcard_match(session->user->name, filter->user))
		return FALSE;
	if (filter->domain != NULL &&
	    !wildcard_match(session->user->domain->name, filter->domain))
		return FALSE;
	if (filter->ip_bits > 0 &&
	    !net_is_in_network(&session->ip->ip, &filter->ip, filter->ip_bits))
		return FALSE;
	return TRUE;
}

static bool
mail_export_filter_match_user_common(const struct mail_export_filter *filter,
				     const struct mail_user *user)
{
	struct mail_session *s;
	bool connected = FALSE, ip_ok = FALSE;

	if (filter->user != NULL &&
	    !wildcard_match(user->name, filter->user))
		return FALSE;

	if (filter->connected || filter->ip_bits > 0) {
		for (s = user->sessions; s != NULL; s = s->user_next) {
			if (!s->disconnected)
				connected = TRUE;
			if (filter->ip_bits > 0 &&
			    net_is_in_network(&s->ip->ip, &filter->ip,
					      filter->ip_bits))
				ip_ok = TRUE;

		}
		if (filter->connected && !connected)
			return FALSE;
		if (filter->ip_bits > 0 && !ip_ok)
			return FALSE;
	}
	return TRUE;
}

static bool
mail_export_filter_match_user(const struct mail_export_filter *filter,
			      const struct mail_user *user)
{
	if (filter->since > user->last_update.tv_sec)
		return FALSE;
	if (filter->domain != NULL &&
	    !wildcard_match(user->domain->name, filter->domain))
		return FALSE;
	return mail_export_filter_match_user_common(filter, user);
}

static bool
mail_export_filter_match_domain(const struct mail_export_filter *filter,
				const struct mail_domain *domain)
{
	struct mail_user *user;

	if (filter->since > domain->last_update.tv_sec)
		return FALSE;
	if (filter->domain != NULL &&
	    !wildcard_match(domain->name, filter->domain))
		return FALSE;

	if (filter->user != NULL || filter->connected || filter->ip_bits > 0) {
		for (user = domain->users; user != NULL; user = user->domain_next) {
			if (mail_export_filter_match_user_common(filter, user))
				break;
		}
		if (user == NULL)
			return FALSE;
	}
	return TRUE;
}

static bool
mail_export_filter_match_ip(const struct mail_export_filter *filter,
			    const struct mail_ip *ip)
{
	struct mail_session *s;
	bool connected = FALSE, user_ok = FALSE, domain_ok = FALSE;

	if (filter->connected || filter->ip_bits > 0) {
		for (s = ip->sessions; s != NULL; s = s->ip_next) {
			if (!s->disconnected)
				connected = TRUE;
			if (filter->user != NULL &&
			    wildcard_match(s->user->name, filter->user))
				user_ok = TRUE;
			if (filter->domain != NULL &&
			    wildcard_match(s->user->domain->name, filter->domain))
				domain_ok = TRUE;
		}
		if (filter->connected && !connected)
			return FALSE;
		if (filter->user != NULL && !user_ok)
			return FALSE;
		if (filter->domain != NULL && !domain_ok)
			return FALSE;
	}
	if (filter->since > ip->last_update.tv_sec)
		return FALSE;
	if (filter->ip_bits > 0 &&
	    !net_is_in_network(&ip->ip, &filter->ip, filter->ip_bits))
		return FALSE;
	return TRUE;
}

static void client_export_timeval(string_t *str, const struct timeval *tv)
{
	str_printfa(str, "\t%ld.%06u", (long)tv->tv_sec,
		    (unsigned int)tv->tv_usec);
}

static int client_export_iter_command(struct client *client)
{
	struct client_export_cmd *cmd = client->cmd_export;
	struct mail_command *command = client->mail_cmd_iter;

	i_assert(cmd->level == MAIL_EXPORT_LEVEL_COMMAND);
	mail_command_unref(&client->mail_cmd_iter);

	if (!cmd->header_sent) {
		o_stream_nsend_str(client->output,
			"cmd\targs\tsession\tuser\tlast_update\t");
		client_export_stats_headers(client);
		cmd->header_sent = TRUE;
	}

	for (; command != NULL; command = command->stable_next) {
		if (client_is_busy(client))
			break;
		if (!mail_export_filter_match_session(&cmd->filter,
						      command->session))
			continue;

		str_truncate(cmd->str, 0);
		str_append_tabescaped(cmd->str, command->name);
		str_append_c(cmd->str, '\t');
		str_append_tabescaped(cmd->str, command->args);
		str_append_c(cmd->str, '\t');
		str_append(cmd->str, command->session->id);
		str_append_c(cmd->str, '\t');
		str_append_tabescaped(cmd->str,
				      command->session->user->name);
		client_export_timeval(cmd->str, &command->last_update);
		str_append_c(cmd->str, '\t');
		client_export_stats(cmd->str, command->stats);
		str_append_c(cmd->str, '\n');
		o_stream_nsend(client->output, str_data(cmd->str),
			       str_len(cmd->str));
	}

	if (command != NULL) {
		client->mail_cmd_iter = command;
		mail_command_ref(command);
		return 0;
	}
	return 1;
}

static int client_export_iter_session(struct client *client)
{
	struct client_export_cmd *cmd = client->cmd_export;
	struct mail_session *session = client->mail_session_iter;

	i_assert(cmd->level == MAIL_EXPORT_LEVEL_SESSION);
	mail_session_unref(&client->mail_session_iter);

	if (!cmd->header_sent) {
		o_stream_nsend_str(client->output,
			"session\tuser\tip\tservice\tpid\tconnected"
			"\tlast_update\tnum_cmds\t");
		client_export_stats_headers(client);
		cmd->header_sent = TRUE;
	}

	for (; session != NULL; session = session->stable_next) {
		if (client_is_busy(client))
			break;
		if (!mail_export_filter_match_session(&cmd->filter, session))
			continue;

		str_truncate(cmd->str, 0);
		str_append(cmd->str, session->id);
		str_append_c(cmd->str, '\t');
		str_append_tabescaped(cmd->str, session->user->name);
		str_append_c(cmd->str, '\t');
		if (session->ip != NULL) T_BEGIN {
			str_append(cmd->str, net_ip2addr(&session->ip->ip));
		} T_END;
		str_append_c(cmd->str, '\t');
		str_append_tabescaped(cmd->str, session->service);
		str_printfa(cmd->str, "\t%ld", (long)session->pid);
		str_printfa(cmd->str, "\t%d", !session->disconnected);
		client_export_timeval(cmd->str, &session->last_update);
		str_printfa(cmd->str, "\t%u\t", session->num_cmds);
		client_export_stats(cmd->str, session->stats);
		str_append_c(cmd->str, '\n');
		o_stream_nsend(client->output, str_data(cmd->str),
			       str_len(cmd->str));
	}

	if (session != NULL) {
		client->mail_session_iter = session;
		mail_session_ref(session);
		return 0;
	}
	return 1;
}

static int client_export_iter_user(struct client *client)
{
	struct client_export_cmd *cmd = client->cmd_export;
	struct mail_user *user = client->mail_user_iter;

	i_assert(cmd->level == MAIL_EXPORT_LEVEL_USER);
	mail_user_unref(&client->mail_user_iter);

	if (!cmd->header_sent) {
		o_stream_nsend_str(client->output,
			"user\treset_timestamp\tlast_update"
			"\tnum_logins\tnum_cmds\t");
		client_export_stats_headers(client);
		cmd->header_sent = TRUE;
	}

	for (; user != NULL; user = user->stable_next) {
		if (client_is_busy(client))
			break;
		if (!mail_export_filter_match_user(&cmd->filter, user))
			continue;

		str_truncate(cmd->str, 0);
		str_append_tabescaped(cmd->str, user->name);
		str_printfa(cmd->str, "\t%ld", (long)user->reset_timestamp);
		client_export_timeval(cmd->str, &user->last_update);
		str_printfa(cmd->str, "\t%u\t%u\t",
			    user->num_logins, user->num_cmds);
		client_export_stats(cmd->str, user->stats);
		str_append_c(cmd->str, '\n');
		o_stream_nsend(client->output, str_data(cmd->str),
			       str_len(cmd->str));
	}

	if (user != NULL) {
		client->mail_user_iter = user;
		mail_user_ref(user);
		return 0;
	}
	return 1;
}

static int client_export_iter_domain(struct client *client)
{
	struct client_export_cmd *cmd = client->cmd_export;
	struct mail_domain *domain = client->mail_domain_iter;

	i_assert(cmd->level == MAIL_EXPORT_LEVEL_DOMAIN);
	mail_domain_unref(&client->mail_domain_iter);

	if (!cmd->header_sent) {
		o_stream_nsend_str(client->output,
			"domain\treset_timestamp\tlast_update"
			"\tnum_logins\tnum_cmds\tnum_connected_sessions\t");
		client_export_stats_headers(client);
		cmd->header_sent = TRUE;
	}

	for (; domain != NULL; domain = domain->stable_next) {
		if (client_is_busy(client))
			break;
		if (!mail_export_filter_match_domain(&cmd->filter, domain))
			continue;

		str_truncate(cmd->str, 0);
		str_append_tabescaped(cmd->str, domain->name);
		str_printfa(cmd->str, "\t%ld", (long)domain->reset_timestamp);
		client_export_timeval(cmd->str, &domain->last_update);
		str_printfa(cmd->str, "\t%u\t%u\t%u\t",
			    domain->num_logins, domain->num_cmds,
			    domain->num_connected_sessions);
		client_export_stats(cmd->str, domain->stats);
		str_append_c(cmd->str, '\n');
		o_stream_nsend(client->output, str_data(cmd->str),
			       str_len(cmd->str));
	}

	if (domain != NULL) {
		client->mail_domain_iter = domain;
		mail_domain_ref(domain);
		return 0;
	}
	return 1;
}

static int client_export_iter_ip(struct client *client)
{
	struct client_export_cmd *cmd = client->cmd_export;
	struct mail_ip *ip = client->mail_ip_iter;

	i_assert(cmd->level == MAIL_EXPORT_LEVEL_IP);
	mail_ip_unref(&client->mail_ip_iter);

	if (!cmd->header_sent) {
		o_stream_nsend_str(client->output,
			"ip\treset_timestamp\tlast_update"
			"\tnum_logins\tnum_cmds\tnum_connected_sessions\t");
		client_export_stats_headers(client);
		cmd->header_sent = TRUE;
	}

	for (; ip != NULL; ip = ip->stable_next) {
		if (client_is_busy(client))
			break;
		if (!mail_export_filter_match_ip(&cmd->filter, ip))
			continue;

		str_truncate(cmd->str, 0);
		T_BEGIN {
			str_append(cmd->str, net_ip2addr(&ip->ip));
		} T_END;
		str_printfa(cmd->str, "\t%ld", (long)ip->reset_timestamp);
		client_export_timeval(cmd->str, &ip->last_update);
		str_printfa(cmd->str, "\t%u\t%u\t%u\t",
			    ip->num_logins, ip->num_cmds, ip->num_connected_sessions);
		client_export_stats(cmd->str, ip->stats);
		str_append_c(cmd->str, '\n');
		o_stream_nsend(client->output, str_data(cmd->str),
			       str_len(cmd->str));
	}

	if (ip != NULL) {
		client->mail_ip_iter = ip;
		mail_ip_ref(ip);
		return 0;
	}
	return 1;
}

static int client_export_iter_global(struct client *client)
{
	struct client_export_cmd *cmd = client->cmd_export;
	struct mail_global *g = &mail_global_stats;

	i_assert(cmd->level == MAIL_EXPORT_LEVEL_GLOBAL);

	if (!cmd->header_sent) {
		o_stream_nsend_str(client->output,
			"reset_timestamp\tlast_update"
			"\tnum_logins\tnum_cmds\tnum_connected_sessions\t");
		client_export_stats_headers(client);
		cmd->header_sent = TRUE;
	}

	str_truncate(cmd->str, 0);
	str_printfa(cmd->str, "%ld", (long)g->reset_timestamp);
	client_export_timeval(cmd->str, &g->last_update);
	str_printfa(cmd->str, "\t%u\t%u\t%u\t",
		    g->num_logins, g->num_cmds, g->num_connected_sessions);
	client_export_stats(cmd->str, g->stats);
	str_append_c(cmd->str, '\n');
	o_stream_nsend(client->output, str_data(cmd->str),
		       str_len(cmd->str));
	return 1;
}

static int client_export_more(struct client *client)
{
	if (client->cmd_export->export_iter(client) == 0)
		return 0;
	o_stream_nsend_str(client->output, "\n");
	return 1;
}

static bool client_export_iter_init(struct client *client)
{
	struct client_export_cmd *cmd = client->cmd_export;

	if (cmd->filter.user != NULL && strchr(cmd->filter.user, '*') == NULL &&
	    (cmd->level == MAIL_EXPORT_LEVEL_USER ||
	     cmd->level == MAIL_EXPORT_LEVEL_SESSION)) {
		/* exact user */
		struct mail_user *user = mail_user_lookup(cmd->filter.user);
		if (user == NULL)
			return FALSE;
		if (cmd->level == MAIL_EXPORT_LEVEL_SESSION) {
			client->mail_session_iter = user->sessions;
			if (client->mail_session_iter == NULL)
				return FALSE;
			mail_session_ref(client->mail_session_iter);
			cmd->export_iter = client_export_iter_session;
		} else {
			client->mail_user_iter = user;
			mail_user_ref(user);
			cmd->export_iter = client_export_iter_user;
		}
		return TRUE;
	}
	if (cmd->filter.ip_bits == IPADDR_BITS(&cmd->filter.ip) &&
	    (cmd->level == MAIL_EXPORT_LEVEL_IP ||
	     cmd->level == MAIL_EXPORT_LEVEL_SESSION)) {
		/* exact IP address */
		struct mail_ip *ip = mail_ip_lookup(&cmd->filter.ip);
		if (ip == NULL)
			return FALSE;
		if (cmd->level == MAIL_EXPORT_LEVEL_SESSION) {
			client->mail_session_iter = ip->sessions;
			if (client->mail_session_iter == NULL)
				return FALSE;
			mail_session_ref(client->mail_session_iter);
			cmd->export_iter = client_export_iter_session;
		} else {
			client->mail_ip_iter = ip;
			mail_ip_ref(ip);
			cmd->export_iter = client_export_iter_ip;
		}
		return TRUE;
	}
	if (cmd->filter.domain != NULL &&
	    strchr(cmd->filter.domain, '*') == NULL &&
	    (cmd->level == MAIL_EXPORT_LEVEL_DOMAIN ||
	     cmd->level == MAIL_EXPORT_LEVEL_USER)) {
		/* exact domain */
		struct mail_domain *domain =
			mail_domain_lookup(cmd->filter.domain);
		if (domain == NULL)
			return FALSE;
		if (cmd->level == MAIL_EXPORT_LEVEL_USER) {
			client->mail_user_iter = domain->users;
			mail_user_ref(client->mail_user_iter);
			cmd->export_iter = client_export_iter_user;
		} else {
			client->mail_domain_iter = domain;
			mail_domain_ref(domain);
			cmd->export_iter = client_export_iter_domain;
		}
		return TRUE;
	}

	switch (cmd->level) {
	case MAIL_EXPORT_LEVEL_COMMAND:
		client->mail_cmd_iter = stable_mail_commands_head;
		if (client->mail_cmd_iter == NULL)
			return FALSE;
		mail_command_ref(client->mail_cmd_iter);
		cmd->export_iter = client_export_iter_command;
		break;
	case MAIL_EXPORT_LEVEL_SESSION:
		client->mail_session_iter = stable_mail_sessions;
		if (client->mail_session_iter == NULL)
			return FALSE;
		mail_session_ref(client->mail_session_iter);
		cmd->export_iter = client_export_iter_session;
		break;
	case MAIL_EXPORT_LEVEL_USER:
		client->mail_user_iter = stable_mail_users;
		if (client->mail_user_iter == NULL)
			return FALSE;
		mail_user_ref(client->mail_user_iter);
		cmd->export_iter = client_export_iter_user;
		break;
	case MAIL_EXPORT_LEVEL_DOMAIN:
		client->mail_domain_iter = stable_mail_domains;
		if (client->mail_domain_iter == NULL)
			return FALSE;
		mail_domain_ref(client->mail_domain_iter);
		cmd->export_iter = client_export_iter_domain;
		break;
	case MAIL_EXPORT_LEVEL_IP:
		client->mail_ip_iter = stable_mail_ips;
		if (client->mail_ip_iter == NULL)
			return FALSE;
		mail_ip_ref(client->mail_ip_iter);
		cmd->export_iter = client_export_iter_ip;
		break;
	case MAIL_EXPORT_LEVEL_GLOBAL:
		cmd->export_iter = client_export_iter_global;
		break;
	}
	i_assert(cmd->export_iter != NULL);
	return TRUE;
}

int client_export(struct client *client, const char *const *args,
		  const char **error_r)
{
	const char *level_str = args[0];
	struct client_export_cmd *cmd;

	p_clear(client->cmd_pool);
	cmd = p_new(client->cmd_pool, struct client_export_cmd, 1);
	cmd->str = str_new(client->cmd_pool, 256);

	if (level_str == NULL) {
		*error_r = "Missing level parameter";
		return -1;
	}
	if (mail_export_level_parse(level_str, &cmd->level) < 0) {
		*error_r = "Invalid level";
		return -1;
	}
	if (mail_export_parse_filter(args + 1, client->cmd_pool,
				     &cmd->filter, error_r) < 0)
		return -1;

	client->cmd_export = cmd;
	if (!client_export_iter_init(client)) {
		/* nothing to export */
		o_stream_nsend_str(client->output, "\n");
		return 1;
	}
	client->cmd_more = client_export_more;
	return client_export_more(client);
}
