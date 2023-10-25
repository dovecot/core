/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "process-title.h"
#include "settings.h"
#include "master-service.h"
#include "doveadm.h"
#include "doveadm-settings.h"
#include "client-connection-private.h"

bool doveadm_client_is_allowed_command(const struct doveadm_settings *set,
				       const char *cmd_name)
{
	bool ret = FALSE;

	if (array_is_empty(&set->doveadm_allowed_commands))
		return TRUE;

	T_BEGIN {
		const char *const *cmds =
			settings_boollist_get(&set->doveadm_allowed_commands);
		for (; *cmds != NULL; cmds++) {
			if (strcmp(*cmds, cmd_name) == 0) {
				ret = TRUE;
				break;
			}
		}
	} T_END;
	return ret;
}

static int client_connection_read_settings(struct client_connection *conn)
{
	const char *error;

	if (settings_get(conn->event, &doveadm_setting_parser_info, 0,
			 &conn->set, &error) < 0) {
		e_error(conn->event, "%s", error);
		return -1;
	}
	return 0;
}

int client_connection_init(struct client_connection *conn,
	enum doveadm_client_type type, pool_t pool, int fd)
{
	const char *ip;

	i_assert(type != DOVEADM_CONNECTION_TYPE_CLI);

	conn->type = type;
	conn->pool = pool;

	if (net_getsockname(fd, &conn->local_ip, &conn->local_port) == 0)
		event_add_ip(conn->event, "local_ip", &conn->local_ip);
	if (net_getpeername(fd, &conn->remote_ip, &conn->remote_port) == 0)
		event_add_ip(conn->event, "remote_ip", &conn->local_ip);

	ip = net_ip2addr(&conn->remote_ip);
	if (ip[0] != '\0')
		i_set_failure_prefix("doveadm(%s): ", ip);

	conn->name = conn->remote_ip.family == 0 ? "<local>" :
		p_strdup(pool, net_ip2addr(&conn->remote_ip));

	return client_connection_read_settings(conn);
}

void client_connection_destroy(struct client_connection **_conn)
{
	struct client_connection *conn = *_conn;

	*_conn = NULL;

	if (conn->free != NULL)
		conn->free(conn);

	doveadm_client = NULL;
	master_service_client_connection_destroyed(master_service);

	if (doveadm_verbose_proctitle)
		process_title_set("[idling]");

	settings_free(conn->set);
	event_unref(&conn->event);
	pool_unref(&conn->pool);
}

void client_connection_set_proctitle(struct client_connection *conn,
				     const char *text)
{
	const char *str;

	if (!doveadm_verbose_proctitle)
		return;

	if (text[0] == '\0')
		str = t_strdup_printf("[%s]", conn->name);
	else
		str = t_strdup_printf("[%s %s]", conn->name, text);
	process_title_set(str);
}

void doveadm_server_deinit(void)
{
	if (doveadm_client != NULL)
		client_connection_destroy(&doveadm_client);
}
