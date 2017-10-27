/* Copyright (c) 2010-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "process-title.h"
#include "settings-parser.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "doveadm.h"
#include "doveadm-settings.h"
#include "doveadm-server.h"
#include "client-connection-private.h"

bool doveadm_client_is_allowed_command(const struct doveadm_settings *set,
				       const char *cmd_name)
{
	bool ret = FALSE;

	if (*set->doveadm_allowed_commands == '\0')
		return TRUE;

	T_BEGIN {
		const char *const *cmds =
			t_strsplit(set->doveadm_allowed_commands, ",");
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
	const struct setting_parser_info *set_roots[] = {
		&doveadm_setting_parser_info,
		NULL
	};
	struct master_service_settings_input input;
	struct master_service_settings_output output;
	const char *error;
	void *set;

	i_zero(&input);
	input.roots = set_roots;
	input.service = "doveadm";
	input.local_ip = conn->local_ip;
	input.remote_ip = conn->remote_ip;

	if (master_service_settings_read(master_service, &input,
					 &output, &error) < 0) {
		i_error("Error reading configuration: %s", error);
		return -1;
	}
	set = master_service_settings_get_others(master_service)[0];
	conn->set = settings_dup(&doveadm_setting_parser_info, set, conn->pool);
	return 0;
}

int client_connection_init(struct client_connection *conn,
	enum doveadm_client_connection_type type, pool_t pool, int fd)
{
	const char *ip;

	i_assert(type != CLIENT_CONNECTION_TYPE_CLI);

	conn->type = type;
	conn->pool = pool;

	(void)net_getsockname(fd, &conn->local_ip, &conn->local_port);
	(void)net_getpeername(fd, &conn->remote_ip, &conn->remote_port);

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

void doveadm_server_init(void)
{
	doveadm_http_server_init();
}

void doveadm_server_deinit(void)
{
	if (doveadm_client != NULL)
		client_connection_destroy(&doveadm_client);
	doveadm_http_server_deinit();
}
