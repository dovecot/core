/* Copyright (c) 2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "restrict-access.h"
#include "master-interface.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "auth-connection.h"
#include "doveadm-connection.h"
#include "login-connection.h"
#include "notify-connection.h"
#include "director.h"
#include "director-host.h"
#include "director-connection.h"
#include "director-request.h"
#include "mail-host.h"

#include <unistd.h>

#define AUTH_SOCKET_PATH "login/login"

static struct director *director;
static struct notify_connection *notify_conn;
static char *auth_socket_path;

static int director_client_connected(int fd, const struct ip_addr *ip)
{
	if (director_host_lookup_ip(director, ip) == NULL) {
		i_warning("Connection from %s: Server not listed in "
			  "director_servers, dropping", net_ip2addr(ip));
		return -1;
	}

	director_connection_init_in(director, fd);
	return 0;
}

static void client_connected(const struct master_service_connection *conn)
{
	struct auth_connection *auth;
	const char *path, *name;
	struct ip_addr ip;
	unsigned int port, len;

	if (conn->fifo) {
		if (notify_conn != NULL) {
			i_error("Received another proxy-notify connection");
			(void)close(conn->fd);
			return;
		}
		notify_conn = notify_connection_init(director, conn->fd);
		return;
	}

	if (net_getpeername(conn->fd, &ip, &port) == 0 &&
	    (IPADDR_IS_V4(&ip) || IPADDR_IS_V6(&ip))) {
		/* TCP/IP connection - this is another director */
		if (director_client_connected(conn->fd, &ip) < 0)
			(void)close(conn->fd);
		return;
	}

	if (net_getunixname(conn->listen_fd, &path) < 0)
		i_fatal("getsockname(%d) failed: %m", conn->listen_fd);

	name = strrchr(path, '/');
	if (name == NULL)
		name = path;
	else
		name++;

	len = strlen(name);
	if (len > 6 && strcmp(name + len - 6, "-admin") == 0) {
		/* doveadm connection */
		(void)doveadm_connection_init(director, conn->fd);
	} else {
		/* login connection */
		auth = auth_connection_init(auth_socket_path);
		if (auth_connection_connect(auth) == 0)
			login_connection_init(director, conn->fd, auth);
		else {
			(void)close(conn->fd);
			auth_connection_deinit(&auth);
		}
	}
}

static unsigned int find_inet_listener_port(struct ip_addr *ip_r)
{
	unsigned int i, socket_count, port;

	socket_count = master_service_get_socket_count(master_service);
	for (i = 0; i < socket_count; i++) {
		int fd = MASTER_LISTEN_FD_FIRST + i;

		if (net_getsockname(fd, ip_r, &port) == 0 && port > 0)
			return port;
	}
	return 0;
}

static void director_state_changed(struct director *dir)
{
	struct director_request *const *requestp;
	bool ret;

	if (!dir->ring_handshaked ||
	    array_count(&dir->desynced_host_changes) != 0 ||
	    mail_host_get_by_hash(0) == NULL)
		return;

	/* if there are any pending client requests, finish them now */
	array_foreach(&dir->pending_requests, requestp) {
		ret = director_request_continue(*requestp);
		i_assert(ret);
	}
	array_clear(&dir->pending_requests);

	if (dir->to_request != NULL)
		timeout_remove(&dir->to_request);
}

static void main_init(void)
{
	const struct director_settings *set;
	struct ip_addr listen_ip;
	unsigned int listen_port;

	set = master_service_settings_get_others(master_service)[0];

	auth_socket_path = i_strconcat(set->base_dir,
				       "/"AUTH_SOCKET_PATH, NULL);

	mail_hosts_init();
	if (mail_hosts_parse_and_add(set->director_mail_servers) < 0)
		i_fatal("Invalid value for director_mail_servers setting");

	listen_port = find_inet_listener_port(&listen_ip);
	if (listen_port == 0 && *set->director_servers != '\0') {
		i_fatal("No inet_listeners defined for director service "
			"(for standalone keep director_servers empty)");
	}

	director = director_init(set, &listen_ip, listen_port,
				 director_state_changed);
	director_host_add_from_string(director, set->director_servers);

	director_connect(director);
}

static void main_deinit(void)
{
	notify_connection_deinit(&notify_conn);
	director_deinit(&director);
	doveadm_connections_deinit();
	login_connections_deinit();
	auth_connections_deinit();
	mail_hosts_deinit();
	i_free(auth_socket_path);
}

int main(int argc, char *argv[])
{
	const struct setting_parser_info *set_roots[] = {
		&director_setting_parser_info,
		NULL
	};
	const char *error;

	master_service = master_service_init("director", 0, &argc, &argv, NULL);
	if (master_getopt(master_service) > 0)
		return FATAL_DEFAULT;
	if (master_service_settings_read_simple(master_service, set_roots,
						&error) < 0)
		i_fatal("Error reading configuration: %s", error);

	master_service_init_log(master_service, "director: ");

	restrict_access_by_env(NULL, FALSE);
	restrict_access_allow_coredumps(TRUE);
	master_service_init_finish(master_service);

	main_init();
	master_service_run(master_service, client_connected);
	main_deinit();

	master_service_deinit(&master_service);
        return 0;
}
