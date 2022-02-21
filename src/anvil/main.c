/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "str.h"
#include "env-util.h"
#include "fdpass.h"
#include "ioloop.h"
#include "process-title.h"
#include "restrict-access.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "master-interface.h"
#include "admin-client-pool.h"
#include "connect-limit.h"
#include "penalty.h"
#include "anvil-connection.h"

#include <unistd.h>

#define ANVIL_CLIENT_POOL_MAX_CONNECTIONS 100
#define ANVIL_PROCTITLE_REFRESH_INTERVAL_MSECS 1000

struct connect_limit *connect_limit;
struct penalty *penalty;
bool anvil_restarted;

static bool verbose_proctitle = FALSE;
static struct io *log_fdpass_io;
static struct admin_client_pool *admin_pool;
static struct timeout *to_refresh;
static unsigned int prev_cmd_counter = 0;
static unsigned int prev_connect_dump_counter = 0;

static void anvil_refresh_proctitle(void *context ATTR_UNUSED)
{
	unsigned int connections_count;
	unsigned int kicks_pending_count;
	unsigned int cmd_counter, cmd_diff;
	unsigned int connect_dump_counter, connect_dump_diff;
	anvil_get_global_counts(&connections_count, &kicks_pending_count,
				&cmd_counter, &connect_dump_counter);
	if (cmd_counter >= prev_cmd_counter)
		cmd_diff = cmd_counter - prev_cmd_counter;
	else {
		/* wrapped */
		cmd_diff = (UINT_MAX - prev_cmd_counter + 1) + cmd_counter;
	}
	if (connect_dump_counter >= prev_connect_dump_counter) {
		connect_dump_diff = connect_dump_counter -
			prev_connect_dump_counter;
	} else {
		/* wrapped */
		connect_dump_diff = (UINT_MAX - prev_connect_dump_counter + 1) +
			connect_dump_counter;
	}
	prev_cmd_counter = cmd_counter;
	prev_connect_dump_counter = connect_dump_counter;

	process_title_set(t_strdup_printf(
		"[%u connections, %u requests, %u user-lists, %u user-kicks]",
		connections_count, cmd_diff,
		connect_dump_diff, kicks_pending_count));

	if (cmd_diff == 0 && connect_dump_diff == 0 && kicks_pending_count == 0)
		timeout_remove(&to_refresh);
}

void anvil_refresh_proctitle_delayed(void)
{
	if (!verbose_proctitle)
		return;

	if (to_refresh != NULL)
		return;
	to_refresh = timeout_add(ANVIL_PROCTITLE_REFRESH_INTERVAL_MSECS,
				 anvil_refresh_proctitle, NULL);
}

#undef admin_cmd_send
void admin_cmd_send(const char *service, pid_t pid, const char *cmd,
		    admin_cmd_callback_t *callback, void *context)
{
	struct anvil_connection *conn = anvil_connection_find(service, pid);
	if (conn != NULL) {
		anvil_connection_send_cmd(conn, cmd, callback, context);
		return;
	}
	admin_client_pool_send_cmd(admin_pool, service, pid, cmd,
				   callback, context);
}

static void client_connected(struct master_service_connection *conn)
{
	bool master = conn->listen_fd == MASTER_LISTEN_FD_FIRST;

	master_service_client_connection_accept(conn);
	anvil_connection_create(conn->fd, master, conn->fifo);
}

static void ATTR_NULL(1)
log_fdpass_input(void *context ATTR_UNUSED)
{
	int fd;
	char c;
	ssize_t ret;

	/* master wants us to replace the log fd */
	ret = fd_read(MASTER_ANVIL_LOG_FDPASS_FD, &c, 1, &fd);
	if (ret < 0)
		i_error("fd_read(log fd) failed: %m");
	else if (ret == 0) {
		/* master died. lib-master should notice it soon. */
		io_remove(&log_fdpass_io);
	} else {
		if (dup2(fd, STDERR_FILENO) < 0)
			i_fatal("dup2(fd_read  log fd, stderr) failed: %m");
		if (close(fd) < 0)
			i_error("close(fd_read log fd) failed: %m");
	}
}

static void main_init(void)
{
	const struct master_service_settings *set =
		master_service_settings_get(master_service);

	/* delay dying until all of our clients are gone */
	master_service_set_die_with_master(master_service, FALSE);

	verbose_proctitle = set->verbose_proctitle;
	anvil_restarted = getenv("ANVIL_RESTARTED") != NULL;
	anvil_connections_init(set->base_dir, ANVIL_CLIENT_POOL_MAX_CONNECTIONS);
	admin_clients_init();
	admin_pool = admin_client_pool_init(set->base_dir,
					    ANVIL_CLIENT_POOL_MAX_CONNECTIONS);
	connect_limit = connect_limit_init();
	penalty = penalty_init();
	log_fdpass_io = io_add(MASTER_ANVIL_LOG_FDPASS_FD, IO_READ,
			       log_fdpass_input, NULL);
}

static void main_deinit(void)
{
	io_remove(&log_fdpass_io);
	penalty_deinit(&penalty);
	connect_limit_deinit(&connect_limit);
	admin_client_pool_deinit(&admin_pool);
	admin_clients_deinit();
	anvil_connections_deinit();
	timeout_remove(&to_refresh);
}

int main(int argc, char *argv[])
{
	const enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_DONT_SEND_STATS;
	const char *error;

	master_service = master_service_init("anvil", service_flags,
					     &argc, &argv, "");
	if (master_getopt(master_service) > 0)
		return FATAL_DEFAULT;
	if (master_service_settings_read_simple(master_service,
						NULL, &error) < 0)
		i_fatal("Error reading configuration: %s", error);
	master_service_init_log(master_service);

	restrict_access_by_env(RESTRICT_ACCESS_FLAG_ALLOW_ROOT, NULL);
	restrict_access_allow_coredumps(TRUE);

	main_init();
	master_service_init_finish(master_service);

	master_service_run(master_service, client_connected);

	main_deinit();
	master_service_deinit(&master_service);
        return 0;
}
