/* Copyright (c) 2005-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "ioloop.h"
#include "fd-close-on-exec.h"
#include "restrict-access.h"
#include "randgen.h"
#include "sql-api.h"
#include "dict.h"
#include "dict-client.h"
#include "dict-server.h"
#include "module-dir.h"

#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>

#define DICT_MASTER_LISTENER_FD 3

struct ioloop *ioloop;

static struct io *log_io;
static struct module *modules;
static struct dict_server *dict_server;

static void sig_die(int signo, void *context ATTR_UNUSED)
{
	/* warn about being killed because of some signal, except SIGINT (^C)
	   which is too common at least while testing :) */
	if (signo != SIGINT)
		i_warning("Killed with signal %d", signo);
	io_loop_stop(ioloop);
}

static void log_error_callback(void *context ATTR_UNUSED)
{
	io_loop_stop(ioloop);
}

static void drop_privileges(void)
{
	/* Log file or syslog opening probably requires roots */
	i_set_failure_internal();

	/* Maybe needed. Have to open /dev/urandom before possible
	   chrooting. */
	random_init();

	/* Load built-in SQL drivers (if any) */
	sql_drivers_init();
	sql_drivers_register_all();

	restrict_access_by_env(NULL, FALSE);
}

static void main_init(void)
{
	const char *version, *path;
	int fd;

	version = getenv("DOVECOT_VERSION");
	if (version != NULL && strcmp(version, PACKAGE_VERSION) != 0) {
		i_fatal("Dovecot version mismatch: "
			"Master is v%s, dict is v"PACKAGE_VERSION" "
			"(if you don't care, set version_ignore=yes)", version);
	}

	lib_signals_init();
        lib_signals_set_handler(SIGINT, TRUE, sig_die, NULL);
        lib_signals_set_handler(SIGTERM, TRUE, sig_die, NULL);
        lib_signals_ignore(SIGPIPE, TRUE);
        lib_signals_ignore(SIGALRM, FALSE);

	/* If master dies, the log fd gets closed and we'll quit */
	log_io = io_add(STDERR_FILENO, IO_ERROR, log_error_callback, NULL);

	dict_drivers_register_all();

	modules = module_dir_load(DICT_MODULE_DIR, NULL, TRUE, version);
	module_dir_init(modules);

	path = getenv("DICT_LISTEN_FROM_FD");
	fd = path == NULL ? -1 : DICT_MASTER_LISTENER_FD;
	if (path == NULL)
		path = DEFAULT_DICT_SERVER_SOCKET_PATH;

	dict_server = dict_server_init(path, fd);
}

static void main_deinit(void)
{
	io_remove(&log_io);
	dict_server_deinit(dict_server);

	module_dir_unload(&modules);

	dict_drivers_unregister_all();

	sql_drivers_deinit();
	random_deinit();
	lib_signals_deinit();
	closelog();
}

int main(void)
{
#ifdef DEBUG
	if (getenv("GDB") == NULL)
		fd_debug_verify_leaks(DICT_MASTER_LISTENER_FD+1, 1024);
#endif

	/* NOTE: we start rooted, so keep the code minimal until
	   restrict_access_by_env() is called */
	lib_init();
	drop_privileges();

	ioloop = io_loop_create();

	main_init();
        io_loop_run(ioloop);
	main_deinit();

	io_loop_destroy(&ioloop);
	lib_deinit();

	return 0;
}
