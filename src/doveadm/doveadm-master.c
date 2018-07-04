/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "strescape.h"
#include "istream.h"
#include "write-full.h"
#include "doveadm.h"
#include "doveadm-print.h"

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#define MASTER_PID_FILE_NAME "master.pid"

static bool pid_file_read(const char *path, pid_t *pid_r)
{
	char buf[32];
	int fd;
	ssize_t ret;
	bool found;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		if (errno == ENOENT)
			return FALSE;
		i_fatal("open(%s) failed: %m", path);
	}

	ret = read(fd, buf, sizeof(buf)-1);
	if (ret <= 0) {
		if (ret == 0)
			i_error("Empty PID file in %s", path);
		else
			i_fatal("read(%s) failed: %m", path);
		found = FALSE;
	} else {
		if (buf[ret-1] == '\n')
			ret--;
		buf[ret] = '\0';
		if (str_to_pid(buf, pid_r) < 0)
			found = FALSE;
		else {
			found = !(*pid_r == getpid() ||
				  (kill(*pid_r, 0) < 0 && errno == ESRCH));
		}
	}
	i_close_fd(&fd);
	return found;
}

void doveadm_master_send_signal(int signo)
{
	const char *pidfile_path;
	unsigned int i;
	pid_t pid;

	pidfile_path = t_strconcat(doveadm_settings->base_dir,
				   "/"MASTER_PID_FILE_NAME, NULL);

	if (!pid_file_read(pidfile_path, &pid))
		i_fatal("Dovecot is not running (read from %s)", pidfile_path);

	if (kill(pid, signo) < 0)
		i_fatal("kill(%s, %d) failed: %m", dec2str(pid), signo);

	if (signo == SIGTERM) {
		/* wait for a while for the process to die */
		usleep(1000);
		for (i = 0; i < 30; i++) {
			if (kill(pid, 0) < 0) {
				if (errno != ESRCH)
					i_error("kill() failed: %m");
				break;
			}
			usleep(100000);
		}
	}
}

static void cmd_stop(int argc ATTR_UNUSED, char *argv[] ATTR_UNUSED)
{
	doveadm_master_send_signal(SIGTERM);
}

static void cmd_reload(int argc ATTR_UNUSED, char *argv[] ATTR_UNUSED)
{
	doveadm_master_send_signal(SIGHUP);
}

static struct istream *master_service_send_cmd(const char *cmd)
{
	const char *path;

	path = t_strconcat(doveadm_settings->base_dir, "/master", NULL);
	int fd = net_connect_unix(path);
	if (fd == -1)
		i_fatal("net_connect_unix(%s) failed: %m", path);
	net_set_nonblock(fd, FALSE);

	const char *str =
		t_strdup_printf("VERSION\tmaster-client\t1\t0\n%s\n", cmd);
	if (write_full(fd, str, strlen(str)) < 0)
		i_error("write(%s) failed: %m", path);
	return i_stream_create_fd_autoclose(&fd, IO_BLOCK_SIZE);
}

static struct istream *
master_service_send_cmd_with_args(const char *cmd, const char *const *args)
{
	string_t *str = t_str_new(128);

	str_append(str, cmd);
	if (args != NULL) {
		for (unsigned int i = 0; args[i] != NULL; i++) {
			str_append_c(str, '\t');
			str_append_tabescaped(str, args[i]);
		}
	}
	return master_service_send_cmd(str_c(str));
}

static void cmd_service_stop(struct doveadm_cmd_context *cctx)
{
	const char *line, *const *services;

	if (!doveadm_cmd_param_array(cctx, "service", &services))
		i_fatal("service parameter missing");

	struct istream *input =
		master_service_send_cmd_with_args("STOP", services);

	alarm(5);
	if (i_stream_read_next_line(input) == NULL ||
	    (line = i_stream_read_next_line(input)) == NULL) {
		i_error("read(%s) failed: %s", i_stream_get_name(input),
			i_stream_get_error(input));
		doveadm_exit_code = EX_TEMPFAIL;
	} else if (line[0] == '-') {
		doveadm_exit_code = DOVEADM_EX_NOTFOUND;
		i_error("%s", line+1);
	} else if (line[0] != '+') {
		i_error("Unexpected input from %s: %s",
			i_stream_get_name(input), line);
		doveadm_exit_code = EX_TEMPFAIL;
	}
	alarm(0);
	i_stream_destroy(&input);
}

static void cmd_service_status(struct doveadm_cmd_context *cctx)
{
	const char *line, *const *services;
	unsigned int fields_count;

	if (!doveadm_cmd_param_array(cctx, "service", &services))
		services = NULL;

	struct istream *input = master_service_send_cmd("SERVICE-STATUS");

	doveadm_print_init(DOVEADM_PRINT_TYPE_PAGER);
	doveadm_print_header_simple("name");
	doveadm_print_header_simple("process_count");
	doveadm_print_header_simple("process_avail");
	doveadm_print_header_simple("process_limit");
	doveadm_print_header_simple("client_limit");
	doveadm_print_header_simple("throttle_secs");
	doveadm_print_header_simple("exit_failure_last");
	doveadm_print_header_simple("exit_failures_in_sec");
	doveadm_print_header_simple("last_drop_warning");
	doveadm_print_header_simple("listen_pending");
	doveadm_print_header_simple("listening");
	doveadm_print_header_simple("doveadm_stop");
	fields_count = doveadm_print_get_headers_count();

	alarm(5);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		if (line[0] == '\0')
			break;
		T_BEGIN {
			const char *const *args = t_strsplit_tabescaped(line);
			if (args[0] != NULL &&
			    (services == NULL ||
			     str_array_find(services, args[0]))) {
				unsigned int i;
				for (i = 0; i < fields_count && args[i] != NULL; i++)
					doveadm_print(args[i]);
				for (; i < fields_count; i++)
					doveadm_print("");
			}
		} T_END;
	}
	if (line == NULL) {
		i_error("read(%s) failed: %s", i_stream_get_name(input),
			i_stream_get_error(input));
		doveadm_exit_code = EX_TEMPFAIL;
	}
	alarm(0);
	i_stream_destroy(&input);
}

static void cmd_process_status(struct doveadm_cmd_context *cctx)
{
	const char *line, *const *services;

	if (!doveadm_cmd_param_array(cctx, "service", &services))
		services = NULL;

	struct istream *input =
		master_service_send_cmd_with_args("PROCESS-STATUS", services);

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	doveadm_print_header_simple("name");
	doveadm_print_header_simple("pid");
	doveadm_print_header_simple("available_count");
	doveadm_print_header_simple("total_count");
	doveadm_print_header_simple("idle_start");
	doveadm_print_header_simple("last_status_update");
	doveadm_print_header_simple("last_kill_sent");

	alarm(5);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		if (line[0] == '\0')
			break;
		T_BEGIN {
			const char *const *args = t_strsplit_tabescaped(line);
			if (str_array_length(args) >= 7) {
				for (unsigned int i = 0; i < 7; i++)
					doveadm_print(args[i]);
			}
		} T_END;
	}
	if (line == NULL) {
		i_error("read(%s) failed: %s", i_stream_get_name(input),
			i_stream_get_error(input));
		doveadm_exit_code = EX_TEMPFAIL;
	}
	alarm(0);
	i_stream_destroy(&input);
}

struct doveadm_cmd_ver2 doveadm_cmd_stop_ver2 = {
	.old_cmd = cmd_stop,
	.name = "stop",
	.usage = "",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_reload_ver2 = {
        .old_cmd = cmd_reload,
        .name = "reload",
        .usage = "",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_service_stop_ver2 = {
	.cmd = cmd_service_stop,
	.name = "service stop",
	.usage = "<service> [<service> [...]]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('\0', "service", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_service_status_ver2 = {
	.cmd = cmd_service_status,
	.name = "service status",
	.usage = "[<service> [...]]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('\0', "service", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_process_status_ver2 = {
	.cmd = cmd_process_status,
	.name = "process status",
	.usage = "[<service> [...]]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('\0', "service", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};
