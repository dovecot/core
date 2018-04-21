/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "env-util.h"
#include "execv-const.h"
#include "fdpass.h"
#include "restrict-access.h"
#include "str.h"
#include "strescape.h"
#include "settings-parser.h"
#include "mail-storage-service.h"
#include "master-interface.h"
#include "master-service.h"
#include "master-service-settings.h"

#include <unistd.h>

#define SCRIPT_LOGIN_PROTOCOL_VERSION_MAJOR 1
#define SCRIPT_LOGIN_READ_TIMEOUT_SECS 10
#define ENV_USERDB_KEYS "USERDB_KEYS"
#define SCRIPT_COMM_FD 3

static const char **exec_args;
static bool drop_to_userdb_privileges = FALSE;

static void client_connected(struct master_service_connection *conn)
{
	enum mail_storage_service_flags flags =
		MAIL_STORAGE_SERVICE_FLAG_ALLOW_ROOT |
		MAIL_STORAGE_SERVICE_FLAG_NO_PLUGINS;
	string_t *instr, *keys;
	const char *const *args, *key, *value, *error, *version_line, *data_line;
	struct mail_storage_service_ctx *service_ctx;
	struct mail_storage_service_input input;
	struct mail_storage_service_user *user;
	char buf[1024];
	unsigned int i, socket_count;
	int fd = -1;
	ssize_t ret;

	alarm(SCRIPT_LOGIN_READ_TIMEOUT_SECS);

	net_set_nonblock(conn->fd, FALSE);
	instr = t_str_new(1024);
	ret = fd_read(conn->fd, buf, sizeof(buf), &fd);
	while (ret > 0) {
		str_append_data(instr, buf, ret);
		if (buf[ret-1] == '\n' &&
		    strchr(str_c(instr), '\n')[1] != '\0') {
			str_truncate(instr, str_len(instr)-1);
			break;
		}

		ret = read(conn->fd, buf, sizeof(buf));
	}

	version_line = str_c(instr);
	data_line = strchr(version_line, '\n');
	if (data_line != NULL)
		version_line = t_strdup_until(version_line, data_line++);
	else
		version_line = NULL;

	if (ret > 0 || version_line != NULL) {
		if (version_line == NULL ||
		    !version_string_verify(version_line, "script-login",
				SCRIPT_LOGIN_PROTOCOL_VERSION_MAJOR)) {
			i_fatal("Client not compatible with this binary "
				"(connecting to wrong socket?)");
		}
	}

	if (ret <= 0) {
		if (ret < 0)
			i_fatal("read() failed: %m");
		else
			i_fatal("read() failed: disconnected");
	}
	if (fd == -1)
		i_fatal("client fd not received");

	alarm(0);

	/* put everything to environment */
	env_clean();
	keys = t_str_new(256);
	args = t_strsplit_tabescaped(data_line);

	if (str_array_length(args) < 3)
		i_fatal("Missing input fields");

	i = 0;
	i_zero(&input);
	input.module = "mail"; /* need to get mail_uid, mail_gid */
	input.service = "script-login";
	(void)net_addr2ip(args[i++], &input.local_ip);
	(void)net_addr2ip(args[i++], &input.remote_ip);
	input.username = args[i++];
	input.userdb_fields = args + i;

	env_put(t_strconcat("LOCAL_IP=", net_ip2addr(&input.local_ip), NULL));
	env_put(t_strconcat("IP=", net_ip2addr(&input.remote_ip), NULL));
	env_put(t_strconcat("USER=", input.username, NULL));

	for (; args[i] != NULL; i++) {
		value = strchr(args[i], '=');
		if (value != NULL) {
			key = t_str_ucase(t_strdup_until(args[i], value));
			env_put(t_strconcat(key, value, NULL));
			str_printfa(keys, "%s ", key);
		}
	}
	env_put(t_strconcat(ENV_USERDB_KEYS"=", str_c(keys), NULL));

	master_service_init_log(master_service,
		t_strdup_printf("script-login(%s): ", input.username));

	if (drop_to_userdb_privileges) {
		service_ctx = mail_storage_service_init(master_service, NULL, flags);
		if (mail_storage_service_lookup(service_ctx, &input, &user, &error) <= 0)
			i_fatal("%s", error);
		mail_storage_service_restrict_setenv(service_ctx, user);
		/* we can't exec anything in a chroot */
		env_remove("RESTRICT_CHROOT");
		restrict_access_by_env(0, getenv("HOME"));
	}

	if (dup2(fd, STDIN_FILENO) < 0)
		i_fatal("dup2() failed: %m");
	if (dup2(fd, STDOUT_FILENO) < 0)
		i_fatal("dup2() failed: %m");
	if (close(fd) < 0)
		i_fatal("close() failed: %m");
	if (conn->fd != SCRIPT_COMM_FD) {
		if (dup2(conn->fd, SCRIPT_COMM_FD) < 0)
			i_fatal("dup2() failed: %m");
		if (close(conn->fd) < 0)
			i_fatal("close() failed: %m");
	}

	/* close all listener sockets */
	socket_count = master_service_get_socket_count(master_service);
	for (i = 0; i < socket_count; i++) {
		if (close(MASTER_LISTEN_FD_FIRST + i) < 0)
			i_error("close(listener) failed: %m");
	}
	if (close(MASTER_STATUS_FD) < 0)
		i_error("close(status) failed: %m");

	execvp_const(exec_args[0], exec_args);
}

static void script_execute_finish(void)
{
	const char *keys_str, *username, *const *keys, *value;
	string_t *reply = t_str_new(512);
	ssize_t ret;

	keys_str = getenv(ENV_USERDB_KEYS);
	if (keys_str == NULL)
		i_fatal(ENV_USERDB_KEYS" environment missing");

	username = getenv("USER");
	if (username == NULL)
		i_fatal("USER environment missing");
	str_append(reply, username);

	for (keys = t_strsplit_spaces(keys_str, " "); *keys != NULL; keys++) {
		value = getenv(t_str_ucase(*keys));
		if (value != NULL) {
			str_append_c(reply, '\t');
			str_append_tabescaped(reply,
					    t_strconcat(t_str_lcase(*keys), "=",
							value, NULL));
		}
	}
	str_append_c(reply, '\n');

	/* finish by sending the fd to the mail process */
	ret = fd_send(SCRIPT_COMM_FD, STDOUT_FILENO,
		      str_data(reply), str_len(reply));
	if (ret == (ssize_t)str_len(reply)) {
		/* success */
	} else {
		if (ret < 0)
			i_error("fd_send() failed: %m");
		else
			i_error("fd_send() sent partial output");
		/* exit with 0 even though we failed. non-0 exit just makes
		   master log an unnecessary error. */
	}
}

int main(int argc, char *argv[])
{
	enum master_service_flags flags = 0;
	int i, c;

	if (getenv(MASTER_IS_PARENT_ENV) == NULL)
		flags |= MASTER_SERVICE_FLAG_STANDALONE;

	master_service = master_service_init("script-login", flags,
					     &argc, &argv, "+d");
	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'd':
			drop_to_userdb_privileges = TRUE;
			break;
		default:
			return FATAL_DEFAULT;
		}
	}
	argc -= optind;
	argv += optind;

	master_service_init_log(master_service, "script-login: ");

	if (!drop_to_userdb_privileges &&
	    (flags & MASTER_SERVICE_FLAG_STANDALONE) == 0) {
		/* drop to privileges defined by service settings */
		restrict_access_by_env(RESTRICT_ACCESS_FLAG_ALLOW_ROOT, NULL);
	}

	master_service_init_finish(master_service);
	master_service_set_service_count(master_service, 1);

	if ((flags & MASTER_SERVICE_FLAG_STANDALONE) != 0) {
		/* The last post-login script is calling us to finish login */
		script_execute_finish();
	} else {
		if (argv[0] == NULL)
			i_fatal("Missing script path");
		exec_args = i_new(const char *, argc + 2);
		for (i = 0; i < argc; i++)
			exec_args[i] = argv[i];
		exec_args[i] = PKG_LIBEXECDIR"/script-login";
		exec_args[i+1] = NULL;

		if (exec_args[0][0] != '/') {
			exec_args[0] = t_strconcat(PKG_LIBEXECDIR"/",
						   exec_args[0], NULL);
		}

		master_service_run(master_service, client_connected);
	}
	master_service_deinit(&master_service);
        return 0;
}
