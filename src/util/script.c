/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "env-util.h"
#include "fdpass.h"
#include "str.h"
#include "strescape.h"
#include "master-interface.h"
#include "master-service.h"

#include <stdlib.h>
#include <unistd.h>

#define ENV_USERDB_KEYS "USERDB_KEYS"
#define SCRIPT_COMM_FD 3
#define SCRIPT_CLIENT_FD 1

static char **exec_args;

static void client_connected(const struct master_service_connection *conn)
{
	string_t *input, *keys;
	const char **args, *arg, *key, *value, *username;
	char buf[1024];
	unsigned int i;
	int fd = -1;
	ssize_t ret;

	input = t_str_new(1024);
	ret = fd_read(conn->fd, buf, sizeof(buf), &fd);
	while (ret > 0) {
		str_append_n(input, buf, ret);
		if (buf[ret-1] == '\n') {
			str_truncate(input, str_len(input)-1);
			break;
		}

		ret = read(conn->fd, buf, sizeof(buf));
	}
	if (ret <= 0) {
		if (ret < 0)
			i_fatal("read() failed: %m");
		else
			i_fatal("read() failed: disconnected");
		(void)close(conn->fd);
		return;
	}
	if (fd == -1)
		i_fatal("client fd not received");

	/* put everything to environment */
	env_clean();
	keys = t_str_new(256);
	args = t_strsplit(str_c(input), "\t");

	if (str_array_length(args) < 3)
		i_fatal("Missing input fields");

	i = 0;
	env_put(t_strconcat("LOCAL_IP=", args[i++], NULL));
	env_put(t_strconcat("IP=", args[i++], NULL));
	username = args[i++];
	env_put(t_strconcat("USER=", username, NULL));

	for (; args[i] != '\0'; i++) {
		arg = str_tabunescape(t_strdup_noconst(args[i]));
		value = strchr(arg, '=');
		if (value != NULL) {
			key = t_str_ucase(t_strdup_until(arg, value));
			env_put(t_strconcat(key, value, NULL));
			str_printfa(keys, "%s ", key);
		}
	}
	env_put(t_strconcat(ENV_USERDB_KEYS"=", str_c(keys), NULL));

	if (dup2(fd, SCRIPT_CLIENT_FD) < 0)
		i_fatal("dup2() failed: %m");
	if (conn->fd != SCRIPT_COMM_FD) {
		if (dup2(conn->fd, SCRIPT_COMM_FD) < 0)
			i_fatal("dup2() failed: %m");
	}

	master_service_init_log(master_service,
				t_strdup_printf("script(%s): ", username));

	(void)execvp(exec_args[0], exec_args);
	i_fatal("execvp(%s) failed: %m", exec_args[0]);
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
			str_tabescape_write(reply,
					    t_strconcat(t_str_lcase(*keys), "=",
							value, NULL));
		}
	}
	str_append_c(reply, '\n');

	ret = fd_send(SCRIPT_COMM_FD, SCRIPT_CLIENT_FD,
		      str_data(reply), str_len(reply));
	if (ret < 0)
		i_fatal("fd_send() failed: %m");
	else if (ret != (ssize_t)str_len(reply))
		i_fatal("fd_send() sent partial output");
}

int main(int argc, char *argv[])
{
	enum master_service_flags flags = 0;
	int i;

	if (getenv(MASTER_UID_ENV) == NULL)
		flags |= MASTER_SERVICE_FLAG_STANDALONE;

	master_service = master_service_init("script", flags,
					     &argc, &argv, NULL);
	if (master_getopt(master_service) > 0)
		return FATAL_DEFAULT;

	master_service_init_log(master_service, "script: ");
	master_service_init_finish(master_service);
	master_service_set_service_count(master_service, 1);

	if ((flags & MASTER_SERVICE_FLAG_STANDALONE) != 0)
		script_execute_finish();
	else {
		if (argv[1] == NULL)
			i_fatal("Missing script path");
		exec_args = i_new(char *, argc + 1);
		for (i = 1; i < argc; i++)
			exec_args[i-1] = argv[i];
		exec_args[i-1] = PKG_LIBEXECDIR"/script";
		exec_args[i] = NULL;

		master_service_run(master_service, client_connected);
	}
	master_service_deinit(&master_service);
        return 0;
}
