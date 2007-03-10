/* Copyright (C) 2004-2005 Timo Sirainen */

#include "common.h"

#ifdef PASSDB_CHECKPASSWORD

#include "lib-signals.h"
#include "buffer.h"
#include "str.h"
#include "ioloop.h"
#include "hash.h"
#include "env-util.h"
#include "passdb.h"
#include "safe-memset.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

struct checkpassword_passdb_module {
	struct passdb_module module;

	const char *checkpassword_path, *checkpassword_reply_path;
	struct hash_table *clients;
};

struct chkpw_auth_request {
	int fd_out, fd_in;
	struct io *io_out, *io_in;
	pid_t pid;

	string_t *input_buf;
	char *password;
	unsigned int write_pos;

	struct auth_request *request;
	verify_plain_callback_t *callback;

	int exit_status;
	unsigned int exited:1;
};

static void checkpassword_request_close(struct chkpw_auth_request *request)
{
	if (request->io_in != NULL)
		io_remove(&request->io_in);
	if (request->io_out != NULL)
		io_remove(&request->io_out);

	if (request->fd_in != -1) {
		if (close(request->fd_in) < 0)
			i_error("checkpassword: close() failed: %m");
		request->fd_in = -1;
	}
	if (request->fd_out != -1) {
		if (close(request->fd_out) < 0)
			i_error("checkpassword: close() failed: %m");
	}
}

static void checkpassword_request_finish(struct chkpw_auth_request *request,
					 enum passdb_result result)
{
	struct passdb_module *_module = request->request->passdb->passdb;
	struct checkpassword_passdb_module *module =
		(struct checkpassword_passdb_module *)_module;

	hash_remove(module->clients, POINTER_CAST(request->pid));

	if (result == PASSDB_RESULT_OK) {
		if (strchr(str_c(request->input_buf), '\n') != NULL) {
			auth_request_log_error(request->request,
				"checkpassword",
				"LF characters in checkpassword reply");
			result = PASSDB_RESULT_INTERNAL_FAILURE;
		} else {
			auth_request_set_fields(request->request,
				t_strsplit(str_c(request->input_buf), "\t"),
				NULL);
		}
	}

	request->callback(result, request->request);
	auth_request_unref(&request->request);

        checkpassword_request_close(request);

	if (request->input_buf != NULL)
		str_free(&request->input_buf);

	safe_memset(request->password, 0, strlen(request->password));
	i_free(request->password);
	i_free(request);
}

static void
checkpassword_request_half_finish(struct chkpw_auth_request *request)
{
	if (!request->exited || request->fd_in != -1)
		return;

	switch (request->exit_status) {
	/* vpopmail exit codes: */
	case 3:		/* password fail / vpopmail user not found */
	case 12: 	/* null user name given */
	case 13:	/* null password given */
	case 15:	/* user has no password */
	case 20:	/* invalid user/domain characters */
	case 21:	/* system user not found */
	case 22:	/* system user shadow entry not found */
	case 23:	/* system password fail */

	/* standard checkpassword exit codes: */
	case 1:
		/* (1 is additionally defined in vpopmail for
		   "pop/smtp/webmal/ imap/access denied") */
		auth_request_log_info(request->request, "checkpassword",
				      "Login failed (status=%d)",
				      request->exit_status);
		checkpassword_request_finish(request,
					     PASSDB_RESULT_PASSWORD_MISMATCH);
		break;
	case 0:
		if (request->input_buf != NULL) {
			checkpassword_request_finish(request, PASSDB_RESULT_OK);
			break;
		}
		/* missing input - fall through */
	case 2:
		/* checkpassword is called with wrong
		   parameters? unlikely */
	case 111:
		/* temporary problem, treat as internal error */
	default:
		/* whatever error.. */
		auth_request_log_error(request->request, "checkpassword",
			"Child %s exited with status %d",
			dec2str(request->pid), request->exit_status);
		checkpassword_request_finish(request,
					     PASSDB_RESULT_INTERNAL_FAILURE);
		break;
	}
}

static void sigchld_handler(int signo __attr_unused__, void *context)
{
	struct checkpassword_passdb_module *module = context;
	struct chkpw_auth_request *request;
	int status;
	pid_t pid;

	/* FIXME: if we ever do some other kind of forking, this needs fixing */
	while ((pid = waitpid(-1, &status, WNOHANG)) != 0) {
		if (pid == -1) {
			if (errno != ECHILD && errno != EINTR)
				i_error("waitpid() failed: %m");
			return;
		}

		request = hash_lookup(module->clients, POINTER_CAST(pid));
		if (request == NULL) {
			/* unknown child finished */
			if (WIFSIGNALED(status)) {
				i_error("checkpassword: Unknown child %s died "
					"with signal %d", dec2str(pid),
					WTERMSIG(status));
			}
			continue;
		}

		if (WIFSIGNALED(status)) {
			i_error("checkpassword: Child %s died with signal %d",
				dec2str(pid), WTERMSIG(status));
		} else if (WIFEXITED(status)) {
			request->exited = TRUE;
			request->exit_status = WEXITSTATUS(status);

			auth_request_log_debug(request->request,
				"checkpassword", "exit_status=%d",
				request->exit_status);

			checkpassword_request_half_finish(request);
			request = NULL;
		} else {
			/* shouldn't happen */
			auth_request_log_debug(request->request,
				"checkpassword", "Child exited with status=%d",
				status);
		}

		if (request != NULL) {
			checkpassword_request_finish(request,
				PASSDB_RESULT_INTERNAL_FAILURE);
		}
	}
}

static void env_put_extra_fields(const char *extra_fields)
{
	const char *const *tmp;
	const char *key, *p;

	for (tmp = t_strsplit(extra_fields, "\t"); *tmp != NULL; tmp++) {
		key = t_str_ucase(t_strcut(*tmp, '='));
		p = strchr(*tmp, '=');
		if (p == NULL)
			env_put(t_strconcat(key, "=1", NULL));
		else
			env_put(t_strconcat(key, p, NULL));
	}
}

static void __attr_noreturn__
checkpassword_verify_plain_child(struct auth_request *request,
				 struct checkpassword_passdb_module *module,
				 int fd_in, int fd_out)
{
	const char *cmd, *const *args;

	if (dup2(fd_out, 3) < 0 || dup2(fd_in, 4) < 0) {
		auth_request_log_error(request, "checkpassword",
				       "dup2() failed: %m");
	} else {
		/* Besides passing the standard username and password in a
		   pipe, also pass some other possibly interesting information
		   via environment. Use UCSPI names for local/remote IPs. */
		env_put("PROTO=TCP"); /* UCSPI */
		env_put(t_strconcat("SERVICE=", request->service, NULL));
		if (request->local_ip.family != 0) {
			env_put(t_strconcat("TCPLOCALIP=",
					    net_ip2addr(&request->local_ip),
					    NULL));
			/* FIXME: for backwards compatibility only,
			   remove some day */
			env_put(t_strconcat("LOCAL_IP=",
					    net_ip2addr(&request->local_ip),
					    NULL));
		}
		if (request->remote_ip.family != 0) {
			env_put(t_strconcat("TCPREMOTEIP=",
					    net_ip2addr(&request->remote_ip),
					    NULL));
			/* FIXME: for backwards compatibility only,
			   remove some day */
			env_put(t_strconcat("REMOTE_IP=",
					    net_ip2addr(&request->remote_ip),
					    NULL));
		}
		if (request->master_user != NULL) {
			env_put(t_strconcat("MASTER_USER=",
					    request->master_user, NULL));
		}
		if (request->extra_fields != NULL) {
			const char *fields =
				auth_stream_reply_export(request->extra_fields);

			/* extra fields could come from master db */
			env_put_extra_fields(fields);
		}

		/* very simple argument splitting. */
		cmd = t_strconcat(module->checkpassword_path, " ",
				  module->checkpassword_reply_path, NULL);
		auth_request_log_debug(request, "checkpassword",
				       "execute: %s", cmd);

		args = t_strsplit(cmd, " ");
		execv(args[0], (char **)args);
		auth_request_log_error(request, "checkpassword",
				       "execv(%s) failed: %m", args[0]);
	}
	exit(2);
}

static void checkpassword_child_input(struct chkpw_auth_request *request)
{
	unsigned char buf[1024];
	ssize_t ret;

	ret = read(request->fd_in, buf, sizeof(buf));
	if (ret <= 0) {
		if (ret < 0) {
			auth_request_log_error(request->request,
				"checkpassword", "read() failed: %m");
		}

		auth_request_log_debug(request->request, "checkpassword",
				       "Received no input");
		checkpassword_request_close(request);
		checkpassword_request_half_finish(request);
	} else {
		if (request->input_buf == NULL)
			request->input_buf = str_new(default_pool, 512);
		str_append_n(request->input_buf, buf, ret);

		auth_request_log_debug(request->request, "checkpassword",
			"Received input: %s", str_c(request->input_buf));
	}
}

static void checkpassword_child_output(struct chkpw_auth_request *request)
{
	/* Send: username \0 password \0 timestamp \0.
	   Must be 512 bytes or less. The "timestamp" parameter is actually
	   useful only for APOP authentication. We don't support it, so
	   keep it empty */
	struct auth_request *auth_request = request->request;
	buffer_t *buf;
	const unsigned char *data;
	size_t size;
	ssize_t ret;

	buf = buffer_create_dynamic(pool_datastack_create(), 512+1);
	buffer_append(buf, auth_request->user, strlen(auth_request->user)+1);
	buffer_append(buf, request->password, strlen(request->password)+1);
	buffer_append_c(buf, '\0');
	data = buffer_get_data(buf, &size);

	if (size > 512) {
		auth_request_log_error(request->request, "checkpassword",
			"output larger than 512 bytes: %"PRIuSIZE_T, size);
		checkpassword_request_finish(request,
					     PASSDB_RESULT_INTERNAL_FAILURE);
		return;
	}

	ret = write(request->fd_out, data + request->write_pos,
		    size - request->write_pos);
	if (ret <= 0) {
		if (ret < 0) {
			auth_request_log_error(request->request,
				"checkpassword", "write() failed: %m");
		}
		checkpassword_request_finish(request,
					     PASSDB_RESULT_INTERNAL_FAILURE);
		return;
	}

	request->write_pos += ret;
	if (request->write_pos < size)
		return;

	io_remove(&request->io_out);

	if (close(request->fd_out) < 0)
		i_error("checkpassword: close() failed: %m");
        request->fd_out = -1;
}

static void
checkpassword_verify_plain(struct auth_request *request, const char *password,
			   verify_plain_callback_t *callback)
{
	struct passdb_module *_module = request->passdb->passdb;
	struct checkpassword_passdb_module *module =
		(struct checkpassword_passdb_module *)_module;
	struct chkpw_auth_request *chkpw_auth_request;
	int fd_in[2], fd_out[2];
	pid_t pid;

	fd_in[0] = -1;
	if (pipe(fd_in) < 0 || pipe(fd_out) < 0) {
		auth_request_log_error(request, "checkpassword",
				       "pipe() failed: %m");
		callback(PASSDB_RESULT_INTERNAL_FAILURE, request);
		if (fd_in[0] != -1) {
			(void)close(fd_in[0]);
			(void)close(fd_in[1]);
		}
		return;
	}

	pid = fork();
	if (pid == -1) {
		auth_request_log_error(request, "checkpassword",
				       "fork() failed: %m");
		callback(PASSDB_RESULT_INTERNAL_FAILURE, request);
		(void)close(fd_in[0]);
		(void)close(fd_in[1]);
		(void)close(fd_out[0]);
		(void)close(fd_out[1]);
		return;
	}

	if (pid == 0) {
		(void)close(fd_in[0]);
		(void)close(fd_out[1]);
		checkpassword_verify_plain_child(request, module,
						 fd_in[1], fd_out[0]);
		/* not reached */
	}

	if (close(fd_in[1]) < 0) {
		auth_request_log_error(request, "checkpassword",
				       "close(fd_in[1]) failed: %m");
	}
	if (close(fd_out[0]) < 0) {
		auth_request_log_error(request, "checkpassword",
				       "close(fd_out[0]) failed: %m");
	}

	auth_request_ref(request);
	chkpw_auth_request = i_new(struct chkpw_auth_request, 1);
	chkpw_auth_request->fd_in = fd_in[0];
	chkpw_auth_request->fd_out = fd_out[1];
	chkpw_auth_request->pid = pid;
	chkpw_auth_request->password = i_strdup(password);
	chkpw_auth_request->request = request;
	chkpw_auth_request->callback = callback;

	chkpw_auth_request->io_in =
		io_add(fd_in[0], IO_READ, checkpassword_child_input,
		       chkpw_auth_request);
	chkpw_auth_request->io_out =
		io_add(fd_out[1], IO_WRITE, checkpassword_child_output,
		       chkpw_auth_request);

	hash_insert(module->clients, POINTER_CAST(pid), chkpw_auth_request);
}

static struct passdb_module *
checkpassword_preinit(struct auth_passdb *auth_passdb, const char *args)
{
	struct checkpassword_passdb_module *module;

	module = p_new(auth_passdb->auth->pool,
		       struct checkpassword_passdb_module, 1);
	module->checkpassword_path = p_strdup(auth_passdb->auth->pool, args);
	module->checkpassword_reply_path =
		PKG_LIBEXECDIR"/checkpassword-reply";

	module->clients =
		hash_create(default_pool, default_pool, 0, NULL, NULL);

	return &module->module;
}

static void checkpassword_init(struct passdb_module *module,
			       const char *args __attr_unused__)
{
	lib_signals_set_handler(SIGCHLD, TRUE, sigchld_handler, module);
}

static void checkpassword_deinit(struct passdb_module *_module)
{
	struct checkpassword_passdb_module *module =
		(struct checkpassword_passdb_module *)_module;
	struct hash_iterate_context *iter;
	void *key, *value;

	lib_signals_unset_handler(SIGCHLD, sigchld_handler, module);

	iter = hash_iterate_init(module->clients);
	while (hash_iterate(iter, &key, &value)) {
		checkpassword_request_finish(value,
					     PASSDB_RESULT_INTERNAL_FAILURE);
	}
	hash_iterate_deinit(iter);
	hash_destroy(module->clients);
}

struct passdb_module_interface passdb_checkpassword = {
	"checkpassword",

	checkpassword_preinit,
	checkpassword_init,
	checkpassword_deinit,

	checkpassword_verify_plain,
	NULL,
	NULL
};

#endif
