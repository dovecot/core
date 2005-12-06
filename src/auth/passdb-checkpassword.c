/* Copyright (C) 2004-2005 Timo Sirainen */

#include "common.h"

#ifdef PASSDB_CHECKPASSWORD

#include "buffer.h"
#include "str.h"
#include "ioloop.h"
#include "hash.h"
#include "passdb.h"
#include "safe-memset.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

struct checkpassword_passdb_module {
	struct passdb_module module;

	const char *checkpassword_path, *checkpassword_reply_path;
	struct hash_table *clients;
	struct timeout *to_wait;
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
	if (request->fd_in != -1) {
		if (close(request->fd_in) < 0)
			i_error("checkpassword: close() failed: %m");
		request->fd_in = -1;
	}
	if (request->io_in != NULL) {
		io_remove(request->io_in);
		request->io_in = NULL;
	}

	if (request->io_out != NULL)
		io_remove(request->io_out);
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
		request->request->extra_fields =
			auth_stream_reply_init(request->request);
		auth_stream_reply_import(request->request->extra_fields,
					 str_c(request->input_buf));
	}

	if (auth_request_unref(request->request)) {
		request->callback(result, request->request);
	}

        checkpassword_request_close(request);

	if (request->input_buf != NULL) {
		str_free(request->input_buf);
		request->input_buf = NULL;
	}

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
	case 0:
		if (request->input_buf != NULL) {
			checkpassword_request_finish(request, PASSDB_RESULT_OK);
			break;
		}
		/* missing input - fall through */
	case 1:
		auth_request_log_info(request->request, "checkpassword",
				      "Unknown user");
		checkpassword_request_finish(request,
					     PASSDB_RESULT_USER_UNKNOWN);
		break;
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

static void wait_timeout(void *context)
{
	struct checkpassword_passdb_module *module = context;
	struct chkpw_auth_request *request;
	int status;
	pid_t pid;

	/* FIXME: if we ever do some other kind of forking, this needs fixing */
	while ((pid = waitpid(-1, &status, WNOHANG)) != 0) {
		if (pid == -1) {
			if (errno == ECHILD) {
				timeout_remove(module->to_wait);
				module->to_wait = NULL;
			} else if (errno != EINTR)
				i_error("waitpid() failed: %m");
			return;
		}

		request = hash_lookup(module->clients, POINTER_CAST(pid));

		if (WIFSIGNALED(status)) {
			i_error("checkpassword: Child %s died with signal %d",
				dec2str(pid), WTERMSIG(status));
		} else if (WIFEXITED(status) && request != NULL) {
			auth_request_log_debug(request->request,
				"checkpassword", "exit_status=%d",
				request->exit_status);

			request->exited = TRUE;
			request->exit_status = WEXITSTATUS(status);
			checkpassword_request_half_finish(request);
			request = NULL;
		} else {
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

static void
checkpassword_verify_plain_child(struct auth_request *request,
				 struct checkpassword_passdb_module *module,
				 int fd_in, int fd_out)
{
	const char *args[3];

	if (dup2(fd_out, 3) < 0 || dup2(fd_in, 4) < 0) {
		auth_request_log_error(request, "checkpassword",
				       "dup2() failed: %m");
	} else {
		args[0] = module->checkpassword_path;
		args[1] = module->checkpassword_reply_path;
		args[2] = NULL;

		auth_request_log_debug(request, "checkpassword",
			"Executed: %s %s", args[0], args[1]);

		execv(module->checkpassword_path, (char **)args);
		auth_request_log_error(request, "checkpassword",
			"execv(%s) failed: %m", module->checkpassword_path);
	}
	exit(2);
}

static void checkpassword_child_input(void *context)
{
	struct chkpw_auth_request *request = context;
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

static void checkpassword_child_output(void *context)
{
	/* Send: username \0 password \0 timestamp \0.
	   Must be 512 bytes or less. The "timestamp" parameter is actually
	   useful only for APOP authentication. We don't support it, so
	   keep it empty */
	struct chkpw_auth_request *request = context;
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

	if (close(request->fd_out) < 0)
		i_error("checkpassword: close() failed: %m");
        request->fd_out = -1;

	io_remove(request->io_out);
	request->io_out = NULL;
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

	if (module->to_wait == NULL) {
		/* FIXME: we could use SIGCHLD */
		module->to_wait = timeout_add(100, wait_timeout, module);
	}
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

static void checkpassword_deinit(struct passdb_module *_module)
{
	struct checkpassword_passdb_module *module =
		(struct checkpassword_passdb_module *)_module;
	struct hash_iterate_context *iter;
	void *key, *value;

	iter = hash_iterate_init(module->clients);
	while (hash_iterate(iter, &key, &value)) {
		checkpassword_request_finish(value,
					     PASSDB_RESULT_INTERNAL_FAILURE);
	}
	hash_iterate_deinit(iter);
	hash_destroy(module->clients);

	if (module->to_wait != NULL)
		timeout_remove(module->to_wait);
}

struct passdb_module_interface passdb_checkpassword = {
	"checkpassword",

	checkpassword_preinit,
	NULL,
	checkpassword_deinit,

	checkpassword_verify_plain,
	NULL
};

#endif
