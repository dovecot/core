#include "config.h"
#undef HAVE_CONFIG_H

#ifdef PASSDB_CHECKPASSWORD

#include "common.h"
#include "buffer.h"
#include "str.h"
#include "ioloop.h"
#include "hash.h"
#include "passdb.h"
#include "safe-memset.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

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

static char *checkpassword_path, *checkpassword_reply_path;
struct hash_table *clients;
static struct timeout *to_wait;

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
	hash_remove(clients, POINTER_CAST(request->pid));

	if (result == PASSDB_RESULT_OK) {
		request->request->extra_fields =
			p_strdup(request->request->pool,
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
		i_error("checkpassword: Child %s exited with status %d",
			dec2str(request->pid), request->exit_status);
		checkpassword_request_finish(request,
					     PASSDB_RESULT_INTERNAL_FAILURE);
		break;
	}
}

static void wait_timeout(void *context __attr_unused__)
{
	struct chkpw_auth_request *request;
	int status;
	pid_t pid;

	/* FIXME: if we ever do some other kind of forking, this needs fixing */
	while ((pid = waitpid(-1, &status, WNOHANG)) != 0) {
		if (pid == -1) {
			if (errno == ECHILD) {
				timeout_remove(to_wait);
				to_wait = NULL;
			} else if (errno != EINTR)
				i_error("waitpid() failed: %m");
			return;
		}

		request = hash_lookup(clients, POINTER_CAST(pid));

		if (WIFSIGNALED(status)) {
			i_error("checkpassword: Child %s died with signal %d",
				dec2str(pid), WTERMSIG(status));
		} else if (WIFEXITED(status) && request != NULL) {
			request->exited = TRUE;
			request->exit_status = WEXITSTATUS(status);
			checkpassword_request_half_finish(request);
			request = NULL;
		}

		if (request != NULL) {
			checkpassword_request_finish(request,
				PASSDB_RESULT_INTERNAL_FAILURE);
		}
	}
}

static void checkpassword_verify_plain_child(int fd_in, int fd_out)
{
	char *args[3];

	if (dup2(fd_out, 3) < 0)
		i_error("checkpassword: dup2() failed: %m");
	else if (dup2(fd_in, 4) < 0)
		i_error("checkpassword: dup2() failed: %m");
	else {
		args[0] = checkpassword_path;
		args[1] = checkpassword_reply_path;
		args[2] = NULL;

		execv(checkpassword_path, args);
		i_error("checkpassword: execv(%s) failed: %m",
			checkpassword_path);
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
		if (ret < 0)
			i_error("checkpassword: read() failed: %m");
		checkpassword_request_close(request);
		checkpassword_request_half_finish(request);
	} else {
		if (request->input_buf == NULL)
			request->input_buf = str_new(default_pool, 512);
		str_append_n(request->input_buf, buf, ret);
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
		i_error("checkpassword: output larger than 512 bytes: "
			"%"PRIuSIZE_T, size);
		checkpassword_request_finish(request,
					     PASSDB_RESULT_INTERNAL_FAILURE);
		return;
	}

	ret = write(request->fd_out, data + request->write_pos,
		    size - request->write_pos);
	if (ret <= 0) {
		if (ret < 0)
			i_error("checkpassword: write() failed: %m");
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
		checkpassword_verify_plain_child(fd_in[1], fd_out[0]);
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

	hash_insert(clients, POINTER_CAST(pid), chkpw_auth_request);

	if (to_wait == NULL) {
		/* FIXME: we could use SIGCHLD */
		to_wait = timeout_add(100, wait_timeout, NULL);
	}
}

static void checkpassword_init(const char *args)
{
	checkpassword_path = i_strdup(args);
	checkpassword_reply_path =
		i_strdup(PKG_LIBEXECDIR"/checkpassword-reply");

	to_wait = NULL;
	clients = hash_create(default_pool, default_pool, 0, NULL, NULL);
}

static void checkpassword_deinit(void)
{
	struct hash_iterate_context *iter;
	void *key, *value;

	iter = hash_iterate_init(clients);
	while (hash_iterate(iter, &key, &value)) {
		checkpassword_request_finish(value,
					     PASSDB_RESULT_INTERNAL_FAILURE);
	}
	hash_iterate_deinit(iter);
	hash_destroy(clients);

	if (to_wait != NULL)
		timeout_remove(to_wait);

	i_free(checkpassword_path);
	i_free(checkpassword_reply_path);
}

struct passdb_module passdb_checkpassword = {
	"checkpassword",

	NULL,
	checkpassword_init,
	checkpassword_deinit,

	checkpassword_verify_plain,
	NULL
};

#endif
