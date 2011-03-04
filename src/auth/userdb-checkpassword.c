/* Copyright (c) 2004-2011 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "execv-const.h"
#include "userdb.h"

#ifdef USERDB_CHECKPASSWORD

#include "db-checkpassword.h"

struct checkpassword_userdb_module {
	struct userdb_module module;

	const char *checkpassword_path, *checkpassword_reply_path;
	struct hash_table *clients;
};

static struct child_wait *checkpassword_userdb_children = NULL;

static void checkpassword_request_finish(struct chkpw_auth_request *request,
					 enum userdb_result result)
{
	struct userdb_module *_module = request->request->userdb->userdb;
	struct checkpassword_userdb_module *module =
		(struct checkpassword_userdb_module *)_module;
	userdb_callback_t *callback =
		(userdb_callback_t *)request->callback;

	hash_table_remove(module->clients, POINTER_CAST(request->pid));

	if (result == USERDB_RESULT_OK) {
		if (strchr(str_c(request->input_buf), '\n') != NULL) {
			auth_request_log_error(request->request,
				"userdb-checkpassword",
				"LF characters in checkpassword reply");
			result = USERDB_RESULT_INTERNAL_FAILURE;
		} else {
			auth_request_init_userdb_reply(request->request);
			auth_request_set_fields(request->request,
				t_strsplit(str_c(request->input_buf), "\t"),
				NULL);
		}
	}

	callback(result, request->request);

	auth_request_unref(&request->request);
	checkpassword_request_free(request);
}

static void
checkpassword_request_half_finish(struct chkpw_auth_request *request)
{
	if (!request->exited || request->fd_in != -1)
		return;

	switch (request->exit_status) {
	case 3:
		/* User does not exist. */
		auth_request_log_info(request->request, "userdb-checkpassword",
				      "User unknown");
		checkpassword_request_finish(request,
					     USERDB_RESULT_USER_UNKNOWN);
		break;
	case 2:
		/* This is intentionally not 0. checkpassword-reply exits with
		   2 on success when AUTHORIZED is set. */
		if (request->input_buf != NULL) {
			checkpassword_request_finish(request, USERDB_RESULT_OK);
			break;
		}
		/* missing input - fall through */
	default:
		/* whatever error... */
		auth_request_log_error(request->request, "userdb-checkpassword",
			"Child %s exited with status %d",
			dec2str(request->pid), request->exit_status);
		checkpassword_request_finish(request,
					     USERDB_RESULT_INTERNAL_FAILURE);
		break;
	}
}

static void sigchld_handler(const struct child_wait_status *status,
			    struct checkpassword_userdb_module *module)
{
	struct chkpw_auth_request *request = 
		hash_table_lookup(module->clients, POINTER_CAST(status->pid));

	switch (checkpassword_sigchld_handler(status, request)) {
	case SIGCHLD_RESULT_UNKNOWN_CHILD:
	case SIGCHLD_RESULT_DEAD_CHILD:
		break;
	case SIGCHLD_RESULT_UNKNOWN_ERROR:
		checkpassword_request_finish(request,
					     USERDB_RESULT_INTERNAL_FAILURE);
		break;
	case SIGCHLD_RESULT_OK:
		checkpassword_request_half_finish(request);
		request = NULL;
		break;
	}
}

static void ATTR_NORETURN
checkpassword_lookup_child(struct auth_request *request,
			   struct checkpassword_userdb_module *module,
			   int fd_in, int fd_out)
{
	const char *cmd, *const *args;

	if (dup2(fd_out, 3) < 0 || dup2(fd_in, 4) < 0) {
		auth_request_log_error(request, "userdb-checkpassword",
				       "dup2() failed: %m");
	} else {
		/* We want to retrieve user data and don't do
		   authorization, so we need to signalize the
		   checkpassword program that the password shall be
		   ignored by setting AUTHORIZED.  This needs a
		   special checkpassword program which knows how to
		   handle this. */
		env_put("AUTHORIZED=1");
		checkpassword_setup_env(request);
		cmd = checkpassword_get_cmd(request, module->checkpassword_path,
					    module->checkpassword_reply_path);
		auth_request_log_debug(request, "userdb-checkpassword",
				       "execute: %s", cmd);

		/* very simple argument splitting. */
		args = t_strsplit(cmd, " ");
		execv_const(args[0], args);
	}
	exit(2);
}

static void
checkpassword_lookup(struct auth_request *request, userdb_callback_t *callback)
{
	struct userdb_module *_module = request->userdb->userdb;
	struct checkpassword_userdb_module *module =
		(struct checkpassword_userdb_module *)_module;
	struct chkpw_auth_request *chkpw_auth_request;
	int fd_in[2], fd_out[2];
	pid_t pid;

	fd_in[0] = -1;
	if (pipe(fd_in) < 0 || pipe(fd_out) < 0) {
		auth_request_log_error(request, "userdb-checkpassword",
				       "pipe() failed: %m");
		callback(USERDB_RESULT_INTERNAL_FAILURE, request);
		if (fd_in[0] != -1) {
			(void)close(fd_in[0]);
			(void)close(fd_in[1]);
		}
		return;
	}

	pid = fork();
	if (pid == -1) {
		auth_request_log_error(request, "userdb-checkpassword",
				       "fork() failed: %m");
		callback(USERDB_RESULT_INTERNAL_FAILURE, request);
		(void)close(fd_in[0]);
		(void)close(fd_in[1]);
		(void)close(fd_out[0]);
		(void)close(fd_out[1]);
		return;
	}

	if (pid == 0) {
		(void)close(fd_in[0]);
		(void)close(fd_out[1]);
		checkpassword_lookup_child(request, module,
						 fd_in[1], fd_out[0]);
		/* not reached */
	}

	if (close(fd_in[1]) < 0) {
		auth_request_log_error(request, "userdb-checkpassword",
				       "close(fd_in[1]) failed: %m");
	}
	if (close(fd_out[0]) < 0) {
		auth_request_log_error(request, "userdb-checkpassword",
				       "close(fd_out[0]) failed: %m");
	}

	auth_request_ref(request);
	chkpw_auth_request = i_new(struct chkpw_auth_request, 1);
	chkpw_auth_request->fd_in = fd_in[0];
	chkpw_auth_request->fd_out = fd_out[1];
	chkpw_auth_request->pid = pid;
	chkpw_auth_request->request = request;
	chkpw_auth_request->callback = callback;
	chkpw_auth_request->half_finish_callback =
		checkpassword_request_half_finish;
	chkpw_auth_request->finish_callback =
		checkpassword_request_finish;
	chkpw_auth_request->internal_failure_code =
		USERDB_RESULT_INTERNAL_FAILURE;

	chkpw_auth_request->io_in =
		io_add(fd_in[0], IO_READ, checkpassword_child_input,
		       chkpw_auth_request);
	chkpw_auth_request->io_out =
		io_add(fd_out[1], IO_WRITE, checkpassword_child_output,
		       chkpw_auth_request);

	hash_table_insert(module->clients, POINTER_CAST(pid),
			  chkpw_auth_request);

	if (checkpassword_userdb_children != NULL)
		child_wait_add_pid(checkpassword_userdb_children, pid);
	else {
		checkpassword_userdb_children =
			child_wait_new_with_pid(pid, sigchld_handler, module);
	}
}

static struct userdb_module *
checkpassword_preinit(pool_t pool, const char *args)
{
	struct checkpassword_userdb_module *module;

	module = p_new(pool, struct checkpassword_userdb_module, 1);
	module->checkpassword_path = p_strdup(pool, args);
	module->checkpassword_reply_path =
		PKG_LIBEXECDIR"/checkpassword-reply";

	module->clients =
		hash_table_create(default_pool, default_pool, 0, NULL, NULL);

	return &module->module;
}

static void checkpassword_deinit(struct userdb_module *_module)
{
	struct checkpassword_userdb_module *module =
		(struct checkpassword_userdb_module *)_module;
	struct hash_iterate_context *iter;
	void *key, *value;

	iter = hash_table_iterate_init(module->clients);
	while (hash_table_iterate(iter, &key, &value)) {
		checkpassword_request_finish(value,
					     USERDB_RESULT_INTERNAL_FAILURE);
	}
	hash_table_iterate_deinit(&iter);
	hash_table_destroy(&module->clients);

	if (checkpassword_userdb_children != NULL)
		child_wait_free(&checkpassword_userdb_children);
}

struct userdb_module_interface userdb_checkpassword = {
	"checkpassword",

	checkpassword_preinit,
	NULL,
	checkpassword_deinit,

	checkpassword_lookup,

	NULL,
	NULL,
	NULL
};
#else
struct userdb_module_interface userdb_checkpassword = {
	.name = "checkpassword"
};
#endif
