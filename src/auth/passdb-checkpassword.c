/* Copyright (c) 2004-2011 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "execv-const.h"
#include "passdb.h"

#ifdef PASSDB_CHECKPASSWORD 

#include "db-checkpassword.h"

struct checkpassword_passdb_module {
	struct passdb_module module;

	const char *checkpassword_path, *checkpassword_reply_path;
	struct hash_table *clients;
};

static struct child_wait *checkpassword_passdb_children = NULL;

static void checkpassword_request_finish(struct chkpw_auth_request *request,
					 enum passdb_result result)
{
	struct passdb_module *_module = request->request->passdb->passdb;
	struct checkpassword_passdb_module *module =
		(struct checkpassword_passdb_module *)_module;
	verify_plain_callback_t *callback =
		(verify_plain_callback_t *)request->callback;

	hash_table_remove(module->clients, POINTER_CAST(request->pid));

	if (result == PASSDB_RESULT_OK) {
		if (strchr(str_c(request->input_buf), '\n') != NULL) {
			auth_request_log_error(request->request,
				"checkpassword",
				"LF characters in checkpassword reply");
			result = PASSDB_RESULT_INTERNAL_FAILURE;
		} else {
			auth_request_log_debug(request->request,
					       "checkpassword", "input: %s",
					       str_c(request->input_buf));
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
		auth_request_log_error(request->request, "checkpassword",
			"Child %s exited with status 2 (tried to use "
			"userdb-only checkpassword program for passdb?)",
			dec2str(request->pid));
		checkpassword_request_finish(request,
					     PASSDB_RESULT_INTERNAL_FAILURE);
		break;
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

static void sigchld_handler(const struct child_wait_status *status,
			    struct checkpassword_passdb_module *module)
{
	struct chkpw_auth_request *request = 
		hash_table_lookup(module->clients, POINTER_CAST(status->pid));

	switch (checkpassword_sigchld_handler(status, request)) {
	case SIGCHLD_RESULT_UNKNOWN_CHILD:
	case SIGCHLD_RESULT_DEAD_CHILD:
		break;
	case SIGCHLD_RESULT_UNKNOWN_ERROR:
		checkpassword_request_finish(request,
					     PASSDB_RESULT_INTERNAL_FAILURE);
		break;
	case SIGCHLD_RESULT_OK:
		checkpassword_request_half_finish(request);
		request = NULL;
		break;
	}
}

static void ATTR_NORETURN
checkpassword_verify_plain_child(struct auth_request *request,
				 struct checkpassword_passdb_module *module,
				 int fd_in, int fd_out)
{
	const char *cmd, *const *args;

	if (dup2(fd_out, 3) < 0 || dup2(fd_in, 4) < 0) {
		auth_request_log_error(request, "checkpassword",
				       "dup2() failed: %m");
	} else {
		checkpassword_setup_env(request);
		cmd = checkpassword_get_cmd(request, module->checkpassword_path,
					    module->checkpassword_reply_path);
		auth_request_log_debug(request, "checkpassword",
				       "execute: %s", cmd);

		/* very simple argument splitting. */
		args = t_strsplit(cmd, " ");
		execv_const(args[0], args);
	}
	exit(2);
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
	chkpw_auth_request->half_finish_callback =
		checkpassword_request_half_finish;
	chkpw_auth_request->finish_callback =
		checkpassword_request_finish;
	chkpw_auth_request->internal_failure_code =
		PASSDB_RESULT_INTERNAL_FAILURE;

	chkpw_auth_request->io_in =
		io_add(fd_in[0], IO_READ, checkpassword_child_input,
		       chkpw_auth_request);
	chkpw_auth_request->io_out =
		io_add(fd_out[1], IO_WRITE, checkpassword_child_output,
		       chkpw_auth_request);

	hash_table_insert(module->clients, POINTER_CAST(pid),
			  chkpw_auth_request);

	if (checkpassword_passdb_children != NULL)
		child_wait_add_pid(checkpassword_passdb_children, pid);
	else {
		checkpassword_passdb_children =
			child_wait_new_with_pid(pid, sigchld_handler, module);
	}
}

static struct passdb_module *
checkpassword_preinit(pool_t pool, const char *args)
{
	struct checkpassword_passdb_module *module;

	module = p_new(pool, struct checkpassword_passdb_module, 1);
	module->checkpassword_path = p_strdup(pool, args);
	module->checkpassword_reply_path =
		PKG_LIBEXECDIR"/checkpassword-reply";

	module->clients =
		hash_table_create(default_pool, default_pool, 0, NULL, NULL);

	return &module->module;
}

static void checkpassword_deinit(struct passdb_module *_module)
{
	struct checkpassword_passdb_module *module =
		(struct checkpassword_passdb_module *)_module;
	struct hash_iterate_context *iter;
	void *key, *value;

	iter = hash_table_iterate_init(module->clients);
	while (hash_table_iterate(iter, &key, &value)) {
		checkpassword_request_finish(value,
					     PASSDB_RESULT_INTERNAL_FAILURE);
	}
	hash_table_iterate_deinit(&iter);
	hash_table_destroy(&module->clients);

	if (checkpassword_passdb_children != NULL)
		child_wait_free(&checkpassword_passdb_children);
}

struct passdb_module_interface passdb_checkpassword = {
	"checkpassword",

	checkpassword_preinit,
	NULL,
	checkpassword_deinit,

	checkpassword_verify_plain,
	NULL,
	NULL
};
#else
struct passdb_module_interface passdb_checkpassword = {
	.name = "checkpassword"
};
#endif
