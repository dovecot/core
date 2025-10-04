/*
 * NTLM and Negotiate authentication mechanisms,
 * using Samba winbind daemon
 *
 * Copyright (c) 2007 Dmitry Butskoy <dmitry@butskoy.name>
 *
 * This software is released under the MIT license.
 */

#include "lib.h"
#include "lib-signals.h"
#include "str.h"
#include "buffer.h"
#include "array.h"
#include "base64.h"
#include "execv-const.h"
#include "istream.h"
#include "ostream.h"

#include "sasl-server-protected.h"

#include <unistd.h>
#include <sys/wait.h>

#define MAX_LINE_LENGTH 16384
#define KILL_TIMEOUT 5000

enum helper_result {
	HR_OK	= 0,	/* OK or continue */
	HR_FAIL	= -1,	/* authentication failed */
	HR_RESTART = -2	/* FAIL + try to restart helper */
};

struct winbind_helper {
	const char *path;
	const char *param;

	struct event *event;
	pid_t pid;

	struct istream *in_pipe;
	struct ostream *out_pipe;
	struct timeout *to_kill;

	bool sent_term:1;
};

struct winbind_auth_request {
	struct sasl_server_mech_request auth_request;

	bool continued;
};

struct winbind_auth_mech_data {
	struct sasl_server_mech_data data;

	ARRAY(struct winbind_helper *) helpers;
};

struct winbind_auth_mech {
	struct sasl_server_mech mech;

	struct winbind_helper *helper;
};

static const struct sasl_server_mech_def mech_ntlm;
static const struct sasl_server_mech_def mech_gss_spnego;

static struct winbind_helper *
winbind_helper_create(struct winbind_auth_mech_data *wb_mdata,
		      const char *path, const char *param,
		      struct event *event_parent)
{
	struct winbind_helper *helper;
	pool_t pool = wb_mdata->data.pool;

	array_foreach_elem(&wb_mdata->helpers, helper) {
		if (strcmp(helper->path, path) == 0 &&
		    strcmp(helper->param, param) == 0)
			return helper;
	}

	helper = p_new(pool, struct winbind_helper, 1);
	helper->path = p_strdup(pool, path);
	helper->param = p_strdup(pool, param);
	helper->pid = -1;

	helper->event = event_create(event_parent);
	event_set_append_log_prefix(helper->event, "helper: ");

	array_append(&wb_mdata->helpers, &helper, 1);

	return helper;
}

static void winbind_helper_terminated(struct winbind_helper *helper)
{
	e_debug(helper->event, "Terminated");
	helper->pid = -1;
	helper->sent_term = FALSE;
	timeout_remove(&helper->to_kill);
}

static void winbind_helper_kill_now(struct winbind_helper *helper)
{
	timeout_remove(&helper->to_kill);

	if (helper->pid < 0)
		return;

	e_debug(helper->event, "Sending SIGKILL signal to helper");

	/* kill it brutally now: it should die right away */
	if (kill(helper->pid, SIGKILL) < 0) {
		e_error(helper->event,
			"Failed to send SIGKILL signal to helper");
	} else if (waitpid(helper->pid, NULL, 0) < 0) {
		e_error(helper->event,
			"waitpid(%d) failed: %m", helper->pid);
	}
	winbind_helper_terminated(helper);
}

static void winbind_helper_kill(struct winbind_helper *helper)
{
	timeout_remove(&helper->to_kill);

	if (helper->pid < 0)
		return;

	if (helper->sent_term) {
		/* Timed out again */
		e_debug(helper->event,
			"Did not terminate after %d milliseconds",
			KILL_TIMEOUT);
		winbind_helper_kill_now(helper);
		return;
	}

	e_debug(helper->event, "Still running after %u milliseconds: "
		"Sending TERM signal to helper", KILL_TIMEOUT / 2);

	/* kill helper gently first */
	if (kill(helper->pid, SIGTERM) < 0) {
		e_error(helper->event,
			"Failed to send SIGTERM signal to helper");
		(void)kill(helper->pid, SIGKILL);
		winbind_helper_terminated(helper);
		return;
	}
	helper->sent_term = TRUE;

	helper->to_kill = timeout_add_short(KILL_TIMEOUT / 2,
					    winbind_helper_kill, helper);
}

static void winbind_helper_disconnect(struct winbind_helper *helper)
{
	i_stream_destroy(&helper->in_pipe);
	o_stream_destroy(&helper->out_pipe);
}

static void winbind_helper_restart(struct winbind_helper *helper)
{
	winbind_helper_disconnect(helper);

	helper->to_kill = timeout_add_short(KILL_TIMEOUT / 2,
					    winbind_helper_kill, helper);
}

static void winbind_helper_destroy(struct winbind_helper *helper)
{
	winbind_helper_disconnect(helper);
	winbind_helper_kill_now(helper);
	event_unref(&helper->event);
}

static void winbind_wait_pid(struct winbind_helper *helper)
{
	int status, ret;

	if (helper->pid == -1)
		return;

	/* FIXME: use child-wait.h API */
	if ((ret = waitpid(helper->pid, &status, WNOHANG)) <= 0) {
		if (ret < 0 && errno != ECHILD && errno != EINTR)
			e_error(helper->event, "waitpid() failed: %m");
		return;
	}

	if (WIFSIGNALED(status)) {
		e_error(helper->event, "Died with signal %d",
			WTERMSIG(status));
	} else if (WIFEXITED(status)) {
		e_error(helper->event, "Exited with exit code %d",
			WEXITSTATUS(status));
	} else {
		/* shouldn't happen */
		e_error(helper->event, "Exited with status %d", status);
	}
	winbind_helper_terminated(helper);
}

static void
sigchld_handler(const siginfo_t *si ATTR_UNUSED, void *context)
{
	struct winbind_helper *helper = context;

	winbind_wait_pid(helper);
}

static void winbind_helper_connect(struct winbind_helper *helper)
{
	int infd[2], outfd[2];
	pid_t pid;

	if (helper->in_pipe != NULL || helper->pid != -1)
		return;

	if (pipe(infd) < 0) {
		e_error(helper->event, "pipe() failed: %m");
		return;
	}
	if (pipe(outfd) < 0) {
		i_close_fd(&infd[0]); i_close_fd(&infd[1]);
		return;
	}

	pid = fork();
	if (pid < 0) {
		e_error(helper->event, "fork() failed: %m");
		i_close_fd(&infd[0]); i_close_fd(&infd[1]);
		i_close_fd(&outfd[0]); i_close_fd(&outfd[1]);
		return;
	}

	if (pid == 0) {
		/* child */
		const char *args[3];

		i_close_fd(&infd[0]);
		i_close_fd(&outfd[1]);

		if (dup2(outfd[0], STDIN_FILENO) < 0 ||
		    dup2(infd[1], STDOUT_FILENO) < 0)
			i_fatal("dup2() failed: %m");

		args[0] = helper->path;
		args[1] = helper->param;
		args[2] = NULL;
		execv_const(args[0], args);
	}

	/* parent */
	i_close_fd(&infd[1]);
	i_close_fd(&outfd[0]);

	e_debug(helper->event, "Connected");

	helper->pid = pid;
	helper->in_pipe =
		i_stream_create_fd_autoclose(&infd[0], MAX_LINE_LENGTH);
	helper->out_pipe =
		o_stream_create_fd_autoclose(&outfd[1], SIZE_MAX);

	lib_signals_set_handler(SIGCHLD, LIBSIG_FLAGS_SAFE,
				sigchld_handler, helper);
}

static enum helper_result
do_auth_continue(struct winbind_auth_request *request,
		 const unsigned char *data, size_t data_size)
{
	struct sasl_server_mech_request *auth_request = &request->auth_request;
	const struct winbind_auth_mech *wb_mech =
		container_of(auth_request->mech,
			     const struct winbind_auth_mech, mech);
	struct istream *in_pipe = wb_mech->helper->in_pipe;
	string_t *str;
	char *answer;
	const char **token;
	bool gss_spnego = (auth_request->mech->def == &mech_gss_spnego);

	if (wb_mech->helper->in_pipe == NULL)
		return HR_RESTART;

	str = t_str_new(MAX_BASE64_ENCODED_SIZE(data_size + 1) + 4);
	str_printfa(str, "%s ", request->continued ? "KK" : "YR");
	base64_encode(data, data_size, str);
	str_append_c(str, '\n');

	if (o_stream_send(wb_mech->helper->out_pipe,
			  str_data(str), str_len(str)) < 0 ||
	    o_stream_flush(wb_mech->helper->out_pipe) < 0) {
		e_error(auth_request->event,
			"write(out_pipe) failed: %s",
			o_stream_get_error(wb_mech->helper->out_pipe));
		return HR_RESTART;
	}
	request->continued = FALSE;

	while ((answer = i_stream_read_next_line(in_pipe)) == NULL) {
		if (in_pipe->stream_errno != 0 || in_pipe->eof)
			break;
	}
	if (answer == NULL) {
		if (in_pipe->stream_errno != 0) {
			e_error(auth_request->event,
				"read(in_pipe) failed: %m");
		} else {
			e_error(auth_request->event,
				"read(in_pipe) failed: "
				"unexpected end of file");
		}
		return HR_RESTART;
	}

	token = t_strsplit_spaces(answer, " ");
	if (token[0] == NULL ||
	    (token[1] == NULL && strcmp(token[0], "BH") != 0) ||
	    (gss_spnego && (token[1] == NULL || token[2] == NULL))) {
		e_error(auth_request->event, "Invalid input from helper: %s",
			answer);
		return HR_RESTART;
	}

	/*
	 *  NTLM:
	 *  The child's reply contains 2 parts:
	 *   - The code: TT, AF or NA
	 *   - The argument:
	 *        For TT it's the blob to send to the client, coded in base64
	 *        For AF it's user or DOMAIN\user
	 *        For NA it's the NT error code
	 *
	 *  GSS-SPNEGO:
	 *  The child's reply contains 3 parts:
	 *   - The code: TT, AF or NA
	 *   - The blob to send to the client, coded in base64
	 *   - The argument:
	 *        For TT it's a dummy '*'
	 *        For AF it's DOMAIN\user
	 *        For NA it's the NT error code
	 */

	if (strcmp(token[0], "TT") == 0) {
		buffer_t *buf;

		i_assert(token[1] != NULL);
		buf = t_base64_decode_str(token[1]);
		sasl_server_request_output(auth_request, buf->data, buf->used);
		request->continued = TRUE;
		return HR_OK;
	} else if (strcmp(token[0], "NA") == 0) {
		const char *error =
			t_strarray_join(gss_spnego ? token+2 : token+1, " ");

		e_info(auth_request->event, "user not authenticated: %s",
		       error);
		return HR_FAIL;
	} else if (strcmp(token[0], "AF") == 0) {
		const char *user, *p;

		user = t_strarray_join(gss_spnego ? token+2 : token+1, " ");
		i_assert(user != NULL);

		p = strchr(user, '\\');
		if (p != NULL) {
			/* change "DOMAIN\user" to uniform style
			   "user@DOMAIN" */
			user = t_strconcat(p+1, "@",
					   t_strdup_until(user, p), NULL);
		}

		if (!sasl_server_request_set_authid(
				auth_request, SASL_SERVER_AUTHID_TYPE_USERNAME,
				user))
			return HR_FAIL;

		if (gss_spnego && strcmp(token[1], "*") != 0) {
			buffer_t *buf;

			buf = t_base64_decode_str(token[1]);
			sasl_server_request_success(&request->auth_request,
						    buf->data, buf->used);
		} else {
			sasl_server_request_success(&request->auth_request,
						    "", 0);
		}
		return HR_OK;
	} else if (strcmp(token[0], "BH") == 0) {
		e_info(auth_request->event,
		       "ntlm_auth reports broken helper: %s",
		       token[1] != NULL ? token[1] : "");
		return HR_RESTART;
	} else {
		e_error(auth_request->event,
			"Invalid input from helper: %s", answer);
		return HR_RESTART;
	}
}

static void
mech_winbind_auth_initial(struct sasl_server_mech_request *auth_request,
			  const unsigned char *data, size_t data_size)
{
	const struct winbind_auth_mech *wb_mech =
		container_of(auth_request->mech,
			     const struct winbind_auth_mech, mech);

	winbind_helper_connect(wb_mech->helper);
	sasl_server_mech_generic_auth_initial(auth_request, data, data_size);
}

static void
mech_winbind_auth_continue(struct sasl_server_mech_request *auth_request,
			   const unsigned char *data, size_t data_size)
{
	const struct winbind_auth_mech *wb_mech =
		container_of(auth_request->mech,
			     const struct winbind_auth_mech, mech);
	struct winbind_auth_request *request =
		container_of(auth_request,
			     struct winbind_auth_request, auth_request);
	enum helper_result res;

	res = do_auth_continue(request, data, data_size);
	if (res != HR_OK) {
		if (res == HR_RESTART)
			winbind_helper_restart(wb_mech->helper);
		sasl_server_request_failure(auth_request);
	}
}

static struct sasl_server_mech_request *
mech_winbind_auth_new(const struct sasl_server_mech *mech ATTR_UNUSED,
		      pool_t pool)
{
	struct winbind_auth_request *request;

	request = p_new(pool, struct winbind_auth_request, 1);

	return &request->auth_request;
}

static struct sasl_server_mech_data *mech_winbind_data_new(pool_t pool)
{
	struct winbind_auth_mech_data *wb_mdata;

	wb_mdata = p_new(pool, struct winbind_auth_mech_data, 1);
	p_array_init(&wb_mdata->helpers, pool, 4);

	return &wb_mdata->data;
}

static void mech_winbind_data_free(struct sasl_server_mech_data *mdata)
{
	struct winbind_auth_mech_data *wb_mdata =
		container_of(mdata, struct winbind_auth_mech_data, data);
	struct winbind_helper *helper;

	array_foreach_elem(&wb_mdata->helpers, helper)
		winbind_helper_destroy(helper);
	array_clear(&wb_mdata->helpers);
}

static struct sasl_server_mech *mech_winbind_mech_new(pool_t pool)
{
	struct winbind_auth_mech *wb_mech;

	wb_mech = p_new(pool, struct winbind_auth_mech, 1);

	return &wb_mech->mech;
}

static const struct sasl_server_mech_funcs mech_winbind_funcs = {
	.auth_new = mech_winbind_auth_new,
	.auth_initial = mech_winbind_auth_initial,
	.auth_continue = mech_winbind_auth_continue,

	.data_new = mech_winbind_data_new,
	.data_free = mech_winbind_data_free,

	.mech_new = mech_winbind_mech_new,
};

static const struct sasl_server_mech_def mech_ntlm = {
	.name = SASL_MECH_NAME_NTLM,

	.flags = SASL_MECH_SEC_DICTIONARY | SASL_MECH_SEC_ACTIVE |
		 SASL_MECH_SEC_ALLOW_NULS,
	.passdb_need = SASL_MECH_PASSDB_NEED_NOTHING,

	.funcs = &mech_winbind_funcs,
};

static const struct sasl_server_mech_def mech_gss_spnego = {
	.name = SASL_MECH_NAME_GSS_SPNEGO,

	.flags = SASL_MECH_SEC_ALLOW_NULS,
	.passdb_need = SASL_MECH_PASSDB_NEED_NOTHING,

	.funcs = &mech_winbind_funcs,
};

static void
sasl_server_mech_register_winbind(
	struct sasl_server_instance *sinst,
	const struct sasl_server_mech_def *mech_def, const char *helper_param,
	const struct sasl_server_winbind_settings *set)
{
	struct sasl_server_mech *mech;

	i_assert(set->helper_path != NULL);

	mech = sasl_server_mech_register(sinst, mech_def, NULL);

	struct winbind_auth_mech *wb_mech =
		container_of(mech, struct winbind_auth_mech, mech);
	struct winbind_auth_mech_data *wb_mdata =
		container_of(mech->data, struct winbind_auth_mech_data, data);

	wb_mech->helper = winbind_helper_create(wb_mdata, set->helper_path,
						helper_param, mech->event);
}

void sasl_server_mech_register_winbind_ntlm(
	struct sasl_server_instance *sinst,
	const struct sasl_server_winbind_settings *set)
{
	sasl_server_mech_register_winbind(sinst, &mech_ntlm,
					  "--helper-protocol=squid-2.5-ntlmssp",
					  set);
}

void sasl_server_mech_register_winbind_gss_spnego(
	struct sasl_server_instance *sinst,
	const struct sasl_server_winbind_settings *set)
{
	sasl_server_mech_register_winbind(sinst, &mech_gss_spnego,
					  "--helper-protocol=gss-spnego", set);
}
