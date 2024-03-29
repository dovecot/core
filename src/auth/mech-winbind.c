/*
 * NTLM and Negotiate authentication mechanisms,
 * using Samba winbind daemon
 *
 * Copyright (c) 2007 Dmitry Butskoy <dmitry@butskoy.name>
 *
 * This software is released under the MIT license.
 */

#include "auth-common.h"
#include "lib-signals.h"
#include "mech.h"
#include "str.h"
#include "buffer.h"
#include "base64.h"
#include "execv-const.h"
#include "istream.h"
#include "ostream.h"

#include <unistd.h>
#include <sys/wait.h>

enum helper_result {
	HR_OK	= 0,	/* OK or continue */
	HR_FAIL	= -1,	/* authentication failed */
	HR_RESTART = -2	/* FAIL + try to restart helper */
};

struct winbind_helper {
	const char *param;
	pid_t pid;

	struct istream *in_pipe;
	struct ostream *out_pipe;
};

struct winbind_auth_request {
	struct auth_request auth_request;

	struct winbind_helper *winbind;
	bool continued;
};

static struct winbind_helper winbind_ntlm_context = {
	"--helper-protocol=squid-2.5-ntlmssp", -1, NULL, NULL
};
static struct winbind_helper winbind_spnego_context = {
	"--helper-protocol=gss-spnego", -1, NULL, NULL
};

static bool sigchld_handler_set = FALSE;

static void winbind_helper_disconnect(struct winbind_helper *winbind)
{
	i_stream_destroy(&winbind->in_pipe);
	o_stream_destroy(&winbind->out_pipe);
}

static void winbind_wait_pid(struct winbind_helper *winbind)
{
	int status, ret;

	if (winbind->pid == -1)
		return;

	/* FIXME: use child-wait.h API */
	if ((ret = waitpid(winbind->pid, &status, WNOHANG)) <= 0) {
		if (ret < 0 && errno != ECHILD && errno != EINTR)
			i_error("waitpid() failed: %m");
		return;
	}

	if (WIFSIGNALED(status)) {
		i_error("winbind: ntlm_auth died with signal %d",
			WTERMSIG(status));
	} else if (WIFEXITED(status)) {
		i_error("winbind: ntlm_auth exited with exit code %d",
			WEXITSTATUS(status));
	} else {
		/* shouldn't happen */
		i_error("winbind: ntlm_auth exited with status %d",
			status);
	}
	winbind->pid = -1;
}

static void sigchld_handler(const siginfo_t *si ATTR_UNUSED,
			    void *context ATTR_UNUSED)
{
	winbind_wait_pid(&winbind_ntlm_context);
	winbind_wait_pid(&winbind_spnego_context);
}

static void
winbind_helper_connect(const struct auth_settings *set,
		       struct winbind_helper *winbind,
		       struct event *event)
{
	int infd[2], outfd[2];
	pid_t pid;

	if (winbind->in_pipe != NULL || winbind->pid != -1)
		return;

	if (pipe(infd) < 0) {
		e_error(event, "pipe() failed: %m");
		return;
	}
	if (pipe(outfd) < 0) {
		i_close_fd(&infd[0]); i_close_fd(&infd[1]);
		return;
	}

	pid = fork();
	if (pid < 0) {
		e_error(event, "fork() failed: %m");
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

		args[0] = set->winbind_helper_path;
		args[1] = winbind->param;
		args[2] = NULL;
		execv_const(args[0], args);
	}

	/* parent */
	i_close_fd(&infd[1]);
	i_close_fd(&outfd[0]);

	winbind->pid = pid;
	winbind->in_pipe =
		i_stream_create_fd_autoclose(&infd[0], AUTH_CLIENT_MAX_LINE_LENGTH);
	winbind->out_pipe =
		o_stream_create_fd_autoclose(&outfd[1], SIZE_MAX);

	if (!sigchld_handler_set) {
		sigchld_handler_set = TRUE;
		lib_signals_set_handler(SIGCHLD, LIBSIG_FLAGS_SAFE,
					sigchld_handler, NULL);
	}
}

static enum helper_result
do_auth_continue(struct auth_request *auth_request,
		 const unsigned char *data, size_t data_size)
{
	struct winbind_auth_request *request =
		(struct winbind_auth_request *)auth_request;
	struct istream *in_pipe = request->winbind->in_pipe;
	string_t *str;
	char *answer;
	const char **token;
	bool gss_spnego = request->winbind == &winbind_spnego_context;

	if (request->winbind->in_pipe == NULL)
		return HR_RESTART;

	str = t_str_new(MAX_BASE64_ENCODED_SIZE(data_size + 1) + 4);
	str_printfa(str, "%s ", request->continued ? "KK" : "YR");
	base64_encode(data, data_size, str);
	str_append_c(str, '\n');

	if (o_stream_send(request->winbind->out_pipe,
			  str_data(str), str_len(str)) < 0 ||
	    o_stream_flush(request->winbind->out_pipe) < 0) {
		e_error(auth_request->mech_event,
			"write(out_pipe) failed: %s",
			o_stream_get_error(request->winbind->out_pipe));
		return HR_RESTART;
	}
	request->continued = FALSE;

	while ((answer = i_stream_read_next_line(in_pipe)) == NULL) {
		if (in_pipe->stream_errno != 0 || in_pipe->eof)
			break;
	}
	if (answer == NULL) {
		if (in_pipe->stream_errno != 0) {
			e_error(auth_request->mech_event,
				"read(in_pipe) failed: %m");
		} else {
			e_error(auth_request->mech_event,
				"read(in_pipe) failed: "
				"unexpected end of file");
		}
		return HR_RESTART;
	}

	token = t_strsplit_spaces(answer, " ");
	if (token[0] == NULL ||
	    (token[1] == NULL && strcmp(token[0], "BH") != 0) ||
	    (gss_spnego && (token[1] == NULL || token[2] == NULL))) {
		e_error(auth_request->mech_event,
			"Invalid input from helper: %s", answer);
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
		auth_request_handler_reply_continue(auth_request, buf->data,
						    buf->used);
		request->continued = TRUE;
		return HR_OK;
	} else if (strcmp(token[0], "NA") == 0) {
		const char *error = gss_spnego ? token[2] : token[1];

		e_info(auth_request->mech_event,
		       "user not authenticated: %s", error);
		return HR_FAIL;
	} else if (strcmp(token[0], "AF") == 0) {
		const char *user, *p, *error;

		user = t_strarray_join(gss_spnego ? token+2 : token+1, " ");
		i_assert(user != NULL);

		p = strchr(user, '\\');
		if (p != NULL) {
			/* change "DOMAIN\user" to uniform style
			   "user@DOMAIN" */
			user = t_strconcat(p+1, "@",
					   t_strdup_until(user, p), NULL);
		}

		if (!auth_request_set_username(auth_request, user, &error)) {
			e_info(auth_request->mech_event,
			       "%s", error);
			return HR_FAIL;
		}

		request->auth_request.passdb_success = TRUE;
		if (gss_spnego && strcmp(token[1], "*") != 0) {
			buffer_t *buf;

			buf = t_base64_decode_str(token[1]);
			auth_request_success(&request->auth_request,
					     buf->data, buf->used);
		} else {
			auth_request_success(&request->auth_request, "", 0);
		}
		return HR_OK;
	} else if (strcmp(token[0], "BH") == 0) {
		e_info(auth_request->mech_event,
		       "ntlm_auth reports broken helper: %s",
		       token[1] != NULL ? token[1] : "");
		return HR_RESTART;
	} else {
		e_error(auth_request->mech_event,
			"Invalid input from helper: %s", answer);
		return HR_RESTART;
	}
}

static void
mech_winbind_auth_initial(struct auth_request *auth_request,
			  const unsigned char *data, size_t data_size)
{
	struct winbind_auth_request *request =
		(struct winbind_auth_request *)auth_request;

	winbind_helper_connect(auth_request->set, request->winbind,
			       auth_request->event);
	mech_generic_auth_initial(auth_request, data, data_size);
}

static void
mech_winbind_auth_continue(struct auth_request *auth_request,
			   const unsigned char *data, size_t data_size)
{
	struct winbind_auth_request *request =
		(struct winbind_auth_request *)auth_request;
	enum helper_result res;

	res = do_auth_continue(auth_request, data, data_size);
	if (res != HR_OK) {
		if (res == HR_RESTART)
			winbind_helper_disconnect(request->winbind);
		auth_request_fail(auth_request);
	}
}

static struct auth_request *do_auth_new(struct winbind_helper *winbind)
{
	struct winbind_auth_request *request;
	pool_t pool;

	pool = pool_alloconly_create(MEMPOOL_GROWING"winbind_auth_request", 2048);
	request = p_new(pool, struct winbind_auth_request, 1);
	request->auth_request.pool = pool;

	request->winbind = winbind;
	return &request->auth_request;
}

static struct auth_request *mech_winbind_ntlm_auth_new(void)
{
	return do_auth_new(&winbind_ntlm_context);
}

static struct auth_request *mech_winbind_spnego_auth_new(void)
{
	return do_auth_new(&winbind_spnego_context);
}

const struct mech_module mech_winbind_ntlm = {
	"NTLM",

	.flags = MECH_SEC_DICTIONARY | MECH_SEC_ACTIVE |
		 MECH_SEC_ALLOW_NULS,
	.passdb_need = MECH_PASSDB_NEED_NOTHING,

	mech_winbind_ntlm_auth_new,
	mech_winbind_auth_initial,
	mech_winbind_auth_continue,
	mech_generic_auth_free
};

const struct mech_module mech_winbind_spnego = {
	"GSS-SPNEGO",

	.flags = 0,
	.passdb_need = MECH_PASSDB_NEED_NOTHING,

	mech_winbind_spnego_auth_new,
	mech_winbind_auth_initial,
	mech_winbind_auth_continue,
	mech_generic_auth_free
};
