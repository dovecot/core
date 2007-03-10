/*
   Based on auth_pam.c from popa3d by Solar Designer <solar@openwall.com>.

   You're allowed to do whatever you like with this software (including
   re-distribution in source and/or binary form, with or without
   modification), provided that credit is given where it is due and any
   modified versions are marked as such.  There's absolutely no warranty.
*/

#include "common.h"

#ifdef PASSDB_PAM

#include "lib-signals.h"
#include "buffer.h"
#include "ioloop.h"
#include "hash.h"
#include "str.h"
#include "var-expand.h"
#include "network.h"
#include "passdb.h"
#include "mycrypt.h"
#include "safe-memset.h"

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>

#define PAM_CHILD_TIMEOUT (60*2)
#define PAM_CHILD_CHECK_TIMEOUT (10*1000)

#ifdef HAVE_SECURITY_PAM_APPL_H
#  include <security/pam_appl.h>
#elif defined(HAVE_PAM_PAM_APPL_H)
#  include <pam/pam_appl.h>
#endif

#if !defined(_SECURITY_PAM_APPL_H) && !defined(LINUX_PAM) && !defined(_OPENPAM)
/* Sun's PAM doesn't use const. we use a bit dirty hack to check it.
   Originally it was just __sun__ check, but HP/UX also uses Sun's PAM
   so I thought this might work better. */
#  define linux_const
#else
#  define linux_const			const
#endif
typedef linux_const void *pam_item_t;

#ifdef AUTH_PAM_USERPASS
#  include <security/pam_client.h>

#  ifndef PAM_BP_RCONTROL
/* Linux-PAM prior to 0.74 */
#    define PAM_BP_RCONTROL	PAM_BP_CONTROL
#    define PAM_BP_WDATA	PAM_BP_DATA
#    define PAM_BP_RDATA	PAM_BP_DATA
#  endif

#  define USERPASS_AGENT_ID		"userpass"
#  define USERPASS_AGENT_ID_LENGTH	8

#  define USERPASS_USER_MASK		0x03
#  define USERPASS_USER_REQUIRED	1
#  define USERPASS_USER_KNOWN		2
#  define USERPASS_USER_FIXED		3
#endif

struct pam_passdb_module {
	struct passdb_module module;

	bool pam_setcred, pam_session;
	const char *service_name, *pam_cache_key;
};

struct pam_auth_request {
	int refcount;
	int fd;
	struct io *io;

	time_t start_time;
	pid_t pid;

	struct auth_request *request;
        verify_plain_callback_t *callback;
};

struct pam_userpass {
	const char *user;
	const char *pass;
};

static struct hash_table *pam_requests;
static struct timeout *to;

static int pam_userpass_conv(int num_msg, linux_const struct pam_message **msg,
	struct pam_response **resp, void *appdata_ptr)
{
	/* @UNSAFE */
	struct pam_userpass *userpass = (struct pam_userpass *) appdata_ptr;
#ifdef AUTH_PAM_USERPASS
	pamc_bp_t prompt;
	const char *input;
	char *output;
	char flags;
	size_t userlen, passlen;

	if (num_msg != 1 || msg[0]->msg_style != PAM_BINARY_PROMPT)
		return PAM_CONV_ERR;

	prompt = (pamc_bp_t)msg[0]->msg;
	input = PAM_BP_RDATA(prompt);

	if (PAM_BP_RCONTROL(prompt) != PAM_BPC_SELECT ||
	    strncmp(input, USERPASS_AGENT_ID "/", USERPASS_AGENT_ID_LENGTH + 1))
		return PAM_CONV_ERR;

	flags = input[USERPASS_AGENT_ID_LENGTH + 1];
	input += USERPASS_AGENT_ID_LENGTH + 1 + 1;

	if ((flags & USERPASS_USER_MASK) == USERPASS_USER_FIXED &&
	    strcmp(input, userpass->user))
		return PAM_CONV_AGAIN;

	if (!(*resp = malloc(sizeof(struct pam_response))))
		return PAM_CONV_ERR;

	userlen = strlen(userpass->user);
	passlen = strlen(userpass->pass);

	prompt = NULL;
	PAM_BP_RENEW(&prompt, PAM_BPC_DONE, userlen + 1 + passlen);
	output = PAM_BP_WDATA(prompt);

	memcpy(output, userpass->user, userlen + 1);
	memcpy(output + userlen + 1, userpass->pass, passlen);

	(*resp)[0].resp_retcode = 0;
	(*resp)[0].resp = (char *)prompt;
#else
	char *string;
	int i;

	if (!(*resp = malloc(num_msg * sizeof(struct pam_response))))
		return PAM_CONV_ERR;

	for (i = 0; i < num_msg; i++) {
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_ON:
			string = strdup(userpass->user);
			if (string == NULL)
				i_fatal_status(FATAL_OUTOFMEM, "Out of memory");
			break;
		case PAM_PROMPT_ECHO_OFF:
			string = strdup(userpass->pass);
			if (string == NULL)
				i_fatal_status(FATAL_OUTOFMEM, "Out of memory");
			break;
		case PAM_ERROR_MSG:
		case PAM_TEXT_INFO:
			string = NULL;
			break;
		default:
			while (--i >= 0) {
				if ((*resp)[i].resp == NULL)
					continue;
				safe_memset((*resp)[i].resp, 0,
					    strlen((*resp)[i].resp));
				free((*resp)[i].resp);
				(*resp)[i].resp = NULL;
			}

			free(*resp);
			*resp = NULL;

			return PAM_CONV_ERR;
		}

		(*resp)[i].resp_retcode = PAM_SUCCESS;
		(*resp)[i].resp = string;
	}
#endif

	return PAM_SUCCESS;
}

static int pam_auth(struct auth_request *request,
		    pam_handle_t *pamh, const char **error)
{
        struct passdb_module *_module = request->passdb->passdb;
        struct pam_passdb_module *module = (struct pam_passdb_module *)_module;
	void *item;
	int status;

	*error = NULL;

	if ((status = pam_authenticate(pamh, 0)) != PAM_SUCCESS) {
		*error = t_strdup_printf("pam_authenticate() failed: %s",
					 pam_strerror(pamh, status));
		return status;
	}

#ifdef HAVE_PAM_SETCRED
	if (module->pam_setcred) {
		if ((status = pam_setcred(pamh, PAM_ESTABLISH_CRED)) !=
		    PAM_SUCCESS) {
			*error = t_strdup_printf("pam_setcred() failed: %s",
						 pam_strerror(pamh, status));
			return status;
		}
	}
#endif

	if ((status = pam_acct_mgmt(pamh, 0)) != PAM_SUCCESS) {
		*error = t_strdup_printf("pam_acct_mgmt() failed: %s",
					 pam_strerror(pamh, status));
		return status;
	}

	if (module->pam_session) {
	        if ((status = pam_open_session(pamh, 0)) != PAM_SUCCESS) {
			*error = t_strdup_printf(
					"pam_open_session() failed: %s",
					pam_strerror(pamh, status));
	                return status;
	        }

	        if ((status = pam_close_session(pamh, 0)) != PAM_SUCCESS) {
			*error = t_strdup_printf(
					"pam_close_session() failed: %s",
	                                pam_strerror(pamh, status));
	                return status;
	        }
	}

	/* FIXME: this doesn't actually work since we're in the child
	   process.. */
	status = pam_get_item(pamh, PAM_USER, (linux_const void **)&item);
	if (status != PAM_SUCCESS) {
		*error = t_strdup_printf("pam_get_item() failed: %s",
					 pam_strerror(pamh, status));
		return status;
	}
        auth_request_set_field(request, "user", item, NULL);

	return PAM_SUCCESS;
}

static enum passdb_result 
pam_verify_plain_child(struct auth_request *request, const char *service,
		       const char *password, int fd)
{
	pam_handle_t *pamh;
	struct pam_userpass userpass;
	struct pam_conv conv;
	enum passdb_result result;
	int ret, status, status2;
	const char *str;
	size_t size;
	buffer_t *buf;

	conv.conv = pam_userpass_conv;
	conv.appdata_ptr = &userpass;

	userpass.user = request->user;
	userpass.pass = password;

	status = pam_start(service, request->user, &conv, &pamh);
	if (status != PAM_SUCCESS) {
		result = PASSDB_RESULT_INTERNAL_FAILURE;
		str = t_strdup_printf("pam_start() failed: %s",
				      pam_strerror(pamh, status));
	} else {
		const char *host = net_ip2addr(&request->remote_ip);

		/* Set some PAM items. They shouldn't fail, and we don't really
		   care if they do. */
		if (host != NULL)
			(void)pam_set_item(pamh, PAM_RHOST, host);
		/* TTY is needed by eg. pam_access module */
		(void)pam_set_item(pamh, PAM_TTY, "dovecot");

		status = pam_auth(request, pamh, &str);
		if ((status2 = pam_end(pamh, status)) == PAM_SUCCESS) {
			switch (status) {
			case PAM_SUCCESS:
				result = PASSDB_RESULT_OK;
				break;
			case PAM_USER_UNKNOWN:
				result = PASSDB_RESULT_USER_UNKNOWN;
				break;
			case PAM_NEW_AUTHTOK_REQD:
			case PAM_ACCT_EXPIRED:
				result = PASSDB_RESULT_PASS_EXPIRED;
				break;
			default:
				result = PASSDB_RESULT_PASSWORD_MISMATCH;
				break;
			}
		} else {
			result = PASSDB_RESULT_INTERNAL_FAILURE;
			str = t_strdup_printf("pam_end() failed: %s",
					      pam_strerror(pamh, status2));
		}
	}

	if (worker) {
		/* blocking=yes code path in auth worker */
		return result;
	}

	buf = buffer_create_dynamic(pool_datastack_create(), 512);
	buffer_append(buf, &result, sizeof(result));

	if (str != NULL) 
		buffer_append(buf, str, strlen(str));

	/* Don't send larger writes than what would block. truncated error
	   message isn't that bad.. */
        size = I_MIN(buf->used, PIPE_BUF);
	if ((ret = write(fd, buf->data, size)) != (int)size) {
		if (ret < 0)
			i_error("write() failed: %m");
		else {
			i_error("write() failed: %d != %"PRIuSIZE_T,
				ret, buf->used);
		}
	}
	return result;
}

static void pam_child_input(struct pam_auth_request *request)
{
	struct auth_request *auth_request = request->request;
	enum passdb_result result;
	char buf[PIPE_BUF + 1];
	ssize_t ret;

	/* POSIX guarantees that writing PIPE_BUF bytes or less to pipes is
	   atomic. We rely on that. */
	ret = read(request->fd, buf, sizeof(buf)-1);
	if (ret < 0) {
		auth_request_log_error(auth_request, "pam",
				       "read() from child process failed: %m");
		result = PASSDB_RESULT_INTERNAL_FAILURE;
	} else if (ret == 0) {
		/* it died */
		auth_request_log_error(auth_request, "pam",
				       "Child process died");
		result = PASSDB_RESULT_INTERNAL_FAILURE;
	} else if ((size_t)ret < sizeof(result)) {
		auth_request_log_error(auth_request, "pam",
			"Child process returned only %d bytes", (int)ret);
		result = PASSDB_RESULT_INTERNAL_FAILURE;
	} else {
		memcpy(&result, buf, sizeof(result));

		if ((size_t)ret > sizeof(result)) {
			/* error message included */
			buf[ret] = '\0';

			if (result == PASSDB_RESULT_INTERNAL_FAILURE) {
				auth_request_log_error(auth_request, "pam",
					"%s", buf + sizeof(result));
			} else {
				auth_request_log_info(auth_request, "pam",
					"%s", buf + sizeof(result));
			}
		}
	}

	io_remove(&request->io);
	if (close(request->fd) < 0) {
		auth_request_log_error(auth_request, "pam",
				       "close(child input) failed: %m");
	}

	request->callback(result, auth_request);
	auth_request_unref(&auth_request);

	if (--request->refcount == 0)
		i_free(request);
}

static void sigchld_handler(int signo __attr_unused__,
			    void *context __attr_unused__)
{
	struct pam_auth_request *request;
	int status;
	pid_t pid;

	/* FIXME: if we ever do some other kind of forking, this needs fixing */
	while ((pid = waitpid(-1, &status, WNOHANG)) != 0) {
		if (pid == -1) {
			if (errno != ECHILD && errno != EINTR)
				i_error("waitpid() failed: %m");
			return;
		}

		request = hash_lookup(pam_requests, POINTER_CAST(pid));
		if (request == NULL) {
			i_error("PAM: Unknown child %s exited with status %d",
				dec2str(pid), status);
			continue;
		}

		if (WIFSIGNALED(status)) {
			i_error("PAM: Child %s died with signal %d",
				dec2str(pid), WTERMSIG(status));
		} else if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
			i_error("PAM: Child %s exited unexpectedly with "
				"exit code %d", dec2str(pid),
				WEXITSTATUS(status));
		}

		hash_remove(pam_requests, POINTER_CAST(request->pid));
		if (--request->refcount == 0)
			i_free(request);
	}
}

static void
pam_verify_plain(struct auth_request *request, const char *password,
		 verify_plain_callback_t *callback)
{
        struct passdb_module *_module = request->passdb->passdb;
        struct pam_passdb_module *module = (struct pam_passdb_module *)_module;
        struct pam_auth_request *pam_auth_request;
	enum passdb_result result;
	string_t *expanded_service;
	const char *service;
	int fd[2];
	pid_t pid;

	expanded_service = t_str_new(64);
	var_expand(expanded_service, module->service_name,
		   auth_request_get_var_expand_table(request, NULL));
	service = str_c(expanded_service);

	auth_request_log_debug(request, "pam", "lookup service=%s", service);

	if (worker) {
		/* blocking=yes code path in auth worker */
		result = pam_verify_plain_child(request, service, password, -1);
		callback(result, request);
		return;
	}

	if (pipe(fd) < 0) {
		auth_request_log_error(request, "pam", "pipe() failed: %m");
		callback(PASSDB_RESULT_INTERNAL_FAILURE, request);
		return;
	}

	pid = fork();
	if (pid == -1) {
		auth_request_log_error(request, "pam", "fork() failed: %m");
		callback(PASSDB_RESULT_INTERNAL_FAILURE, request);
		(void)close(fd[0]);
		(void)close(fd[1]);
		return;
	}

	if (pid == 0) {
		(void)close(fd[0]);
		pam_verify_plain_child(request, service, password, fd[1]);
		_exit(0);
	}

	if (close(fd[1]) < 0) {
		auth_request_log_error(request, "pam",
				       "close(fd[1]) failed: %m");
	}

	auth_request_ref(request);
	pam_auth_request = i_new(struct pam_auth_request, 1);
	pam_auth_request->refcount = 2;
	pam_auth_request->fd = fd[0];
	pam_auth_request->request = request;
	pam_auth_request->callback = callback;
	pam_auth_request->pid = pid;
	pam_auth_request->start_time = ioloop_time;

	pam_auth_request->io =
		io_add(fd[0], IO_READ, pam_child_input, pam_auth_request);
	hash_insert(pam_requests, POINTER_CAST(pid), pam_auth_request);
}

static struct passdb_module *
pam_preinit(struct auth_passdb *auth_passdb, const char *args)
{
	struct pam_passdb_module *module;
	const char *const *t_args;
	int i;

	module = p_new(auth_passdb->auth->pool, struct pam_passdb_module, 1);
	module->service_name = "dovecot";

	t_push();
	t_args = t_strsplit(args, " ");
	for(i = 0; t_args[i] != NULL; i++) {
		/* -session for backwards compatibility */
		if (strcmp(t_args[i], "-session") == 0 ||
		    strcmp(t_args[i], "session=yes") == 0)
			module->pam_session = TRUE;
		else if (strcmp(t_args[i], "setcred=yes") == 0)
			module->pam_setcred = TRUE;
		else if (strncmp(t_args[i], "cache_key=", 10) == 0) {
			module->module.cache_key =
				p_strdup(auth_passdb->auth->pool,
					 t_args[i] + 10);
		} else if (strcmp(t_args[i], "blocking=yes") == 0) {
			module->module.blocking = TRUE;
		} else if (strcmp(t_args[i], "*") == 0) {
			/* for backwards compatibility */
			module->service_name = "%s";
		} else if (t_args[i+1] == NULL) {
			if (*t_args[i] != '\0') {
				module->service_name =
					p_strdup(auth_passdb->auth->pool,
						 t_args[i]);
			}
		} else {
			i_fatal("Unexpected PAM parameter: %s", t_args[i]);
		}
	}
	t_pop();

	lib_signals_set_handler(SIGCHLD, TRUE, sigchld_handler, NULL);
	return &module->module;
}

static void pam_child_timeout(void *context __attr_unused__)
{
	struct hash_iterate_context *iter;
	void *key, *value;
	time_t timeout = ioloop_time - PAM_CHILD_TIMEOUT;

	iter = hash_iterate_init(pam_requests);
	while (hash_iterate(iter, &key, &value)) {
		struct pam_auth_request *request = value;

		if (request->start_time > timeout)
			continue;

		auth_request_log_error(request->request, "pam",
			"PAM child process %s timed out, killing it",
			dec2str(request->pid));
		if (kill(request->pid, SIGKILL) < 0) {
			i_error("PAM: kill(%s) failed: %m",
				dec2str(request->pid));
		}
	}
	hash_iterate_deinit(iter);
}

static void pam_init(struct passdb_module *_module __attr_unused__,
		     const char *args __attr_unused__)
{
	if (pam_requests != NULL)
		i_fatal("Can't support more than one PAM passdb");

	/* we're caching the password by using directly the plaintext password
	   given by the auth mechanism */
	_module->default_pass_scheme = "PLAIN";

	if (!_module->blocking) {
		pam_requests = hash_create(default_pool, default_pool, 0,
					   NULL, NULL);
		to = timeout_add(PAM_CHILD_CHECK_TIMEOUT,
				 pam_child_timeout, NULL);

		lib_signals_set_handler(SIGCHLD, TRUE, sigchld_handler, NULL);
	}
}

static void pam_deinit(struct passdb_module *_module __attr_unused__)
{
	if (!_module->blocking) {
		lib_signals_unset_handler(SIGCHLD, sigchld_handler, NULL);
		hash_destroy(pam_requests);
		timeout_remove(&to);
	}
}

struct passdb_module_interface passdb_pam = {
	"pam",

	pam_preinit,
	pam_init,
	pam_deinit,

	pam_verify_plain,
	NULL,
	NULL
};

#endif
