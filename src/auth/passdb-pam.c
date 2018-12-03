/*
   Based on auth_pam.c from popa3d by Solar Designer <solar@openwall.com>.

   You're allowed to do whatever you like with this software (including
   re-distribution in source and/or binary form, with or without
   modification), provided that credit is given where it is due and any
   modified versions are marked as such.  There's absolutely no warranty.
*/

#include "auth-common.h"
#include "passdb.h"

#ifdef PASSDB_PAM

#include "lib-signals.h"
#include "str.h"
#include "net.h"
#include "safe-memset.h"
#include "auth-cache.h"

#include <sys/stat.h>

#ifdef HAVE_SECURITY_PAM_APPL_H
#  include <security/pam_appl.h>
#elif defined(HAVE_PAM_PAM_APPL_H)
#  include <pam/pam_appl.h>
#endif

#if defined(sun) || defined(__sun__) || defined(_HPUX_SOURCE)
#  define pam_const
#else
#  define pam_const const
#endif

typedef pam_const void *pam_item_t;

#define PASSDB_PAM_DEFAULT_MAX_REQUESTS 100

struct pam_passdb_module {
	struct passdb_module module;

	const char *service_name, *pam_cache_key;
	unsigned int requests_left;

	bool pam_setcred:1;
	bool pam_session:1;
	bool failure_show_msg:1;
};

struct pam_conv_context {
	struct auth_request *request;
	const char *pass;
	const char *failure_msg;
};

static int
pam_userpass_conv(int num_msg, pam_const struct pam_message **msg,
		  struct pam_response **resp_r, void *appdata_ptr)
{
	/* @UNSAFE */
	struct pam_conv_context *ctx = appdata_ptr;
	struct passdb_module *_passdb = ctx->request->passdb->passdb;
	struct pam_passdb_module *passdb = (struct pam_passdb_module *)_passdb;
	struct pam_response *resp;
	char *string;
	int i;

	*resp_r = NULL;

	resp = calloc(num_msg, sizeof(struct pam_response));
	if (resp == NULL)
		i_fatal_status(FATAL_OUTOFMEM, "Out of memory");

	for (i = 0; i < num_msg; i++) {
		e_debug(authdb_event(ctx->request),
			"#%d/%d style=%d msg=%s", i+1, num_msg,
			msg[i]->msg_style,
			msg[i]->msg != NULL ? msg[i]->msg : "");
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_ON:
			/* Assume we're asking for user. We might not ever
			   get here because PAM already knows the user. */
			string = strdup(ctx->request->user);
			if (string == NULL)
				i_fatal_status(FATAL_OUTOFMEM, "Out of memory");
			break;
		case PAM_PROMPT_ECHO_OFF:
			/* Assume we're asking for password */
			if (passdb->failure_show_msg)
				ctx->failure_msg = t_strdup(msg[i]->msg);
			string = strdup(ctx->pass);
			if (string == NULL)
				i_fatal_status(FATAL_OUTOFMEM, "Out of memory");
			break;
		case PAM_ERROR_MSG:
		case PAM_TEXT_INFO:
			string = NULL;
			break;
		default:
			while (--i >= 0) {
				if (resp[i].resp != NULL) {
					safe_memset(resp[i].resp, 0,
						    strlen(resp[i].resp));
					free(resp[i].resp);
				}
			}

			free(resp);
			return PAM_CONV_ERR;
		}

		resp[i].resp_retcode = PAM_SUCCESS;
		resp[i].resp = string;
	}

	*resp_r = resp;
	return PAM_SUCCESS;
}

static const char *
pam_get_missing_service_file_path(const char *service ATTR_UNUSED)
{
#ifdef SUNPAM
	/* Uses /etc/pam.conf - we're not going to parse that */
	return NULL;
#else
	static bool service_checked = FALSE;
	const char *path;
	struct stat st;

	if (service_checked) {
		/* check and complain only once */
		return NULL;
	}
	service_checked = TRUE;

	path = t_strdup_printf("/etc/pam.d/%s", service);
	if (stat(path, &st) < 0 && errno == ENOENT) {
		/* looks like it's missing. but before assuming that the system
		   even uses /etc/pam.d, make sure that it exists. */
		if (stat("/etc/pam.d", &st) == 0)
			return path;
	}
	/* exists or is unknown */
	return NULL;
#endif
}

static int try_pam_auth(struct auth_request *request, pam_handle_t *pamh,
			const char *service)
{
        struct passdb_module *_module = request->passdb->passdb;
        struct pam_passdb_module *module = (struct pam_passdb_module *)_module;
	const char *path, *str;
	pam_item_t item;
	int status;

	if ((status = pam_authenticate(pamh, 0)) != PAM_SUCCESS) {
		path = pam_get_missing_service_file_path(service);
		switch (status) {
		case PAM_USER_UNKNOWN:
			str = "unknown user";
			break;
		default:
			str = t_strconcat("pam_authenticate() failed: ",
					  pam_strerror(pamh, status), NULL);
			break;
		}
		if (path != NULL) {
			/* log this as error, since it probably is */
			str = t_strdup_printf("%s (%s missing?)", str, path);
			e_error(authdb_event(request), "%s", str);
		} else if (status == PAM_AUTH_ERR) {
			str = t_strconcat(str, " ("AUTH_LOG_MSG_PASSWORD_MISMATCH"?)", NULL);
			if (request->set->debug_passwords) {
				str = t_strconcat(str, " (given password: ",
						  request->mech_password,
						  ")", NULL);
			}
			e_info(authdb_event(request), "%s", str);
		} else {
			if (status == PAM_USER_UNKNOWN)
				auth_request_log_unknown_user(request, AUTH_SUBSYS_DB);
			else {
				e_info(authdb_event(request),
				       "%s", str);
			}
		}
		return status;
	}

#ifdef HAVE_PAM_SETCRED
	if (module->pam_setcred) {
		if ((status = pam_setcred(pamh, PAM_ESTABLISH_CRED)) !=
		    PAM_SUCCESS) {
			e_error(authdb_event(request),
				"pam_setcred() failed: %s",
				pam_strerror(pamh, status));
			return status;
		}
	}
#endif

	if ((status = pam_acct_mgmt(pamh, 0)) != PAM_SUCCESS) {
		e_error(authdb_event(request),
			"pam_acct_mgmt() failed: %s",
			pam_strerror(pamh, status));
		return status;
	}

	if (module->pam_session) {
	        if ((status = pam_open_session(pamh, 0)) != PAM_SUCCESS) {
			e_error(authdb_event(request),
				"pam_open_session() failed: %s",
				pam_strerror(pamh, status));
	                return status;
	        }

	        if ((status = pam_close_session(pamh, 0)) != PAM_SUCCESS) {
			e_error(authdb_event(request),
				"pam_close_session() failed: %s",
				pam_strerror(pamh, status));
			return status;
	        }
	}

	status = pam_get_item(pamh, PAM_USER, &item);
	if (status != PAM_SUCCESS) {
		e_error(authdb_event(request),
			"pam_get_item(PAM_USER) failed: %s",
			pam_strerror(pamh, status));
		return status;
	}
	auth_request_set_field(request, "user", item, NULL);
	return PAM_SUCCESS;
}

static void set_pam_items(struct auth_request *request, pam_handle_t *pamh)
{
	const char *host;

	/* These shouldn't fail, and we don't really care if they do. */
	host = net_ip2addr(&request->remote_ip);
	if (host[0] != '\0')
		(void)pam_set_item(pamh, PAM_RHOST, host);
	(void)pam_set_item(pamh, PAM_RUSER, request->user);
	/* TTY is needed by eg. pam_access module */
	(void)pam_set_item(pamh, PAM_TTY, "dovecot");
}

static enum passdb_result 
pam_verify_plain_call(struct auth_request *request, const char *service,
		      const char *password)
{
	pam_handle_t *pamh;
	struct pam_conv_context ctx;
	struct pam_conv conv;
	enum passdb_result result;
	int status, status2;

	conv.conv = pam_userpass_conv;
	conv.appdata_ptr = &ctx;

	i_zero(&ctx);
	ctx.request = request;
	ctx.pass = password;

	status = pam_start(service, request->user, &conv, &pamh);
	if (status != PAM_SUCCESS) {
		e_error(authdb_event(request),
			"pam_start() failed: %s",
			pam_strerror(pamh, status));
		return PASSDB_RESULT_INTERNAL_FAILURE;
	}

	set_pam_items(request, pamh);
	status = try_pam_auth(request, pamh, service);
	if ((status2 = pam_end(pamh, status)) != PAM_SUCCESS) {
		e_error(authdb_event(request),
			"pam_end() failed: %s",
			pam_strerror(pamh, status2));
		return PASSDB_RESULT_INTERNAL_FAILURE;
	}

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

	if (result != PASSDB_RESULT_OK && ctx.failure_msg != NULL) {
		auth_request_set_field(request, "reason",
				       ctx.failure_msg, NULL);
	}
	return result;
}

static void
pam_verify_plain(struct auth_request *request, const char *password,
		 verify_plain_callback_t *callback)
{
        struct passdb_module *_module = request->passdb->passdb;
        struct pam_passdb_module *module = (struct pam_passdb_module *)_module;
	enum passdb_result result;
	const char *service, *error;

	if (module->requests_left > 0) {
		if (--module->requests_left == 0)
			worker_restart_request = TRUE;
	}

	if (t_auth_request_var_expand(module->service_name, request, NULL,
				      &service, &error) <= 0) {
		e_debug(authdb_event(request),
			"Failed to expand service %s: %s",
			module->service_name, error);
		callback(PASSDB_RESULT_INTERNAL_FAILURE, request);
		return;
	}

	e_debug(authdb_event(request),
		"lookup service=%s", service);

	result = pam_verify_plain_call(request, service, password);
	callback(result, request);
}

static struct passdb_module *
pam_preinit(pool_t pool, const char *args)
{
	struct pam_passdb_module *module;
	const char *const *t_args;
	int i;

	module = p_new(pool, struct pam_passdb_module, 1);
	module->service_name = "dovecot";
	/* we're caching the password by using directly the plaintext password
	   given by the auth mechanism */
	module->module.default_pass_scheme = "PLAIN";
	module->module.blocking = TRUE;
	module->requests_left = PASSDB_PAM_DEFAULT_MAX_REQUESTS;

	t_args = t_strsplit_spaces(args, " ");
	for(i = 0; t_args[i] != NULL; i++) {
		/* -session for backwards compatibility */
		if (strcmp(t_args[i], "-session") == 0 ||
		    strcmp(t_args[i], "session=yes") == 0)
			module->pam_session = TRUE;
		else if (strcmp(t_args[i], "setcred=yes") == 0)
			module->pam_setcred = TRUE;
		else if (str_begins(t_args[i], "cache_key=")) {
			module->module.default_cache_key =
				auth_cache_parse_key(pool, t_args[i] + 10);
		} else if (strcmp(t_args[i], "blocking=yes") == 0) {
			/* ignore, for backwards compatibility */
		} else if (strcmp(t_args[i], "failure_show_msg=yes") == 0) {
			module->failure_show_msg = TRUE;
		} else if (strcmp(t_args[i], "*") == 0) {
			/* for backwards compatibility */
			module->service_name = "%Ls";
		} else if (str_begins(t_args[i], "max_requests=")) {
			if (str_to_uint(t_args[i] + 13,
					&module->requests_left) < 0) {
				i_error("pam: Invalid requests_left value: %s",
					t_args[i] + 13);
			}
		} else if (t_args[i+1] == NULL) {
			module->service_name = p_strdup(pool, t_args[i]);
		} else {
			i_fatal("pam: Unknown setting: %s", t_args[i]);
		}
	}
	return &module->module;
}

struct passdb_module_interface passdb_pam = {
	"pam",

	pam_preinit,
	NULL,
	NULL,

	pam_verify_plain,
	NULL,
	NULL
};
#else
struct passdb_module_interface passdb_pam = {
	.name = "pam"
};
#endif
