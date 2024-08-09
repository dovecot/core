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
#include "settings.h"

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

struct pam_passdb_module {
	struct passdb_module module;

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

struct auth_pam_settings {
	pool_t pool;

	bool session;
	bool setcred;
	const char *service_name;
	unsigned int max_requests;
	bool failure_show_msg;
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("passdb_pam_"#name, name, struct auth_pam_settings)

static const struct setting_define auth_pam_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "passdb_pam", },
	DEF(BOOL, session),
	DEF(BOOL, setcred),
	DEF(STR, service_name),
	DEF(UINT, max_requests),
	DEF(BOOL, failure_show_msg),

	SETTING_DEFINE_LIST_END
};

static const struct auth_pam_settings auth_pam_default_settings = {
	.session = FALSE,
	.setcred = FALSE,
	.service_name = "dovecot",
	.max_requests = 100,
	.failure_show_msg = FALSE,
};

static const struct setting_keyvalue auth_pam_default_settings_keyvalue[] = {
	{ "passdb_pam/passdb_use_worker", "yes"},
	{ NULL, NULL }
};
const struct setting_parser_info auth_pam_setting_parser_info = {
	.name = "auth_pam",

	.defines = auth_pam_setting_defines,
	.defaults = &auth_pam_default_settings,
	.default_settings = auth_pam_default_settings_keyvalue,

	.struct_size = sizeof(struct auth_pam_settings),
	.pool_offset1 = 1 + offsetof(struct auth_pam_settings, pool),
};

static int
pam_userpass_conv(int num_msg, pam_const struct pam_message **msg,
		  struct pam_response **resp_r, void *appdata_ptr)
{
	/* @UNSAFE */
	struct pam_conv_context *ctx = appdata_ptr;
	struct pam_passdb_module *passdb =
		container_of(ctx->request->passdb->passdb,
			     struct pam_passdb_module, module);
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
			string = strdup(ctx->request->fields.user);
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
        struct pam_passdb_module *module =
		container_of(request->passdb->passdb, struct pam_passdb_module,
			     module);
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
				auth_request_db_log_unknown_user(request);
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
	host = net_ip2addr(&request->fields.remote_ip);
	if (host[0] != '\0')
		(void)pam_set_item(pamh, PAM_RHOST, host);
	(void)pam_set_item(pamh, PAM_RUSER, request->fields.user);
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

	status = pam_start(service, request->fields.user, &conv, &pamh);
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
        struct pam_passdb_module *module =
		container_of(request->passdb->passdb, struct pam_passdb_module,
			     module);
	const struct auth_pam_settings *set;
	enum passdb_result result;
	const char *error;

	if (settings_get(authdb_event(request), &auth_pam_setting_parser_info, 0,
			 &set, &error) < 0) {
		e_error(request->event, "%s", error);
		callback(PASSDB_RESULT_INTERNAL_FAILURE, request);
		return;
	}

	if (module->requests_left > 0) {
		if (--module->requests_left == 0)
			worker_restart_request = TRUE;
	}

	if (auth_request_set_passdb_fields(request, NULL) < 0) {
		settings_free(set);
		callback(PASSDB_RESULT_INTERNAL_FAILURE, request);
		return;
	}

	e_debug(authdb_event(request),
		"lookup service=%s", set->service_name);

	result = pam_verify_plain_call(request, set->service_name, password);
	callback(result, request);
	settings_free(set);
}


static int pam_preinit(pool_t pool, struct event *event,
		       struct passdb_module **module_r, const char **error_r)
{
	const struct auth_pam_settings *set;
	const struct auth_passdb_post_settings *post_set;
	struct pam_passdb_module *module;

	if (settings_get(event, &auth_pam_setting_parser_info,
			 SETTINGS_GET_FLAG_NO_EXPAND,
			 &set, error_r) < 0)
		return -1;

	if (settings_get(event,
			 &auth_passdb_post_setting_parser_info,
			 SETTINGS_GET_FLAG_NO_CHECK |
			 SETTINGS_GET_FLAG_NO_EXPAND,
			 &post_set, error_r) < 0) {
		settings_free(set);
		return -1;
	}

	module = p_new(pool, struct pam_passdb_module, 1);
	module->module.default_cache_key =
		auth_cache_parse_key_and_fields(pool,
						t_strdup_printf("%%u/%s", set->service_name),
						&post_set->fields, "pam");
	module->requests_left = set->max_requests;
	module->pam_setcred = set->setcred;
	module->pam_session = set->session;
	module->failure_show_msg = set->failure_show_msg;

	settings_free(post_set);
	settings_free(set);

	*module_r = &module->module;
	return 0;
}

struct passdb_module_interface passdb_pam = {
	.name = "pam",

	.preinit = pam_preinit,
	.verify_plain = pam_verify_plain,
};
#else
struct passdb_module_interface passdb_pam = {
	.name = "pam"
};
#endif
