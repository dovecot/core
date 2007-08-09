/* Copyright (C) 2002-2005 Timo Sirainen */

/* Thanks to Courier-IMAP for showing how the vpopmail API should be used */

#include "common.h"

#ifdef PASSDB_VPOPMAIL

#include "safe-memset.h"
#include "passdb.h"
#include "password-scheme.h"

#include "userdb-vpopmail.h"

#include <stdlib.h>

#define VPOPMAIL_DEFAULT_PASS_SCHEME "CRYPT"

static char *
vpopmail_password_lookup(struct auth_request *auth_request, bool cleartext,
			 enum passdb_result *result_r)
{
	char vpop_user[VPOPMAIL_LIMIT], vpop_domain[VPOPMAIL_LIMIT];
	struct vqpasswd *vpw;
	char *password;

	auth_request_log_debug(auth_request, "vpopmail",
			       "lookup user=%s domain=%s",
			       vpop_user, vpop_domain);

	vpw = vpopmail_lookup_vqp(auth_request, vpop_user, vpop_domain);
	if (vpw == NULL) {
		*result_r = PASSDB_RESULT_USER_UNKNOWN;
		return NULL;
	}

	if (((vpw->pw_gid & NO_IMAP) != 0 &&
	     strcmp(auth_request->service, "IMAP") == 0) ||
	    ((vpw->pw_gid & NO_POP) != 0 &&
	     strcmp(auth_request->service, "POP3") == 0)) {
		auth_request_log_info(auth_request, "vpopmail",
				      "%s disabled", auth_request->service);
		password = NULL;
		*result_r = PASSDB_RESULT_USER_DISABLED;
	} else {
		password = t_strdup_noconst(cleartext ? vpw->pw_clear_passwd :
					   vpw->pw_passwd);
		*result_r = password != NULL ? PASSDB_RESULT_OK :
			PASSDB_RESULT_SCHEME_NOT_AVAILABLE;
	}

	safe_memset(vpw->pw_passwd, 0, strlen(vpw->pw_passwd));
	if (vpw->pw_clear_passwd != NULL) {
		safe_memset(vpw->pw_clear_passwd, 0,
			    strlen(vpw->pw_clear_passwd));
	}

	return password;
}

static void vpopmail_lookup_credentials(struct auth_request *request,
					lookup_credentials_callback_t *callback)
{
	enum passdb_result result;
	char *password;

	password = vpopmail_password_lookup(request, TRUE, &result);
	if (password == NULL) {
		callback(result, "", 0, request);
		return;
	}
	
	passdb_handle_credentials(PASSDB_RESULT_OK, password, "CLEARTEXT",
				  callback, request);
	safe_memset(password, 0, strlen(password));
}

static void
vpopmail_verify_plain(struct auth_request *request, const char *password,
		      verify_plain_callback_t *callback)
{
	enum passdb_result result;
	const char *scheme, *tmp_pass;
	char *crypted_pass;
	int ret;

	crypted_pass = vpopmail_password_lookup(request, FALSE, &result);
	if (crypted_pass == NULL) {
		callback(result, request);
		return;
	}

	tmp_pass = crypted_pass;
	scheme = password_get_scheme(&tmp_pass);
	if (scheme == NULL)
		scheme = request->passdb->passdb->default_pass_scheme;

	ret = auth_request_password_verify(request, password,
					   tmp_pass, scheme, "vpopmail");
	safe_memset(crypted_pass, 0, strlen(crypted_pass));

	if (ret <= 0) {
		callback(PASSDB_RESULT_PASSWORD_MISMATCH, request);
		return;
	}

#ifdef HAVE_VPOPMAIL_OPEN_SMTP_RELAY
	if (strcmp(request->service, "POP3") == 0 ||
	    strcmp(request->service, "IMAP") == 0) {
		const char *host = net_ip2addr(&request->remote_ip);
		if (host != NULL) {
			/* use putenv() directly rather than env_put() which
			   would leak memory every time we got here. use a
			   static buffer for putenv() as SUSv2 requirements
			   would otherwise corrupt our environment later. */
			static char ip_env[256];

			i_snprintf(ip_env, sizeof(ip_env),
				   "TCPREMOTEIP=%s", host);
			putenv(ip_env);
			open_smtp_relay();
		}
	}
#endif

	callback(PASSDB_RESULT_OK, request);
}

static struct passdb_module *
vpopmail_preinit(struct auth_passdb *auth_passdb, const char *args)
{
	struct passdb_module *module;

	module = p_new(auth_passdb->auth->pool, struct passdb_module, 1);
	module->default_pass_scheme = VPOPMAIL_DEFAULT_PASS_SCHEME;

	if (strncmp(args, "cache_key=", 10) == 0) {
		module->cache_key =
			auth_cache_parse_key(auth_passdb->auth->pool,
					     args + 10);
	}
	return module;
}

static void vpopmail_deinit(struct passdb_module *module __attr_unused__)
{
	vclose();
}

struct passdb_module_interface passdb_vpopmail = {
	"vpopmail",

	vpopmail_preinit,
	NULL,
	vpopmail_deinit,

	vpopmail_verify_plain,
	vpopmail_lookup_credentials,
	NULL
};

#endif
