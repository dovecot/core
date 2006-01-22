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

static void
vpopmail_verify_plain(struct auth_request *request, const char *password,
		      verify_plain_callback_t *callback)
{
	char vpop_user[VPOPMAIL_LIMIT], vpop_domain[VPOPMAIL_LIMIT];
	struct vqpasswd *vpw;
	const char *crypted_pass;
	const char *scheme;
	int ret;

	vpw = vpopmail_lookup_vqp(request, vpop_user, vpop_domain);
	if (vpw == NULL) {
		callback(PASSDB_RESULT_USER_UNKNOWN, request);
		return;
	}

	if (((vpw->pw_gid & NO_IMAP) != 0 &&
	     strcmp(request->service, "IMAP") == 0) ||
	    ((vpw->pw_gid & NO_POP) != 0 &&
	     strcmp(request->service, "POP3") == 0)) {
		auth_request_log_info(request, "vpopmail",
				      "%s disabled", request->service);
		callback(PASSDB_RESULT_USER_DISABLED, request);
		return;
	}

	auth_request_log_debug(request, "vpopmail",
			       "crypted password=%s", vpw->pw_passwd);

	crypted_pass = vpw->pw_passwd;
	scheme = password_get_scheme(&crypted_pass);
	if (scheme == NULL)
		scheme = request->passdb->passdb->default_pass_scheme;

	ret = auth_request_password_verify(request, password, crypted_pass,
					   scheme, "vpopmail");

	safe_memset(vpw->pw_passwd, 0, strlen(vpw->pw_passwd));
	if (vpw->pw_clear_passwd != NULL) {
		safe_memset(vpw->pw_clear_passwd, 0,
			    strlen(vpw->pw_clear_passwd));
	}

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
			p_strdup(auth_passdb->auth->pool, args + 10);
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
	NULL
};

#endif
