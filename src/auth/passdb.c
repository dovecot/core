/* Copyright (C) 2002-2003 Timo Sirainen */

#include "common.h"
#include "auth-module.h"
#include "password-scheme.h"
#include "auth-worker-server.h"
#include "passdb.h"

#include <stdlib.h>

extern struct passdb_module passdb_passwd;
extern struct passdb_module passdb_bsdauth;
extern struct passdb_module passdb_shadow;
extern struct passdb_module passdb_passwd_file;
extern struct passdb_module passdb_pam;
extern struct passdb_module passdb_checkpassword;
extern struct passdb_module passdb_vpopmail;
extern struct passdb_module passdb_ldap;
extern struct passdb_module passdb_sql;

struct passdb_module *passdbs[] = {
#ifdef PASSDB_PASSWD
	&passdb_passwd,
#endif
#ifdef PASSDB_BSDAUTH
	&passdb_bsdauth,
#endif
#ifdef PASSDB_PASSWD_FILE
	&passdb_passwd_file,
#endif
#ifdef PASSDB_PAM
	&passdb_pam,
#endif
#ifdef PASSDB_CHECKPASSWORD
	&passdb_checkpassword,
#endif
#ifdef PASSDB_SHADOW
	&passdb_shadow,
#endif
#ifdef PASSDB_VPOPMAIL
	&passdb_vpopmail,
#endif
#ifdef PASSDB_LDAP
	&passdb_ldap,
#endif
#ifdef PASSDB_SQL
	&passdb_sql,
#endif
	NULL
};

static const char *
passdb_credentials_to_str(enum passdb_credentials credentials)
{
	switch (credentials) {
	case _PASSDB_CREDENTIALS_INTERNAL:
		break;
	case PASSDB_CREDENTIALS_PLAINTEXT:
		return "PLAIN";
	case PASSDB_CREDENTIALS_CRYPT:
		return "CRYPT";
	case PASSDB_CREDENTIALS_CRAM_MD5:
		return "HMAC-MD5";
	case PASSDB_CREDENTIALS_DIGEST_MD5:
		return "DIGEST-MD5";
	case PASSDB_CREDENTIALS_LANMAN:
		return "LANMAN";
	case PASSDB_CREDENTIALS_NTLM:
		return "NTLM";
	case PASSDB_CREDENTIALS_RPA:
		return "RPA";
	}

	return "??";
}

void passdb_handle_credentials(enum passdb_result result,
			       enum passdb_credentials credentials,
			       const char *password, const char *scheme,
			       lookup_credentials_callback_t *callback,
                               struct auth_request *auth_request)
{
	const char *wanted_scheme;

	if (result != PASSDB_RESULT_OK) {
		callback(result, NULL, auth_request);
		return;
	}
	i_assert(password != NULL);

	if (credentials == PASSDB_CREDENTIALS_CRYPT) {
		/* anything goes */
		password = t_strdup_printf("{%s}%s", scheme, password);
		callback(result, password, auth_request);
		return;
	}

	wanted_scheme = passdb_credentials_to_str(credentials);
	if (strcasecmp(scheme, wanted_scheme) != 0) {
		if (strcasecmp(scheme, "PLAIN") != 0 &&
		    strcasecmp(scheme, "CLEARTEXT") != 0) {
			auth_request_log_info(auth_request, "password",
				"Requested %s scheme, but we have only %s",
				wanted_scheme, scheme);
			callback(PASSDB_RESULT_SCHEME_NOT_AVAILABLE,
				 NULL, auth_request);
			return;
		}

		/* we can generate anything out of plaintext passwords */
		password = password_generate(password, auth_request->user,
					     wanted_scheme);
		i_assert(password != NULL);
	}

	callback(PASSDB_RESULT_OK, password, auth_request);
}

void passdb_preinit(struct auth *auth, const char *driver, const char *args)
{
	struct passdb_module **p;
        struct auth_passdb *auth_passdb, **dest;

	if (args == NULL) args = "";

	auth_passdb = p_new(auth->pool, struct auth_passdb, 1);
	auth_passdb->auth = auth;
	auth_passdb->args = p_strdup(auth->pool, args);

	for (dest = &auth->passdbs; *dest != NULL; dest = &(*dest)->next)
		auth_passdb->num++;
	*dest = auth_passdb;

	for (p = passdbs; *p != NULL; p++) {
		if (strcmp((*p)->name, driver) == 0) {
			auth_passdb->passdb = *p;
			break;
		}
	}
	
#ifdef HAVE_MODULES
	if (auth_passdb->passdb == NULL)
		auth_passdb->module = auth_module_open(driver);
	if (auth_passdb->module != NULL) {
		auth_passdb->passdb =
			auth_module_sym(auth_passdb->module,
					t_strconcat("passdb_", driver, NULL));
	}
#endif

	if (auth_passdb->passdb == NULL)
		i_fatal("Unknown passdb driver '%s'", driver);

	if (auth_passdb->passdb->preinit != NULL)
		auth_passdb->passdb->preinit(auth_passdb->args);
}

void passdb_init(struct auth_passdb *passdb)
{
	if (passdb->passdb->init != NULL)
		passdb->passdb->init(passdb->args);

	i_assert(passdb->passdb->default_pass_scheme != NULL ||
		 passdb->passdb->cache_key == NULL);

	if (passdb->passdb->blocking && !worker) {
		/* blocking passdb - we need an auth server */
		auth_worker_server_init();
	}
}

void passdb_deinit(struct auth_passdb *passdb)
{
	if (passdb->passdb->deinit != NULL)
		passdb->passdb->deinit();
#ifdef HAVE_MODULES
	if (passdb->module != NULL)
                auth_module_close(passdb->module);
#endif
}
