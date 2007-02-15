/* Copyright (C) 2002-2003 Timo Sirainen */

#include "common.h"
#include "auth-module.h"
#include "password-scheme.h"
#include "auth-worker-server.h"
#include "passdb.h"

#include <stdlib.h>

extern struct passdb_module_interface passdb_passwd;
extern struct passdb_module_interface passdb_bsdauth;
extern struct passdb_module_interface passdb_shadow;
extern struct passdb_module_interface passdb_passwd_file;
extern struct passdb_module_interface passdb_pam;
extern struct passdb_module_interface passdb_checkpassword;
extern struct passdb_module_interface passdb_vpopmail;
extern struct passdb_module_interface passdb_ldap;
extern struct passdb_module_interface passdb_sql;
extern struct passdb_module_interface passdb_sia;

struct passdb_module_interface *passdb_interfaces[] = {
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
#ifdef PASSDB_SIA
	&passdb_sia,
#endif
	NULL
};

const char *
passdb_credentials_to_str(enum passdb_credentials credentials,
			  const char *wanted_scheme)
{
	switch (credentials) {
	case _PASSDB_CREDENTIALS_INTERNAL:
		break;
	case PASSDB_CREDENTIALS_PLAINTEXT:
		if (strcasecmp(wanted_scheme, "CLEARTEXT") == 0)
			return wanted_scheme;
		return "PLAIN";
	case PASSDB_CREDENTIALS_CRYPT:
		return "CRYPT";
	case PASSDB_CREDENTIALS_CRAM_MD5:
		if (strcasecmp(wanted_scheme, "HMAC-MD5") == 0)
			return wanted_scheme;
		return "CRAM-MD5";
	case PASSDB_CREDENTIALS_DIGEST_MD5:
		return "DIGEST-MD5";
	case PASSDB_CREDENTIALS_LANMAN:
		return "LANMAN";
	case PASSDB_CREDENTIALS_NTLM:
		return "NTLM";
	case PASSDB_CREDENTIALS_OTP:
		return "OTP";
	case PASSDB_CREDENTIALS_SKEY:
		return "SKEY";
	case PASSDB_CREDENTIALS_RPA:
		return "RPA";
	}

	return "??";
}

const char *
passdb_get_credentials(struct auth_request *auth_request,
		       const char *password, const char *scheme)
{
	const char *wanted_scheme;

	if (auth_request->credentials == PASSDB_CREDENTIALS_CRYPT) {
		/* anything goes */
		return t_strdup_printf("{%s}%s", scheme, password);
	}

	wanted_scheme = passdb_credentials_to_str(auth_request->credentials,
						  scheme);
	if (strcasecmp(scheme, wanted_scheme) != 0) {
		if (strcasecmp(scheme, "PLAIN") != 0 &&
		    strcasecmp(scheme, "CLEARTEXT") != 0) {
			auth_request_log_info(auth_request, "password",
				"Requested %s scheme, but we have only %s",
				wanted_scheme, scheme);
			return NULL;
		}

		/* we can generate anything out of plaintext passwords */
		password = password_generate(password, auth_request->user,
					     wanted_scheme);
		i_assert(password != NULL);
	}

	return password;
}

void passdb_handle_credentials(enum passdb_result result,
			       const char *password, const char *scheme,
			       lookup_credentials_callback_t *callback,
                               struct auth_request *auth_request)
{
	if (result != PASSDB_RESULT_OK) {
		callback(result, NULL, auth_request);
		return;
	}

	password = password == NULL ? NULL :
		passdb_get_credentials(auth_request, password, scheme);
	if (password == NULL)
		result = PASSDB_RESULT_SCHEME_NOT_AVAILABLE;
	callback(result, password, auth_request);
}

struct auth_passdb *passdb_preinit(struct auth *auth, const char *driver,
				   const char *args, unsigned int id)
{
	struct passdb_module_interface **p, *iface;
        struct auth_passdb *auth_passdb;

	if (args == NULL) args = "";

	auth_passdb = p_new(auth->pool, struct auth_passdb, 1);
	auth_passdb->auth = auth;
        auth_passdb->args = p_strdup(auth->pool, args);
        auth_passdb->id = id;

	iface = NULL;
	for (p = passdb_interfaces; *p != NULL; p++) {
		if (strcmp((*p)->name, driver) == 0) {
			iface = *p;
			break;
		}
	}
	
#ifdef HAVE_MODULES
	if (iface == NULL)
		auth_passdb->module = auth_module_open(driver);
	if (auth_passdb->module != NULL) {
		iface = auth_module_sym(auth_passdb->module,
					t_strconcat("passdb_", driver, NULL));
	}
#endif

	if (iface == NULL) {
		i_fatal("Unknown passdb driver '%s' "
			"(typo, or Dovecot was built without support for it? "
			"Check with dovecot --build-options)",
			driver);
	}

	if (iface->preinit == NULL) {
		auth_passdb->passdb =
			p_new(auth->pool, struct passdb_module, 1);
	} else {
		auth_passdb->passdb =
			iface->preinit(auth_passdb, auth_passdb->args);
	}
	auth_passdb->passdb->iface = *iface;
	return auth_passdb;
}

void passdb_init(struct auth_passdb *passdb)
{
	if (passdb->passdb->iface.init != NULL)
		passdb->passdb->iface.init(passdb->passdb, passdb->args);

	i_assert(passdb->passdb->default_pass_scheme != NULL ||
		 passdb->passdb->cache_key == NULL);

	if (passdb->passdb->blocking && !worker) {
		/* blocking passdb - we need an auth server */
		auth_worker_server_init();
	}
}

void passdb_deinit(struct auth_passdb *passdb)
{
	if (passdb->passdb->iface.deinit != NULL)
		passdb->passdb->iface.deinit(passdb->passdb);
#ifdef HAVE_MODULES
	if (passdb->module != NULL)
                auth_module_close(&passdb->module);
#endif
}
