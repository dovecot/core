/* Copyright (C) 2002-2003 Timo Sirainen */

#include "common.h"
#include "auth-module.h"
#include "password-scheme.h"
#include "passdb.h"
#include "passdb-cache.h"

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
			if (verbose) {
				i_info("password(%s): Requested %s "
				       "scheme, but we have only %s",
				       auth_request->user,
				       wanted_scheme, scheme);
			}
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

void passdb_preinit(struct auth *auth, const char *data)
{
	struct passdb_module **p;
	const char *name, *args;

	args = strchr(data, ' ');
	name = t_strcut(data, ' ');

	if (args == NULL) args = "";
	while (*args == ' ' || *args == '\t')
		args++;

	auth->passdb_args = i_strdup(args);

	for (p = passdbs; *p != NULL; p++) {
		if (strcmp((*p)->name, name) == 0) {
			auth->passdb = *p;
			break;
		}
	}
	
#ifdef HAVE_MODULES
	auth->passdb_module = auth->passdb != NULL ? NULL :
		auth_module_open(name);
	if (auth->passdb_module != NULL) {
		auth->passdb = auth_module_sym(auth->passdb_module,
					       t_strconcat("passdb_", name,
							   NULL));
	}
#endif

	if (auth->passdb == NULL)
		i_fatal("Unknown passdb type '%s'", name);

	if (auth->passdb->preinit != NULL)
		auth->passdb->preinit(auth->passdb_args);
}

void passdb_init(struct auth *auth)
{
	passdb_cache_init();
	if (auth->passdb->init != NULL)
		auth->passdb->init(auth->passdb_args);
}

void passdb_deinit(struct auth *auth)
{
	if (auth->passdb->deinit != NULL)
		auth->passdb->deinit();
#ifdef HAVE_MODULES
	if (auth->passdb_module != NULL)
                auth_module_close(auth->passdb_module);
#endif
	passdb_cache_deinit();
	i_free(auth->passdb_args);
}
