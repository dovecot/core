/* Copyright (C) 2002-2003 Timo Sirainen */

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef PASSDB_PASSWD_FILE

#include "common.h"
#include "passdb.h"
#include "password-scheme.h"
#include "db-passwd-file.h"

struct passwd_file *passdb_pwf = NULL;

static void
passwd_file_verify_plain(struct auth_request *request, const char *password,
			 verify_plain_callback_t *callback)
{
	struct passwd_user *pu;
	const char *scheme, *crypted_pass;
	int ret;

	pu = db_passwd_file_lookup(passdb_pwf, request->user);
	if (pu == NULL) {
		callback(PASSDB_RESULT_USER_UNKNOWN, request);
		return;
	}

	crypted_pass = pu->password;
	scheme = password_get_scheme(&crypted_pass);
	if (scheme == NULL) scheme = "CRYPT";

	ret = password_verify(password, crypted_pass, scheme,
			      request->user);
	if (ret > 0)
		callback(PASSDB_RESULT_OK, request);
	else {
		if (ret < 0) {
			i_error("passwd-file(%s): Unknown password scheme %s",
				pu->user_realm, scheme);
		} else if (verbose) {
			i_info("passwd-file(%s): %s password mismatch",
			       pu->user_realm, scheme);
		}
		callback(PASSDB_RESULT_PASSWORD_MISMATCH, request);
	}
}

static void
passwd_file_lookup_credentials(struct auth_request *request,
			       enum passdb_credentials credentials,
			       lookup_credentials_callback_t *callback)
{
	struct passwd_user *pu;
	const char *crypted_pass, *scheme;

	pu = db_passwd_file_lookup(passdb_pwf, request->user);
	if (pu == NULL) {
		callback(NULL, request);
		return;
	}

	crypted_pass = pu->password;
	scheme = password_get_scheme(&crypted_pass);

	passdb_handle_credentials(credentials, request->user, crypted_pass,
				  scheme, callback, request);
}

static void passwd_file_init(const char *args)
{
	if (userdb_pwf != NULL && strcmp(userdb_pwf->path, args) == 0) {
		passdb_pwf = userdb_pwf;
                passdb_pwf->refcount++;
	} else {
		passdb_pwf = db_passwd_file_parse(args);
	}
}

static void passwd_file_deinit(void)
{
	db_passwd_file_unref(passdb_pwf);
}

struct passdb_module passdb_passwd_file = {
	passwd_file_init,
	passwd_file_deinit,

	passwd_file_verify_plain,
	passwd_file_lookup_credentials
};

#endif
