/* Copyright (C) 2002-2003 Timo Sirainen */

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef PASSDB_PASSWD_FILE

#include "common.h"
#include "passdb.h"
#include "db-passwd-file.h"

#include "hex-binary.h"
#include "md5.h"
#include "mycrypt.h"

struct passwd_file *passdb_pwf = NULL;

static void
passwd_file_verify_plain(struct auth_request *request, const char *password,
			 verify_plain_callback_t *callback)
{
	struct passwd_user *pu;
	unsigned char digest[16];
	const char *str;

	pu = db_passwd_file_lookup(passdb_pwf, request->user, request->realm);
	if (pu == NULL) {
		callback(PASSDB_RESULT_USER_UNKNOWN, request);
		return;
	}

	switch (pu->password_type) {
	case PASSWORD_NONE:
		callback(PASSDB_RESULT_PASSWORD_MISMATCH, request);
		return;

	case PASSWORD_DES:
		if (strcmp(mycrypt(password, pu->password),
			   pu->password) == 0) {
			callback(PASSDB_RESULT_OK, request);
			return;
		}

		if (verbose) {
			i_info("passwd-file(%s): DES password mismatch",
			       pu->user_realm);
		}
		callback(PASSDB_RESULT_PASSWORD_MISMATCH, request);
		return;

	case PASSWORD_MD5:
		md5_get_digest(password, strlen(password), digest);
		str = binary_to_hex(digest, sizeof(digest));

		if (strcmp(str, pu->password) == 0) {
			callback(PASSDB_RESULT_OK, request);
			return;
		}

		if (verbose) {
			i_info("passwd-file(%s): MD5 password mismatch",
			       pu->user_realm);
		}
		callback(PASSDB_RESULT_PASSWORD_MISMATCH, request);
		return;

	case PASSWORD_DIGEST_MD5:
		/* user:realm:passwd */
		str = t_strconcat(t_strcut(pu->user_realm, '@'), ":",
				  pu->realm == NULL ? "" : pu->realm,  ":",
				  password, NULL);

		md5_get_digest(str, strlen(str), digest);
		str = binary_to_hex(digest, sizeof(digest));

		if (strcmp(str, pu->password) == 0) {
			callback(PASSDB_RESULT_OK, request);
			return;
		}

		if (verbose) {
			i_info("passwd-file(%s): DIGEST-MD5 password mismatch",
			       pu->user_realm);
		}

		callback(PASSDB_RESULT_PASSWORD_MISMATCH, request);
		return;
	}

	i_unreached();
}

static void
passwd_file_lookup_credentials(struct auth_request *request,
			       enum passdb_credentials credentials,
			       lookup_credentials_callback_t *callback)
{
	struct passwd_user *pu;

	pu = db_passwd_file_lookup(passdb_pwf, request->user, request->realm);
	if (pu == NULL) {
		callback(NULL, request);
		return;
	}

	if (pu->password_type == PASSWORD_NONE) {
		if (verbose)
			i_info("passwd-file(%s): No password", pu->user_realm);
		callback(NULL, request);
		return;
	}

	switch (credentials) {
	case PASSDB_CREDENTIALS_DIGEST_MD5:
		if (pu->password_type == PASSWORD_DIGEST_MD5) {
			callback(pu->password, request);
			return;
		}

		if (verbose) {
			i_info("passwd-file(%s): No DIGEST-MD5 password",
			       pu->user_realm);
		}
		callback(NULL, request);
		return;
	default:
		if (verbose) {
			i_info("passwd-file(%s): Unsupported credentials %u",
			       pu->user_realm, (unsigned int)credentials);
		}
		callback(NULL, request);
		return;
	}
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
