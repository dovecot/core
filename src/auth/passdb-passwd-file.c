/* Copyright (C) 2002-2003 Timo Sirainen */

#include "common.h"

#ifdef PASSDB_PASSWD_FILE

#include "passdb.h"
#include "password-scheme.h"
#include "db-passwd-file.h"

#define PASSWD_FILE_CACHE_KEY "%u"
#define PASSWD_FILE_DEFAULT_SCHEME "CRYPT"

struct passwd_file_passdb_module {
	struct passdb_module module;

	struct db_passwd_file *pwf;
};

static void
passwd_file_verify_plain(struct auth_request *request, const char *password,
			 verify_plain_callback_t *callback)
{
	struct passdb_module *_module = request->passdb->passdb;
	struct passwd_file_passdb_module *module =
		(struct passwd_file_passdb_module *)_module;
	struct passwd_user *pu;
	const char *scheme, *crypted_pass;
	int ret;

	pu = db_passwd_file_lookup(module->pwf, request);
	if (pu == NULL) {
		callback(PASSDB_RESULT_USER_UNKNOWN, request);
		return;
	}

	crypted_pass = pu->password;
	scheme = password_get_scheme(&crypted_pass);
	if (scheme == NULL) scheme = _module->default_pass_scheme;

	/* save the password so cache can use it */
	auth_request_set_field(request, "password", crypted_pass, scheme);

	ret = password_verify(password, crypted_pass, scheme,
			      request->user);
	if (ret > 0)
		callback(PASSDB_RESULT_OK, request);
	else {
		if (ret < 0) {
			auth_request_log_error(request, "passwd-file",
				"unknown password scheme %s", scheme);
		} else {
			auth_request_log_info(request, "passwd-file",
					      "password mismatch");
		}
		callback(PASSDB_RESULT_PASSWORD_MISMATCH, request);
	}
}

static void
passwd_file_lookup_credentials(struct auth_request *request,
			       lookup_credentials_callback_t *callback)
{
	struct passdb_module *_module = request->passdb->passdb;
	struct passwd_file_passdb_module *module =
		(struct passwd_file_passdb_module *)_module;
	struct passwd_user *pu;
	const char *crypted_pass, *scheme;

	pu = db_passwd_file_lookup(module->pwf, request);
	if (pu == NULL) {
		callback(PASSDB_RESULT_USER_UNKNOWN, NULL, request);
		return;
	}

	crypted_pass = pu->password;
	scheme = password_get_scheme(&crypted_pass);

	passdb_handle_credentials(PASSDB_RESULT_OK, crypted_pass, scheme,
				  callback, request);
}

static struct passdb_module *
passwd_file_preinit(struct auth_passdb *auth_passdb,
		    const char *args __attr_unused__)
{
	struct passwd_file_passdb_module *module;

	module = p_new(auth_passdb->auth->pool,
		       struct passwd_file_passdb_module, 1);
	module->module.cache_key = PASSWD_FILE_CACHE_KEY;
	module->module.default_pass_scheme = PASSWD_FILE_DEFAULT_SCHEME;
	return &module->module;
}

static void passwd_file_init(struct passdb_module *_module, const char *args)
{
	struct passwd_file_passdb_module *module =
		(struct passwd_file_passdb_module *)_module;

	module->pwf = db_passwd_file_parse(args, FALSE);
}

static void passwd_file_deinit(struct passdb_module *_module)
{
	struct passwd_file_passdb_module *module =
		(struct passwd_file_passdb_module *)_module;

	db_passwd_file_unref(module->pwf);
}

struct passdb_module_interface passdb_passwd_file = {
	"passwd-file",

	passwd_file_preinit,
	passwd_file_init,
	passwd_file_deinit,

	passwd_file_verify_plain,
	passwd_file_lookup_credentials
};

#endif
