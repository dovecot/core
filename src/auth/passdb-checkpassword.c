/* Copyright (c) 2004-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "passdb.h"

#ifdef PASSDB_CHECKPASSWORD 

#include "password-scheme.h"
#include "db-checkpassword.h"

struct checkpassword_passdb_module {
	struct passdb_module module;
	struct db_checkpassword *db;
};

static void
auth_checkpassword_callback(struct auth_request *request,
			    enum db_checkpassword_status status,
			    const char *const *extra_fields,
			    verify_plain_callback_t *callback)
{
	const char *scheme, *crypted_pass = NULL;
	unsigned int i;

	switch (status) {
	case DB_CHECKPASSWORD_STATUS_INTERNAL_FAILURE:
		callback(PASSDB_RESULT_INTERNAL_FAILURE, request);
		return;
	case DB_CHECKPASSWORD_STATUS_FAILURE:
		callback(PASSDB_RESULT_PASSWORD_MISMATCH, request);
		return;
	case DB_CHECKPASSWORD_STATUS_OK:
		break;
	}
	for (i = 0; extra_fields[i] != NULL; i++) {
		if (str_begins(extra_fields[i], "password="))
			crypted_pass = extra_fields[i]+9;
		else if (extra_fields[i][0] != '\0') {
			auth_request_set_field_keyvalue(request,
							extra_fields[i], NULL);
		}
	}
	if (crypted_pass != NULL) {
		/* for cache */
		scheme = password_get_scheme(&crypted_pass);
		if (scheme != NULL) {
			auth_request_set_field(request, "password",
					       crypted_pass, scheme);
		} else {
			auth_request_log_error(request, AUTH_SUBSYS_DB,
				"password field returned without {scheme} prefix");
		}
	}
	callback(PASSDB_RESULT_OK, request);
}

static void
checkpassword_verify_plain(struct auth_request *request, const char *password,
			   verify_plain_callback_t *callback)
{
	struct passdb_module *_module = request->passdb->passdb;
	struct checkpassword_passdb_module *module =
		(struct checkpassword_passdb_module *)_module;

	db_checkpassword_call(module->db, request, password,
			      auth_checkpassword_callback, callback);
}

static void
credentials_checkpassword_callback(struct auth_request *request,
				   enum db_checkpassword_status status,
				   const char *const *extra_fields,
				   lookup_credentials_callback_t *callback)
{
	const char *scheme, *crypted_pass = NULL;
	unsigned int i;

	switch (status) {
	case DB_CHECKPASSWORD_STATUS_INTERNAL_FAILURE:
		callback(PASSDB_RESULT_INTERNAL_FAILURE, NULL, 0, request);
		return;
	case DB_CHECKPASSWORD_STATUS_FAILURE:
		callback(PASSDB_RESULT_USER_UNKNOWN, NULL, 0, request);
		return;
	case DB_CHECKPASSWORD_STATUS_OK:
		break;
	}
	for (i = 0; extra_fields[i] != NULL; i++) {
		if (str_begins(extra_fields[i], "password="))
			crypted_pass = extra_fields[i]+9;
		else if (extra_fields[i][0] != '\0') {
			auth_request_set_field_keyvalue(request,
							extra_fields[i], NULL);
		}
	}
	scheme = password_get_scheme(&crypted_pass);
	if (scheme == NULL)
		scheme = request->credentials_scheme;

	passdb_handle_credentials(PASSDB_RESULT_OK, crypted_pass, scheme,
				  callback, request);
}

static void
checkpassword_lookup_credentials(struct auth_request *request,
				 lookup_credentials_callback_t *callback)
{
	struct passdb_module *_module = request->passdb->passdb;
	struct checkpassword_passdb_module *module =
		(struct checkpassword_passdb_module *)_module;

	db_checkpassword_call(module->db, request, NULL,
			      credentials_checkpassword_callback, callback);
}

static struct passdb_module *
checkpassword_preinit(pool_t pool, const char *args)
{
	struct checkpassword_passdb_module *module;
	const char *checkpassword_path = args;
	const char *checkpassword_reply_path =
		PKG_LIBEXECDIR"/checkpassword-reply";

	module = p_new(pool, struct checkpassword_passdb_module, 1);
	module->db = db_checkpassword_init(checkpassword_path,
					   checkpassword_reply_path);
	return &module->module;
}

static void checkpassword_deinit(struct passdb_module *_module)
{
	struct checkpassword_passdb_module *module =
		(struct checkpassword_passdb_module *)_module;

	db_checkpassword_deinit(&module->db);
}

struct passdb_module_interface passdb_checkpassword = {
	"checkpassword",

	checkpassword_preinit,
	NULL,
	checkpassword_deinit,

	checkpassword_verify_plain,
	checkpassword_lookup_credentials,
	NULL
};
#else
struct passdb_module_interface passdb_checkpassword = {
	.name = "checkpassword"
};
#endif
