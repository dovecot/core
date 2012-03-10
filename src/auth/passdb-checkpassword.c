/* Copyright (c) 2004-2012 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "passdb.h"

#ifdef PASSDB_CHECKPASSWORD 

#include "db-checkpassword.h"

struct checkpassword_passdb_module {
	struct passdb_module module;
	struct db_checkpassword *db;
};

static void
auth_checkpassword_callback(struct auth_request *request,
			    enum db_checkpassword_status status,
			    const char *const *extra_fields,
			    void *context)
{
	verify_plain_callback_t *callback = context;

	switch (status) {
	case DB_CHECKPASSWORD_STATUS_INTERNAL_FAILURE:
		callback(PASSDB_RESULT_INTERNAL_FAILURE, request);
		break;
	case DB_CHECKPASSWORD_STATUS_FAILURE:
		callback(PASSDB_RESULT_PASSWORD_MISMATCH, request);
		break;
	case DB_CHECKPASSWORD_STATUS_OK:
		auth_request_set_fields(request, extra_fields, NULL);
		callback(PASSDB_RESULT_OK, request);
		break;
	}
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
	NULL,
	NULL
};
#else
struct passdb_module_interface passdb_checkpassword = {
	.name = "checkpassword"
};
#endif
