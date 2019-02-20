/* Copyright (c) 2004-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "userdb.h"

#ifdef USERDB_CHECKPASSWORD

#include "db-checkpassword.h"

struct checkpassword_userdb_module {
	struct userdb_module module;
	struct db_checkpassword *db;
};

static void
userdb_checkpassword_callback(struct auth_request *request,
			      enum db_checkpassword_status status,
			      const char *const *extra_fields,
			      userdb_callback_t *callback)
{
	unsigned int i;

	switch (status) {
	case DB_CHECKPASSWORD_STATUS_INTERNAL_FAILURE:
		callback(USERDB_RESULT_INTERNAL_FAILURE, request);
		break;
	case DB_CHECKPASSWORD_STATUS_FAILURE:
		callback(USERDB_RESULT_USER_UNKNOWN, request);
		break;
	case DB_CHECKPASSWORD_STATUS_OK:
		for (i = 0; extra_fields[i] != NULL; i++) {
			if (!str_begins(extra_fields[i], "userdb_"))
				continue;
			auth_request_set_field_keyvalue(request,
							extra_fields[i], NULL);
		}
		callback(USERDB_RESULT_OK, request);
		break;
	}
}

static void
checkpassword_lookup(struct auth_request *request, userdb_callback_t *callback)
{
	struct userdb_module *_module = request->userdb->userdb;
	struct checkpassword_userdb_module *module =
		(struct checkpassword_userdb_module *)_module;

	db_checkpassword_call(module->db, request, NULL,
			      userdb_checkpassword_callback, callback);
}

static struct userdb_module *
checkpassword_preinit(pool_t pool, const char *args)
{
	struct checkpassword_userdb_module *module;
	const char *checkpassword_path = args;
	const char *checkpassword_reply_path =
		PKG_LIBEXECDIR"/checkpassword-reply";

	module = p_new(pool, struct checkpassword_userdb_module, 1);
	module->db = db_checkpassword_init(checkpassword_path,
					   checkpassword_reply_path);
	return &module->module;
}

static void checkpassword_deinit(struct userdb_module *_module)
{
	struct checkpassword_userdb_module *module =
		(struct checkpassword_userdb_module *)_module;

	db_checkpassword_deinit(&module->db);
}

struct userdb_module_interface userdb_checkpassword = {
	"checkpassword",

	checkpassword_preinit,
	NULL,
	checkpassword_deinit,

	checkpassword_lookup,

	NULL,
	NULL,
	NULL
};
#else
struct userdb_module_interface userdb_checkpassword = {
	.name = "checkpassword"
};
#endif
