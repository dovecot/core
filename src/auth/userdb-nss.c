/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

/* Currently supports only GLIBC-compatible NSS modules */

#include "auth-common.h"
#include "userdb.h"

#ifdef USERDB_NSS

#include "module-dir.h"

#include <pwd.h>
#include <unistd.h>
#include <dlfcn.h>
#include <nss.h>

#define USER_CACHE_KEY "%u"

struct nss_userdb_module {
	struct userdb_module module;

	char *buf;
	size_t bufsize;

	struct module nss_module;
	enum nss_status (*getpwnam_r)(const char *name, struct passwd *pwd,
				      char *buffer, size_t buflen, int *errnop);
};

static void
userdb_nss_lookup(struct auth_request *auth_request,
		  userdb_callback_t *callback)
{
	struct userdb_module *_module = auth_request->userdb->userdb;
	struct nss_userdb_module *module = (struct nss_userdb_module *)_module;
	struct passwd pw;
	enum nss_status status;
	enum userdb_result result = USERDB_RESULT_INTERNAL_FAILURE;
	int err;

	auth_request_log_debug(auth_request, "nss", "lookup");

	status = module->getpwnam_r(auth_request->user, &pw,
				    module->buf, module->bufsize, &err);
	switch (status) {
	case NSS_STATUS_TRYAGAIN:
		auth_request_log_error(auth_request, "nss",
				       "returned tryagain (err=%d)", err);
		break;
	case NSS_STATUS_UNAVAIL:
		auth_request_log_error(auth_request, "nss",
				       "unavailable (err=%d)", err);
		break;
	case NSS_STATUS_NOTFOUND:
		auth_request_log_info(auth_request, "nss", "unknown user");
		result = USERDB_RESULT_USER_UNKNOWN;
		break;
	case NSS_STATUS_SUCCESS:
		result = USERDB_RESULT_OK;
		break;
	default:
		auth_request_log_info(auth_request, "nss",
				      "returned %d (err=%d)", status, err);
		break;
	}

	if (result != USERDB_RESULT_OK) {
		callback(result, auth_request);
		return;
	}

	auth_request_set_field(auth_request, "user", pw.pw_name, NULL);

	auth_request_init_userdb_reply(auth_request);
	auth_request_set_userdb_field(auth_request, "system_groups_user",
				      pw.pw_name);
	auth_request_set_userdb_field(auth_request, "uid", dec2str(pw.pw_uid));
	auth_request_set_userdb_field(auth_request, "gid", dec2str(pw.pw_gid));
	auth_request_set_userdb_field(auth_request, "home", pw.pw_dir);

	callback(USERDB_RESULT_OK, auth_request);
}

static void
userdb_nss_load_module(struct nss_userdb_module *module, pool_t pool)
{
	const char *name = module->nss_module.name;
	char *path;

	path = p_strdup_printf(pool, "/usr/lib/libnss_%s.so", name);
	module->nss_module.handle = dlopen(path, RTLD_GLOBAL | RTLD_NOW);
	if (module->nss_module.handle == NULL)
		i_fatal("dlopen(%s) failed: %s", path, dlerror());
	module->nss_module.path = path;

	module->getpwnam_r =
		module_get_symbol(&module->nss_module,
				  t_strdup_printf("_nss_%s_getpwnam_r", name));
	if (module->getpwnam_r == NULL)
		i_fatal("userdb nss: Module %s missing getpwnam_r()", path);
}

static struct userdb_module *
userdb_nss_preinit(pool_t pool, const char *args)
{
	struct nss_userdb_module *module;
	const char *const *tmp;

	module = p_new(pool, struct nss_userdb_module, 1);
	module->bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	module->buf = p_malloc(pool, module->bufsize);
	module->module.blocking = TRUE;

	for (tmp = t_strsplit(args, " "); *tmp != NULL; tmp++) {
		if (strcmp(*tmp, "blocking=no") == 0)
			module->module.blocking = FALSE;
		else if (strncmp(*tmp, "service=", 8) == 0)
			module->nss_module.name = p_strdup(pool, *tmp + 8);
		else
			i_fatal("userdb nss: Unknown setting: %s", *tmp);
	}

	if (module->nss_module.name == NULL)
		i_fatal("userdb nss: Missing service");
	userdb_nss_load_module(module, pool);

	module->module.cache_key = USER_CACHE_KEY;
	return &module->module;
}

static void userdb_nss_deinit(struct userdb_module *_module)
{
	struct nss_userdb_module *module = (struct nss_userdb_module *)_module;
	void (*mod_endpwent)(void);
	const char *symbol;

	symbol = t_strdup_printf("_nss_%s_endpwent", module->nss_module.name);
	mod_endpwent = module_get_symbol(&module->nss_module, symbol);
	if (mod_endpwent != NULL)
		mod_endpwent();
}

struct userdb_module_interface userdb_nss = {
	"nss",

	userdb_nss_preinit,
	NULL,
	userdb_nss_deinit,

	userdb_nss_lookup,

	NULL,
	NULL,
	NULL
};
#else
struct userdb_module_interface userdb_nss = {
	.name = "nss"
};
#endif
