/* Copyright (c) the Dovecot authors, based on code by Michael Slusarz.
 * See the included COPYING file */

#include "lib.h"
#include "mail-storage-hooks.h"
#include "str-parse.h"
#include "fts-user.h"
#include "fts-backend-flatcurve.h"
#include "fts-backend-flatcurve-xapian.h"
#include "fts-flatcurve-plugin.h"

#define FTS_FLATCURVE_PLUGIN_COMMIT_LIMIT "fts_flatcurve_commit_limit"
#define FTS_FLATCURVE_COMMIT_LIMIT_DEFAULT 500

#define FTS_FLATCURVE_PLUGIN_MAX_TERM_SIZE "fts_flatcurve_max_term_size"
#define FTS_FLATCURVE_MAX_TERM_SIZE_DEFAULT 30
#define FTS_FLATCURVE_MAX_TERM_SIZE_MAX 200

#define FTS_FLATCURVE_PLUGIN_MIN_TERM_SIZE "fts_flatcurve_min_term_size"
#define FTS_FLATCURVE_MIN_TERM_SIZE_DEFAULT 2

#define FTS_FLATCURVE_PLUGIN_OPTIMIZE_LIMIT "fts_flatcurve_optimize_limit"
#define FTS_FLATCURVE_OPTIMIZE_LIMIT_DEFAULT 10

#define FTS_FLATCURVE_PLUGIN_ROTATE_COUNT "fts_flatcurve_rotate_count"
#define FTS_FLATCURVE_ROTATE_SIZE_DEFAULT 5000

#define FTS_FLATCURVE_PLUGIN_ROTATE_TIME "fts_flatcurve_rotate_time"
#define FTS_FLATCURVE_ROTATE_TIME_DEFAULT 5000

#define FTS_FLATCURVE_PLUGIN_SUBSTRING_SEARCH "fts_flatcurve_substring_search"

const char *fts_flatcurve_plugin_version = DOVECOT_ABI_VERSION;

struct fts_flatcurve_user_module fts_flatcurve_user_module =
	MODULE_CONTEXT_INIT(&mail_user_module_register);

static void fts_flatcurve_mail_user_deinit(struct mail_user *user)
{
	struct fts_flatcurve_user *fuser =
		FTS_FLATCURVE_USER_CONTEXT_REQUIRE(user);

	fts_mail_user_deinit(user);
	fuser->module_ctx.super.deinit(user);
}

static int
fts_flatcurve_plugin_init_settings(struct mail_user *user,
				   struct fts_flatcurve_settings *set,
				   const char **error_r)
{
	const char *pset;
	unsigned int val;

	set->commit_limit = FTS_FLATCURVE_COMMIT_LIMIT_DEFAULT;
	pset = mail_user_plugin_getenv(user, FTS_FLATCURVE_PLUGIN_COMMIT_LIMIT);
	if (pset != NULL) {
		if (str_to_uint(pset, &val) < 0) {
			*error_r = t_strdup_printf("Invalid %s: %s",
				FTS_FLATCURVE_PLUGIN_COMMIT_LIMIT, pset);
			return -1;
		}
		set->commit_limit = val;
	}

	set->max_term_size = FTS_FLATCURVE_MAX_TERM_SIZE_DEFAULT;
	pset = mail_user_plugin_getenv(user, FTS_FLATCURVE_PLUGIN_MAX_TERM_SIZE);
	if (pset != NULL) {
		if (str_to_uint(pset, &val) < 0) {
			*error_r = t_strdup_printf("Invalid %s: %s",
				FTS_FLATCURVE_PLUGIN_MAX_TERM_SIZE, pset);
			return -1;
		}
		set->max_term_size = I_MIN(val, FTS_FLATCURVE_MAX_TERM_SIZE_MAX);
	}

	set->min_term_size = FTS_FLATCURVE_MIN_TERM_SIZE_DEFAULT;
	pset = mail_user_plugin_getenv(user, FTS_FLATCURVE_PLUGIN_MIN_TERM_SIZE);
	if (pset != NULL) {
		if (str_to_uint(pset, &val) < 0) {
			*error_r = t_strdup_printf("Invalid %s: %s",
				FTS_FLATCURVE_PLUGIN_MIN_TERM_SIZE, pset);
			return -1;
		}
		set->min_term_size = val;
	}

	set->optimize_limit = FTS_FLATCURVE_OPTIMIZE_LIMIT_DEFAULT;
	pset = mail_user_plugin_getenv(user, FTS_FLATCURVE_PLUGIN_OPTIMIZE_LIMIT);
	if (pset != NULL) {
		if (str_to_uint(pset, &val) < 0) {
			*error_r = t_strdup_printf("Invalid %s: %s",
				FTS_FLATCURVE_PLUGIN_OPTIMIZE_LIMIT, pset);
			return -1;
		}
		set->optimize_limit = val;
	}

	set->rotate_count = FTS_FLATCURVE_ROTATE_SIZE_DEFAULT;
	pset = mail_user_plugin_getenv(user, FTS_FLATCURVE_PLUGIN_ROTATE_COUNT);
	if (pset != NULL) {
		if (str_to_uint(pset, &val) < 0) {
			*error_r = t_strdup_printf("Invalid %s: %s",
				FTS_FLATCURVE_PLUGIN_ROTATE_COUNT, pset);
			return -1;
		}
		set->rotate_count = val;
	}

	set->rotate_time = FTS_FLATCURVE_ROTATE_TIME_DEFAULT;
	pset = mail_user_plugin_getenv(user, FTS_FLATCURVE_PLUGIN_ROTATE_TIME);
	if (pset != NULL) {
		const char *error;
		if (str_parse_get_interval_msecs(pset, &val, &error) < 0) {
			*error_r = t_strdup_printf("Invalid %s: %s",
				FTS_FLATCURVE_PLUGIN_ROTATE_TIME, error);
			return -1;
		}
		set->rotate_time = val;
	}

	set->substring_search = mail_user_plugin_getenv_bool(
		user, FTS_FLATCURVE_PLUGIN_SUBSTRING_SEARCH);

	return 0;
}

static void fts_flatcurve_mail_user_created(struct mail_user *user)
{
	struct mail_user_vfuncs *v = user->vlast;
	struct fts_flatcurve_user *fuser;
	const char *error;

	fuser = p_new(user->pool, struct fts_flatcurve_user, 1);

	if (fts_flatcurve_plugin_init_settings(user, &fuser->set, &error) < 0 ||
	    fts_mail_user_init(user, TRUE, &error) < 0) {
		e_error(user->event, FTS_FLATCURVE_DEBUG_PREFIX "%s", error);
		return;
	}

	fuser->module_ctx.super = *v;
	user->vlast = &fuser->module_ctx.super;
	v->deinit = fts_flatcurve_mail_user_deinit;
	MODULE_CONTEXT_SET(user, fts_flatcurve_user_module, fuser);
}

static struct mail_storage_hooks fts_backend_mail_storage_hooks = {
	.mail_user_created = fts_flatcurve_mail_user_created
};

void fts_flatcurve_plugin_init(struct module *module)
{
	fts_backend_register(&fts_backend_flatcurve);
	mail_storage_hooks_add(module, &fts_backend_mail_storage_hooks);
}

void fts_flatcurve_plugin_deinit(void)
{
	fts_backend_unregister(fts_backend_flatcurve.name);
	mail_storage_hooks_remove(&fts_backend_mail_storage_hooks);
}

const char *fts_flatcurve_plugin_dependencies[] = { "fts", NULL };
