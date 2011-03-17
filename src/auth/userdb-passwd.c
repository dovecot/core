/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "userdb.h"

#ifdef USERDB_PASSWD

#include "ioloop.h"
#include "ipwd.h"
#include "userdb-static.h"

#define USER_CACHE_KEY "%u"

struct passwd_userdb_module {
	struct userdb_module module;
	struct userdb_static_template *tmpl;
};

struct passwd_userdb_iterate_context {
	struct userdb_iterate_context ctx;
	struct passwd_userdb_iterate_context *next_waiting;
	const struct auth_settings *set;
};

static struct passwd_userdb_iterate_context *cur_userdb_iter = NULL;
static struct timeout *cur_userdb_iter_to = NULL;

static void passwd_lookup(struct auth_request *auth_request,
			  userdb_callback_t *callback)
{
	struct userdb_module *_module = auth_request->userdb->userdb;
	struct passwd_userdb_module *module =
		(struct passwd_userdb_module *)_module;
	struct passwd pw;

	auth_request_log_debug(auth_request, "passwd", "lookup");

	switch (i_getpwnam(auth_request->user, &pw)) {
	case -1:
		auth_request_log_error(auth_request, "passwd",
				       "getpwnam() failed: %m");
		callback(USERDB_RESULT_INTERNAL_FAILURE, auth_request);
		return;
	case 0:
		auth_request_log_info(auth_request, "passwd", "unknown user");
		callback(USERDB_RESULT_USER_UNKNOWN, auth_request);
		return;
	}

	auth_request_set_field(auth_request, "user", pw.pw_name, NULL);

	auth_request_init_userdb_reply(auth_request);
	userdb_static_template_export(module->tmpl, auth_request);

	/* FIXME: the system_user is for backwards compatibility */
	if (!userdb_static_template_isset(module->tmpl, "system_groups_user") &&
	    !userdb_static_template_isset(module->tmpl, "system_user")) {
		auth_request_set_userdb_field(auth_request,
					      "system_groups_user",
					      pw.pw_name);
	}
	if (!userdb_static_template_isset(module->tmpl, "uid")) {
		auth_request_set_userdb_field(auth_request,
					      "uid", dec2str(pw.pw_uid));
	}
	if (!userdb_static_template_isset(module->tmpl, "gid")) {
		auth_request_set_userdb_field(auth_request,
					      "gid", dec2str(pw.pw_gid));
	}
	if (!userdb_static_template_isset(module->tmpl, "home"))
		auth_request_set_userdb_field(auth_request, "home", pw.pw_dir);

	callback(USERDB_RESULT_OK, auth_request);
}

static struct userdb_iterate_context *
passwd_iterate_init(struct userdb_module *userdb,
		    userdb_iter_callback_t *callback, void *context)
{
	struct passwd_userdb_iterate_context *ctx;

	ctx = i_new(struct passwd_userdb_iterate_context, 1);
	ctx->ctx.userdb = userdb;
	ctx->ctx.callback = callback;
	ctx->ctx.context = context;
	ctx->set = auth_find_service("")->set;
	setpwent();

	if (cur_userdb_iter == NULL)
		cur_userdb_iter = ctx;
	return &ctx->ctx;
}

static void passwd_iterate_next(struct userdb_iterate_context *_ctx)
{
	struct passwd_userdb_iterate_context *ctx =
		(struct passwd_userdb_iterate_context *)_ctx;
	struct passwd *pw;

	if (cur_userdb_iter != NULL && cur_userdb_iter != ctx) {
		/* we can't support concurrent userdb iteration.
		   wait until the previous one is done */
		ctx->next_waiting = cur_userdb_iter->next_waiting;
		cur_userdb_iter->next_waiting = ctx;
		return;
	}

	errno = 0;
	while ((pw = getpwent()) != NULL) {
		/* skip entries not in valid UID range.
		   they're users for daemons and such. */
		if (pw->pw_uid >= (uid_t)ctx->set->first_valid_uid &&
		    (ctx->set->last_valid_uid == 0 ||
		     pw->pw_uid <= (uid_t)ctx->set->last_valid_uid)) {
			_ctx->callback(pw->pw_name, _ctx->context);
			return;
		}
	}
	if (errno != 0) {
		i_error("getpwent() failed: %m");
		_ctx->failed = TRUE;
	}
	_ctx->callback(NULL, _ctx->context);
}

static void passwd_iterate_next_timeout(void *context ATTR_UNUSED)
{
	timeout_remove(&cur_userdb_iter_to);
	passwd_iterate_next(&cur_userdb_iter->ctx);
}

static int passwd_iterate_deinit(struct userdb_iterate_context *_ctx)
{
	struct passwd_userdb_iterate_context *ctx =
		(struct passwd_userdb_iterate_context *)_ctx;
	int ret = _ctx->failed ? -1 : 0;

	cur_userdb_iter = ctx->next_waiting;
	i_free(ctx);

	if (cur_userdb_iter != NULL) {
		cur_userdb_iter_to =
			timeout_add(0, passwd_iterate_next_timeout, NULL);
	}
	return ret;
}

static struct userdb_module *
passwd_passwd_preinit(pool_t pool, const char *args)
{
	struct passwd_userdb_module *module;
	const char *value;

	module = p_new(pool, struct passwd_userdb_module, 1);
	module->module.cache_key = USER_CACHE_KEY;
	module->tmpl = userdb_static_template_build(pool, "passwd", args);

	if (userdb_static_template_remove(module->tmpl, "blocking",
					  &value)) {
		module->module.blocking = value == NULL ||
			strcasecmp(value, "yes") == 0;
	}
	return &module->module;
}

struct userdb_module_interface userdb_passwd = {
	"passwd",

	passwd_passwd_preinit,
	NULL,
	NULL,

	passwd_lookup,

	passwd_iterate_init,
	passwd_iterate_next,
	passwd_iterate_deinit
};
#else
struct userdb_module_interface userdb_passwd = {
	.name = "passwd"
};
#endif
