/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "userdb.h"

#ifdef USERDB_PASSWD

#include "ioloop.h"
#include "ipwd.h"
#include "time-util.h"

#define USER_CACHE_KEY "%u"
#define PASSWD_SLOW_WARN_MSECS (10*1000)
#define PASSWD_SLOW_MASTER_WARN_MSECS 50
#define PASSDB_SLOW_MASTER_WARN_COUNT_INTERVAL 100
#define PASSDB_SLOW_MASTER_WARN_MIN_PERCENTAGE 5

struct passwd_userdb_module {
	struct userdb_module module;

	unsigned int fast_count, slow_count;
	bool slow_warned:1;
};

struct passwd_userdb_iterate_context {
	struct userdb_iterate_context ctx;
	struct passwd_userdb_iterate_context *next_waiting;
};

static struct passwd_userdb_iterate_context *cur_userdb_iter = NULL;
static struct timeout *cur_userdb_iter_to = NULL;

static void
passwd_check_warnings(struct auth_request *auth_request,
		      struct passwd_userdb_module *module,
		      const struct timeval *start_tv)
{
	struct timeval end_tv;
	unsigned int percentage;
	long long msecs;

	i_gettimeofday(&end_tv);

	msecs = timeval_diff_msecs(&end_tv, start_tv);
	if (msecs >= PASSWD_SLOW_WARN_MSECS) {
		e_warning(authdb_event(auth_request), "Lookup for %s took %lld secs",
			  auth_request->fields.user, msecs/1000);
		return;
	}
	if (worker || module->slow_warned)
		return;

	if (msecs < PASSWD_SLOW_MASTER_WARN_MSECS) {
		module->fast_count++;
		return;
	}
	module->slow_count++;
	if (module->fast_count + module->slow_count <
	    PASSDB_SLOW_MASTER_WARN_COUNT_INTERVAL)
		return;

	percentage = module->slow_count * 100 /
		(module->slow_count + module->fast_count);
	if (percentage < PASSDB_SLOW_MASTER_WARN_MIN_PERCENTAGE) {
		/* start from beginning */
		module->slow_count = module->fast_count = 0;
	} else {
		e_warning(authdb_event(auth_request),
			  "%u%% of last %u lookups took over "
			  "%u milliseconds, "
			  "you may want to set blocking=yes for userdb",
			  percentage, PASSDB_SLOW_MASTER_WARN_COUNT_INTERVAL,
			  PASSWD_SLOW_MASTER_WARN_MSECS);
		module->slow_warned = TRUE;
	}
}

static void passwd_lookup(struct auth_request *auth_request,
			  userdb_callback_t *callback)
{
	struct userdb_module *_module = auth_request->userdb->userdb;
	struct passwd_userdb_module *module =
		(struct passwd_userdb_module *)_module;
	struct passwd pw;
	struct timeval start_tv;
	int ret;

	e_debug(authdb_event(auth_request), "lookup");

	i_gettimeofday(&start_tv);
	ret = i_getpwnam(auth_request->fields.user, &pw);
	if (start_tv.tv_sec != 0)
		passwd_check_warnings(auth_request, module, &start_tv);

	struct auth_fields *pwd_fields = auth_fields_init(auth_request->pool);
	switch (ret) {
	case -1:
		e_error(authdb_event(auth_request),
			"getpwnam() failed: %m");
		callback(USERDB_RESULT_INTERNAL_FAILURE, auth_request);
		return;
	case 0:
		auth_request_db_log_unknown_user(auth_request);
		callback(USERDB_RESULT_USER_UNKNOWN, auth_request);
		return;
	}

	auth_request_set_field(auth_request, "user", pw.pw_name, NULL);

	if (auth_request->userdb->set->fields_import_all) {
		auth_request_set_userdb_field(auth_request, "system_groups_user",
					      pw.pw_name);
		auth_request_set_userdb_field(auth_request, "uid", dec2str(pw.pw_uid));
		auth_request_set_userdb_field(auth_request, "home", pw.pw_dir);
		auth_request_set_userdb_field(auth_request, "gid", dec2str(pw.pw_gid));
	}
	auth_fields_add(pwd_fields, "system_groups_user", pw.pw_name, 0);
	auth_fields_add(pwd_fields, "uid", dec2str(pw.pw_uid), 0);
	auth_fields_add(pwd_fields, "home", pw.pw_dir, 0);
	auth_fields_add(pwd_fields, "gid", dec2str(pw.pw_gid), 0);

	if (auth_request_set_userdb_fields(auth_request, pwd_fields) < 0) {
		callback(USERDB_RESULT_INTERNAL_FAILURE, auth_request);
		return;
	}

	callback(USERDB_RESULT_OK, auth_request);
}

static struct userdb_iterate_context *
passwd_iterate_init(struct auth_request *auth_request,
		    userdb_iter_callback_t *callback, void *context)
{
	struct passwd_userdb_iterate_context *ctx;

	ctx = i_new(struct passwd_userdb_iterate_context, 1);
	ctx->ctx.auth_request = auth_request;
	ctx->ctx.callback = callback;
	ctx->ctx.context = context;
	setpwent();

	if (cur_userdb_iter == NULL)
		cur_userdb_iter = ctx;
	return &ctx->ctx;
}

static bool
passwd_iterate_want_pw(struct passwd *pw, const struct auth_settings *set)
{
	/* skip entries not in valid UID range.
	   they're users for daemons and such. */
	if (pw->pw_uid < (uid_t)set->first_valid_uid)
		return FALSE;
	if (pw->pw_uid > (uid_t)set->last_valid_uid && set->last_valid_uid != 0)
		return FALSE;
	if (pw->pw_gid < (gid_t)set->first_valid_gid)
		return FALSE;
	if (pw->pw_gid > (gid_t)set->last_valid_gid && set->last_valid_gid != 0)
		return FALSE;
	return TRUE;
}

static void passwd_iterate_next(struct userdb_iterate_context *_ctx)
{
	struct passwd_userdb_iterate_context *ctx =
		(struct passwd_userdb_iterate_context *)_ctx;
	const struct auth_settings *set = _ctx->auth_request->set;
	struct passwd *pw;

	if (cur_userdb_iter != NULL && cur_userdb_iter != ctx) {
		/* we can't support concurrent userdb iteration.
		   wait until the previous one is done */
		ctx->next_waiting = cur_userdb_iter->next_waiting;
		cur_userdb_iter->next_waiting = ctx;
		return;
	}

	/* reset errno since it might have been set when we got here */
	errno = 0;
	while ((pw = getpwent()) != NULL) {
		if (passwd_iterate_want_pw(pw, set)) {
			_ctx->callback(pw->pw_name, _ctx->context);
			return;
		}
		/* getpwent might set errno to something even if it
		   returns non-NULL. */
		errno = 0;
	}
	if (errno != 0) {
		e_error(authdb_event(_ctx->auth_request),
			"getpwent() failed: %m");
		_ctx->failed = TRUE;
	}
	_ctx->callback(NULL, _ctx->context);
}

static void ATTR_NULL(1)
passwd_iterate_next_timeout(void *context ATTR_UNUSED)
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
		cur_userdb_iter_to = timeout_add(0, passwd_iterate_next_timeout,
						 NULL);
	}
        endpwent();
	return ret;
}

static int passwd_preinit(pool_t pool, struct event *event ATTR_UNUSED,
			  struct userdb_module **module_r,
			  const char **error_r ATTR_UNUSED)
{
	struct passwd_userdb_module *module =
		p_new(pool, struct passwd_userdb_module, 1);

	module->module.default_cache_key = USER_CACHE_KEY;
	*module_r = &module->module;
	return 0;
}

struct userdb_module_interface userdb_passwd = {
	.name = "passwd",

	.preinit = passwd_preinit,

	.lookup = passwd_lookup,

	.iterate_init = passwd_iterate_init,
	.iterate_next = passwd_iterate_next,
	.iterate_deinit = passwd_iterate_deinit
};
#else
struct userdb_module_interface userdb_passwd = {
	.name = "passwd"
};
#endif
