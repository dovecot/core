/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "userdb.h"

#ifdef USERDB_PASSWD

#include "ioloop.h"
#include "ipwd.h"
#include "time-util.h"
#include "userdb-template.h"

#define USER_CACHE_KEY "%u"
#define PASSWD_SLOW_WARN_MSECS (10*1000)
#define PASSWD_SLOW_MASTER_WARN_MSECS 50
#define PASSDB_SLOW_MASTER_WARN_COUNT_INTERVAL 100
#define PASSDB_SLOW_MASTER_WARN_MIN_PERCENTAGE 5

struct passwd_userdb_module {
	struct userdb_module module;
	struct userdb_template *tmpl;

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
	unsigned int msecs, percentage;

	if (gettimeofday(&end_tv, NULL) < 0)
		return;

	msecs = timeval_diff_msecs(&end_tv, start_tv);
	if (msecs >= PASSWD_SLOW_WARN_MSECS) {
		i_warning("passwd: Lookup for %s took %u secs",
			  auth_request->user, msecs/1000);
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
		i_warning("passwd: %u%% of last %u lookups took over "
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
	const char *error;
	int ret;

	e_debug(authdb_event(auth_request), "lookup");

	if (gettimeofday(&start_tv, NULL) < 0)
		start_tv.tv_sec = 0;
	ret = i_getpwnam(auth_request->user, &pw);
	if (start_tv.tv_sec != 0)
		passwd_check_warnings(auth_request, module, &start_tv);

	switch (ret) {
	case -1:
		e_error(authdb_event(auth_request),
			"getpwnam() failed: %m");
		callback(USERDB_RESULT_INTERNAL_FAILURE, auth_request);
		return;
	case 0:
		auth_request_log_unknown_user(auth_request, AUTH_SUBSYS_DB);
		callback(USERDB_RESULT_USER_UNKNOWN, auth_request);
		return;
	}

	auth_request_set_field(auth_request, "user", pw.pw_name, NULL);

	auth_request_set_userdb_field(auth_request, "system_groups_user",
				      pw.pw_name);
	auth_request_set_userdb_field(auth_request, "uid", dec2str(pw.pw_uid));
	auth_request_set_userdb_field(auth_request, "gid", dec2str(pw.pw_gid));
	auth_request_set_userdb_field(auth_request, "home", pw.pw_dir);

	if (userdb_template_export(module->tmpl, auth_request, &error) < 0) {
		e_error(authdb_event(auth_request),
			"Failed to expand template: %s", error);
		callback(USERDB_RESULT_INTERNAL_FAILURE, auth_request);
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
		i_error("getpwent() failed: %m");
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
	return ret;
}

static struct userdb_module *
passwd_passwd_preinit(pool_t pool, const char *args)
{
	struct passwd_userdb_module *module;
	const char *value;

	module = p_new(pool, struct passwd_userdb_module, 1);
	module->module.default_cache_key = USER_CACHE_KEY;
	module->tmpl = userdb_template_build(pool, "passwd", args);
	module->module.blocking = TRUE;

	if (userdb_template_remove(module->tmpl, "blocking", &value))
		module->module.blocking = strcasecmp(value, "yes") == 0;
	/* FIXME: backwards compatibility */
	if (!userdb_template_is_empty(module->tmpl))
		i_warning("userdb passwd: Move templates args to override_fields setting");
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
