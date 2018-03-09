/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "llist.h"
#include "str.h"
#include "time-util.h"
#include "settings-parser.h"
#include "mail-stats.h"
#include "stats.h"
#include "mail-stats-connection.h"
#include "stats-plugin.h"

#define STATS_CONTEXT(obj) \
	MODULE_CONTEXT(obj, stats_storage_module)
#define STATS_CONTEXT_REQUIRE(obj) \
	MODULE_CONTEXT_REQUIRE(obj, stats_storage_module)

/* If session isn't refreshed every 15 minutes, it's dropped.
   Must be smaller than MAIL_SESSION_IDLE_TIMEOUT_MSECS in stats server */
#define SESSION_STATS_FORCE_REFRESH_SECS (5*60)
#define REFRESH_CHECK_INTERVAL 100
#define MAIL_STATS_FIFO_NAME "old-stats-mail"

struct stats_storage {
	union mail_storage_module_context module_ctx;

	struct mail_storage_callbacks old_callbacks;
	void *old_context;
};

struct stats_mailbox {
	union mailbox_module_context module_ctx;
};

const char *stats_plugin_version = DOVECOT_ABI_VERSION;

struct stats_user_module stats_user_module =
	MODULE_CONTEXT_INIT(&mail_user_module_register);
struct stats_storage_module stats_storage_module =
	MODULE_CONTEXT_INIT(&mail_storage_module_register);

static struct stats_item *mail_stats_item;
static struct stats_connection *global_stats_conn = NULL;
static struct mail_user *stats_global_user = NULL;
static unsigned int stats_user_count = 0;

static void session_stats_refresh_timeout(struct mail_user *user);

static void stats_io_activate(struct mail_user *user)
{
	struct stats_user *suser = STATS_USER_CONTEXT_REQUIRE(user);
	struct mail_stats *mail_stats;

	if (stats_user_count == 1) {
		/* the first user sets the global user. the second user sets
		   it to NULL. when we get back to one user we'll need to set
		   the global user again somewhere. do it here. */
		stats_global_user = user;
		/* skip time spent waiting in ioloop */
		mail_stats = stats_fill_ptr(suser->pre_io_stats, mail_stats_item);
		mail_stats->clock_time = ioloop_timeval;
	} else {
		i_assert(stats_global_user == NULL);

		mail_user_stats_fill(user, suser->pre_io_stats);
	}
}

static void stats_add_session(struct mail_user *user)
{
	struct stats_user *suser = STATS_USER_CONTEXT_REQUIRE(user);
	struct stats *new_stats, *diff_stats;
	const char *error;

	new_stats = stats_alloc(pool_datastack_create());
	diff_stats = stats_alloc(pool_datastack_create());

	mail_user_stats_fill(user, new_stats);
	/* we'll count new_stats-pre_io_stats and add the changes to
	   session_stats. the new_stats can't be directly copied to
	   session_stats because there are some fields that don't start from
	   zero, like clock_time. (actually with stats_global_user code we're
	   requiring that clock_time is the only such field..) */
	if (!stats_diff(suser->pre_io_stats, new_stats, diff_stats, &error))
		i_error("stats: session stats shrank: %s", error);
	stats_add(suser->session_stats, diff_stats);
	/* copying is only needed if stats_global_user=NULL */
	stats_copy(suser->pre_io_stats, new_stats);
}

static bool
session_stats_need_send(struct stats_user *suser, time_t now,
			bool *changed_r, unsigned int *to_next_secs_r)
{
	unsigned int diff;

	*to_next_secs_r = SESSION_STATS_FORCE_REFRESH_SECS;

	if (stats_have_changed(suser->last_sent_session_stats,
			       suser->session_stats)) {
		*to_next_secs_r = suser->refresh_secs;
		*changed_r = TRUE;
		return TRUE;
	}
	*changed_r = FALSE;

	diff = now - suser->last_session_update;
	if (diff >= SESSION_STATS_FORCE_REFRESH_SECS)
		return TRUE;
	*to_next_secs_r = SESSION_STATS_FORCE_REFRESH_SECS - diff;

	if (!suser->session_sent_duplicate) {
		if (suser->last_session_update != now) {
			/* send one duplicate notification so stats reader
			   knows that this session is idle now */
			return TRUE;
		}
	}
	return FALSE;
}

static void session_stats_refresh(struct mail_user *user)
{
	struct stats_user *suser = STATS_USER_CONTEXT_REQUIRE(user);
	unsigned int to_next_secs;
	time_t now = time(NULL);
	bool changed;

	if (!suser->stats_connected) {
		if (mail_stats_connection_connect(suser->stats_conn, user) == 0)
			suser->stats_connected = TRUE;
	}
	if (session_stats_need_send(suser, now, &changed, &to_next_secs) &&
	    suser->stats_connected) {
		suser->session_sent_duplicate = !changed;
		suser->last_session_update = now;
		stats_copy(suser->last_sent_session_stats, suser->session_stats);
		mail_stats_connection_send_session(suser->stats_conn, user,
						   suser->session_stats);
	}

	timeout_remove(&suser->to_stats_timeout);
	suser->to_stats_timeout =
		timeout_add(to_next_secs*1000,
			    session_stats_refresh_timeout, user);
}

static struct mailbox_transaction_context *
stats_transaction_begin(struct mailbox *box,
			enum mailbox_transaction_flags flags,
			const char *reason)
{
	struct stats_user *suser = STATS_USER_CONTEXT_REQUIRE(box->storage->user);
	struct stats_mailbox *sbox = STATS_CONTEXT_REQUIRE(box);
	struct mailbox_transaction_context *trans;
	struct stats_transaction_context *strans;

	trans = sbox->module_ctx.super.transaction_begin(box, flags, reason);
	trans->stats_track = TRUE;

	strans = i_new(struct stats_transaction_context, 1);
	strans->trans = trans;
	DLLIST_PREPEND(&suser->transactions, strans);

	MODULE_CONTEXT_SET(trans, stats_storage_module, strans);
	return trans;
}

static void stats_transaction_free(struct stats_user *suser,
				   struct stats_transaction_context *strans)
{
	const struct mailbox_transaction_stats *src = &strans->trans->stats;
	struct mailbox_transaction_stats *dest =
		&suser->finished_transaction_stats;

	DLLIST_REMOVE(&suser->transactions, strans);

	dest->open_lookup_count += src->open_lookup_count;
	dest->stat_lookup_count += src->stat_lookup_count;
	dest->fstat_lookup_count += src->fstat_lookup_count;
	dest->files_read_count += src->files_read_count;
	dest->files_read_bytes += src->files_read_bytes;
	dest->cache_hit_count += src->cache_hit_count;
	i_free(strans);
}

static int
stats_transaction_commit(struct mailbox_transaction_context *ctx,
			 struct mail_transaction_commit_changes *changes_r)
{
	struct stats_transaction_context *strans = STATS_CONTEXT_REQUIRE(ctx);
	struct stats_mailbox *sbox = STATS_CONTEXT_REQUIRE(ctx->box);
	struct stats_user *suser = STATS_USER_CONTEXT_REQUIRE(ctx->box->storage->user);

	stats_transaction_free(suser, strans);
	return sbox->module_ctx.super.transaction_commit(ctx, changes_r);
}

static void
stats_transaction_rollback(struct mailbox_transaction_context *ctx)
{
	struct stats_transaction_context *strans = STATS_CONTEXT_REQUIRE(ctx);
	struct stats_mailbox *sbox = STATS_CONTEXT_REQUIRE(ctx->box);
	struct stats_user *suser = STATS_USER_CONTEXT_REQUIRE(ctx->box->storage->user);

	stats_transaction_free(suser, strans);
	sbox->module_ctx.super.transaction_rollback(ctx);
}

static bool stats_search_next_nonblock(struct mail_search_context *ctx,
				       struct mail **mail_r, bool *tryagain_r)
{
	struct stats_mailbox *sbox = STATS_CONTEXT_REQUIRE(ctx->transaction->box);
	struct mail_user *user = ctx->transaction->box->storage->user;
	struct stats_user *suser = STATS_USER_CONTEXT_REQUIRE(user);
	bool ret;

	ret = sbox->module_ctx.super.
		search_next_nonblock(ctx, mail_r, tryagain_r);
	if (!ret && !*tryagain_r) {
		/* end of search */
		return FALSE;
	}

	if (*tryagain_r ||
	    ++suser->refresh_check_counter % REFRESH_CHECK_INTERVAL == 0) {
		/* a) retrying, so this is a long running search.
		   b) we've returned enough matches */
		if (time(NULL) != suser->last_session_update)
			session_stats_refresh(user);
	}
	return ret;
}

static void
stats_notify_ok(struct mailbox *box, const char *text, void *context)
{
	struct stats_storage *sstorage = STATS_CONTEXT_REQUIRE(box->storage);

	/* most importantly we want to refresh stats for very long running
	   mailbox syncs */
	session_stats_refresh(box->storage->user);

	if (sstorage->old_callbacks.notify_ok != NULL)
		sstorage->old_callbacks.notify_ok(box, text, context);
}

static void stats_register_notify_callbacks(struct mail_storage *storage)
{
	struct stats_storage *sstorage = STATS_CONTEXT(storage);

	if (sstorage != NULL)
		return;

	sstorage = p_new(storage->pool, struct stats_storage, 1);
	sstorage->old_callbacks = storage->callbacks;
	storage->callbacks.notify_ok = stats_notify_ok;

	MODULE_CONTEXT_SET(storage, stats_storage_module, sstorage);
}

static void stats_mailbox_allocated(struct mailbox *box)
{
	struct mailbox_vfuncs *v = box->vlast;
	struct stats_mailbox *sbox;
	struct stats_user *suser = STATS_USER_CONTEXT(box->storage->user);

	if (suser == NULL)
		return;

	stats_register_notify_callbacks(box->storage);

	sbox = p_new(box->pool, struct stats_mailbox, 1);
	sbox->module_ctx.super = *v;
	box->vlast = &sbox->module_ctx.super;

	v->transaction_begin = stats_transaction_begin;
	v->transaction_commit = stats_transaction_commit;
	v->transaction_rollback = stats_transaction_rollback;
	v->search_next_nonblock = stats_search_next_nonblock;
	MODULE_CONTEXT_SET(box, stats_storage_module, sbox);
}

static void session_stats_refresh_timeout(struct mail_user *user)
{
	if (stats_global_user != NULL)
		stats_add_session(user);
	session_stats_refresh(user);
}

static void stats_io_deactivate(struct mail_user *user)
{
	struct stats_user *suser = STATS_USER_CONTEXT_REQUIRE(user);
	unsigned int last_update_secs;

	if (stats_global_user == NULL)
		stats_add_session(user);

	last_update_secs = time(NULL) - suser->last_session_update;
	if (last_update_secs >= suser->refresh_secs) {
		if (stats_global_user != NULL)
			stats_add_session(user);
		session_stats_refresh(user);
	} else if (suser->to_stats_timeout == NULL) {
		suser->to_stats_timeout =
			timeout_add(suser->refresh_secs*1000,
				    session_stats_refresh_timeout, user);
	}
}

static void stats_user_stats_fill(struct mail_user *user, struct stats *stats)
{
	struct stats_user *suser = STATS_USER_CONTEXT_REQUIRE(user);
	struct mail_stats *mail_stats;

	mail_stats = stats_fill_ptr(stats, mail_stats_item);
	mail_stats_fill(suser, mail_stats);

	suser->module_ctx.super.stats_fill(user, stats);
}

static void stats_user_deinit(struct mail_user *user)
{
	struct stats_user *suser = STATS_USER_CONTEXT_REQUIRE(user);
	struct stats_connection *stats_conn = suser->stats_conn;

	i_assert(stats_user_count > 0);

	stats_user_count--;
	if (stats_global_user != NULL) {
		/* we were updating the session lazily. do one final update. */
		i_assert(stats_global_user == user);
		stats_add_session(user);
		stats_global_user = NULL;
	}

	io_loop_context_remove_callbacks(suser->ioloop_ctx,
					 stats_io_activate,
					 stats_io_deactivate, user);
	/* send final stats before disconnection */
	session_stats_refresh(user);
	if (suser->stats_connected)
		mail_stats_connection_disconnect(stats_conn, user);

	timeout_remove(&suser->to_stats_timeout);
	suser->module_ctx.super.deinit(user);

	stats_connection_unref(&stats_conn);
}

static void stats_user_created(struct mail_user *user)
{
	struct ioloop_context *ioloop_ctx =
		io_loop_get_current_context(current_ioloop);
	struct stats_user *suser;
	struct mail_user_vfuncs *v = user->vlast;
	const char *path, *str, *error;
	unsigned int refresh_secs;

	if (ioloop_ctx == NULL) {
		/* we're probably running some test program, or at least
		   mail-storage-service wasn't used to create this user.
		   disable stats tracking. */
		return;
	}
	if (user->autocreated) {
		/* lda / shared user. we're not tracking this one. */
		return;
	}

	/* get refresh time */
	str = mail_user_plugin_getenv(user, "old_stats_refresh");
	if (str == NULL)
		return;
	if (settings_get_time(str, &refresh_secs, &error) < 0) {
		i_error("stats: Invalid old_stats_refresh setting: %s", error);
		return;
	}
	if (refresh_secs == 0)
		return;
	if (refresh_secs > SESSION_STATS_FORCE_REFRESH_SECS) {
		i_warning("stats: stats_refresh too large, changing to %u",
			  SESSION_STATS_FORCE_REFRESH_SECS);
		refresh_secs = SESSION_STATS_FORCE_REFRESH_SECS;
	}

	if (global_stats_conn == NULL) {
		path = mail_user_plugin_getenv(user, "old_stats_notify_path");
		if (path == NULL)
			path = MAIL_STATS_FIFO_NAME;
		if (path[0] != '/')
			path = t_strconcat(user->set->base_dir, "/", path, NULL);
		global_stats_conn = stats_connection_create(path);
	}
	stats_connection_ref(global_stats_conn);

	if (stats_user_count == 0) {
		/* first user connection */
		stats_global_user = user;
	} else if (stats_user_count == 1) {
		/* second user connection. we'll need to start doing
		   per-io callback tracking now. (we might have been doing it
		   also previously but just temporarily quickly dropped to
		   having 1 user, in which case stats_global_user=NULL) */
		if (stats_global_user != NULL) {
			stats_add_session(stats_global_user);
			stats_global_user = NULL;
		}
	}
	stats_user_count++;

	suser = p_new(user->pool, struct stats_user, 1);
	suser->module_ctx.super = *v;
	user->vlast = &suser->module_ctx.super;
	v->deinit = stats_user_deinit;
	v->stats_fill = stats_user_stats_fill;

	suser->refresh_secs = refresh_secs;
	if (mail_user_plugin_getenv_bool(user, "old_stats_track_cmds"))
		suser->track_commands = TRUE;

	suser->stats_conn = global_stats_conn;
	if (user->session_id != NULL && user->session_id[0] != '\0')
		suser->stats_session_id = user->session_id;
	else {
		guid_128_t guid;

		guid_128_generate(guid);
		suser->stats_session_id =
			p_strdup(user->pool, guid_128_to_string(guid));
	}
	suser->last_session_update = time(NULL);
	user->stats_enabled = TRUE;

	suser->ioloop_ctx = ioloop_ctx;
	io_loop_context_add_callbacks(ioloop_ctx,
				      stats_io_activate,
				      stats_io_deactivate, user);

	suser->pre_io_stats = stats_alloc(user->pool);
	suser->session_stats = stats_alloc(user->pool);
	suser->last_sent_session_stats = stats_alloc(user->pool);

	MODULE_CONTEXT_SET(user, stats_user_module, suser);
	if (mail_stats_connection_connect(suser->stats_conn, user) == 0)
		suser->stats_connected = TRUE;
	suser->to_stats_timeout =
		timeout_add(suser->refresh_secs*1000,
			    session_stats_refresh_timeout, user);
	/* fill the initial values. this is necessary for the process-global
	   values (e.g. getrusage()) if the process is reused for multiple
	   users. otherwise the next user will start with the previous one's
	   last values. */
	mail_user_stats_fill(user, suser->pre_io_stats);
}

static struct mail_storage_hooks stats_mail_storage_hooks = {
	.mailbox_allocated = stats_mailbox_allocated,
	.mail_user_created = stats_user_created
};

void old_stats_plugin_init(struct module *module)
{
	mail_stats_item = stats_register(&mail_stats_vfuncs);
	mail_storage_hooks_add(module, &stats_mail_storage_hooks);
}

void old_stats_plugin_preinit(void)
{
	mail_stats_global_preinit();
}

void old_stats_plugin_deinit(void)
{
	if (global_stats_conn != NULL)
		stats_connection_unref(&global_stats_conn);
	mail_stats_fill_global_deinit();
	mail_storage_hooks_remove(&stats_mail_storage_hooks);
	stats_unregister(&mail_stats_item);
}
