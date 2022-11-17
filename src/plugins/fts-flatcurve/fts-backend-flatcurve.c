/* Copyright (c) the Dovecot authors, based on code by Michael Slusarz.
 * See the included COPYING file */

#include "lib.h"
#include "array.h"
#include "imap-util.h"
#include "mail-storage-private.h"
#include "mail-search-build.h"
#include "mailbox-list-iter.h"
#include "str.h"
#include "time-util.h"
#include "unlink-directory.h"
#include "fts-backend-flatcurve.h"
#include "fts-backend-flatcurve-xapian.h"

enum fts_backend_flatcurve_action {
	FTS_BACKEND_FLATCURVE_ACTION_OPTIMIZE,
	FTS_BACKEND_FLATCURVE_ACTION_RESCAN
};

struct event_category event_category_fts_flatcurve = {
	.name = FTS_FLATCURVE_LABEL,
	.parent = &event_category_fts
};

static struct fts_backend *fts_backend_flatcurve_alloc(void)
{
	struct flatcurve_fts_backend *backend;
	pool_t pool;

	pool = pool_alloconly_create(FTS_FLATCURVE_LABEL " pool", 4096);

	backend = i_new(struct flatcurve_fts_backend, 1);
	backend->backend = fts_backend_flatcurve;
	backend->pool = pool;

	return &backend->backend;
}

static int
fts_backend_flatcurve_init(struct fts_backend *_backend, const char **error_r)
{
	struct flatcurve_fts_backend *backend =
		container_of(_backend, struct flatcurve_fts_backend, backend);
	struct fts_flatcurve_user *fuser =
		FTS_FLATCURVE_USER_CONTEXT(_backend->ns->user);

	if (fuser == NULL) {
		*error_r = "Invalid fts-flatcurve settings";
		return -1;
	}

	backend->boxname = str_new(backend->pool, 128);
	backend->db_path = str_new(backend->pool, 256);
	backend->fuser = fuser;

	fuser->backend = backend;

	fts_flatcurve_xapian_init(backend);

	backend->event = event_create(_backend->event);
	event_add_category(backend->event, &event_category_fts_flatcurve);

	return fts_backend_flatcurve_close_mailbox(backend, error_r);
}

int
fts_backend_flatcurve_close_mailbox(struct flatcurve_fts_backend *backend,
				    const char **error_r)
{
	int ret = 0;
	if (str_len(backend->boxname) > 0) {
		ret = fts_flatcurve_xapian_close(backend, error_r);

		str_truncate(backend->boxname, 0);
		str_truncate(backend->db_path, 0);
	}

	event_set_append_log_prefix(backend->event, FTS_FLATCURVE_DEBUG_PREFIX);
	return ret;
}

static int fts_backend_flatcurve_refresh(struct fts_backend * _backend)
{
	const char *error;
	struct flatcurve_fts_backend *backend =
		(struct flatcurve_fts_backend *)_backend;

	int ret = fts_flatcurve_xapian_refresh(backend, &error);
	if (ret < 0)
		e_error(backend->event, "%s", error);
	return ret;
}

static void fts_backend_flatcurve_deinit(struct fts_backend *_backend)
{
	const char *error;
	struct flatcurve_fts_backend *backend =
		(struct flatcurve_fts_backend *)_backend;

	int ret = fts_backend_flatcurve_close_mailbox(backend, &error);
	fts_flatcurve_xapian_deinit(backend);
	if (ret < 0)
		e_error(backend->event, "%s", error);

	event_unref(&backend->event);
	pool_unref(&backend->pool);
	i_free(backend);
}

int
fts_backend_flatcurve_set_mailbox(struct flatcurve_fts_backend *backend,
                                  struct mailbox *box, const char **error_r)
{
	const char *path;
	struct mail_storage *storage;

	if (str_len(backend->boxname) > 0 &&
	    strcasecmp(box->vname, str_c(backend->boxname)) == 0)
		return 0;

	if (fts_backend_flatcurve_close_mailbox(backend, error_r) < 0) {
		*error_r = t_strdup_printf("Could not open mailbox: %s: %s",
					   box->vname, *error_r);
		return -1;
	}

	if (mailbox_open(box) < 0 ||
	    mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_INDEX, &path) <= 0) {
		*error_r = t_strdup_printf("Could not open mailbox: %s: %s",
					   box->vname,
					   mailbox_get_last_internal_error(box, NULL));
		return -1;
	}

	str_append(backend->boxname, box->vname);
	str_printfa(backend->db_path, "%s/%s/", path, FTS_FLATCURVE_LABEL);

	storage = mailbox_get_storage(box);
	backend->parsed_lock_method = storage->set->parsed_lock_method;

	fts_flatcurve_xapian_set_mailbox(backend);
	return 0;
}

static int
fts_backend_flatcurve_get_last_uid(struct fts_backend *_backend,
				   struct mailbox *box, uint32_t *last_uid_r)
{
	const char *error;
	struct flatcurve_fts_backend *backend =
		(struct flatcurve_fts_backend *)_backend;

	if (fts_backend_flatcurve_set_mailbox(backend, box, &error) < 0 ||
	    fts_flatcurve_xapian_get_last_uid(backend, last_uid_r, &error) < 0) {
		e_error(backend->event, "%s", error);
		return -1;
	}
	return 0;
}

static struct fts_backend_update_context
*fts_backend_flatcurve_update_init(struct fts_backend *_backend)
{
	struct flatcurve_fts_backend *backend =
		(struct flatcurve_fts_backend *)_backend;
	struct flatcurve_fts_backend_update_context *ctx;

	ctx = p_new(backend->pool,
		    struct flatcurve_fts_backend_update_context, 1);
	ctx->ctx.backend = _backend;
	ctx->backend = backend;
	ctx->hdr_name = str_new(backend->pool, 128);
	i_gettimeofday(&ctx->start);

	return &ctx->ctx;
}

static int
fts_backend_flatcurve_update_deinit(struct fts_backend_update_context *_ctx)
{
	struct flatcurve_fts_backend_update_context *ctx =
		(struct flatcurve_fts_backend_update_context *)_ctx;
	int diff, ret = _ctx->failed ? -1 : 0;
	struct timeval now;

	if (ret == 0) {
		i_gettimeofday(&now);
		diff = timeval_diff_msecs(&now, &ctx->start);

		e_debug(ctx->backend->event, "Update transaction completed in "
			"%u.%03u secs", diff/1000, diff%1000);
	}

	str_free(&ctx->hdr_name);
	p_free(ctx->backend->pool, ctx);

	return ret;
}

static void
fts_backend_flatcurve_update_set_mailbox(struct fts_backend_update_context *_ctx,
					 struct mailbox *box)
{
	const char *error;
	struct flatcurve_fts_backend_update_context *ctx =
		(struct flatcurve_fts_backend_update_context *)_ctx;

	int ret = box == NULL ?
		fts_backend_flatcurve_close_mailbox(ctx->backend, &error) :
		fts_backend_flatcurve_set_mailbox(ctx->backend, box, &error);
	if (ret < 0)
		e_error(ctx->backend->event, "%s", error);
}

static void
fts_backend_flatcurve_update_expunge(struct fts_backend_update_context *_ctx,
				     uint32_t uid)
{
	const char *error;
	struct flatcurve_fts_backend_update_context *ctx =
		(struct flatcurve_fts_backend_update_context *)_ctx;

	e_debug(event_create_passthrough(ctx->backend->event)->
		set_name("fts_flatcurve_expunge")->
		add_str("mailbox", str_c(ctx->backend->boxname))->
		add_int("uid", uid)->event(),
		"Expunge uid=%d", uid);

	if (fts_flatcurve_xapian_expunge(ctx->backend, uid, &error) < 0)
		e_error(ctx->backend->event, "%s", error);
}

static bool
fts_backend_flatcurve_update_set_build_key(struct fts_backend_update_context *_ctx,
					   const struct fts_backend_build_key *key)
{
	struct flatcurve_fts_backend_update_context *ctx =
		(struct flatcurve_fts_backend_update_context *)_ctx;

	i_assert(str_len(ctx->backend->boxname) > 0);

	if (_ctx->failed || ctx->skip_uid)
		return FALSE;

	bool changed = FALSE;
	if (ctx->uid != key->uid) {
		changed = TRUE;
		ctx->skip_uid = FALSE;
		ctx->uid = key->uid;
	}
	ctx->type = key->type;

	/* Specifically init message, as there is a chance that there
	 * is no valid search info in a message so the message will
	 * not be saved to DB after processing. */
	if (changed) {
		const char *error;
		int ret = fts_flatcurve_xapian_init_msg(ctx, &error);
		if (ret < 0) {
			e_error(ctx->backend->event, "%s", error);
			return FALSE;
		}
		if (ret == 0) {
			/* This UID has already been indexed, so skip all
			 * future update calls. */
			ctx->skip_uid = TRUE;
			return FALSE;
		}

		e_debug(event_create_passthrough(ctx->backend->event)->
			set_name("fts_flatcurve_index")->
			add_str("mailbox", str_c(ctx->backend->boxname))->
			add_int("uid", key->uid)->event(),
			"Indexing uid=%d", key->uid);
	}

	switch (key->type) {
	case FTS_BACKEND_BUILD_KEY_HDR:
		i_assert(key->hdr_name != NULL);
		str_append(ctx->hdr_name, key->hdr_name);
		ctx->indexed_hdr = fts_header_want_indexed(key->hdr_name);
		break;
	case FTS_BACKEND_BUILD_KEY_MIME_HDR:
	case FTS_BACKEND_BUILD_KEY_BODY_PART:
		/* noop */
		break;
	case FTS_BACKEND_BUILD_KEY_BODY_PART_BINARY:
		i_unreached();
	}
	return TRUE;
}

static void
fts_backend_flatcurve_update_unset_build_key(struct fts_backend_update_context *_ctx)
{
	struct flatcurve_fts_backend_update_context *ctx =
		(struct flatcurve_fts_backend_update_context *)_ctx;

	str_truncate(ctx->hdr_name, 0);
}

static int
fts_backend_flatcurve_update_build_more(struct fts_backend_update_context *_ctx,
					const unsigned char *data, size_t size)
{
	struct flatcurve_fts_backend_update_context *ctx =
		(struct flatcurve_fts_backend_update_context *)_ctx;

	i_assert(ctx->uid != 0);

	if (_ctx->failed || ctx->skip_uid)
		return -1;

	if (size < ctx->backend->fuser->set.min_term_size)
		return 0;

	/* Xapian has a hard limit of "245 bytes", at least with the glass
	 * and chert backends.  However, it is highly doubtful that people
	 * are realistically going to search with more than 10s of
	 * characters. Therefore, limit term size (via a configurable
	 * value). */
	size = I_MIN(size, ctx->backend->fuser->set.max_term_size);

	const char *error;
	int ret;
	switch (ctx->type) {
	case FTS_BACKEND_BUILD_KEY_HDR:
	case FTS_BACKEND_BUILD_KEY_MIME_HDR:
		ret = fts_flatcurve_xapian_index_header(ctx, data, size, &error);
		break;
	case FTS_BACKEND_BUILD_KEY_BODY_PART:
		ret = fts_flatcurve_xapian_index_body(ctx, data, size, &error);
		break;
	default:
		i_unreached();
	}

	if (ret < 0)
		e_error(ctx->backend->event, "%s", error);
	return ret < 0 || _ctx->failed ? -1 : 0;
}

static const char *
fts_backend_flatcurve_seq_range_string(ARRAY_TYPE(seq_range) *uids)
{
	string_t *dest = t_str_new(256);
	imap_write_seq_range(dest, uids);
	return str_c(dest);
}

static struct flatcurve_fts_query *
fts_backend_flatcurve_create_query(struct flatcurve_fts_backend *backend,
				   pool_t pool)
{
	struct flatcurve_fts_query *query =
		p_new(pool, struct flatcurve_fts_query, 1);

	query->pool = pool;
	query->backend = backend;
	query->qtext = str_new(pool, 128);
	return query;
}

static int
fts_backend_flatcurve_rescan_box(struct flatcurve_fts_backend *backend,
				 struct mailbox *box, pool_t pool,
				 const char **error_r)
{
	bool dbexist = FALSE;
	struct event_passthrough *e;
	struct fts_flatcurve_xapian_query_iter *iter;
	struct seq_range_iter iter2;
	uint32_t low_uid = 0;
	struct mail *mail;
	ARRAY_TYPE(seq_range) expunged, missing, uids;
	struct flatcurve_fts_query *query;
	struct fts_flatcurve_xapian_query_result *result;
	struct mail_search_args *search_args;
	struct mail_search_context *search_ctx;
	struct mailbox_transaction_context *trans;

	/* Check for non-indexed mails. */
	if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FULL_READ) < 0) {
		*error_r = mailbox_get_last_internal_error(box, NULL);
		return -1;
	}

	trans = mailbox_transaction_begin(box, 0, __func__);
	search_args = mail_search_build_init();
	mail_search_build_add_all(search_args);

	p_array_init(&missing, pool, 32);
	p_array_init(&uids, pool, 256);

	int ret = 0;
	search_ctx = mailbox_search_init(trans, search_args, NULL, 0, NULL);
	while (mailbox_search_next(search_ctx, &mail)) {
		seq_range_array_add(&uids, mail->uid);
		ret = fts_flatcurve_xapian_uid_exists(backend, mail->uid, error_r);
		if (ret < 0)
			break;
		if (ret == 0)
			seq_range_array_add(&missing, mail->uid);
		dbexist = TRUE;
	}

	if (mailbox_search_deinit(&search_ctx) < 0)
		e_error(backend->event, "Could not deinit %s: %s",
			box->vname, mailbox_get_last_internal_error(box, NULL));

	mail_search_args_unref(&search_args);
	if (mailbox_transaction_commit(&trans) < 0)
		e_error(backend->event, "Could not commit %s: %s",
			box->vname, mailbox_get_last_internal_error(box, NULL));

	if (ret < 0 || !dbexist)
		return ret;

	e = event_create_passthrough(backend->event)->
				     set_name("fts_flatcurve_rescan")->
				     add_str("mailbox", box->name);

	if (!array_is_empty(&missing)) {
		/* There does not seem to be an easy way via FTS API (as of
		 * 2.3.15) to indicate what specific uids need to be indexed.
		 * Instead, delete all messages above the lowest, non-indexed
		 * UID and recreate the index the next time the mailbox
		 * is accessed. */
		seq_range_array_iter_init(&iter2, &missing);
		bool ret1 = seq_range_array_iter_nth(&iter2, 0, &low_uid);
		i_assert(ret1);
	}

	query = fts_backend_flatcurve_create_query(backend, pool);
	fts_flatcurve_xapian_build_query_match_all(query);

	p_array_init(&expunged, pool, 256);

	iter = fts_flatcurve_xapian_query_iter_init(query);
	while (fts_flatcurve_xapian_query_iter_next(iter, &result)) {
		if ((low_uid > 0  && result->uid >= low_uid) ||
		    (low_uid == 0 && !seq_range_exists(&uids, result->uid))) {
			if (fts_flatcurve_xapian_expunge(
				backend, result->uid, error_r) < 0)
				e_error(backend->event, "%s", *error_r);
			else
				seq_range_array_add(&expunged, result->uid);
		}
	}

	ret = fts_flatcurve_xapian_query_iter_deinit(&iter, error_r);
	fts_flatcurve_xapian_destroy_query(query);
	if (ret < 0)
		return -1;

	if (array_is_empty(&expunged)) {
		e_debug(e->add_str("status", "ok")->event(),
			"Rescan: no issues found");
	} else T_BEGIN {
		const char *u = fts_backend_flatcurve_seq_range_string(&expunged);
		e->add_str("expunged", u);

		if (low_uid > 0) {
			const char *u2 = fts_backend_flatcurve_seq_range_string(&missing);
			e_debug(e->add_str("status", "missing_msgs")->
				add_str("uids", u2)->event(),
				"Rescan: missing messages uids=%s expunged=%s",
				u2, u);
		} else {
			e_debug(e->add_str("status", "expunge_msgs")->event(),
				"Rescan: expunge non-existent messages "
				"expunged=%s", u);
		}
	} T_END;
	return 0;
}

static int
fts_backend_flatcurve_iterate_ns(struct fts_backend *_backend,
				 enum fts_backend_flatcurve_action act)
{
	const char *error;
	struct flatcurve_fts_backend *backend =
		(struct flatcurve_fts_backend *)_backend;
	struct mailbox *box;
	const struct mailbox_info *info;
	struct mailbox_list_iterate_context *iter;
	const enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_NO_AUTO_BOXES |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	enum mailbox_flags mbox_flags = 0;
	pool_t pool = NULL;

	bool failed = FALSE;
	iter = mailbox_list_iter_init(_backend->ns->list, "*", iter_flags);
	while ((info = mailbox_list_iter_next(iter)) != NULL) {
		box = mailbox_alloc(backend->backend.ns->list, info->vname,
				    mbox_flags);

		if (fts_backend_flatcurve_set_mailbox(
			backend, box, &error) < 0) {
			e_error(backend->event, "%s", error);
			failed = TRUE;
			continue;
		}

		switch (act) {
		case FTS_BACKEND_FLATCURVE_ACTION_OPTIMIZE:
			if (fts_flatcurve_xapian_optimize_box(
				backend, &error) < 0) {
				e_error(backend->event, "%s", error);
				failed = TRUE;
			}
			break;
		case FTS_BACKEND_FLATCURVE_ACTION_RESCAN:
			if (pool == NULL)
				pool = pool_alloconly_create(
					FTS_FLATCURVE_LABEL " rescan pool",
					4096);
			if (fts_backend_flatcurve_rescan_box(
				backend, box, pool, &error) < 0) {
				e_error(backend->event, "%s", error);
				failed = TRUE;
			}
			p_clear(pool);
			break;
		}

		mailbox_free(&box);
	}
	if (mailbox_list_iter_deinit(&iter) < 0)
		e_error(backend->event, "%s",
			mailbox_list_get_last_internal_error(
				_backend->ns->list, NULL));

	pool_unref(&pool);

	return failed ? -1 : 0;
}

static int fts_backend_flatcurve_optimize(struct fts_backend *backend)
{
	return fts_backend_flatcurve_iterate_ns(backend,
			FTS_BACKEND_FLATCURVE_ACTION_OPTIMIZE);
}

static int fts_backend_flatcurve_rescan(struct fts_backend *backend)
{
	return fts_backend_flatcurve_iterate_ns(backend,
			FTS_BACKEND_FLATCURVE_ACTION_RESCAN);
}

static int
fts_backend_flatcurve_lookup_multi(struct fts_backend *_backend,
				   struct mailbox *const boxes[],
				   struct mail_search_arg *args,
				   enum fts_lookup_flags flags,
				   struct fts_multi_result *result)
{
	const char *error;
	struct flatcurve_fts_backend *backend =
		(struct flatcurve_fts_backend *)_backend;
	ARRAY(struct fts_result) box_results;
	struct flatcurve_fts_result *fresult;
	unsigned int i;
	struct flatcurve_fts_query *query;
	struct fts_result *r;
	int ret = 0;

	/* Create query */
	query = fts_backend_flatcurve_create_query(backend, result->pool);
	query->args = args;
	query->flags = flags;
	fts_flatcurve_xapian_build_query(query);

	p_array_init(&box_results, result->pool, 8);
	for (i = 0; boxes[i] != NULL; i++) {
		r = array_append_space(&box_results);
		r->box = boxes[i];

		fresult = p_new(result->pool, struct flatcurve_fts_result, 1);
		p_array_init(&fresult->scores, result->pool, 32);
		p_array_init(&fresult->uids, result->pool, 32);

		if (fts_backend_flatcurve_set_mailbox(backend, r->box, &error) < 0) {
			ret = -1;
			break;
		}

		if (fts_flatcurve_xapian_run_query(query, fresult, &error) < 0) {
			ret = -1;
			break;
		}

		if ((query->maybe) ||
		    ((flags & FTS_LOOKUP_FLAG_NO_AUTO_FUZZY) != 0))
			r->maybe_uids = fresult->uids;
		else
			r->definite_uids = fresult->uids;
		r->scores = fresult->scores;

		if (str_len(query->qtext) == 0) {
			/* This was an empty query - skip output of debug info. */
			continue;
		}

		T_BEGIN {
			const char *u = fts_backend_flatcurve_seq_range_string(&fresult->uids);
			e_debug(event_create_passthrough(backend->event)->
				set_name("fts_flatcurve_query")->
				add_int("count", array_count(&fresult->uids))->
				add_str("mailbox", r->box->vname)->
				add_str("maybe", query->maybe ? "yes" : "no")->
				add_str("query", str_c(query->qtext))->
				add_str("uids", u)->event(), "Query (%s) "
				"%smatches=%d uids=%s", str_c(query->qtext),
				query->maybe ? "maybe_" : "",
				array_count(&fresult->uids), u);
		} T_END;
	}

	if (ret == 0) {
		array_append_zero(&box_results);
		result->box_results = array_idx_modifiable(&box_results, 0);
	} else {
		e_error(backend->event, "%s", error);
	}

	fts_flatcurve_xapian_destroy_query(query);
	return ret;
}

static int
fts_backend_flatcurve_lookup(struct fts_backend *_backend, struct mailbox *box,
			     struct mail_search_arg *args,
			     enum fts_lookup_flags flags,
			     struct fts_result *result)
{
	struct mailbox *boxes[2];
	struct fts_multi_result multi_result;
	const struct fts_result *br;
	int ret;

	boxes[0] = box;
	boxes[1] = NULL;

	i_zero(&multi_result);
	multi_result.pool = pool_alloconly_create(FTS_FLATCURVE_LABEL
						  " results pool", 4096);
	ret = fts_backend_flatcurve_lookup_multi(_backend, boxes, args,
						 flags, &multi_result);

	if ((ret == 0) &&
	    (multi_result.box_results != NULL) &&
	    (multi_result.box_results[0].box != NULL)) {
		br = &multi_result.box_results[0];
		result->box = br->box;
		if (array_is_created(&br->definite_uids))
			array_append_array(&result->definite_uids,
					   &br->definite_uids);
		if (array_is_created(&br->maybe_uids))
			array_append_array(&result->maybe_uids,
					   &br->maybe_uids);
		array_append_array(&result->scores, &br->scores);
		result->scores_sorted = TRUE;
	}
	pool_unref(&multi_result.pool);

	return ret;
}

/* Returns: 0 if FTS directory doesn't exist, 1 on deletion, -1 on error */
int fts_backend_flatcurve_delete_dir(const char *path, const char **error_r)
{
	struct stat st;
	enum unlink_directory_flags unlink_flags = UNLINK_DIRECTORY_FLAG_RMDIR;

	if (stat(path, &st) < 0) {
		if (errno == ENOENT)
			return 0;
		else {
			*error_r = t_strdup_printf("Deleting fts data failed: "
				"stat(%s) failed: %m", path);
			return -1;
		}
	}

	if (S_ISDIR(st.st_mode)) {
		if (unlink_directory(path, unlink_flags, error_r) < 0) {
			*error_r = t_strdup_printf("Deleting fts data failed: "
				"unlink_directory(%s) failed: %s", path, *error_r);
			return -1;
		}
	} else if (unlink(path) < 0) {
		*error_r = t_strdup_printf("Deleting fts data failed: "
			"unlink(%s) failed: %m", path);
		return -1;
	}

	return 1;
}


struct fts_backend fts_backend_flatcurve = {
	.name = "flatcurve",
	.flags = FTS_BACKEND_FLAG_TOKENIZED_INPUT,
	.v = {
		.alloc = fts_backend_flatcurve_alloc,
		.init = fts_backend_flatcurve_init,
		.deinit = fts_backend_flatcurve_deinit,
		.get_last_uid = fts_backend_flatcurve_get_last_uid,
		.update_init = fts_backend_flatcurve_update_init,
		.update_deinit = fts_backend_flatcurve_update_deinit,
		.update_set_mailbox = fts_backend_flatcurve_update_set_mailbox,
		.update_expunge = fts_backend_flatcurve_update_expunge,
		.update_set_build_key = fts_backend_flatcurve_update_set_build_key,
		.update_unset_build_key = fts_backend_flatcurve_update_unset_build_key,
		.update_build_more = fts_backend_flatcurve_update_build_more,
		.refresh = fts_backend_flatcurve_refresh,
		.rescan = fts_backend_flatcurve_rescan,
		.optimize = fts_backend_flatcurve_optimize,
		.can_lookup = fts_backend_default_can_lookup,
		.lookup = fts_backend_flatcurve_lookup,
		.lookup_multi = fts_backend_flatcurve_lookup_multi,
		.lookup_done = NULL,
	}
};
