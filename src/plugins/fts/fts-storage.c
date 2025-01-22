/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "str.h"
#include "strescape.h"
#include "write-full.h"
#include "settings.h"
#include "mail-search-build.h"
#include "mail-storage.h"
#include "mailbox-list-private.h"
#include "fts-api-private.h"
#include "lang-tokenizer.h"
#include "fts-indexer.h"
#include "fts-build-mail.h"
#include "fts-search-serialize.h"
#include "fts-plugin.h"
#include "fts-user.h"
#include "fts-storage.h"
#include "hash.h"
#include "fts-user.h"


#define FTS_CONTEXT(obj) \
	MODULE_CONTEXT(obj, fts_storage_module)
#define FTS_CONTEXT_REQUIRE(obj) \
	MODULE_CONTEXT_REQUIRE(obj, fts_storage_module)
#define FTS_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT_REQUIRE(obj, fts_mail_module)
#define FTS_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, fts_mailbox_list_module)
#define FTS_LIST_CONTEXT_REQUIRE(obj) \
	MODULE_CONTEXT_REQUIRE(obj, fts_mailbox_list_module)

#define INDEXER_SOCKET_NAME "indexer"
#define INDEXER_HANDSHAKE "VERSION\tindexer-client\t1\t0\n"

struct fts_mailbox_list {
	union mailbox_list_module_context module_ctx;
	struct fts_backend *backend;
	struct fts_backend_update_context *update_ctx;
	unsigned int update_ctx_refcount;

	bool failed:1;
};

struct fts_mailbox {
	union mailbox_module_context module_ctx;
	const struct fts_settings *set;
	struct fts_backend_update_context *sync_update_ctx;
};

struct fts_transaction_context {
	union mailbox_transaction_module_context module_ctx;

	struct fts_scores *scores;
	uint32_t highest_virtual_uid;
	unsigned int precache_extra_count;

	bool indexing:1;
	bool precached:1;
	bool mails_saved:1;
	const char *failure_reason;
};

struct fts_mail {
	union mail_module_context module_ctx;
	char score[30];

	bool virtual_mail:1;
};

static MODULE_CONTEXT_DEFINE_INIT(fts_storage_module,
				  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(fts_mail_module, &mail_module_register);
static MODULE_CONTEXT_DEFINE_INIT(fts_mailbox_list_module,
				  &mailbox_list_module_register);

static int fts_mailbox_get_last_indexed_uid(struct mailbox *box, uint32_t *uid_r)
{
	struct fts_mailbox_list *flist = FTS_LIST_CONTEXT_REQUIRE(box->list);
	int ret = fts_search_get_first_missing_uid(flist->backend, box, uid_r);
	if (ret < 0) {
		mail_storage_set_internal_error(box->storage);
		return -1;
	}
	return 0;
}

int fts_mailbox_get_status(struct mailbox *box, enum mailbox_status_items items,
			   struct mailbox_status *status_r)
{
	struct fts_mailbox *fbox = FTS_CONTEXT_REQUIRE(box);
	if (fbox->module_ctx.super.get_status(
			box, items & ENUM_NEGATE(STATUS_FTS_LAST_INDEXED_UID),
			status_r) < 0)
		return -1;

	if ((items & STATUS_FTS_LAST_INDEXED_UID) != 0 &&
	    fts_mailbox_get_last_indexed_uid(
			box, &status_r->fts_last_indexed_uid) < 0)
		return -1;

	return 0;
}

static void fts_scores_unref(struct fts_scores **_scores)
{
	struct fts_scores *scores = *_scores;

	*_scores = NULL;
	if (--scores->refcount == 0) {
		array_free(&scores->score_map);
		i_free(scores);
	}
}

static void fts_try_build_init(struct mail_search_context *ctx,
			       struct fts_search_context *fctx)
{
	int ret;

	i_assert(!fts_backend_is_updating(fctx->backend));

	ret = fts_indexer_init(fctx->backend, ctx->transaction->box,
			       &fctx->indexer_ctx);
	if (ret < 0)
		return;

	if (ret == 0) {
		/* the index was up to date */
		fts_search_lookup(fctx);
	} else {
		/* hide "searching" notifications while building index */
		mailbox_search_set_progress_hidden(ctx, TRUE);
	}
}

static bool fts_want_build_args(const struct mail_search_arg *args)
{
	/* we want to update index only when searching from message body.
	   it's not worth the wait for searching only from headers, which
	   could be in cache file already */
	for (; args != NULL; args = args->next) {
		switch (args->type) {
		case SEARCH_OR:
		case SEARCH_SUB:
		case SEARCH_INTHREAD:
			if (fts_want_build_args(args->value.subargs))
				return TRUE;
			break;
		case SEARCH_BODY:
		case SEARCH_TEXT:
			if (!args->no_fts)
				return TRUE;
			break;
		default:
			break;
		}
	}
	return FALSE;
}

static struct mail_search_context *
fts_mailbox_search_init(struct mailbox_transaction_context *t,
			struct mail_search_args *args,
			const enum mail_sort_type *sort_program,
			enum mail_fetch_field wanted_fields,
			struct mailbox_header_lookup_ctx *wanted_headers)
{
	struct fts_transaction_context *ft = FTS_CONTEXT_REQUIRE(t);
	struct fts_mailbox *fbox = FTS_CONTEXT_REQUIRE(t->box);
	struct fts_mailbox_list *flist = FTS_LIST_CONTEXT_REQUIRE(t->box->list);
	struct mail_search_context *ctx;
	struct fts_search_context *fctx;

	ctx = fbox->module_ctx.super.search_init(t, args, sort_program,
						 wanted_fields, wanted_headers);

	if (!fbox->set->search ||
	    !fts_backend_can_lookup(flist->backend, args->args))
		return ctx;

	fctx = i_new(struct fts_search_context, 1);
	fctx->box = t->box;
	fctx->backend = flist->backend;
	fctx->t = t;
	fctx->args = args;
	fctx->result_pool = pool_alloconly_create("fts results", 1024*64);
	fctx->orig_matches = buffer_create_dynamic(default_pool, 64);
	fctx->virtual_mailbox = t->box->virtual_vfuncs != NULL;
	if (fctx->virtual_mailbox) {
		hash_table_create(&fctx->last_indexed_virtual_uids,
				  default_pool, 0, str_hash, strcmp);
	}
	i_array_init(&fctx->levels, 8);
	fctx->scores = i_new(struct fts_scores, 1);
	fctx->scores->refcount = 1;
	i_array_init(&fctx->scores->score_map, 64);
	MODULE_CONTEXT_SET(ctx, fts_storage_module, fctx);

	/* transaction contains the last search's scores. they can be
	   queried later with mail_get_special() */
	if (ft->scores != NULL)
		fts_scores_unref(&ft->scores);
	ft->scores = fctx->scores;
	ft->scores->refcount++;

	if (!fbox->set->parsed_search_add_missing_body_only ||
	    fts_want_build_args(args->args))
		fts_try_build_init(ctx, fctx);
	else
		fts_search_lookup(fctx);
	return ctx;
}

static bool fts_mailbox_build_continue(struct mail_search_context *ctx)
{
	struct fts_search_context *fctx = FTS_CONTEXT_REQUIRE(ctx);
	int ret;

	ret = fts_indexer_more(fctx->indexer_ctx);
	if (ret == 0)
		return FALSE;

	/* indexing finished */
	mailbox_search_set_progress_hidden(ctx, FALSE);
	mailbox_search_reset_progress_start(ctx);
	if (fts_indexer_deinit(&fctx->indexer_ctx) < 0)
		ret = -1;
	if (ret > 0)
		fts_search_lookup(fctx);
	if (ret < 0) {
		/* if indexing timed out, it probably means that
		   the mailbox is still being indexed, but it's a large
		   mailbox and it takes a while. in this situation
		   we'll simply abort the search.

		   if indexing failed for any other reason, just
		   fallback to searching the slow way. */
		fctx->indexing_timed_out =
			mailbox_get_last_mail_error(fctx->box) == MAIL_ERROR_INUSE;
	}
	return TRUE;
}

static bool
fts_mailbox_search_next_nonblock(struct mail_search_context *ctx,
				 struct mail **mail_r, bool *tryagain_r)
{
	struct mailbox *box = ctx->transaction->box;
	struct fts_mailbox *fbox = FTS_CONTEXT_REQUIRE(box);
	struct fts_search_context *fctx = FTS_CONTEXT(ctx);

	if (fctx != NULL && fctx->indexer_ctx != NULL) {
		/* this command is still building the indexes */
		if (!fts_mailbox_build_continue(ctx)) {
			*tryagain_r = TRUE;
			return FALSE;
		}
		if (fctx->indexing_timed_out || fctx->mailbox_failed) {
			*tryagain_r = FALSE;
			return FALSE;
		}
	}
	if (fctx != NULL && !fctx->fts_lookup_success &&
	    !fbox->set->search_read_fallback)
		return FALSE;

	return fbox->module_ctx.super.
		search_next_nonblock(ctx, mail_r, tryagain_r);
}

static void
fts_search_apply_results_level(struct mail_search_context *ctx,
			       struct mail_search_arg *args, unsigned int *idx)
{
	struct fts_search_context *fctx = FTS_CONTEXT_REQUIRE(ctx);
	const struct fts_search_level *level;

	level = array_idx(&fctx->levels, *idx);

	if (array_is_created(&level->definite_seqs) &&
	    seq_range_exists(&level->definite_seqs, ctx->seq))
		fts_search_deserialize_add_matches(args, level->args_matches);
	else if (!array_is_created(&level->maybe_seqs) ||
		 !seq_range_exists(&level->maybe_seqs, ctx->seq))
		fts_search_deserialize_add_nonmatches(args, level->args_matches);

	for (; args != NULL; args = args->next) {
		if (args->type != SEARCH_OR && args->type != SEARCH_SUB)
			continue;

		*idx += 1;
		fts_search_apply_results_level(ctx, args->value.subargs, idx);
	}
}

/* Returns 1 if already indexed,
   Returns 0 if not yet indexed,
   Returns -1 if not cached at all. */
static int
fts_search_virtual_uid_is_indexed(struct fts_search_context *fctx,
				  const char *backend_vname, uint32_t backend_uid)
{
	HASH_TABLE_TYPE(virtual_last_indexed) *table =
		&fctx->last_indexed_virtual_uids;

	const char *vname;
	void *prev_value;
	if (!hash_table_lookup_full(*table, backend_vname, &vname, &prev_value))
		return -1;

	uint32_t prev_uid = POINTER_CAST_TO(prev_value, uint32_t);
	return backend_uid <= prev_uid ? 1 : 0;
}

static void
fts_search_virtual_uid_set_indexed(struct fts_search_context *fctx,
				   const char *backend_vname, uint32_t backend_uid)
{
	HASH_TABLE_TYPE(virtual_last_indexed) *table =
		&fctx->last_indexed_virtual_uids;

	const char *vname;
	void *prev_value;
	if (!hash_table_lookup_full(*table, backend_vname, &vname, &prev_value)) {
  		vname = p_strdup(fctx->result_pool, backend_vname);
		prev_value = NULL;
	}

	uint32_t prev_uid = POINTER_CAST_TO(prev_value, uint32_t);
  	if (backend_uid > prev_uid)
		hash_table_update(*table, backend_vname, POINTER_CAST(backend_uid));
}

static int
fts_mailbox_search_is_virtual_seq_indexed(struct fts_search_context *fctx,
					  uint32_t seq)
{
	const struct virtual_mailbox_vfuncs *v = fctx->box->virtual_vfuncs;
	struct mailbox *backend_box;
	uint32_t backend_uid;
	v->get_virtual_backend_mail_uid(fctx->box, seq, &backend_box, &backend_uid);

	const char *backend_vname = backend_box->vname;
	int ret = fts_search_virtual_uid_is_indexed(fctx, backend_vname, backend_uid);
	if (ret >= 0)
		return ret;

	struct mailbox_status status;
	if (mailbox_get_status(backend_box, STATUS_FTS_LAST_INDEXED_UID,
			       &status) < 0)
		return -1;

	fts_search_virtual_uid_set_indexed(fctx, backend_vname,
					   status.fts_last_indexed_uid);

	return backend_uid <= status.fts_last_indexed_uid ? 1 : 0;
}

static int
fts_mailbox_search_is_seq_indexed(struct fts_search_context *fctx, uint32_t seq)
{
	const struct virtual_mailbox_vfuncs *v = fctx->box->virtual_vfuncs;
	if (v == NULL)
		return seq < fctx->first_unindexed_seq ? 1 : 0;
	return fts_mailbox_search_is_virtual_seq_indexed(fctx, seq);
}

static bool fts_mailbox_search_next_update_seq(struct mail_search_context *ctx)
{
	struct fts_mailbox *fbox = FTS_CONTEXT_REQUIRE(ctx->transaction->box);
	struct fts_search_context *fctx = FTS_CONTEXT(ctx);
	unsigned int idx;

	if (fctx == NULL || !fctx->fts_lookup_success) {
		/* fts lookup not done for this search */
		if (fctx != NULL &&
		    (fctx->indexing_timed_out || fctx->mailbox_failed))
			return FALSE;
		return fbox->module_ctx.super.search_next_update_seq(ctx);
	}

	/* restore original [non]matches */
	fts_search_deserialize(ctx->args->args, fctx->orig_matches);

	if (!fbox->module_ctx.super.search_next_update_seq(ctx))
		return FALSE;

	int ret = fts_mailbox_search_is_seq_indexed(fctx, ctx->seq);
	if (ret < 0) {
		fctx->mailbox_failed = TRUE;
		return FALSE;
	}
	if (ret == 0)
		return TRUE;

	/* apply [non]matches based on the FTS lookup results */
	idx = 0;
	fts_search_apply_results_level(ctx, ctx->args->args, &idx);
	return TRUE;
}

static int fts_mailbox_search_deinit(struct mail_search_context *ctx)
{
	struct mailbox *box = ctx->transaction->box;
	struct fts_mailbox *fbox = FTS_CONTEXT_REQUIRE(box);
	struct fts_transaction_context *ft = FTS_CONTEXT_REQUIRE(ctx->transaction);
	struct fts_search_context *fctx = FTS_CONTEXT(ctx);
	int ret = 0;

	if (fctx != NULL) {
		if (fctx->virtual_mailbox)
			hash_table_destroy(&fctx->last_indexed_virtual_uids);
		if (fctx->indexer_ctx != NULL) {
			if (fts_indexer_deinit(&fctx->indexer_ctx) < 0)
				ft->failure_reason = "FTS indexing failed";
		}
		if (fctx->indexing_timed_out || fctx->mailbox_failed)
			ret = -1;
		else if (fctx->mailbox_failed) {
			mail_storage_set_internal_error(box->storage);
			ret = -1;
		}
		else if (!fctx->fts_lookup_success &&
			 !fbox->set->search_read_fallback) {
			/* FTS lookup failed and we didn't want to fallback to
			   opening all the mails and searching manually */
			mail_storage_set_internal_error(box->storage);
			ret = -1;
		}

		buffer_free(&fctx->orig_matches);
		array_free(&fctx->levels);
		pool_unref(&fctx->result_pool);
		fts_scores_unref(&fctx->scores);
		i_free(fctx);
	}
	if (fbox->module_ctx.super.search_deinit(ctx) < 0)
		ret = -1;
	return ret;
}

static int fts_score_cmp(const uint32_t *uid, const struct fts_score_map *score)
{
	return *uid < score->uid ? -1 :
		(*uid > score->uid ? 1 : 0);
}

static int fts_mail_get_special(struct mail *_mail, enum mail_fetch_field field,
				const char **value_r)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	struct fts_mail *fmail = FTS_MAIL_CONTEXT(mail);
	struct fts_transaction_context *ft = FTS_CONTEXT_REQUIRE(_mail->transaction);
	const struct fts_score_map *scores;

	if (field != MAIL_FETCH_SEARCH_RELEVANCY || ft->scores == NULL)
		scores = NULL;
	else {
		scores = array_bsearch(&ft->scores->score_map, &_mail->uid,
				       fts_score_cmp);
	}
	if (scores != NULL) {
		i_assert(scores->uid == _mail->uid);
		(void)i_snprintf(fmail->score, sizeof(fmail->score),
				 "%f", scores->score);

		*value_r = fmail->score;
		return 0;
	}

	return fmail->module_ctx.super.get_special(_mail, field, value_r);
}

static int fts_mail_precache_init(struct mail *_mail)
{
	struct fts_transaction_context *ft = FTS_CONTEXT_REQUIRE(_mail->transaction);
	struct fts_mailbox_list *flist = FTS_LIST_CONTEXT_REQUIRE(_mail->box->list);

	uint32_t last_uid;
	if (fts_mailbox_get_last_indexed_uid(_mail->box,&last_uid) < 0) {
		ft->failure_reason = "Failed to lookup last indexed FTS mail";
		return -1;
	}

	uint32_t last_seq = 0, unused ATTR_UNUSED;
	if (last_uid > 0)
		mailbox_get_seq_range(_mail->box, 1, last_uid, &unused, &last_seq);

	ft->precached = TRUE;
	if (flist->update_ctx == NULL)
		flist->update_ctx = fts_backend_update_init(flist->backend);
	flist->update_ctx_refcount++;
	return 0;
}

static int fts_mail_index(struct mail *_mail)
{
	struct fts_transaction_context *ft = FTS_CONTEXT_REQUIRE(_mail->transaction);
	struct fts_mailbox_list *flist = FTS_LIST_CONTEXT_REQUIRE(_mail->box->list);
	struct mail_private *pmail = (struct mail_private *)_mail;

	i_assert(pmail->vmail == NULL);
	if (ft->failure_reason != NULL)
		return -1;

	if (!ft->precached) {
		if (fts_mail_precache_init(_mail) < 0)
			return -1;
	}

	fts_backend_update_set_mailbox(flist->update_ctx, _mail->box);
	return fts_build_mail(flist->update_ctx, _mail) < 0 ? -1 : 0;
}

static int fts_mail_precache(struct mail *_mail)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	struct fts_mail *fmail = FTS_MAIL_CONTEXT(mail);
	struct fts_transaction_context *ft = FTS_CONTEXT_REQUIRE(_mail->transaction);
	int ret;

	i_assert(!fmail->virtual_mail);
	if (fmail->module_ctx.super.precache(_mail) < 0)
		return -1;

	i_assert(!ft->indexing);
	T_BEGIN {
		struct event_reason *reason =
			event_reason_begin("fts:index");
		ft->indexing = TRUE;
		ret = fts_mail_index(_mail);
		i_assert(ft->indexing);
		ft->indexing = FALSE;
		event_reason_end(&reason);
	} T_END;
	return ret;
}

void fts_mail_allocated(struct mail *_mail)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	struct mail_vfuncs *v = mail->vlast;
	struct fts_mailbox *fbox = FTS_CONTEXT(_mail->box);
	struct fts_mail *fmail;

	if (fbox == NULL)
		return;

	fmail = p_new(mail->pool, struct fts_mail, 1);
	fmail->module_ctx.super = *v;
	mail->vlast = &fmail->module_ctx.super;
	fmail->virtual_mail = _mail->box->virtual_vfuncs != NULL;

	v->get_special = fts_mail_get_special;
	v->precache = fts_mail_precache;
	MODULE_CONTEXT_SET(mail, fts_mail_module, fmail);
}

static struct mailbox_transaction_context *
fts_transaction_begin(struct mailbox *box,
		      enum mailbox_transaction_flags flags,
		      const char *reason)
{
	struct fts_mailbox *fbox = FTS_CONTEXT_REQUIRE(box);
	struct mailbox_transaction_context *t;
	struct fts_transaction_context *ft;

	ft = i_new(struct fts_transaction_context, 1);

	t = fbox->module_ctx.super.transaction_begin(box, flags, reason);
	MODULE_CONTEXT_SET(t, fts_storage_module, ft);
	return t;
}

static int fts_transaction_end(struct mailbox_transaction_context *t, const char **error_r)
{
	struct fts_transaction_context *ft = FTS_CONTEXT_REQUIRE(t);
	struct fts_mailbox_list *flist = FTS_LIST_CONTEXT_REQUIRE(t->box->list);
	struct event *event = flist->backend->event;
	int ret = 0;

	if (ft->failure_reason != NULL) {
		*error_r = t_strdup(ft->failure_reason);
		ret = -1;
	}

	struct event_reason *reason = event_reason_begin("fts:index");
	if (ft->precached) {
		i_assert(flist->update_ctx_refcount > 0);
		if (--flist->update_ctx_refcount == 0) {
			if (fts_backend_update_deinit(&flist->update_ctx) < 0) {
				ret = -1;
				*error_r = "backend deinit";
			}
		}
	} else if (ft->highest_virtual_uid > 0) {
		if (fts_index_set_last_uid(t->box, ft->highest_virtual_uid) < 0) {
			ret = -1;
			*error_r = "index last uid setting";
		}
	}
	if (ft->scores != NULL)
		fts_scores_unref(&ft->scores);
	if (ft->precache_extra_count > 0) {
		if (ret < 0) {
			e_error(event,
				"Failed after indexing %u extra mails internally in %s: %s",
			        ft->precache_extra_count, t->box->vname, *error_r);
		} else {
			e_debug(event,
				"Indexed %u extra mails internally in %s",
				ft->precache_extra_count, t->box->vname);
		}
	}
	event_reason_end(&reason);
	i_free(ft);
	return ret;
}

static void fts_transaction_rollback(struct mailbox_transaction_context *t)
{
	struct fts_mailbox *fbox = FTS_CONTEXT_REQUIRE(t->box);
	const char *error;

	(void)fts_transaction_end(t, &error);
	fbox->module_ctx.super.transaction_rollback(t);
}

static void fts_queue_index(struct mailbox *box)
{
	struct mail_user *user = box->storage->user;
	struct fts_mailbox *fbox = FTS_CONTEXT_REQUIRE(box);
	string_t *str = t_str_new(256);
	const char *path;
	int fd;

	path = t_strconcat(user->set->base_dir, "/"INDEXER_SOCKET_NAME, NULL);
	fd = net_connect_unix(path);
	if (fd == -1) {
		e_error(box->event, "net_connect_unix(%s) failed: %m", path);
		return;
	}

	str_append(str, INDEXER_HANDSHAKE);
	str_append(str, "APPEND\t0\t");
	str_append_tabescaped(str, user->username);
	str_append_c(str, '\t');
	str_append_tabescaped(str, box->vname);
	str_printfa(str, "\t%u", fbox->set->autoindex_max_recent_msgs);
	str_append_c(str, '\t');
	str_append_tabescaped(str, box->storage->user->session_id);
	str_append_c(str, '\n');
	if (write_full(fd, str_data(str), str_len(str)) < 0)
		e_error(box->event, "write(%s) failed: %m", path);
	i_close_fd(&fd);
}

static int
fts_transaction_commit(struct mailbox_transaction_context *t,
		       struct mail_transaction_commit_changes *changes_r)
{
	struct mailbox *box = t->box;
	struct fts_transaction_context *ft = FTS_CONTEXT_REQUIRE(t);
	struct fts_mailbox *fbox = FTS_CONTEXT_REQUIRE(box);
	bool autoindex;
	int ret = 0;
	const char *error;

	autoindex = ft->mails_saved && fbox->set->autoindex &&
		fbox->set->search;

	if (fts_transaction_end(t, &error) < 0) {
		mail_storage_set_error(t->box->storage, MAIL_ERROR_TEMP,
				       t_strdup_printf("FTS transaction commit failed: %s",
						       error));
		ret = -1;
	}
	if (fbox->module_ctx.super.transaction_commit(t, changes_r) < 0)
		ret = -1;
	if (ret < 0)
		return -1;

	if (autoindex)
		fts_queue_index(box);
	return 0;
}

static void fts_mailbox_sync_notify(struct mailbox *box, uint32_t uid,
				    enum mailbox_sync_type sync_type)
{
	struct fts_mailbox_list *flist = FTS_LIST_CONTEXT_REQUIRE(box->list);
	struct fts_mailbox *fbox = FTS_CONTEXT_REQUIRE(box);

	if (fbox->module_ctx.super.sync_notify != NULL)
		fbox->module_ctx.super.sync_notify(box, uid, sync_type);

	if (sync_type != MAILBOX_SYNC_TYPE_EXPUNGE) {
		if (uid == 0 && fbox->sync_update_ctx != NULL) {
			/* this sync is finished */
			(void)fts_backend_update_deinit(&fbox->sync_update_ctx);
		}
		return;
	}

	if (fbox->sync_update_ctx == NULL) {
		if (fts_backend_is_updating(flist->backend)) {
			/* FIXME: maildir workaround - we could get here
			   because we're building an index, which doesn't find
			   some mail and starts syncing the mailbox.. */
			return;
		}
		fbox->sync_update_ctx = fts_backend_update_init(flist->backend);
		fts_backend_update_set_mailbox(fbox->sync_update_ctx, box);
	}
	fts_backend_update_expunge(fbox->sync_update_ctx, uid);
}

static int fts_sync_deinit(struct mailbox_sync_context *ctx,
			   struct mailbox_sync_status *status_r)
{
	struct mailbox *box = ctx->box;
	struct fts_mailbox *fbox = FTS_CONTEXT_REQUIRE(box);
	struct fts_mailbox_list *flist = FTS_LIST_CONTEXT(box->list);
	bool optimize;
	int ret = 0;

	optimize = (ctx->flags & (MAILBOX_SYNC_FLAG_FORCE_RESYNC |
				  MAILBOX_SYNC_FLAG_OPTIMIZE)) != 0;
	if (fbox->module_ctx.super.sync_deinit(ctx, status_r) < 0)
		return -1;
	ctx = NULL;

	if (optimize) {
		i_assert(flist != NULL);
		if (fts_backend_optimize(flist->backend) < 0) {
			mailbox_set_critical(box, "FTS optimize failed");
			ret = -1;
		}
	}
	return ret;
}

static int fts_save_finish(struct mail_save_context *ctx)
{
	struct fts_transaction_context *ft = FTS_CONTEXT_REQUIRE(ctx->transaction);
	struct fts_mailbox *fbox = FTS_CONTEXT_REQUIRE(ctx->transaction->box);

	if (fbox->module_ctx.super.save_finish(ctx) < 0)
		return -1;
	ft->mails_saved = TRUE;
	return 0;
}

static int fts_copy(struct mail_save_context *ctx, struct mail *mail)
{
	struct fts_transaction_context *ft = FTS_CONTEXT_REQUIRE(ctx->transaction);
	struct fts_mailbox *fbox = FTS_CONTEXT_REQUIRE(ctx->transaction->box);

	if (fbox->module_ctx.super.copy(ctx, mail) < 0)
		return -1;
	ft->mails_saved = TRUE;
	return 0;
}

static void fts_mailbox_virtual_match_mail(struct mail_search_context *ctx,
					   struct mail *mail)
{
	struct fts_search_context *fctx = FTS_CONTEXT(ctx);
	if (fctx == NULL || !fctx->fts_lookup_success || !fctx->virtual_mailbox ||
	    ctx->seq < fctx->first_unindexed_seq)
		return;

	struct mail *backend_mail;
	if (mail->box->mail_vfuncs->get_backend_mail(mail, &backend_mail) < 0)
		return;

	if (fts_search_virtual_uid_is_indexed(fctx, backend_mail->box->vname,
					      backend_mail->uid) > 0) {
		/* Mail was already indexed in the backend mailbox.
		   Apply [non]matches based on the FTS lookup results */
		struct fts_transaction_context *ft = FTS_CONTEXT_REQUIRE(ctx->transaction);

		if (fctx->next_unindexed_seq == mail->seq) {
			fctx->next_unindexed_seq++;
			ft->highest_virtual_uid = mail->uid;
		}

		unsigned int idx = 0;
		fts_search_apply_results_level(ctx, ctx->args->args, &idx);
	} else {
		fctx->virtual_seen_unindexed_gaps = TRUE;
	}
}

static int fts_mailbox_search_next_match_mail(struct mail_search_context *ctx,
					      struct mail *mail)
{
	struct fts_mailbox *fbox = FTS_CONTEXT_REQUIRE(ctx->transaction->box);

	fts_mailbox_virtual_match_mail(ctx, mail);
	return fbox->module_ctx.super.search_next_match_mail(ctx, mail);
}

static void fts_mailbox_free(struct mailbox *box)
{
	struct fts_mailbox *fbox = FTS_CONTEXT_REQUIRE(box);
	settings_free(fbox->set);
	fbox->module_ctx.super.free(box);
}

void fts_mailbox_allocated(struct mailbox *box)
{
	struct fts_mailbox_list *flist = FTS_LIST_CONTEXT(box->list);
	struct mailbox_vfuncs *v = box->vlast;
	struct fts_mailbox *fbox;

	if (flist == NULL || flist->failed || flist->backend == NULL)
		return;

	const struct fts_settings *set;
	const char *error;
	if (settings_get(box->event, &fts_setting_parser_info, 0, &set, &error) < 0) {
		e_error(box->event, "%s", error);
		return;
	}

	fbox = p_new(box->pool, struct fts_mailbox, 1);
	fbox->module_ctx.super = *v;
	v->free = fts_mailbox_free;
	fbox->set = set;
	box->vlast = &fbox->module_ctx.super;
	v->get_status = fts_mailbox_get_status;
	v->search_init = fts_mailbox_search_init;
	v->search_next_nonblock = fts_mailbox_search_next_nonblock;
	v->search_next_update_seq = fts_mailbox_search_next_update_seq;
	v->search_deinit = fts_mailbox_search_deinit;
	v->transaction_begin = fts_transaction_begin;
	v->transaction_rollback = fts_transaction_rollback;
	v->transaction_commit = fts_transaction_commit;
	v->sync_notify = fts_mailbox_sync_notify;
	v->sync_deinit = fts_sync_deinit;
	v->save_finish = fts_save_finish;
	v->copy = fts_copy;
	v->search_next_match_mail = fts_mailbox_search_next_match_mail;

	MODULE_CONTEXT_SET(box, fts_storage_module, fbox);
}

static void fts_mailbox_list_deinit(struct mailbox_list *list)
{
	struct fts_mailbox_list *flist = FTS_LIST_CONTEXT_REQUIRE(list);

	if (flist->backend != NULL)
		fts_backend_deinit(&flist->backend);
	flist->module_ctx.super.deinit(list);
}

static void
fts_init_namespace(struct fts_mailbox_list *flist, struct mail_namespace *ns)
{
	struct fts_backend *backend;
	const char *error;

	const struct fts_settings *set = NULL;
	if (settings_get(ns->list->event, &fts_setting_parser_info, 0,
			 &set, &error) < 0) {
		flist->failed = TRUE;
		e_error(ns->list->event, "fts: %s", error);
		return;
	}
	if (array_is_empty(&set->fts)) {
		e_debug(ns->list->event,
			"fts: No fts { .. } named list filter - plugin disabled");
		settings_free(set);
		return;
	}

	const char *fts_name_first =
		t_strdup(array_idx_elem(&set->fts, 0));
	if (array_count(&set->fts) > 1) {
		/* Currently only a single fts is supported */
		const char *fts_name_extra = array_idx_elem(&set->fts, 1);
		e_error(ns->list->event,
			"fts: Extra fts %s { .. } named list filter - "
			"only one is currently supported, and "
			"fts %s { .. } is already set",
			fts_name_extra, fts_name_first);
		flist->failed = TRUE;
		settings_free(set);
		return;
	}

	/* Get settings for the first fts list filter */
	struct event *event = event_create(ns->list->event);
	event_add_str(event, "fts", fts_name_first);
	settings_event_add_list_filter_name(event, "fts", fts_name_first);
	settings_free(set);
	if (settings_get(event, &fts_setting_parser_info, 0,
			 &set, &error) < 0) {
		flist->failed = TRUE;
		e_error(ns->list->event, "fts: %s", error);
		event_unref(&event);
		return;
	}

	if (set->driver[0] == '\0') {
		e_debug(ns->list->event,
			"fts: fts_driver is empty - plugin disabled");
		flist->failed = TRUE;
	} else if (fts_backend_init(set->driver, ns, event, &error, &backend) < 0) {
		flist->failed = TRUE;
		e_error(ns->list->event,
			"fts: Failed to initialize backend '%s': %s",
			set->driver, error);
	} else {
		flist->backend = backend;
		if ((flist->backend->flags & FTS_BACKEND_FLAG_FUZZY_SEARCH) != 0)
			ns->user->fuzzy_search = TRUE;
	}
	event_unref(&event);
	settings_free(set);
}

void fts_mail_namespaces_added(struct mail_namespace *ns)
{
	for(; ns != NULL; ns = ns->next) {
		struct fts_mailbox_list *flist = FTS_LIST_CONTEXT(ns->list);
		if (flist != NULL && !flist->failed && flist->backend == NULL)
			fts_init_namespace(flist, ns);
	}
}

void
fts_mailbox_list_created(struct mailbox_list *list)
{
	const char *path;
	if (!mailbox_list_get_root_path(list, MAILBOX_LIST_PATH_TYPE_INDEX, &path)) {
		e_debug(list->event,
			"fts: Indexes disabled for namespace %s",
			list->ns->set->name);
		return;
	}

	struct fts_mailbox_list *flist;
	struct mailbox_list_vfuncs *v = list->vlast;

	flist = p_new(list->pool, struct fts_mailbox_list, 1);
	flist->module_ctx.super = *v;
	list->vlast = &flist->module_ctx.super;
	v->deinit = fts_mailbox_list_deinit;
	MODULE_CONTEXT_SET(list, fts_mailbox_list_module, flist);
}

struct fts_backend *fts_mailbox_backend(struct mailbox *box)
{
	struct fts_mailbox_list *flist = FTS_LIST_CONTEXT_REQUIRE(box->list);

	return flist->backend;
}

struct fts_backend *fts_list_backend(struct mailbox_list *list)
{
	struct fts_mailbox_list *flist = FTS_LIST_CONTEXT(list);

	return flist == NULL ? NULL : flist->backend;
}

const struct fts_settings *fts_mailbox_get_settings(struct mailbox *box)
{
	struct fts_mailbox *fbox = FTS_CONTEXT_REQUIRE(box);
	return fbox->set;
}
