/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "net.h"
#include "str.h"
#include "strescape.h"
#include "write-full.h"
#include "wildcard-match.h"
#include "mail-search-build.h"
#include "mail-storage-private.h"
#include "mailbox-list-private.h"
#include "fts-api-private.h"
#include "fts-tokenizer.h"
#include "fts-indexer.h"
#include "fts-build-mail.h"
#include "fts-search-serialize.h"
#include "fts-plugin.h"
#include "fts-storage.h"


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
#define INDEXER_HANDSHAKE "VERSION\tindexer\t1\t0\n"

struct fts_mailbox_list {
	union mailbox_list_module_context module_ctx;
	struct fts_backend *backend;

	const char *backend_name;
	struct fts_backend_update_context *update_ctx;
	unsigned int update_ctx_refcount;

	bool failed:1;
};

struct fts_mailbox {
	union mailbox_module_context module_ctx;
	struct fts_backend_update_context *sync_update_ctx;
	bool fts_mailbox_excluded;
};

struct fts_transaction_context {
	union mailbox_transaction_module_context module_ctx;

	struct fts_scores *scores;
	uint32_t next_index_seq;
	uint32_t highest_virtual_uid;
	unsigned int precache_extra_count;

	bool indexing:1;
	bool precached:1;
	bool mails_saved:1;
	bool failed:1;
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

static int fts_mailbox_get_last_cached_seq(struct mailbox *box, uint32_t *seq_r)
{
	struct fts_mailbox_list *flist = FTS_LIST_CONTEXT_REQUIRE(box->list);
	uint32_t seq1, seq2, last_uid;

	if (fts_backend_get_last_uid(flist->backend, box, &last_uid) < 0) {
		mail_storage_set_internal_error(box->storage);
		return -1;
	}

	if (last_uid == 0)
		*seq_r = 0;
	else {
		mailbox_get_seq_range(box, 1, last_uid, &seq1, &seq2);
		*seq_r = seq2;
	}
	return 0;
}

static int
fts_mailbox_get_status(struct mailbox *box, enum mailbox_status_items items,
		       struct mailbox_status *status_r)
{
	struct fts_mailbox *fbox = FTS_CONTEXT_REQUIRE(box);
	uint32_t seq;

	if (fbox->module_ctx.super.get_status(box, items, status_r) < 0)
		return -1;

	if ((items & STATUS_LAST_CACHED_SEQ) != 0) {
		if (fts_mailbox_get_last_cached_seq(box, &seq) < 0)
			return -1;

		/* Always use the FTS's last_cached_seq. This is because we
		   don't want to reindex all mails to FTS if .cache file is
		   deleted. */
		status_r->last_cached_seq = seq;
	}
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
		ctx->progress_hidden = TRUE;
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

static bool fts_args_have_fuzzy(const struct mail_search_arg *args)
{
	for (; args != NULL; args = args->next) {
		if (args->fuzzy)
			return TRUE;
		switch (args->type) {
		case SEARCH_OR:
		case SEARCH_SUB:
		case SEARCH_INTHREAD:
			if (fts_args_have_fuzzy(args->value.subargs))
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

	if (!fts_backend_can_lookup(flist->backend, args->args))
		return ctx;

	fctx = i_new(struct fts_search_context, 1);
	fctx->box = t->box;
	fctx->backend = flist->backend;
	fctx->t = t;
	fctx->args = args;
	fctx->result_pool = pool_alloconly_create("fts results", 1024*64);
	fctx->orig_matches = buffer_create_dynamic(default_pool, 64);
	fctx->virtual_mailbox = t->box->virtual_vfuncs != NULL;
	fctx->enforced =
		mail_user_plugin_getenv_bool(t->box->storage->user,
					"fts_enforced");
	i_array_init(&fctx->levels, 8);
	fctx->scores = i_new(struct fts_scores, 1);
	fctx->scores->refcount = 1;
	i_array_init(&fctx->scores->score_map, 64);
	MODULE_CONTEXT_SET(ctx, fts_storage_module, fctx);

	/* FIXME: we'll assume that all the args are fuzzy. not good,
	   but would require much more work to fix it. */
	if (!fts_args_have_fuzzy(args->args) &&
	    mail_user_plugin_getenv_bool(t->box->storage->user,
				    "fts_no_autofuzzy"))
		fctx->flags |= FTS_LOOKUP_FLAG_NO_AUTO_FUZZY;
	/* transaction contains the last search's scores. they can be
	   queried later with mail_get_special() */
	if (ft->scores != NULL)
		fts_scores_unref(&ft->scores);
	ft->scores = fctx->scores;
	ft->scores->refcount++;

	if (fctx->enforced || fts_want_build_args(args->args))
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
	ctx->progress_hidden = FALSE;
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
	struct fts_mailbox *fbox = FTS_CONTEXT_REQUIRE(ctx->transaction->box);
	struct fts_search_context *fctx = FTS_CONTEXT(ctx);
	struct fts_transaction_context *ft = FTS_CONTEXT_REQUIRE(ctx->transaction);

	if (fctx == NULL && ft->failed) {
		/* precaching already failed - stop now instead of potentially
		   going through the same failure for all the mails */
		return FALSE;
	}

	if (fctx != NULL && fctx->indexer_ctx != NULL) {
		/* this command is still building the indexes */
		if (!fts_mailbox_build_continue(ctx)) {
			*tryagain_r = TRUE;
			return FALSE;
		}
		if (fctx->indexing_timed_out) {
			*tryagain_r = FALSE;
			return FALSE;
		}
	}
	if (fctx != NULL && !fctx->fts_lookup_success && fctx->enforced)
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

static bool fts_mailbox_search_next_update_seq(struct mail_search_context *ctx)
{
	struct fts_mailbox *fbox = FTS_CONTEXT_REQUIRE(ctx->transaction->box);
	struct fts_search_context *fctx = FTS_CONTEXT(ctx);
	unsigned int idx;

	if (fctx == NULL || !fctx->fts_lookup_success) {
		/* fts lookup not done for this search */
		if (fctx != NULL && fctx->indexing_timed_out)
			return FALSE;
		return fbox->module_ctx.super.search_next_update_seq(ctx);
	}

	/* restore original [non]matches */
	fts_search_deserialize(ctx->args->args, fctx->orig_matches);

	if (!fbox->module_ctx.super.search_next_update_seq(ctx))
		return FALSE;

	if (ctx->seq >= fctx->first_unindexed_seq) {
		/* we've not indexed this far */
		return TRUE;
	}

	/* apply [non]matches based on the FTS lookup results */
	idx = 0;
	fts_search_apply_results_level(ctx, ctx->args->args, &idx);
	return TRUE;
}

static int fts_mailbox_search_deinit(struct mail_search_context *ctx)
{
	struct fts_mailbox *fbox = FTS_CONTEXT_REQUIRE(ctx->transaction->box);
	struct fts_transaction_context *ft = FTS_CONTEXT_REQUIRE(ctx->transaction);
	struct fts_search_context *fctx = FTS_CONTEXT(ctx);
	int ret = 0;

	if (fctx != NULL) {
		if (fctx->indexer_ctx != NULL) {
			if (fts_indexer_deinit(&fctx->indexer_ctx) < 0)
				ft->failed = TRUE;
		}
		if (fctx->indexing_timed_out)
			ret = -1;
		if (!fctx->fts_lookup_success && fctx->enforced) {
			/* FTS lookup failed and we didn't want to fallback to
			   opening all the mails and searching manually */
			mail_storage_set_internal_error(ctx->transaction->box->storage);
			ret = -1;
		}

		buffer_free(&fctx->orig_matches);
		array_free(&fctx->levels);
		pool_unref(&fctx->result_pool);
		fts_scores_unref(&fctx->scores);
		i_free(fctx);
	} else {
		if (ft->failed)
			ret = -1;
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

static int
fts_mail_precache_range(struct mailbox_transaction_context *trans,
			struct fts_backend_update_context *update_ctx,
			uint32_t seq1, uint32_t seq2, unsigned int *extra_count)
{
	struct mail_search_args *search_args;
	struct mail_search_context *ctx;
	struct mail *mail;
	int ret = 0;

	search_args = mail_search_build_init();
	mail_search_build_add_seqset(search_args, seq1, seq2);
	ctx = mailbox_search_init(trans, search_args, NULL,
				  MAIL_FETCH_STREAM_HEADER |
				  MAIL_FETCH_STREAM_BODY, NULL);
	mail_search_args_unref(&search_args);

	while (mailbox_search_next(ctx, &mail)) {
		if (fts_build_mail(update_ctx, mail) < 0) {
			mail_storage_set_internal_error(trans->box->storage);
			ret = -1;
			break;
		}
		mail_precache(mail);
		*extra_count += 1;
	}
	if (mailbox_search_deinit(&ctx) < 0)
		ret = -1;
	return ret;
}

static int fts_mail_precache_init(struct mail *_mail)
{
	struct fts_transaction_context *ft = FTS_CONTEXT_REQUIRE(_mail->transaction);
	struct fts_mailbox_list *flist = FTS_LIST_CONTEXT_REQUIRE(_mail->box->list);
	uint32_t last_seq;

	if (fts_mailbox_get_last_cached_seq(_mail->box, &last_seq) < 0)
		return -1;

	ft->precached = TRUE;
	ft->next_index_seq = last_seq + 1;
	if (flist->update_ctx == NULL)
		flist->update_ctx = fts_backend_update_init(flist->backend);
	flist->update_ctx_refcount++;
	return 0;
}

static void fts_mail_index(struct mail *_mail)
{
	struct fts_transaction_context *ft = FTS_CONTEXT_REQUIRE(_mail->transaction);
	struct fts_mailbox_list *flist = FTS_LIST_CONTEXT_REQUIRE(_mail->box->list);
	struct mail_private *pmail = (struct mail_private *)_mail;

	if (ft->failed)
		return;

	if (!ft->precached) {
		if (fts_mail_precache_init(_mail) < 0) {
			ft->failed = TRUE;
			return;
		}
	}
	if (pmail->vmail != NULL) {
		/* Indexing via virtual mailbox: Index all the mails in this
		   same real mailbox. */
		uint32_t msgs_count =
			mail_index_view_get_messages_count(_mail->box->view);

		fts_backend_update_set_mailbox(flist->update_ctx, _mail->box);
		if (ft->next_index_seq > msgs_count) {
			/* everything indexed already */
		} else if (fts_mail_precache_range(_mail->transaction,
						   flist->update_ctx,
						   ft->next_index_seq,
						   msgs_count,
						   &ft->precache_extra_count) < 0) {
			ft->failed = TRUE;
		} else {
			ft->next_index_seq = msgs_count+1;
		}
		return;
	}

	if (ft->next_index_seq < _mail->seq) {
		/* we'll first need to index all the missing mails up to the
		   current one. */
		fts_backend_update_set_mailbox(flist->update_ctx, _mail->box);
		if (fts_mail_precache_range(_mail->transaction,
					    flist->update_ctx,
					    ft->next_index_seq,
					    _mail->seq-1,
					    &ft->precache_extra_count) < 0) {
			ft->failed = TRUE;
			return;
		}
		ft->next_index_seq = _mail->seq;
	}

	if (ft->next_index_seq == _mail->seq) {
		fts_backend_update_set_mailbox(flist->update_ctx, _mail->box);
		if (fts_build_mail(flist->update_ctx, _mail) < 0) {
			mail_storage_set_internal_error(_mail->box->storage);
			ft->failed = TRUE;
		}
		ft->next_index_seq = _mail->seq + 1;
	}
}

static void fts_mail_precache(struct mail *_mail)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	struct fts_mail *fmail = FTS_MAIL_CONTEXT(mail);
	struct fts_transaction_context *ft = FTS_CONTEXT_REQUIRE(_mail->transaction);

	fmail->module_ctx.super.precache(_mail);
	if (fmail->virtual_mail) {
		if (ft->highest_virtual_uid < _mail->uid)
			ft->highest_virtual_uid = _mail->uid;
	} else if (!ft->indexing) T_BEGIN {
		/* avoid recursing here from fts_mail_precache_range() */
		ft->indexing = TRUE;
		fts_mail_index(_mail);
		i_assert(ft->indexing);
		ft->indexing = FALSE;
	} T_END;
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
	int ret = ft->failed ? -1 : 0;

	if (ft->failed)
		*error_r = "transaction context";

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
			i_error("fts: Failed after indexing %u extra mails internally in %s: %s",
			       ft->precache_extra_count, t->box->vname, *error_r);
		} else {
			i_info("fts: Indexed %u extra mails internally in %s",
			       ft->precache_extra_count, t->box->vname);
		}
	}
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
	string_t *str = t_str_new(256);
	const char *path, *value;
	unsigned int max_recent_msgs;
	int fd;

	path = t_strconcat(user->set->base_dir, "/"INDEXER_SOCKET_NAME, NULL);
	fd = net_connect_unix(path);
	if (fd == -1) {
		i_error("net_connect_unix(%s) failed: %m", path);
		return;
	}

	value = mail_user_plugin_getenv(user, "fts_autoindex_max_recent_msgs");
	if (value == NULL || str_to_uint(value, &max_recent_msgs) < 0)
		max_recent_msgs = 0;

	str_append(str, INDEXER_HANDSHAKE);
	str_append(str, "APPEND\t0\t");
	str_append_tabescaped(str, user->username);
	str_append_c(str, '\t');
	str_append_tabescaped(str, box->vname);
	str_printfa(str, "\t%u", max_recent_msgs);
	str_append_c(str, '\t');
	str_append_tabescaped(str, box->storage->user->session_id);
	str_append_c(str, '\n');
	if (write_full(fd, str_data(str), str_len(str)) < 0)
		i_error("write(%s) failed: %m", path);
	i_close_fd(&fd);
}

static int
fts_transaction_commit(struct mailbox_transaction_context *t,
		       struct mail_transaction_commit_changes *changes_r)
{
	struct fts_transaction_context *ft = FTS_CONTEXT_REQUIRE(t);
	struct fts_mailbox *fbox = FTS_CONTEXT_REQUIRE(t->box);
	struct mailbox *box = t->box;
	bool autoindex;
	int ret = 0;
	const char *error;

	autoindex = ft->mails_saved && !fbox->fts_mailbox_excluded &&
		mail_user_plugin_getenv_bool(box->storage->user,
					"fts_autoindex");

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

static const char *const *fts_exclude_get_patterns(struct mail_user *user)
{
	ARRAY_TYPE(const_string) patterns;
	const char *str;
	char set_name[21+MAX_INT_STRLEN+1];
	unsigned int i;

	str = mail_user_plugin_getenv(user, "fts_autoindex_exclude");
	if (str == NULL)
		return NULL;

	t_array_init(&patterns, 16);
	for (i = 2; str != NULL; i++) {
		array_append(&patterns, &str, 1);

		if (i_snprintf(set_name, sizeof(set_name),
			       "fts_autoindex_exclude%u", i) < 0)
			i_unreached();
		str = mail_user_plugin_getenv(user, set_name);
	}
	array_append_zero(&patterns);
	return array_idx(&patterns, 0);
}

static bool fts_autoindex_exclude_match(struct mailbox *box)
{
	const char *const *exclude_list;
	unsigned int i;
	const struct mailbox_settings *set;
	const char *const *special_use;
	struct mail_user *user = box->storage->user;

	exclude_list = fts_exclude_get_patterns(user);
	if (exclude_list == NULL)
		return FALSE;

	set = mailbox_settings_find(mailbox_get_namespace(box),
				    mailbox_get_vname(box));
	special_use = set == NULL ? NULL :
		t_strsplit_spaces(set->special_use, " ");
	for (i = 0; exclude_list[i] != NULL; i++) {
		if (exclude_list[i][0] == '\\') {
			/* \Special-use flag */
			if (special_use != NULL &&
			    str_array_icase_find(special_use, exclude_list[i]))
				return TRUE;
		} else {
			/* mailbox name with wildcards */
			if (wildcard_match(box->name, exclude_list[i]))
				return TRUE;
		}
	}
	return FALSE;
}

void fts_mailbox_allocated(struct mailbox *box)
{
	struct fts_mailbox_list *flist = FTS_LIST_CONTEXT(box->list);
	struct mailbox_vfuncs *v = box->vlast;
	struct fts_mailbox *fbox;

	if (flist == NULL || flist->failed)
		return;

	fbox = p_new(box->pool, struct fts_mailbox, 1);
	fbox->module_ctx.super = *v;
	box->vlast = &fbox->module_ctx.super;
	fbox->fts_mailbox_excluded = fts_autoindex_exclude_match(box);

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

	MODULE_CONTEXT_SET(box, fts_storage_module, fbox);
}

static void fts_mailbox_list_deinit(struct mailbox_list *list)
{
	struct fts_mailbox_list *flist = FTS_LIST_CONTEXT_REQUIRE(list);

	if (flist->backend != NULL)
		fts_backend_deinit(&flist->backend);
	flist->module_ctx.super.deinit(list);
}

static int
fts_init_namespace(struct fts_mailbox_list *flist, struct mail_namespace *ns,
		   const char **error_r)
{
	struct fts_backend *backend;
	if (fts_backend_init(flist->backend_name, ns, error_r, &backend) < 0) {
		flist->failed = TRUE;
		return -1;
	}
	flist->backend = backend;
	if ((flist->backend->flags & FTS_BACKEND_FLAG_FUZZY_SEARCH) != 0)
		ns->user->fuzzy_search = TRUE;
	return 0;
}

void fts_mail_namespaces_added(struct mail_namespace *ns)
{
	while(ns != NULL) {
		struct fts_mailbox_list *flist = FTS_LIST_CONTEXT(ns->list);
		const char *error;

		if (flist != NULL && !flist->failed && flist->backend == NULL &&
		    fts_init_namespace(flist, ns, &error) < 0) {
			i_error("fts: Failed to initialize backend '%s': %s",
				flist->backend_name, error);
		}
		ns = ns->next;
	}
}

void
fts_mailbox_list_created(struct mailbox_list *list)
{
	const char *name = mail_user_plugin_getenv(list->ns->user, "fts");
	const char *path;

	if (name == NULL || name[0] == '\0') {
		e_debug(list->ns->user->event,
			"fts: No fts setting - plugin disabled");
		return;
	}

	if (!mailbox_list_get_root_path(list, MAILBOX_LIST_PATH_TYPE_INDEX, &path)) {
		e_debug(list->ns->user->event,
			"fts: Indexes disabled for namespace '%s'",
			list->ns->prefix);
		return;
	}

	struct fts_mailbox_list *flist;
	struct mailbox_list_vfuncs *v = list->vlast;

	flist = p_new(list->pool, struct fts_mailbox_list, 1);
	flist->module_ctx.super = *v;
	flist->backend_name = name;
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
