/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-search.h"
#include "mail-storage-private.h"
#include "mailbox-list-private.h"
#include "../virtual/virtual-storage.h"
#include "fts-api-private.h"
#include "fts-build.h"
#include "fts-search-serialize.h"
#include "fts-plugin.h"
#include "fts-storage.h"

#include <stdlib.h>

#define FTS_CONTEXT(obj) \
	MODULE_CONTEXT(obj, fts_storage_module)
#define FTS_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, fts_mail_module)
#define FTS_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, fts_mailbox_list_module)

struct fts_mailbox_list {
	union mailbox_list_module_context module_ctx;
	struct fts_backend *backend;
};

struct fts_mailbox {
	union mailbox_module_context module_ctx;
	struct fts_backend_update_context *sync_update_ctx;
};

struct fts_transaction_context {
	union mailbox_transaction_module_context module_ctx;

	struct fts_scores *scores;
};

struct fts_mail {
	union mail_module_context module_ctx;
	char score[30];
};

static MODULE_CONTEXT_DEFINE_INIT(fts_storage_module,
				  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(fts_mail_module, &mail_module_register);
static MODULE_CONTEXT_DEFINE_INIT(fts_mailbox_list_module,
				  &mailbox_list_module_register);

static void fts_scores_unref(struct fts_scores **_scores)
{
	struct fts_scores *scores = *_scores;

	*_scores = NULL;
	if (--scores->refcount == 0) {
		array_free(&scores->score_map);
		i_free(scores);
	}
}

static bool fts_try_build_init(struct mail_search_context *ctx,
			       struct fts_search_context *fctx)
{
	if (fts_backend_is_updating(fctx->backend)) {
		/* this process is already building the indexes */
		return FALSE;
	}
	fctx->build_initialized = TRUE;

	switch (fts_build_init(fctx->backend, ctx->transaction->box, FALSE,
			       &fctx->build_ctx)) {
	case -1:
		break;
	case 0:
		/* the index was up to date */
		fts_search_lookup(fctx);
		break;
	case 1:
		/* hide "searching" notifications while building index */
		ctx->progress_hidden = TRUE;
		break;
	}
	return TRUE;
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
			return TRUE;
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
	struct fts_transaction_context *ft = FTS_CONTEXT(t);
	struct fts_mailbox *fbox = FTS_CONTEXT(t->box);
	struct fts_mailbox_list *flist = FTS_LIST_CONTEXT(t->box->list);
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
	i_array_init(&fctx->levels, 8);
	fctx->scores = i_new(struct fts_scores, 1);
	fctx->scores->refcount = 1;
	i_array_init(&fctx->scores->score_map, 64);
	MODULE_CONTEXT_SET(ctx, fts_storage_module, fctx);

	fctx->virtual_mailbox =
		strcmp(t->box->storage->name, VIRTUAL_STORAGE_NAME) == 0;

	/* transaction contains the last search's scores. they can be
	   queried later with mail_get_special() */
	if (ft->scores != NULL)
		fts_scores_unref(&ft->scores);
	ft->scores = fctx->scores;
	ft->scores->refcount++;

	if (fts_want_build_args(args->args))
		(void)fts_try_build_init(ctx, fctx);
	else {
		fctx->build_initialized = TRUE;
		fts_search_lookup(fctx);
	}
	return ctx;
}

static bool fts_mailbox_build_continue(struct mail_search_context *ctx)
{
	struct fts_search_context *fctx = FTS_CONTEXT(ctx);
	int ret;

	if (fctx == NULL)
		return TRUE;

	if (!fctx->build_initialized) {
		/* we're still waiting for this process (but another command)
		   to finish building the indexes */
		if (!fts_try_build_init(ctx, fctx))
			return FALSE;
	}

	if (fctx->build_ctx != NULL) {
		/* this command is still building the indexes */
		ret = fts_build_more(fctx->build_ctx);
		if (ret == 0)
			return FALSE;
		ctx->progress_hidden = FALSE;
		if (fts_build_deinit(&fctx->build_ctx) < 0)
			ret = -1;
		if (ret > 0)
			fts_search_lookup(fctx);
	}
	return TRUE;
}

static bool
fts_mailbox_search_next_nonblock(struct mail_search_context *ctx,
				 struct mail **mail_r, bool *tryagain_r)
{
	struct fts_mailbox *fbox = FTS_CONTEXT(ctx->transaction->box);

	if (!fts_mailbox_build_continue(ctx)) {
		*tryagain_r = TRUE;
		return FALSE;
	}

	return fbox->module_ctx.super.
		search_next_nonblock(ctx, mail_r, tryagain_r);
}

static void
fts_search_apply_results_level(struct mail_search_context *ctx,
			       struct mail_search_arg *args, unsigned int *idx)
{
	struct fts_search_context *fctx = FTS_CONTEXT(ctx);
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
	struct fts_mailbox *fbox = FTS_CONTEXT(ctx->transaction->box);
	struct fts_search_context *fctx = FTS_CONTEXT(ctx);
	unsigned int idx;

	if (fctx == NULL || !fctx->fts_lookup_success) {
		/* fts lookup not done for this search */
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
	struct fts_mailbox *fbox = FTS_CONTEXT(ctx->transaction->box);
	struct fts_search_context *fctx = FTS_CONTEXT(ctx);

	if (fctx != NULL) {
		if (fctx->build_ctx != NULL) {
			/* the search was cancelled */
			(void)fts_build_deinit(&fctx->build_ctx);
		}

		buffer_free(&fctx->orig_matches);
		array_free(&fctx->levels);
		pool_unref(&fctx->result_pool);
		fts_scores_unref(&fctx->scores);
		i_free(fctx);
	}
	return fbox->module_ctx.super.search_deinit(ctx);
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
	struct fts_transaction_context *ft = FTS_CONTEXT(_mail->transaction);
	const struct fts_score_map *scores;

	if (field != MAIL_FETCH_SEARCH_RELEVANCY || ft->scores == NULL)
		scores = NULL;
	else {
		scores = array_bsearch(&ft->scores->score_map, &_mail->uid,
				       fts_score_cmp);
	}
	if (scores != NULL) {
		i_assert(scores->uid == _mail->uid);
		i_snprintf(fmail->score, sizeof(fmail->score),
			   "%f", scores->score);
		*value_r = fmail->score;
		return 0;
	}

	return fmail->module_ctx.super.get_special(_mail, field, value_r);
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

	v->get_special = fts_mail_get_special;
	MODULE_CONTEXT_SET(mail, fts_mail_module, fmail);
}

static struct mailbox_transaction_context *
fts_transaction_begin(struct mailbox *box,
		      enum mailbox_transaction_flags flags)
{
	struct fts_mailbox *fbox = FTS_CONTEXT(box);
	struct mailbox_transaction_context *t;
	struct fts_transaction_context *ft;

	ft = i_new(struct fts_transaction_context, 1);

	t = fbox->module_ctx.super.transaction_begin(box, flags);
	MODULE_CONTEXT_SET(t, fts_storage_module, ft);
	return t;
}

static void fts_transaction_rollback(struct mailbox_transaction_context *t)
{
	struct fts_mailbox *fbox = FTS_CONTEXT(t->box);
	struct fts_transaction_context *ft = FTS_CONTEXT(t);

	if (ft->scores != NULL)
		fts_scores_unref(&ft->scores);
	fbox->module_ctx.super.transaction_rollback(t);
}

static int
fts_transaction_commit(struct mailbox_transaction_context *t,
		       struct mail_transaction_commit_changes *changes_r)
{
	struct fts_mailbox *fbox = FTS_CONTEXT(t->box);
	struct fts_transaction_context *ft = FTS_CONTEXT(t);

	if (ft->scores != NULL)
		fts_scores_unref(&ft->scores);
	return fbox->module_ctx.super.transaction_commit(t, changes_r);
}

static void fts_mailbox_sync_notify(struct mailbox *box, uint32_t uid,
				    enum mailbox_sync_type sync_type)
{
	struct fts_mailbox_list *flist = FTS_LIST_CONTEXT(box->list);
	struct fts_mailbox *fbox = FTS_CONTEXT(box);

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

static int fts_update(struct mailbox *box)
{
	struct fts_storage_build_context *build_ctx;
	struct fts_mailbox_list *flist = FTS_LIST_CONTEXT(box->list);
	int ret = 0;

	if ((ret = fts_build_init(flist->backend, box,
				  TRUE, &build_ctx)) <= 0) {
		if (box->storage->set->mail_debug)
			i_debug("%s: FTS index is up to date", box->vname);
		return ret;
	}

	if (box->storage->set->mail_debug)
		i_debug("%s: Updating FTS index", box->vname);

	while ((ret = fts_build_more(build_ctx)) == 0) ;

	if (fts_build_deinit(&build_ctx) < 0)
		ret = -1;
	return ret < 0 ? -1 : 0;
}

static int fts_sync_deinit(struct mailbox_sync_context *ctx,
			   struct mailbox_sync_status *status_r)
{
	struct mailbox *box = ctx->box;
	struct fts_mailbox *fbox = FTS_CONTEXT(box);
	struct fts_mailbox_list *flist = FTS_LIST_CONTEXT(box->list);
	bool precache, force_resync;
	int ret = 0;

	precache = (ctx->flags & MAILBOX_SYNC_FLAG_PRECACHE) != 0;
	force_resync = (ctx->flags & MAILBOX_SYNC_FLAG_FORCE_RESYNC) != 0;
	if (fbox->module_ctx.super.sync_deinit(ctx, status_r) < 0)
		return -1;
	ctx = NULL;

	flist->backend->syncing = TRUE;
	if (force_resync) {
		if (fts_backend_optimize(flist->backend) < 0) {
			mail_storage_set_critical(box->storage,
				"FTS optimize for mailbox %s failed",
				box->vname);
			ret = -1;
		}
	}
	if (precache) {
		if (fts_update(box) < 0) {
			mail_storage_set_critical(box->storage,
				"FTS index update for mailbox %s failed",
				box->vname);
			ret = -1;
		}
	}
	flist->backend->syncing = FALSE;
	return ret;
}

void fts_mailbox_allocated(struct mailbox *box)
{
	struct fts_mailbox_list *flist = FTS_LIST_CONTEXT(box->list);
	struct mailbox_vfuncs *v = box->vlast;
	struct fts_mailbox *fbox;

	if (flist == NULL)
		return;

	fbox = p_new(box->pool, struct fts_mailbox, 1);
	fbox->module_ctx.super = *v;
	box->vlast = &fbox->module_ctx.super;

	v->search_init = fts_mailbox_search_init;
	v->search_next_nonblock = fts_mailbox_search_next_nonblock;
	v->search_next_update_seq = fts_mailbox_search_next_update_seq;
	v->search_deinit = fts_mailbox_search_deinit;
	v->transaction_begin = fts_transaction_begin;
	v->transaction_rollback = fts_transaction_rollback;
	v->transaction_commit = fts_transaction_commit;
	v->sync_notify = fts_mailbox_sync_notify;
	v->sync_deinit = fts_sync_deinit;

	MODULE_CONTEXT_SET(box, fts_storage_module, fbox);
}

static void fts_mailbox_list_deinit(struct mailbox_list *list)
{
	struct fts_mailbox_list *flist = FTS_LIST_CONTEXT(list);

	fts_backend_deinit(&flist->backend);
	flist->module_ctx.super.deinit(list);
}

void fts_mailbox_list_created(struct mailbox_list *list)
{
	struct fts_backend *backend;
	const char *name, *path, *error;

	name = mail_user_plugin_getenv(list->ns->user, "fts");
	if (name == NULL) {
		if (list->mail_set->mail_debug)
			i_debug("fts: No fts setting - plugin disabled");
		return;
	}

	path = mailbox_list_get_path(list, NULL,
				     MAILBOX_LIST_PATH_TYPE_INDEX);
	if (*path == '\0') {
		if (list->mail_set->mail_debug) {
			i_debug("fts: Indexes disabled for namespace '%s'",
				list->ns->prefix);
		}
		return;
	}

	if (fts_backend_init(name, list->ns, &error, &backend) < 0) {
		i_error("fts: Failed to initialize backend '%s': %s",
			name, error);
	} else {
		struct fts_mailbox_list *flist;
		struct mailbox_list_vfuncs *v = list->vlast;

		flist = p_new(list->pool, struct fts_mailbox_list, 1);
		flist->module_ctx.super = *v;
		flist->backend = backend;
		list->vlast = &flist->module_ctx.super;
		v->deinit = fts_mailbox_list_deinit;
		MODULE_CONTEXT_SET(list, fts_mailbox_list_module, flist);
	}
}

struct fts_backend *fts_mailbox_backend(struct mailbox *box)
{
	struct fts_mailbox_list *flist = FTS_LIST_CONTEXT(box->list);

	return flist->backend;
}

struct fts_backend *fts_list_backend(struct mailbox_list *list)
{
	struct fts_mailbox_list *flist = FTS_LIST_CONTEXT(list);

	return flist == NULL ? NULL : flist->backend;
}
