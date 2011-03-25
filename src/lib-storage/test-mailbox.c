/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-storage-private.h"
#include "test-mail-storage.h"

#define TEST_UID_VALIDITY 1

static bool test_mailbox_is_readonly(struct mailbox *box ATTR_UNUSED)
{
	return FALSE;
}

static bool test_mailbox_allow_new_keywords(struct mailbox *box ATTR_UNUSED)
{
	return TRUE;
}

static int test_mailbox_enable(struct mailbox *box,
			       enum mailbox_feature features)
{
	box->enabled_features |= features;
	return 0;
}

static int test_mailbox_open(struct mailbox *box ATTR_UNUSED)
{
	return 0;
}

static void test_mailbox_close(struct mailbox *box ATTR_UNUSED)
{
}

static int
test_mailbox_create(struct mailbox *box,
		    const struct mailbox_update *update ATTR_UNUSED,
		    bool directory ATTR_UNUSED)
{
	mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
			       "Test mailbox creation isn't supported");
	return -1;
}

static int
test_mailbox_update(struct mailbox *box,
		    const struct mailbox_update *update ATTR_UNUSED)
{
	mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
			       "Test mailbox update isn't supported");
	return -1;
}

static int test_mailbox_delete(struct mailbox *box)
{
	mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
			       "Test mailbox delete isn't supported");
	return -1;
}

static int test_mailbox_rename(struct mailbox *src,
			       struct mailbox *dest ATTR_UNUSED,
			       bool rename_children ATTR_UNUSED)
{
	mail_storage_set_error(src->storage, MAIL_ERROR_NOTPOSSIBLE,
			       "Test mailbox rename isn't supported");
	return -1;
}

static void test_mailbox_get_status(struct mailbox *box ATTR_UNUSED,
				    enum mailbox_status_items items ATTR_UNUSED,
				    struct mailbox_status *status_r)
{
	memset(status_r, 0, sizeof(*status_r));
	status_r->uidvalidity = TEST_UID_VALIDITY;
	status_r->uidnext = 1;
}

static struct mailbox_sync_context *
test_mailbox_sync_init(struct mailbox *box,
		       enum mailbox_sync_flags flags ATTR_UNUSED)
{
	struct mailbox_sync_context *ctx;

	ctx = i_new(struct mailbox_sync_context, 1);
	ctx->box = box;
	return ctx;
}

static bool
test_mailbox_sync_next(struct mailbox_sync_context *ctx ATTR_UNUSED,
		       struct mailbox_sync_rec *sync_rec_r ATTR_UNUSED)
{
	return FALSE;
}

static int
test_mailbox_sync_deinit(struct mailbox_sync_context *ctx,
			 struct mailbox_sync_status *status_r)
{
	if (status_r != NULL)
		memset(status_r, 0, sizeof(*status_r));
	i_free(ctx);
	return 0;
}

static void test_mailbox_notify_changes(struct mailbox *box ATTR_UNUSED)
{
}

static struct mailbox_transaction_context *
test_mailbox_transaction_begin(struct mailbox *box,
			       enum mailbox_transaction_flags flags)
{
	struct mailbox_transaction_context *ctx;

	ctx = i_new(struct mailbox_transaction_context, 1);
	ctx->box = box;
	ctx->flags = flags;
	i_array_init(&ctx->module_contexts, 5);
	return ctx;
}

static void
test_mailbox_transaction_rollback(struct mailbox_transaction_context *t)
{
	array_free(&t->module_contexts);
	i_free(t);
}

static int
test_mailbox_transaction_commit(struct mailbox_transaction_context *t,
				struct mail_transaction_commit_changes *changes_r)
{
	changes_r->uid_validity = TEST_UID_VALIDITY;
	test_mailbox_transaction_rollback(t);
	return 0;
}

static void
test_mailbox_transaction_set_max_modseq(struct mailbox_transaction_context *t ATTR_UNUSED,
					uint64_t max_modseq ATTR_UNUSED,
					ARRAY_TYPE(seq_range) *seqs ATTR_UNUSED)
{
}

static int
test_mailbox_keywords_create(struct mailbox *box ATTR_UNUSED,
			     const char *const keywords[] ATTR_UNUSED,
			     struct mail_keywords **keywords_r,
			     bool skip_invalid ATTR_UNUSED)
{
	*keywords_r = i_new(struct mail_keywords, 1);
	(*keywords_r)->refcount = 1;
	return 0;
}

static struct mail_keywords *
test_mailbox_keywords_create_from_indexes(struct mailbox *box ATTR_UNUSED,
					  const ARRAY_TYPE(keyword_indexes) *idx ATTR_UNUSED)
{
	struct mail_keywords *keywords;

	keywords = i_new(struct mail_keywords, 1);
	keywords->refcount++;
	return keywords;
}

static void test_mailbox_keywords_ref(struct mail_keywords *keywords)
{
	keywords->refcount++;
}

static void test_mailbox_keywords_unref(struct mail_keywords *keywords)
{
	if (--keywords->refcount == 0)
		i_free(keywords);
}

static bool
test_mailbox_keyword_is_valid(struct mailbox *box ATTR_UNUSED,
			      const char *keyword ATTR_UNUSED,
			      const char **error_r ATTR_UNUSED)
{
	return TRUE;
}

static void
test_mailbox_get_seq_range(struct mailbox *box ATTR_UNUSED,
			   uint32_t uid1, uint32_t uid2,
			   uint32_t *seq1_r, uint32_t *seq2_r)
{
	*seq1_r = uid1;
	*seq2_r = uid2;
}

static void
test_mailbox_get_uid_range(struct mailbox *box ATTR_UNUSED,
			   const ARRAY_TYPE(seq_range) *seqs,
			   ARRAY_TYPE(seq_range) *uids)
{
	array_append_array(uids, seqs);
}

static bool
test_mailbox_get_expunged_uids(struct mailbox *box ATTR_UNUSED,
			       uint64_t prev_modseq ATTR_UNUSED,
			       const ARRAY_TYPE(seq_range) *uids_filter ATTR_UNUSED,
			       ARRAY_TYPE(seq_range) *expunged_uids ATTR_UNUSED,
			       ARRAY_TYPE(mailbox_expunge_rec) *expunges ATTR_UNUSED)
{
	return FALSE;
}

static struct mailbox_header_lookup_ctx *
test_mailbox_header_lookup_init(struct mailbox *box,
				const char *const headers[])
{
	struct mailbox_header_lookup_ctx *ctx;

	ctx = i_new(struct mailbox_header_lookup_ctx, 1);
	ctx->box = box;
	ctx->headers = headers; /* now exactly right, but .. */
	return ctx;
}

static void
test_mailbox_header_lookup_deinit(struct mailbox_header_lookup_ctx *ctx)
{
	i_free(ctx);
}

static struct mail_search_context *
test_mailbox_search_init(struct mailbox_transaction_context *t,
			 struct mail_search_args *args,
			 const enum mail_sort_type *sort_program ATTR_UNUSED)
{
	struct mail_search_context *ctx;

	ctx = i_new(struct mail_search_context, 1);
	ctx->transaction = t;
	ctx->args = args;

	i_array_init(&ctx->results, 5);
	i_array_init(&ctx->module_contexts, 5);
	return ctx;
}

static int test_mailbox_search_deinit(struct mail_search_context *ctx)
{
	array_free(&ctx->results);
	array_free(&ctx->module_contexts);
	i_free(ctx);
	return 0;
}

static bool
test_mailbox_search_next_nonblock(struct mail_search_context *ctx ATTR_UNUSED,
				  struct mail *mail ATTR_UNUSED,
				  bool *tryagain_r)
{
	*tryagain_r = FALSE;
	return FALSE;
}

static bool
test_mailbox_search_next_update_seq(struct mail_search_context *ctx ATTR_UNUSED)
{
	return FALSE;
}

static struct mail_save_context *
test_mailbox_save_alloc(struct mailbox_transaction_context *t)
{
	struct mail_save_context *ctx;

	ctx = i_new(struct mail_save_context, 1);
	ctx->transaction = t;
	return ctx;
}

static int
test_mailbox_save_begin(struct mail_save_context *ctx ATTR_UNUSED,
			struct istream *input ATTR_UNUSED)
{
	return -1;
}

static int
test_mailbox_save_continue(struct mail_save_context *ctx ATTR_UNUSED)
{
	return -1;
}

static int
test_mailbox_save_finish(struct mail_save_context *ctx ATTR_UNUSED)
{
	return -1;
}

static void
test_mailbox_save_cancel(struct mail_save_context *ctx ATTR_UNUSED)
{
}

static int
test_mailbox_copy(struct mail_save_context *ctx ATTR_UNUSED,
		  struct mail *mail ATTR_UNUSED)
{
	return -1;
}

static bool test_mailbox_is_inconsistent(struct mailbox *box ATTR_UNUSED)
{
	return FALSE;
}

struct mailbox test_mailbox = {
	.v = {
		test_mailbox_is_readonly,
		test_mailbox_allow_new_keywords,
		test_mailbox_enable,
		test_mailbox_open,
		test_mailbox_close,
		NULL,
		test_mailbox_create,
		test_mailbox_update,
		test_mailbox_delete,
		test_mailbox_rename,
		test_mailbox_get_status,
		NULL,
		NULL,
		NULL,
		test_mailbox_sync_init,
		test_mailbox_sync_next,
		test_mailbox_sync_deinit,
		NULL,
		test_mailbox_notify_changes,
		test_mailbox_transaction_begin,
		test_mailbox_transaction_commit,
		test_mailbox_transaction_rollback,
		test_mailbox_transaction_set_max_modseq,
		test_mailbox_keywords_create,
		test_mailbox_keywords_create_from_indexes,
		test_mailbox_keywords_ref,
		test_mailbox_keywords_unref,
		test_mailbox_keyword_is_valid,
		test_mailbox_get_seq_range,
		test_mailbox_get_uid_range,
		test_mailbox_get_expunged_uids,
		NULL,
		NULL,
		NULL,
		test_mailbox_mail_alloc,
		test_mailbox_header_lookup_init,
		test_mailbox_header_lookup_deinit,
		test_mailbox_search_init,
		test_mailbox_search_deinit,
		test_mailbox_search_next_nonblock,
		test_mailbox_search_next_update_seq,
		test_mailbox_save_alloc,
		test_mailbox_save_begin,
		test_mailbox_save_continue,
		test_mailbox_save_finish,
		test_mailbox_save_cancel,
		test_mailbox_copy,
		NULL,
		test_mailbox_is_inconsistent
	}
};

struct mailbox *
test_mailbox_alloc(struct mail_storage *storage, struct mailbox_list *list,
		   const char *name, enum mailbox_flags flags)
{
	struct mailbox *box;
	pool_t pool;

	pool = pool_alloconly_create("test mailbox", 1024);
	box = p_new(pool, struct mailbox, 1);
	*box = test_mailbox;
	box->name = p_strdup(pool, name);
	box->storage = storage;
	box->list = list;

	box->pool = pool;
	box->flags = flags;

	p_array_init(&box->search_results, pool, 16);
	p_array_init(&box->module_contexts, pool, 5);
	return box;
}
