/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "mail-storage-private.h"
#include "mail-search.h"
#include "squat-trie.h"
#include "fts-squat-plugin.h"

#define SQUAT_FILE_PREFIX "dovecot.index.search"

struct squat_fts_backend {
	struct fts_backend backend;
	struct squat_trie *trie;
};

struct squat_fts_backend_build_context {
	struct fts_backend_build_context ctx;
	struct squat_trie_build_context *trie_ctx;
};

static struct fts_backend *fts_backend_squat_init(struct mailbox *box)
{
	struct squat_fts_backend *backend;
	struct mail_storage *storage;
	struct mailbox_status status;
	const char *path;
	bool mmap_disable;

	storage = mailbox_get_storage(box);
	path = mail_storage_get_mailbox_index_dir(storage,
						  mailbox_get_name(box));
	if (*path == '\0') {
		/* in-memory indexes */
		return NULL;
	}

	mailbox_get_status(box, STATUS_UIDVALIDITY, &status);
	mmap_disable = (storage->flags &
			(MAIL_STORAGE_FLAG_MMAP_DISABLE |
			 MAIL_STORAGE_FLAG_MMAP_NO_WRITE)) != 0;

	backend = i_new(struct squat_fts_backend, 1);
	backend->backend = fts_backend_squat;
	backend->trie =
		squat_trie_open(t_strconcat(path, "/"SQUAT_FILE_PREFIX, NULL),
				status.uidvalidity, storage->lock_method,
				mmap_disable);
	return &backend->backend;
}

static void fts_backend_squat_deinit(struct fts_backend *_backend)
{
	struct squat_fts_backend *backend =
		(struct squat_fts_backend *)_backend;

	squat_trie_close(backend->trie);
	i_free(backend);
}

static int fts_backend_squat_get_last_uid(struct fts_backend *_backend,
					  uint32_t *last_uid_r)
{
	struct squat_fts_backend *backend =
		(struct squat_fts_backend *)_backend;

	return squat_trie_get_last_uid(backend->trie, last_uid_r);
}

static struct fts_backend_build_context *
fts_backend_squat_build_init(struct fts_backend *_backend, uint32_t *last_uid_r)
{
	struct squat_fts_backend *backend =
		(struct squat_fts_backend *)_backend;
	struct squat_fts_backend_build_context *ctx;

	ctx = i_new(struct squat_fts_backend_build_context, 1);
	ctx->ctx.backend = _backend;
	ctx->trie_ctx = squat_trie_build_init(backend->trie, last_uid_r);
	return &ctx->ctx;
}

static int
fts_backend_squat_build_more(struct fts_backend_build_context *_ctx,
			     uint32_t uid, const unsigned char *data,
			     size_t size, bool headers __attr_unused__)
{
	struct squat_fts_backend_build_context *ctx =
		(struct squat_fts_backend_build_context *)_ctx;

	return squat_trie_build_more(ctx->trie_ctx, uid, data, size);
}

static int
fts_backend_squat_build_deinit(struct fts_backend_build_context *_ctx)
{
	struct squat_fts_backend_build_context *ctx =
		(struct squat_fts_backend_build_context *)_ctx;
	int ret;

	ret = squat_trie_build_deinit(ctx->trie_ctx);
	i_free(ctx);
	return ret;
}

static void
fts_backend_squat_expunge(struct fts_backend *_backend __attr_unused__,
			  struct mail *mail __attr_unused__)
{
}

static int get_uids(struct mailbox *box, ARRAY_TYPE(seq_range) *uids,
		    unsigned int *message_count_r)
{
	struct mail_search_arg search_arg;
        struct mailbox_transaction_context *t;
	struct mail_search_context *ctx;
	struct mail *mail;
	unsigned int count = 0;
	int ret;

	memset(&search_arg, 0, sizeof(search_arg));
	search_arg.type = SEARCH_ALL;

	t = mailbox_transaction_begin(box, 0);
	ctx = mailbox_search_init(t, NULL, &search_arg, NULL);

	mail = mail_alloc(t, 0, NULL);
	while (mailbox_search_next(ctx, mail) > 0) {
		seq_range_array_add(uids, 0, mail->uid);
		count++;
	}
	mail_free(&mail);

	ret = mailbox_search_deinit(&ctx);
	mailbox_transaction_rollback(&t);

	*message_count_r = count;
	return ret;
}

static void
fts_backend_squat_expunge_finish(struct fts_backend *_backend,
				 struct mailbox *box, bool committed)
{
	struct squat_fts_backend *backend =
		(struct squat_fts_backend *)_backend;
	ARRAY_TYPE(seq_range) uids = ARRAY_INIT;
	unsigned int count;

	if (!committed)
		return;

	t_push();
	t_array_init(&uids, 128);
	if (get_uids(box, &uids, &count) == 0) {
		(void)squat_trie_mark_having_expunges(backend->trie, &uids,
						      count);
	}
	t_pop();
}

static int fts_backend_squat_lock(struct fts_backend *_backend)
{
	struct squat_fts_backend *backend =
		(struct squat_fts_backend *)_backend;

	return squat_trie_lock(backend->trie, F_RDLCK);
}

static void fts_backend_squat_unlock(struct fts_backend *_backend)
{
	struct squat_fts_backend *backend =
		(struct squat_fts_backend *)_backend;

	squat_trie_unlock(backend->trie);
}

static int
fts_backend_squat_lookup(struct fts_backend *_backend,
			 enum fts_lookup_flags flags __attr_unused__,
			 const char *key, ARRAY_TYPE(seq_range) *result)
{
	struct squat_fts_backend *backend =
		(struct squat_fts_backend *)_backend;

	return squat_trie_lookup(backend->trie, result, key);
}

static int
fts_backend_squat_filter(struct fts_backend *_backend,
			 enum fts_lookup_flags flags __attr_unused__,
			 const char *key, ARRAY_TYPE(seq_range) *result)
{
	struct squat_fts_backend *backend =
		(struct squat_fts_backend *)_backend;

	return squat_trie_filter(backend->trie, result, key);
}

struct fts_backend fts_backend_squat = {
	MEMBER(name) "squat",
	MEMBER(flags) FTS_BACKEND_FLAG_EXACT_LOOKUPS,

	{
		fts_backend_squat_init,
		fts_backend_squat_deinit,
		fts_backend_squat_get_last_uid,
		fts_backend_squat_build_init,
		fts_backend_squat_build_more,
		fts_backend_squat_build_deinit,
		fts_backend_squat_expunge,
		fts_backend_squat_expunge_finish,
		fts_backend_squat_lock,
		fts_backend_squat_unlock,
		fts_backend_squat_lookup,
		fts_backend_squat_filter
	}
};
