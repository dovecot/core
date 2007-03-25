/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "mkdir-parents.h"
#include "mail-storage-private.h"
#include "lucene-wrapper.h"
#include "fts-lucene-plugin.h"

#define LUCENE_INDEX_DIR_NAME "lucene-indexes"
#define LUCENE_LOCK_SUBDIR_NAME "locks"

struct lucene_mail_storage {
	struct lucene_index *index;
	struct mailbox *selected_box;
	int refcount;
};

struct lucene_fts_backend {
	struct fts_backend backend;
	struct lucene_mail_storage *lstorage;
	struct mailbox *box;

	uint32_t last_uid;
};

static void fts_backend_select(struct lucene_fts_backend *backend)
{
	if (backend->lstorage->selected_box != backend->box) {
		lucene_index_select_mailbox(backend->lstorage->index,
					    mailbox_get_name(backend->box));
		backend->lstorage->selected_box = backend->box;
	}
}

static struct fts_backend *fts_backend_lucene_init(struct mailbox *box)
{
	struct lucene_mail_storage *lstorage;
	struct lucene_fts_backend *backend;
	const char *path, *lock_path;

	lstorage = LUCENE_CONTEXT(box->storage);
	if (lstorage == NULL) {
		path = mail_storage_get_mailbox_index_dir(box->storage,
							  "INBOX");
		if (path == NULL) {
			/* in-memory indexes */
			return NULL;
		}

		path = t_strconcat(path, "/"LUCENE_INDEX_DIR_NAME, NULL);
		lock_path = t_strdup_printf("%s/"LUCENE_LOCK_SUBDIR_NAME, path);
		if (mkdir_parents(lock_path, 0700) < 0) {
			i_error("mkdir_parents(%s) failed: %m", lock_path);
			return NULL;
		}

		lstorage = i_new(struct lucene_mail_storage, 1);
		lstorage->index = lucene_index_init(path, lock_path);
		array_idx_set(&box->storage->module_contexts,
			      fts_lucene_storage_module_id, &lstorage);
	}
	lstorage->refcount++;

	backend = i_new(struct lucene_fts_backend, 1);
	backend->backend = fts_backend_lucene;
	backend->lstorage = lstorage;
	backend->box = box;
	return &backend->backend;
}

static void fts_backend_lucene_deinit(struct fts_backend *_backend)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_backend;

	if (--backend->lstorage->refcount == 0) {
		array_idx_clear(&backend->box->storage->module_contexts,
				fts_lucene_storage_module_id);
		lucene_index_deinit(backend->lstorage->index);
		i_free(backend->lstorage);
	}
	i_free(backend);
}

static int
fts_backend_lucene_get_last_uid(struct fts_backend *_backend,
				uint32_t *last_uid_r)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_backend;

	fts_backend_select(backend);
	return lucene_index_get_last_uid(backend->lstorage->index, last_uid_r);
}

static struct fts_backend_build_context *
fts_backend_lucene_build_init(struct fts_backend *_backend, uint32_t *last_uid_r)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_backend;
	struct fts_backend_build_context *ctx;

	fts_backend_select(backend);

	ctx = i_new(struct fts_backend_build_context, 1);
	ctx->backend = _backend;
	if (lucene_index_build_init(backend->lstorage->index,
				    &backend->last_uid) < 0)
		ctx->failed = TRUE;

	*last_uid_r = backend->last_uid;
	return ctx;
}

static int
fts_backend_lucene_build_more(struct fts_backend_build_context *ctx,
			      uint32_t uid, const unsigned char *data,
			      size_t size, bool headers)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)ctx->backend;

	if (ctx->failed)
		return -1;

	i_assert(uid >= backend->last_uid);
	backend->last_uid = uid;

	i_assert(backend->lstorage->selected_box == backend->box);
	return lucene_index_build_more(backend->lstorage->index,
				       uid, data, size, headers);
}

static int
fts_backend_lucene_build_deinit(struct fts_backend_build_context *ctx)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)ctx->backend;
	int ret = ctx->failed ? -1 : 0;

	i_assert(backend->lstorage->selected_box == backend->box);
	lucene_index_build_deinit(backend->lstorage->index);
	i_free(ctx);
	return ret;
}

static void
fts_backend_lucene_expunge(struct fts_backend *_backend, struct mail *mail)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_backend;

	fts_backend_select(backend);
	(void)lucene_index_expunge(backend->lstorage->index, mail->uid);
}

static void
fts_backend_lucene_expunge_finish(struct fts_backend *_backend __attr_unused__,
				  struct mailbox *box __attr_unused__,
				  bool committed __attr_unused__)
{
}

static int
fts_backend_lucene_lock(struct fts_backend *_backend __attr_unused__)
{
	return 1;
}

static void
fts_backend_lucene_unlock(struct fts_backend *_backend __attr_unused__)
{
}

static int
fts_backend_lucene_lookup(struct fts_backend *_backend,
			  enum fts_lookup_flags flags,
			  const char *key, ARRAY_TYPE(seq_range) *result)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_backend;

	fts_backend_select(backend);
	return lucene_index_lookup(backend->lstorage->index,
				   flags, key, result);
}

struct fts_backend fts_backend_lucene = {
	MEMBER(name) "lucene",
	MEMBER(flags) FTS_BACKEND_FLAG_DEFINITE_LOOKUPS,

	{
		fts_backend_lucene_init,
		fts_backend_lucene_deinit,
		fts_backend_lucene_get_last_uid,
		fts_backend_lucene_build_init,
		fts_backend_lucene_build_more,
		fts_backend_lucene_build_deinit,
		fts_backend_lucene_expunge,
		fts_backend_lucene_expunge_finish,
		fts_backend_lucene_lock,
		fts_backend_lucene_unlock,
		fts_backend_lucene_lookup,
		NULL
	}
};
