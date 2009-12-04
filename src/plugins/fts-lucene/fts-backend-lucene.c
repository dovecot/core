/* Copyright (c) 2006-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mkdir-parents.h"
#include "mail-storage-private.h"
#include "lucene-wrapper.h"
#include "fts-lucene-plugin.h"

#define LUCENE_INDEX_DIR_NAME "lucene-indexes"
#define LUCENE_LOCK_SUBDIR_NAME "locks"

#define LUCENE_CONTEXT(obj) \
	MODULE_CONTEXT(obj, fts_lucene_storage_module)

struct lucene_mail_storage {
	union mail_storage_module_context module_ctx;
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

static MODULE_CONTEXT_DEFINE_INIT(fts_lucene_storage_module,
				  &mail_storage_module_register);

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
		path = mailbox_list_get_path(box->list, "INBOX",
					     MAILBOX_LIST_PATH_TYPE_INDEX);
		if (path == NULL) {
			/* in-memory indexes */
			if (box->storage->set->mail_debug)
				i_debug("fts squat: Disabled with in-memory indexes");
			return NULL;
		}

		path = t_strconcat(path, "/"LUCENE_INDEX_DIR_NAME, NULL);
		lock_path = t_strdup_printf("%s/"LUCENE_LOCK_SUBDIR_NAME, path);
		if (mkdir_parents(lock_path, 0700) < 0 && errno != EEXIST) {
			i_error("mkdir_parents(%s) failed: %m", lock_path);
			return NULL;
		}

		lstorage = i_new(struct lucene_mail_storage, 1);
		lstorage->index = lucene_index_init(path, lock_path);
		MODULE_CONTEXT_SET(box->storage, fts_lucene_storage_module,
				   lstorage);
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
		MODULE_CONTEXT_UNSET(backend->box->storage,
				     fts_lucene_storage_module);
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

static int
fts_backend_lucene_build_init(struct fts_backend *_backend,
			      uint32_t *last_uid_r,
			      struct fts_backend_build_context **ctx_r)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_backend;
	struct fts_backend_build_context *ctx;

	fts_backend_select(backend);
	if (lucene_index_build_init(backend->lstorage->index,
				    &backend->last_uid) < 0)
		return -1;

	ctx = i_new(struct fts_backend_build_context, 1);
	ctx->backend = _backend;

	*last_uid_r = backend->last_uid;
	*ctx_r = ctx;
	return 0;
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
fts_backend_lucene_expunge_finish(struct fts_backend *_backend ATTR_UNUSED,
				  struct mailbox *box ATTR_UNUSED,
				  bool committed ATTR_UNUSED)
{
}

static int
fts_backend_lucene_lock(struct fts_backend *_backend ATTR_UNUSED)
{
	return 1;
}

static void
fts_backend_lucene_unlock(struct fts_backend *_backend ATTR_UNUSED)
{
}

static int
fts_backend_lucene_lookup(struct fts_backend *_backend,
			  const char *key, enum fts_lookup_flags flags,
			  ARRAY_TYPE(seq_range) *definite_uids,
			  ARRAY_TYPE(seq_range) *maybe_uids)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_backend;

	i_assert((flags & FTS_LOOKUP_FLAG_INVERT) == 0);

	array_clear(maybe_uids);
	fts_backend_select(backend);
	return lucene_index_lookup(backend->lstorage->index,
				   flags, key, definite_uids);
}

struct fts_backend fts_backend_lucene = {
	.name = "lucene",
	.flags = 0,

	{
		fts_backend_lucene_init,
		fts_backend_lucene_deinit,
		fts_backend_lucene_get_last_uid,
		NULL,
		fts_backend_lucene_build_init,
		fts_backend_lucene_build_more,
		fts_backend_lucene_build_deinit,
		fts_backend_lucene_expunge,
		fts_backend_lucene_expunge_finish,
		fts_backend_lucene_lock,
		fts_backend_lucene_unlock,
		fts_backend_lucene_lookup,
		NULL,
		NULL
	}
};
