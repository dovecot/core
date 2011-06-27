/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-user.h"
#include "mail-namespace.h"
#include "mail-storage-private.h"
#include "mail-search-build.h"
#include "squat-trie.h"
#include "fts-squat-plugin.h"

#include <stdlib.h>

#define SQUAT_FILE_PREFIX "dovecot.index.search"

struct squat_fts_backend {
	struct fts_backend backend;
	struct squat_trie *trie;
};

struct squat_fts_backend_build_context {
	struct fts_backend_build_context ctx;
	struct squat_trie_build_context *build_ctx;
	enum squat_index_type squat_type;
	uint32_t uid;
};

static void
fts_backend_squat_set(struct squat_fts_backend *backend, const char *str)
{
	const char *const *tmp;
	unsigned int len;

	for (tmp = t_strsplit_spaces(str, " "); *tmp != NULL; tmp++) {
		if (strncmp(*tmp, "partial=", 8) == 0) {
			if (str_to_uint(*tmp + 8, &len) < 0 || len == 0) {
				i_fatal("fts_squat: Invalid partial len: %s",
					*tmp + 8);
			}
			squat_trie_set_partial_len(backend->trie, len);
		} else if (strncmp(*tmp, "full=", 5) == 0) {
			if (str_to_uint(*tmp + 5, &len) < 0 || len == 0) {
				i_fatal("fts_squat: Invalid full len: %s",
					*tmp + 5);
			}
			squat_trie_set_full_len(backend->trie, len);
		} else {
			i_fatal("fts_squat: Invalid setting: %s", *tmp);
		}
	}
}

static struct fts_backend *fts_backend_squat_init(struct mailbox *box)
{
	const struct mailbox_permissions *perm = mailbox_get_permissions(box);
	struct squat_fts_backend *backend;
	struct mail_storage *storage;
	struct mailbox_status status;
	const char *path, *env;
	enum squat_index_flags flags = 0;

	storage = mailbox_get_storage(box);
	path = mailbox_list_get_path(box->list, box->name,
				     MAILBOX_LIST_PATH_TYPE_INDEX);
	if (*path == '\0') {
		/* in-memory indexes */
		if (storage->set->mail_debug)
			i_debug("fts squat: Disabled with in-memory indexes");
		return NULL;
	}

	mailbox_get_open_status(box, STATUS_UIDVALIDITY, &status);
	if (storage->set->mmap_disable)
		flags |= SQUAT_INDEX_FLAG_MMAP_DISABLE;
	if (storage->set->mail_nfs_index)
		flags |= SQUAT_INDEX_FLAG_NFS_FLUSH;
	if (storage->set->dotlock_use_excl)
		flags |= SQUAT_INDEX_FLAG_DOTLOCK_USE_EXCL;

	backend = i_new(struct squat_fts_backend, 1);
	backend->backend = fts_backend_squat;
	backend->trie =
		squat_trie_init(t_strconcat(path, "/"SQUAT_FILE_PREFIX, NULL),
				status.uidvalidity,
				storage->set->parsed_lock_method,
				flags, perm->file_create_mode,
				perm->file_create_gid);

	env = mail_user_plugin_getenv(box->storage->user, "fts_squat");
	if (env != NULL)
		fts_backend_squat_set(backend, env);
	return &backend->backend;
}

static void fts_backend_squat_deinit(struct fts_backend *_backend)
{
	struct squat_fts_backend *backend =
		(struct squat_fts_backend *)_backend;

	squat_trie_deinit(&backend->trie);
	i_free(backend);
}

static int fts_backend_squat_get_last_uid(struct fts_backend *_backend,
					  uint32_t *last_uid_r)
{
	struct squat_fts_backend *backend =
		(struct squat_fts_backend *)_backend;

	return squat_trie_get_last_uid(backend->trie, last_uid_r);
}

static int
fts_backend_squat_build_init(struct fts_backend *_backend, uint32_t *last_uid_r,
			     struct fts_backend_build_context **ctx_r)
{
	struct squat_fts_backend *backend =
		(struct squat_fts_backend *)_backend;
	struct squat_fts_backend_build_context *ctx;
	struct squat_trie_build_context *build_ctx;

	if (squat_trie_build_init(backend->trie, last_uid_r, &build_ctx) < 0)
		return -1;

	ctx = i_new(struct squat_fts_backend_build_context, 1);
	ctx->ctx.backend = _backend;
	ctx->build_ctx = build_ctx;

	*ctx_r = &ctx->ctx;
	return 0;
}

static void
fts_backend_squat_build_hdr(struct fts_backend_build_context *_ctx,
			    uint32_t uid)
{
	struct squat_fts_backend_build_context *ctx =
		(struct squat_fts_backend_build_context *)_ctx;

	ctx->squat_type = SQUAT_INDEX_TYPE_HEADER;
	ctx->uid = uid;
}

static bool
fts_backend_squat_build_body_begin(struct fts_backend_build_context *_ctx,
				   uint32_t uid, const char *content_type,
				   const char *content_disposition ATTR_UNUSED)
{
	struct squat_fts_backend_build_context *ctx =
		(struct squat_fts_backend_build_context *)_ctx;

	if (!fts_backend_default_can_index(content_type))
		return FALSE;

	ctx->squat_type = SQUAT_INDEX_TYPE_BODY;
	ctx->uid = uid;
	return TRUE;
}

static int
fts_backend_squat_build_more(struct fts_backend_build_context *_ctx,
			     const unsigned char *data, size_t size)
{
	struct squat_fts_backend_build_context *ctx =
		(struct squat_fts_backend_build_context *)_ctx;

	return squat_trie_build_more(ctx->build_ctx, ctx->uid, ctx->squat_type,
				     data, size);
}

static int get_all_msg_uids(struct mailbox *box, ARRAY_TYPE(seq_range) *uids)
{
	struct mailbox_transaction_context *t;
	struct mail_search_context *search_ctx;
	struct mail_search_args *search_args;
	struct mail *mail;
	int ret;

	t = mailbox_transaction_begin(box, 0);

	search_args = mail_search_build_init();
	mail_search_build_add_all(search_args);
	search_ctx = mailbox_search_init(t, search_args, NULL, 0, NULL);
	mail_search_args_unref(&search_args);

	while (mailbox_search_next(search_ctx, &mail)) {
		/* *2 because even/odd is for body/header */
		seq_range_array_add_range(uids, mail->uid * 2,
					  mail->uid * 2 + 1);
	}
	ret = mailbox_search_deinit(&search_ctx);
	(void)mailbox_transaction_commit(&t);
	return ret;
}

static int
fts_backend_squat_build_deinit(struct fts_backend_build_context *_ctx)
{
	struct squat_fts_backend_build_context *ctx =
		(struct squat_fts_backend_build_context *)_ctx;
	ARRAY_TYPE(seq_range) uids;
	int ret;

	i_array_init(&uids, 1024);
	if (get_all_msg_uids(ctx->ctx.backend->box, &uids) < 0)
		ret = squat_trie_build_deinit(&ctx->build_ctx, NULL);
	else {
		seq_range_array_invert(&uids, 2, (uint32_t)-2);
		ret = squat_trie_build_deinit(&ctx->build_ctx, &uids);
	}
	array_free(&uids);
	i_free(ctx);
	return ret;
}

static void
fts_backend_squat_expunge(struct fts_backend *_backend ATTR_UNUSED,
			  struct mail *mail ATTR_UNUSED)
{
}

static void
fts_backend_squat_expunge_finish(struct fts_backend *_backend ATTR_UNUSED,
				 struct mailbox *box ATTR_UNUSED,
				 bool committed ATTR_UNUSED)
{
	/* FIXME */
}

static int fts_backend_squat_refresh(struct fts_backend *_backend)
{
	struct squat_fts_backend *backend =
		(struct squat_fts_backend *)_backend;

	return squat_trie_refresh(backend->trie);
}

static int
fts_backend_squat_lookup(struct fts_backend *_backend, const char *key,
			 enum fts_lookup_flags flags,
			 ARRAY_TYPE(seq_range) *definite_uids,
			 ARRAY_TYPE(seq_range) *maybe_uids)
{
	struct squat_fts_backend *backend =
		(struct squat_fts_backend *)_backend;
	enum squat_index_type squat_type = 0;

	i_assert((flags & FTS_LOOKUP_FLAG_INVERT) == 0);

	if ((flags & FTS_LOOKUP_FLAG_HEADER) != 0)
		squat_type |= SQUAT_INDEX_TYPE_HEADER;
	if ((flags & FTS_LOOKUP_FLAG_BODY) != 0)
		squat_type |= SQUAT_INDEX_TYPE_BODY;
	i_assert(squat_type != 0);

	return squat_trie_lookup(backend->trie, key, squat_type,
				 definite_uids, maybe_uids);
}

struct fts_backend fts_backend_squat = {
	.name = "squat",
	.flags = 0,

	{
		fts_backend_squat_init,
		fts_backend_squat_deinit,
		fts_backend_squat_get_last_uid,
		NULL,
		fts_backend_squat_build_init,
		fts_backend_squat_build_hdr,
		fts_backend_squat_build_body_begin,
		NULL,
		fts_backend_squat_build_more,
		fts_backend_squat_build_deinit,
		fts_backend_squat_expunge,
		fts_backend_squat_expunge_finish,
		fts_backend_squat_refresh,
		fts_backend_squat_lookup,
		NULL,
		NULL
	}
};
