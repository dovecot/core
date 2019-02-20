/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "unichar.h"
#include "mail-user.h"
#include "mail-namespace.h"
#include "mail-storage-private.h"
#include "mail-search-build.h"
#include "squat-trie.h"
#include "fts-squat-plugin.h"


#define SQUAT_FILE_PREFIX "dovecot.index.search"

struct squat_fts_backend {
	struct fts_backend backend;

	struct mailbox *box;
	struct squat_trie *trie;

	unsigned int partial_len, full_len;
	bool refresh;
};

struct squat_fts_backend_update_context {
	struct fts_backend_update_context ctx;
	struct squat_trie_build_context *build_ctx;

	enum squat_index_type squat_type;
	uint32_t uid;
	string_t *hdr;

	bool failed;
};

static struct fts_backend *fts_backend_squat_alloc(void)
{
	struct squat_fts_backend *backend;

	backend = i_new(struct squat_fts_backend, 1);
	backend->backend = fts_backend_squat;
	return &backend->backend;
}

static int
fts_backend_squat_init(struct fts_backend *_backend, const char **error_r)
{
	struct squat_fts_backend *backend =
		(struct squat_fts_backend *)_backend;
	const char *const *tmp, *env;
	unsigned int len;

	env = mail_user_plugin_getenv(_backend->ns->user, "fts_squat");
	if (env == NULL)
		return 0;

	for (tmp = t_strsplit_spaces(env, " "); *tmp != NULL; tmp++) {
		if (str_begins(*tmp, "partial=")) {
			if (str_to_uint(*tmp + 8, &len) < 0 || len == 0) {
				*error_r = t_strdup_printf(
					"Invalid partial length: %s", *tmp + 8);
				return -1;
			}
			backend->partial_len = len;
		} else if (str_begins(*tmp, "full=")) {
			if (str_to_uint(*tmp + 5, &len) < 0 || len == 0) {
				*error_r = t_strdup_printf(
					"Invalid full length: %s", *tmp + 5);
				return -1;
			}
			backend->full_len = len;
		} else {
			*error_r = t_strdup_printf("Invalid setting: %s", *tmp);
			return -1;
		}
	}
	return 0;
}

static void
fts_backend_squat_unset_box(struct squat_fts_backend *backend)
{
	if (backend->trie != NULL)
		squat_trie_deinit(&backend->trie);
	backend->box = NULL;
}

static void fts_backend_squat_deinit(struct fts_backend *_backend)
{
	struct squat_fts_backend *backend =
		(struct squat_fts_backend *)_backend;

	fts_backend_squat_unset_box(backend);
	i_free(backend);
}

static int
fts_backend_squat_set_box(struct squat_fts_backend *backend,
			  struct mailbox *box)
{
	const struct mailbox_permissions *perm;
	struct mail_storage *storage;
	struct mailbox_status status;
	const char *path;
	enum squat_index_flags flags = 0;
        int ret;

	if (backend->box == box)
        {
		if (backend->refresh) {
                        ret = squat_trie_refresh(backend->trie);
                        if (ret < 0)
				return ret;
			backend->refresh = FALSE;
		}
		return 0;
	}
	fts_backend_squat_unset_box(backend);
	backend->refresh = FALSE;
	if (box == NULL)
		return 0;

	perm = mailbox_get_permissions(box);
	storage = mailbox_get_storage(box);
	if (mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_INDEX, &path) <= 0)
		i_unreached(); /* fts already checked this */

	mailbox_get_open_status(box, STATUS_UIDVALIDITY, &status);
	if (storage->set->mmap_disable)
		flags |= SQUAT_INDEX_FLAG_MMAP_DISABLE;
	if (storage->set->mail_nfs_index)
		flags |= SQUAT_INDEX_FLAG_NFS_FLUSH;
	if (storage->set->dotlock_use_excl)
		flags |= SQUAT_INDEX_FLAG_DOTLOCK_USE_EXCL;

	backend->trie =
		squat_trie_init(t_strconcat(path, "/"SQUAT_FILE_PREFIX, NULL),
				status.uidvalidity,
				storage->set->parsed_lock_method,
				flags, perm->file_create_mode,
				perm->file_create_gid);

	if (backend->partial_len != 0)
		squat_trie_set_partial_len(backend->trie, backend->partial_len);
	if (backend->full_len != 0)
		squat_trie_set_full_len(backend->trie, backend->full_len);
	backend->box = box;
	return squat_trie_open(backend->trie);
}

static int
fts_backend_squat_get_last_uid(struct fts_backend *_backend,
			       struct mailbox *box, uint32_t *last_uid_r)
{
	struct squat_fts_backend *backend =
		(struct squat_fts_backend *)_backend;

	int ret = fts_backend_squat_set_box(backend, box);
	if (ret < 0)
		return -1;
	return squat_trie_get_last_uid(backend->trie, last_uid_r);
}

static struct fts_backend_update_context *
fts_backend_squat_update_init(struct fts_backend *_backend)
{
	struct squat_fts_backend_update_context *ctx;

	ctx = i_new(struct squat_fts_backend_update_context, 1);
	ctx->ctx.backend = _backend;
	ctx->hdr = str_new(default_pool, 1024*32);
	return &ctx->ctx;
}

static int get_all_msg_uids(struct mailbox *box, ARRAY_TYPE(seq_range) *uids)
{
	struct mailbox_transaction_context *t;
	struct mail_search_context *search_ctx;
	struct mail_search_args *search_args;
	struct mail *mail;
	int ret;

	t = mailbox_transaction_begin(box, 0, __func__);

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
fts_backend_squat_update_uid_changed(struct squat_fts_backend_update_context *ctx)
{
	int ret = 0;

	if (ctx->uid == 0)
		return 0;

	if (squat_trie_build_more(ctx->build_ctx, ctx->uid,
				  SQUAT_INDEX_TYPE_HEADER,
				  str_data(ctx->hdr), str_len(ctx->hdr)) < 0)
		ret = -1;
	str_truncate(ctx->hdr, 0);
	return ret;
}

static int
fts_backend_squat_build_deinit(struct squat_fts_backend_update_context *ctx)
{
	struct squat_fts_backend *backend =
		(struct squat_fts_backend *)ctx->ctx.backend;
	ARRAY_TYPE(seq_range) uids;
	int ret = 0;

	if (ctx->build_ctx == NULL)
		return 0;

	if (fts_backend_squat_update_uid_changed(ctx) < 0)
		ret = -1;

	i_array_init(&uids, 1024);
	if (get_all_msg_uids(backend->box, &uids) < 0) {
		(void)squat_trie_build_deinit(&ctx->build_ctx, NULL);
		ret = -1;
	} else {
		seq_range_array_invert(&uids, 2, (uint32_t)-2);
		if (squat_trie_build_deinit(&ctx->build_ctx, &uids) < 0)
			ret = -1;
	}
	array_free(&uids);
	return ret;
}

static int
fts_backend_squat_update_deinit(struct fts_backend_update_context *_ctx)
{
	struct squat_fts_backend_update_context *ctx =
		(struct squat_fts_backend_update_context *)_ctx;
	int ret = ctx->failed ? -1 : 0;

	if (fts_backend_squat_build_deinit(ctx) < 0)
		ret = -1;
	str_free(&ctx->hdr);
	i_free(ctx);
	return ret;
}

static void
fts_backend_squat_update_set_mailbox(struct fts_backend_update_context *_ctx,
				     struct mailbox *box)
{
	struct squat_fts_backend_update_context *ctx =
		(struct squat_fts_backend_update_context *)_ctx;
	struct squat_fts_backend *backend =
		(struct squat_fts_backend *)ctx->ctx.backend;

	if (fts_backend_squat_build_deinit(ctx) < 0)
		ctx->failed = TRUE;
	if (fts_backend_squat_set_box(backend, box) < 0)
		ctx->failed = TRUE;
	else if (box != NULL) {
		if (squat_trie_build_init(backend->trie, &ctx->build_ctx) < 0)
			ctx->failed = TRUE;
	}
}

static void
fts_backend_squat_update_expunge(struct fts_backend_update_context *_ctx ATTR_UNUSED,
				 uint32_t last_uid ATTR_UNUSED)
{
	/* FIXME */
}

static bool
fts_backend_squat_update_set_build_key(struct fts_backend_update_context *_ctx,
				       const struct fts_backend_build_key *key)
{
	struct squat_fts_backend_update_context *ctx =
		(struct squat_fts_backend_update_context *)_ctx;

	if (ctx->failed)
		return FALSE;

	if (key->uid != ctx->uid) {
		if (fts_backend_squat_update_uid_changed(ctx) < 0)
			ctx->failed = TRUE;
	}

	switch (key->type) {
	case FTS_BACKEND_BUILD_KEY_HDR:
	case FTS_BACKEND_BUILD_KEY_MIME_HDR:
		str_printfa(ctx->hdr, "%s: ", key->hdr_name);
		ctx->squat_type = SQUAT_INDEX_TYPE_HEADER;
		break;
	case FTS_BACKEND_BUILD_KEY_BODY_PART:
		ctx->squat_type = SQUAT_INDEX_TYPE_BODY;
		break;
	case FTS_BACKEND_BUILD_KEY_BODY_PART_BINARY:
		i_unreached();
	}
	ctx->uid = key->uid;
	return TRUE;
}

static void
fts_backend_squat_update_unset_build_key(struct fts_backend_update_context *_ctx)
{
	struct squat_fts_backend_update_context *ctx =
		(struct squat_fts_backend_update_context *)_ctx;

	if (ctx->squat_type == SQUAT_INDEX_TYPE_HEADER)
		str_append_c(ctx->hdr, '\n');
}

static int
fts_backend_squat_update_build_more(struct fts_backend_update_context *_ctx,
				    const unsigned char *data, size_t size)
{
	struct squat_fts_backend_update_context *ctx =
		(struct squat_fts_backend_update_context *)_ctx;

	if (ctx->squat_type == SQUAT_INDEX_TYPE_HEADER) {
		str_append_data(ctx->hdr, data, size);
		return 0;
	}
	return squat_trie_build_more(ctx->build_ctx, ctx->uid, ctx->squat_type,
				     data, size);
}

static int fts_backend_squat_refresh(struct fts_backend *_backend)
{
	struct squat_fts_backend *backend =
		(struct squat_fts_backend *)_backend;

	backend->refresh = TRUE;
	return 0;
}

static int fts_backend_squat_optimize(struct fts_backend *_backend ATTR_UNUSED)
{
	/* FIXME: drop expunged messages */
	return 0;
}

static int squat_lookup_arg(struct squat_fts_backend *backend,
			    const struct mail_search_arg *arg, bool and_args,
			    ARRAY_TYPE(seq_range) *definite_uids,
			    ARRAY_TYPE(seq_range) *maybe_uids)
{
	enum squat_index_type squat_type;
	ARRAY_TYPE(seq_range) tmp_definite_uids, tmp_maybe_uids;
	string_t *dtc;
	uint32_t last_uid;
	int ret;

	switch (arg->type) {
	case SEARCH_TEXT:
		squat_type = SQUAT_INDEX_TYPE_HEADER |
			SQUAT_INDEX_TYPE_BODY;
		break;
	case SEARCH_BODY:
		squat_type = SQUAT_INDEX_TYPE_BODY;
		break;
	case SEARCH_HEADER:
	case SEARCH_HEADER_ADDRESS:
	case SEARCH_HEADER_COMPRESS_LWSP:
		squat_type = SQUAT_INDEX_TYPE_HEADER;
		break;
	default:
		return 0;
	}

	i_array_init(&tmp_definite_uids, 128);
	i_array_init(&tmp_maybe_uids, 128);

	dtc = t_str_new(128);
	if (backend->backend.ns->user->
	    default_normalizer(arg->value.str, strlen(arg->value.str), dtc) < 0)
		i_panic("squat: search key not utf8");

	ret = squat_trie_lookup(backend->trie, str_c(dtc), squat_type,
				&tmp_definite_uids, &tmp_maybe_uids);
	if (arg->match_not) {
		/* definite -> non-match
		   maybe -> maybe
		   non-match -> maybe */
		array_clear(&tmp_maybe_uids);

		if (squat_trie_get_last_uid(backend->trie, &last_uid) < 0)
			i_unreached();
		seq_range_array_add_range(&tmp_maybe_uids, 1, last_uid);
		seq_range_array_remove_seq_range(&tmp_maybe_uids,
						 &tmp_definite_uids);
		array_clear(&tmp_definite_uids);
	}

	if (and_args) {
		/* AND:
		   definite && definite -> definite
		   definite && maybe -> maybe
		   maybe && maybe -> maybe */

		/* put definites among maybies, so they can be intersected */
		seq_range_array_merge(maybe_uids, definite_uids);
		seq_range_array_merge(&tmp_maybe_uids, &tmp_definite_uids);

		seq_range_array_intersect(maybe_uids, &tmp_maybe_uids);
		seq_range_array_intersect(definite_uids, &tmp_definite_uids);
		/* remove duplicate maybies that are also definites */
		seq_range_array_remove_seq_range(maybe_uids, definite_uids);
	} else {
		/* OR:
		   definite || definite -> definite
		   definite || maybe -> definite
		   maybe || maybe -> maybe */

		/* remove maybies that are now definites */
		seq_range_array_remove_seq_range(&tmp_maybe_uids,
						 definite_uids);
		seq_range_array_remove_seq_range(maybe_uids,
						 &tmp_definite_uids);

		seq_range_array_merge(definite_uids, &tmp_definite_uids);
		seq_range_array_merge(maybe_uids, &tmp_maybe_uids);
	}

	array_free(&tmp_definite_uids);
	array_free(&tmp_maybe_uids);
	return ret < 0 ? -1 : 1;
}

static int
fts_backend_squat_lookup(struct fts_backend *_backend, struct mailbox *box,
			 struct mail_search_arg *args,
			 enum fts_lookup_flags flags,
			 struct fts_result *result)
{
	struct squat_fts_backend *backend =
		(struct squat_fts_backend *)_backend;
	bool and_args = (flags & FTS_LOOKUP_FLAG_AND_ARGS) != 0;
	bool first = TRUE;
	int ret;

	ret = fts_backend_squat_set_box(backend, box);
	if (ret < 0)
		return -1;

	for (; args != NULL; args = args->next) {
		ret = squat_lookup_arg(backend, args, first ? FALSE : and_args,
				       &result->definite_uids,
				       &result->maybe_uids);
		if (ret < 0)
			return -1;
		if (ret > 0) {
			args->match_always = TRUE;
			first = FALSE;
		}
	}
	return 0;
}

struct fts_backend fts_backend_squat = {
	.name = "squat",
	.flags = FTS_BACKEND_FLAG_NORMALIZE_INPUT,

	{
		fts_backend_squat_alloc,
		fts_backend_squat_init,
		fts_backend_squat_deinit,
		fts_backend_squat_get_last_uid,
		fts_backend_squat_update_init,
		fts_backend_squat_update_deinit,
		fts_backend_squat_update_set_mailbox,
		fts_backend_squat_update_expunge,
		fts_backend_squat_update_set_build_key,
		fts_backend_squat_update_unset_build_key,
		fts_backend_squat_update_build_more,
		fts_backend_squat_refresh,
		NULL,
		fts_backend_squat_optimize,
		fts_backend_default_can_lookup,
		fts_backend_squat_lookup,
		NULL,
		NULL
	}
};
