/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "hex-binary.h"
#include "mail-namespace.h"
#include "mail-storage-private.h"
#include "fts-expunge-log.h"
#include "lucene-wrapper.h"
#include "fts-lucene-plugin.h"

#include <wchar.h>

#define LUCENE_INDEX_DIR_NAME "lucene-indexes"
#define LUCENE_EXPUNGE_LOG_NAME "dovecot-expunges.log"
#define LUCENE_OPTIMIZE_BATCH_MSGS_COUNT 100

struct lucene_fts_backend {
	struct fts_backend backend;
	char *dir_path;

	struct lucene_index *index;
	struct mailbox *selected_box;
	unsigned int selected_box_generation;
	mail_guid_128_t selected_box_guid;

	struct fts_expunge_log *expunge_log;

	unsigned int dir_created:1;
	unsigned int updating:1;
};

struct lucene_fts_backend_update_context {
	struct fts_backend_update_context ctx;

	struct mailbox *box;
	uint32_t last_uid;

	uint32_t uid;
	char *hdr_name;

	unsigned int added_msgs;
	bool lucene_opened;

	struct fts_expunge_log_append_ctx *expunge_ctx;
};

static int fts_backend_lucene_mkdir(struct lucene_fts_backend *backend)
{
	if (backend->dir_created)
		return 0;

	backend->dir_created = TRUE;
	return mailbox_list_mkdir_root(backend->backend.ns->list,
				       backend->dir_path,
				       MAILBOX_LIST_PATH_TYPE_INDEX);
}

static int
fts_lucene_get_mailbox_guid(struct mailbox *box, mail_guid_128_t *guid_r)
{
	struct mailbox_metadata metadata;

	if (mailbox_get_metadata(box, MAILBOX_METADATA_GUID,
				 &metadata) < 0) {
		i_error("lucene: Couldn't get mailbox %s GUID: %s",
			box->vname, mailbox_get_last_error(box, NULL));
		return -1;
	}
	memcpy(guid_r, metadata.guid, MAIL_GUID_128_SIZE);
	return 0;
}

static int
fts_backend_select(struct lucene_fts_backend *backend, struct mailbox *box)
{
	mail_guid_128_t guid;
	unsigned char guid_hex[MAILBOX_GUID_HEX_LENGTH];
	wchar_t wguid_hex[MAILBOX_GUID_HEX_LENGTH];
	buffer_t buf;
	unsigned int i;

	if (backend->selected_box == box &&
	    backend->selected_box_generation == box->generation_sequence)
		return 0;

	if (fts_backend_lucene_mkdir(backend) < 0)
		return -1;

	if (box != NULL) {
		if (fts_lucene_get_mailbox_guid(box, &guid) < 0)
			return -1;
		buffer_create_data(&buf, guid_hex, MAILBOX_GUID_HEX_LENGTH);
		binary_to_hex_append(&buf, guid, MAIL_GUID_128_SIZE);
		for (i = 0; i < N_ELEMENTS(wguid_hex); i++)
			wguid_hex[i] = guid_hex[i];

		lucene_index_select_mailbox(backend->index, wguid_hex);
	} else {
		lucene_index_unselect_mailbox(backend->index);
		memset(&guid, 0, sizeof(guid));
	}
	backend->selected_box = box;
	memcpy(backend->selected_box_guid, guid,
	       sizeof(backend->selected_box_guid));
	backend->selected_box_generation =
		box == NULL ? 0 : box->generation_sequence;
	return 0;
}

static struct fts_backend *fts_backend_lucene_alloc(void)
{
	struct lucene_fts_backend *backend;

	backend = i_new(struct lucene_fts_backend, 1);
	backend->backend = fts_backend_lucene;
	return &backend->backend;
}

static int
fts_backend_lucene_init(struct fts_backend *_backend,
			const char **error_r ATTR_UNUSED)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_backend;
	struct fts_lucene_user *fuser =
		FTS_LUCENE_USER_CONTEXT(_backend->ns->user);
	const char *path;

	path = mailbox_list_get_path(_backend->ns->list, NULL,
				     MAILBOX_LIST_PATH_TYPE_INDEX);
	i_assert(path != NULL); /* fts already checked this */

	backend->dir_path = i_strconcat(path, "/"LUCENE_INDEX_DIR_NAME, NULL);
	if (fuser != NULL) {
		backend->index = lucene_index_init(backend->dir_path,
						   fuser->set.textcat_dir,
						   fuser->set.textcat_conf);
	} else {
		backend->index = lucene_index_init(backend->dir_path,
						   NULL, NULL);
	}

	path = t_strconcat(backend->dir_path, "/"LUCENE_EXPUNGE_LOG_NAME, NULL);
	backend->expunge_log = fts_expunge_log_init(path);
	return 0;
}

static void fts_backend_lucene_deinit(struct fts_backend *_backend)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_backend;

	lucene_index_deinit(backend->index);
	fts_expunge_log_deinit(&backend->expunge_log);
	i_free(backend->dir_path);
	i_free(backend);
}

static int
fts_backend_lucene_get_last_uid(struct fts_backend *_backend,
				struct mailbox *box, uint32_t *last_uid_r)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_backend;

	if (fts_index_get_last_uid(box, last_uid_r))
		return 0;

	/* either nothing has been indexed, or the index was corrupted.
	   do it the slow way. */
	if (fts_backend_select(backend, box) < 0)
		return -1;
	if (lucene_index_get_last_uid(backend->index, last_uid_r) < 0)
		return -1;

	(void)fts_index_set_last_uid(box, *last_uid_r);
	return 0;
}

static struct fts_backend_update_context *
fts_backend_lucene_update_init(struct fts_backend *_backend)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_backend;
	struct lucene_fts_backend_update_context *ctx;

	i_assert(!backend->updating);

	ctx = i_new(struct lucene_fts_backend_update_context, 1);
	ctx->ctx.backend = _backend;
	backend->updating = TRUE;

	if (fts_backend_lucene_mkdir(backend) < 0)
		ctx->ctx.failed = TRUE;
	return &ctx->ctx;
}

static bool
fts_backend_lucene_need_optimize(struct lucene_fts_backend_update_context *ctx)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)ctx->ctx.backend;
	unsigned int expunges;
	uint32_t numdocs;

	if (!ctx->ctx.backend->syncing) {
		/* only indexer process can actually do anything
		   about optimizing */
		return FALSE;
	}
	if (ctx->added_msgs >= LUCENE_OPTIMIZE_BATCH_MSGS_COUNT)
		return TRUE;
	if (lucene_index_get_doc_count(backend->index, &numdocs) < 0)
		return FALSE;

	if (fts_expunge_log_uid_count(backend->expunge_log, &expunges) < 0)
		return FALSE;
	return expunges > 0 &&
		numdocs / expunges <= 50; /* >2% of index has been expunged */
}

static int
fts_backend_lucene_update_deinit(struct fts_backend_update_context *_ctx)
{
	struct lucene_fts_backend_update_context *ctx =
		(struct lucene_fts_backend_update_context *)_ctx;
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_ctx->backend;
	int ret = _ctx->failed ? -1 : 0;

	i_assert(backend->updating);

	backend->updating = FALSE;
	if (ctx->lucene_opened)
		lucene_index_build_deinit(backend->index);

	if (ctx->expunge_ctx != NULL) {
		if (fts_expunge_log_append_commit(&ctx->expunge_ctx) < 0)
			ret = -1;
	}

	if (fts_backend_lucene_need_optimize(ctx))
		(void)fts_backend_optimize(_ctx->backend);

	i_free(ctx);
	return ret;
}

static void
fts_backend_lucene_update_set_mailbox(struct fts_backend_update_context *_ctx,
				      struct mailbox *box)
{
	struct lucene_fts_backend_update_context *ctx =
		(struct lucene_fts_backend_update_context *)_ctx;

	if (ctx->last_uid != 0) {
		(void)fts_index_set_last_uid(ctx->box, ctx->last_uid);
		ctx->last_uid = 0;
	}
	ctx->box = box;
}

static void
fts_backend_lucene_update_expunge(struct fts_backend_update_context *_ctx,
				  uint32_t uid)
{
	struct lucene_fts_backend_update_context *ctx =
		(struct lucene_fts_backend_update_context *)_ctx;
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_ctx->backend;

	if (ctx->expunge_ctx == NULL) {
		ctx->expunge_ctx =
			fts_expunge_log_append_begin(backend->expunge_log);
	}

	if (fts_backend_select(backend, ctx->box) < 0)
		_ctx->failed = TRUE;

	fts_expunge_log_append_next(ctx->expunge_ctx,
				    backend->selected_box_guid, uid);
}

static bool
fts_backend_lucene_update_set_build_key(struct fts_backend_update_context *_ctx,
					const struct fts_backend_build_key *key)
{
	struct lucene_fts_backend_update_context *ctx =
		(struct lucene_fts_backend_update_context *)_ctx;
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_ctx->backend;

	if (!ctx->lucene_opened) {
		if (lucene_index_build_init(backend->index) < 0)
			ctx->ctx.failed = TRUE;
		ctx->lucene_opened = TRUE;
	}

	if (fts_backend_select(backend, ctx->box) < 0)
		_ctx->failed = TRUE;

	switch (key->type) {
	case FTS_BACKEND_BUILD_KEY_HDR:
	case FTS_BACKEND_BUILD_KEY_MIME_HDR:
		i_assert(key->hdr_name != NULL);

		i_free(ctx->hdr_name);
		ctx->hdr_name = i_strdup(key->hdr_name);
		break;
	case FTS_BACKEND_BUILD_KEY_BODY_PART:
		i_free_and_null(ctx->hdr_name);
		break;
	case FTS_BACKEND_BUILD_KEY_BODY_PART_BINARY:
		i_unreached();
	}

	if (key->uid != ctx->last_uid) {
		i_assert(key->uid >= ctx->last_uid);
		ctx->last_uid = key->uid;
		ctx->added_msgs++;
	}

	ctx->uid = key->uid;
	return TRUE;
}

static void
fts_backend_lucene_update_unset_build_key(struct fts_backend_update_context *_ctx)
{
	struct lucene_fts_backend_update_context *ctx =
		(struct lucene_fts_backend_update_context *)_ctx;

	ctx->uid = 0;
	i_free_and_null(ctx->hdr_name);
}

static int
fts_backend_lucene_update_build_more(struct fts_backend_update_context *_ctx,
				     const unsigned char *data, size_t size)
{
	struct lucene_fts_backend_update_context *ctx =
		(struct lucene_fts_backend_update_context *)_ctx;
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_ctx->backend;
	int ret;

	i_assert(ctx->uid != 0);

	if (_ctx->failed)
		return -1;

	T_BEGIN {
		ret = lucene_index_build_more(backend->index, ctx->uid,
					      data, size, ctx->hdr_name);
	} T_END;
	return ret;
}

static int
fts_backend_lucene_refresh(struct fts_backend *_backend)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_backend;

	lucene_index_close(backend->index);
	return 0;
}

static int fts_backend_lucene_rescan(struct fts_backend *_backend)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_backend;

	if (lucene_index_rescan(backend->index, _backend->ns->list) < 0)
		return -1;
	return lucene_index_optimize(backend->index);
}

static int fts_backend_lucene_optimize(struct fts_backend *_backend)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_backend;
	int ret;

	ret = lucene_index_expunge_from_log(backend->index,
					    backend->expunge_log);
	if (ret == 0) {
		/* log was corrupted, need to rescan */
		ret = lucene_index_rescan(backend->index, _backend->ns->list);
	}
	if (ret >= 0)
		ret = lucene_index_optimize(backend->index);
	return ret;
}

static int
fts_backend_lucene_lookup(struct fts_backend *_backend, struct mailbox *box,
			  struct mail_search_arg *args, bool and_args,
			  struct fts_result *result)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_backend;
	int ret;

	if (fts_backend_select(backend, box) < 0)
		return -1;
	T_BEGIN {
		ret = lucene_index_lookup(backend->index, args, and_args,
					  result);
	} T_END;
	return ret;
}

/* a char* hash function from ASU -- from glib */
static unsigned int wstr_hash(const void *p)
{
        const wchar_t *s = p;
	unsigned int g, h = 0;

	while (*s != '\0') {
		h = (h << 4) + *s;
		if ((g = h & 0xf0000000UL)) {
			h = h ^ (g >> 24);
			h = h ^ g;
		}
		s++;
	}

	return h;
}

static int
mailboxes_get_guids(struct mailbox *const boxes[],
		    struct hash_table *guids, struct fts_multi_result *result)
{
	ARRAY_DEFINE(box_results, struct fts_result);
	struct fts_result *box_result;
	const char *guid;
	wchar_t *guid_dup;
	unsigned int i, j;

	p_array_init(&box_results, result->pool, 32);
	for (i = 0; boxes[i] != NULL; i++) {
		if (fts_mailbox_get_guid(boxes[i], &guid) < 0)
			return -1;

		i_assert(strlen(guid) == MAILBOX_GUID_HEX_LENGTH);
		guid_dup = t_new(wchar_t, MAILBOX_GUID_HEX_LENGTH + 1);
		for (j = 0; j < MAILBOX_GUID_HEX_LENGTH; j++)
			guid_dup[j] = guid[j];

		box_result = array_append_space(&box_results);
		box_result->box = boxes[i];
		hash_table_insert(guids, guid_dup, box_result);
	}

	(void)array_append_space(&box_results);
	result->box_results = array_idx_modifiable(&box_results, 0);
	return 0;
}

static int
fts_backend_lucene_lookup_multi(struct fts_backend *_backend,
				struct mailbox *const boxes[],
				struct mail_search_arg *args, bool and_args,
				struct fts_multi_result *result)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_backend;
	int ret;

	if (fts_backend_lucene_mkdir(backend) < 0)
		return -1;

	T_BEGIN {
		struct hash_table *guids;

		guids = hash_table_create(default_pool, default_pool, 0,
					  wstr_hash,
					  (hash_cmp_callback_t *)wcscmp);
		ret = mailboxes_get_guids(boxes, guids, result);
		if (ret == 0) {
			ret = lucene_index_lookup_multi(backend->index,
							guids, args, and_args,
							result);
		}
		hash_table_destroy(&guids);
	} T_END;
	return ret;
}

struct fts_backend fts_backend_lucene = {
	.name = "lucene",
	.flags = 0,

	{
		fts_backend_lucene_alloc,
		fts_backend_lucene_init,
		fts_backend_lucene_deinit,
		fts_backend_lucene_get_last_uid,
		fts_backend_lucene_update_init,
		fts_backend_lucene_update_deinit,
		fts_backend_lucene_update_set_mailbox,
		fts_backend_lucene_update_expunge,
		fts_backend_lucene_update_set_build_key,
		fts_backend_lucene_update_unset_build_key,
		fts_backend_lucene_update_build_more,
		fts_backend_lucene_refresh,
		fts_backend_lucene_rescan,
		fts_backend_lucene_optimize,
		fts_backend_default_can_lookup,
		fts_backend_lucene_lookup,
		fts_backend_lucene_lookup_multi
	}
};
