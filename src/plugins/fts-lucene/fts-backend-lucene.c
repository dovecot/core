/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "hex-binary.h"
#include "strescape.h"
#include "message-part.h"
#include "mail-namespace.h"
#include "mail-storage-private.h"
#include "fts-expunge-log.h"
#include "lucene-wrapper.h"
#include "fts-indexer.h"
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
	guid_128_t selected_box_guid;

	struct fts_expunge_log *expunge_log;

	bool dir_created:1;
	bool updating:1;
};

struct lucene_fts_backend_update_context {
	struct fts_backend_update_context ctx;

	struct mailbox *box;
	uint32_t last_uid;
	uint32_t last_indexed_uid;
	char *first_box_vname;

	uint32_t uid, part_num;
	char *hdr_name;

	unsigned int added_msgs;
	struct fts_expunge_log_append_ctx *expunge_ctx;

	bool lucene_opened;
	bool last_indexed_uid_set;
	bool mime_parts;
};

static int fts_backend_lucene_mkdir(struct lucene_fts_backend *backend)
{
	if (backend->dir_created)
		return 0;

	backend->dir_created = TRUE;
	if (mailbox_list_mkdir_root(backend->backend.ns->list,
				    backend->dir_path,
				    MAILBOX_LIST_PATH_TYPE_INDEX) < 0)
		return -1;
	return 0;
}

static int
fts_lucene_get_mailbox_guid(struct mailbox *box, guid_128_t guid_r)
{
	struct mailbox_metadata metadata;

	if (mailbox_get_metadata(box, MAILBOX_METADATA_GUID,
				 &metadata) < 0) {
		i_error("lucene: Couldn't get mailbox %s GUID: %s",
			box->vname, mailbox_get_last_internal_error(box, NULL));
		return -1;
	}
	memcpy(guid_r, metadata.guid, GUID_128_SIZE);
	return 0;
}

static int
fts_backend_select(struct lucene_fts_backend *backend, struct mailbox *box)
{
	guid_128_t guid;
	unsigned char guid_hex[MAILBOX_GUID_HEX_LENGTH];
	wchar_t wguid_hex[MAILBOX_GUID_HEX_LENGTH];
	buffer_t buf;
	unsigned int i;

	i_assert(box != NULL);

	if (backend->selected_box == box &&
	    backend->selected_box_generation == box->generation_sequence)
		return 0;

	if (fts_lucene_get_mailbox_guid(box, guid) < 0)
		return -1;
	buffer_create_from_data(&buf, guid_hex, MAILBOX_GUID_HEX_LENGTH);
	binary_to_hex_append(&buf, guid, GUID_128_SIZE);
	for (i = 0; i < N_ELEMENTS(wguid_hex); i++)
		wguid_hex[i] = guid_hex[i];

	lucene_index_select_mailbox(backend->index, wguid_hex);

	backend->selected_box = box;
	memcpy(backend->selected_box_guid, guid,
	       sizeof(backend->selected_box_guid));
	backend->selected_box_generation = box->generation_sequence;
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
fts_backend_lucene_init(struct fts_backend *_backend, const char **error_r)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_backend;
	struct fts_lucene_user *fuser =
		FTS_LUCENE_USER_CONTEXT(_backend->ns->user);
	const char *path;

	if (fuser == NULL) {
		/* invalid settings */
		*error_r = "Invalid fts_lucene settings";
		return -1;
	}
	/* fts already checked that index exists */

	if (fuser->set.use_libfts) {
		/* change our flags so we get proper input */
		_backend->flags &= ~FTS_BACKEND_FLAG_FUZZY_SEARCH;
		_backend->flags |= FTS_BACKEND_FLAG_TOKENIZED_INPUT;
	}
	path = mailbox_list_get_root_forced(_backend->ns->list,
					    MAILBOX_LIST_PATH_TYPE_INDEX);

	backend->dir_path = i_strconcat(path, "/"LUCENE_INDEX_DIR_NAME, NULL);
	backend->index = lucene_index_init(backend->dir_path,
					   _backend->ns->list,
					   &fuser->set);

	path = t_strconcat(backend->dir_path, "/"LUCENE_EXPUNGE_LOG_NAME, NULL);
	backend->expunge_log = fts_expunge_log_init(path);
	return 0;
}

static void fts_backend_lucene_deinit(struct fts_backend *_backend)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_backend;

	if (backend->index != NULL)
		lucene_index_deinit(backend->index);
	if (backend->expunge_log != NULL)
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
	struct fts_lucene_user *fuser =
		FTS_LUCENE_USER_CONTEXT_REQUIRE(_backend->ns->user);
	struct fts_index_header hdr;
	uint32_t set_checksum;
	int ret;

	if (fts_index_get_header(box, &hdr)) {
		set_checksum = fts_lucene_settings_checksum(&fuser->set);
		ret = fts_index_have_compatible_settings(_backend->ns->list,
							 set_checksum);
		if (ret < 0)
			return -1;
		if (ret == 0) {
			/* need to rebuild the index */
			*last_uid_r = 0;
		} else {
			*last_uid_r = hdr.last_indexed_uid;
		}
		return 0;
	}

	/* either nothing has been indexed, or the index was corrupted.
	   do it the slow way. */
	if (fts_backend_select(backend, box) < 0)
		return -1;
	if (lucene_index_get_last_uid(backend->index, last_uid_r) < 0)
		return -1;

	fts_index_set_last_uid(box, *last_uid_r);
	return 0;
}

static struct fts_backend_update_context *
fts_backend_lucene_update_init(struct fts_backend *_backend)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_backend;
	struct lucene_fts_backend_update_context *ctx;
	struct fts_lucene_user *fuser =
		FTS_LUCENE_USER_CONTEXT_REQUIRE(_backend->ns->user);

	i_assert(!backend->updating);

	ctx = i_new(struct lucene_fts_backend_update_context, 1);
	ctx->ctx.backend = _backend;
	ctx->mime_parts = fuser->set.mime_parts;
	backend->updating = TRUE;
	return &ctx->ctx;
}

static bool
fts_backend_lucene_need_optimize(struct lucene_fts_backend_update_context *ctx)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)ctx->ctx.backend;
	unsigned int expunges;
	uint32_t numdocs;

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
	if (ctx->lucene_opened) {
		if (lucene_index_build_deinit(backend->index) < 0)
			ret = -1;
	}

	if (ctx->expunge_ctx != NULL) {
		if (fts_expunge_log_append_commit(&ctx->expunge_ctx) < 0) {
			struct stat st;
			ret = -1;

			if (stat(backend->dir_path, &st) < 0 && errno == ENOENT) {
				/* lucene-indexes directory doesn't even exist,
				   so dovecot.index's last_index_uid is wrong.
				   rescan to update them. */
				(void)lucene_index_rescan(backend->index);
				ret = 0;
			}
		}
	}

	if (fts_backend_lucene_need_optimize(ctx)) {
		if (ctx->lucene_opened)
			(void)fts_backend_optimize(_ctx->backend);
		else if (ctx->first_box_vname != NULL) {
			struct mail_user *user = backend->backend.ns->user;
			const char *cmd, *path;
			int fd;

			/* the optimize affects all mailboxes within namespace,
			   so just use any mailbox name in it */
			cmd = t_strdup_printf("OPTIMIZE\t0\t%s\t%s\n",
				str_tabescape(user->username),
				str_tabescape(ctx->first_box_vname));
			fd = fts_indexer_cmd(user, cmd, &path);
			i_close_fd(&fd);
		}
	}

	i_free(ctx->first_box_vname);
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
		fts_index_set_last_uid(ctx->box, ctx->last_uid);
		ctx->last_uid = 0;
	}
	if (ctx->first_box_vname == NULL && box != NULL)
		ctx->first_box_vname = i_strdup(box->vname);
	ctx->box = box;
	ctx->last_indexed_uid_set = FALSE;
}

static void
fts_backend_lucene_update_expunge(struct fts_backend_update_context *_ctx,
				  uint32_t uid)
{
	struct lucene_fts_backend_update_context *ctx =
		(struct lucene_fts_backend_update_context *)_ctx;
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_ctx->backend;
	struct fts_index_header hdr;

	if (!ctx->last_indexed_uid_set) {
		if (!fts_index_get_header(ctx->box, &hdr))
			ctx->last_indexed_uid = 0;
		else
			ctx->last_indexed_uid = hdr.last_indexed_uid;
		ctx->last_indexed_uid_set = TRUE;
	}
	if (ctx->last_indexed_uid == 0 ||
	    uid > ctx->last_indexed_uid + 100) {
		/* don't waste time adding expunge to log for a message that
		   isn't even indexed. this check is racy, because indexer may
		   just be in the middle of indexing this message. we'll
		   attempt to avoid that by skipping the expunging only if
		   indexing hasn't been done for a while (100 msgs). */
		return;
	}

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
		if (fts_backend_lucene_mkdir(backend) < 0)
			ctx->ctx.failed = TRUE;
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
	if (ctx->mime_parts)
		ctx->part_num = message_part_to_idx(key->part);
	return TRUE;
}

static void
fts_backend_lucene_update_unset_build_key(struct fts_backend_update_context *_ctx)
{
	struct lucene_fts_backend_update_context *ctx =
		(struct lucene_fts_backend_update_context *)_ctx;

	ctx->uid = 0;
	ctx->part_num = 0;
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
					      ctx->part_num, data, size,
					      ctx->hdr_name);
	} T_END;
	return ret;
}

static int
fts_backend_lucene_refresh(struct fts_backend *_backend)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_backend;

	if (backend->index != NULL)
		lucene_index_close(backend->index);
	return 0;
}

static int fts_backend_lucene_rescan(struct fts_backend *_backend)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_backend;

	if (lucene_index_rescan(backend->index) < 0)
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
		ret = lucene_index_rescan(backend->index);
	}
	if (ret >= 0)
		ret = lucene_index_optimize(backend->index);
	return ret;
}

static int
fts_backend_lucene_lookup(struct fts_backend *_backend, struct mailbox *box,
			  struct mail_search_arg *args,
			  enum fts_lookup_flags flags,
			  struct fts_result *result)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_backend;
	int ret;

	if (fts_backend_select(backend, box) < 0)
		return -1;
	T_BEGIN {
		ret = lucene_index_lookup(backend->index, args, flags, result);
	} T_END;
	return ret;
}

/* a char* hash function from ASU -- from glib */
static unsigned int wstr_hash(const wchar_t *s)
{
	unsigned int g, h = 0;

	while (*s != '\0') {
		h = (h << 4) + *s;
		if ((g = h & 0xf0000000UL) != 0) {
			h = h ^ (g >> 24);
			h = h ^ g;
		}
		s++;
	}

	return h;
}

static int
mailboxes_get_guids(struct mailbox *const boxes[],
		    HASH_TABLE_TYPE(wguid_result) guids,
		    struct fts_multi_result *result)
{
	ARRAY(struct fts_result) box_results;
	struct fts_result *box_result;
	const char *guid;
	wchar_t *guid_dup;
	unsigned int i, j;

	p_array_init(&box_results, result->pool, 32);
	/* first create the box_results - we'll be using pointers to them
	   later on and appending to the array changes the pointers */
	for (i = 0; boxes[i] != NULL; i++) {
		box_result = array_append_space(&box_results);
		box_result->box = boxes[i];
	}
	for (i = 0; boxes[i] != NULL; i++) {
		if (fts_mailbox_get_guid(boxes[i], &guid) < 0)
			return -1;

		i_assert(strlen(guid) == MAILBOX_GUID_HEX_LENGTH);
		guid_dup = t_new(wchar_t, MAILBOX_GUID_HEX_LENGTH + 1);
		for (j = 0; j < MAILBOX_GUID_HEX_LENGTH; j++)
			guid_dup[j] = guid[j];

		box_result = array_idx_modifiable(&box_results, i);
		hash_table_insert(guids, guid_dup, box_result);
	}

	array_append_zero(&box_results);
	result->box_results = array_front_modifiable(&box_results);
	return 0;
}

static int
fts_backend_lucene_lookup_multi(struct fts_backend *_backend,
				struct mailbox *const boxes[],
				struct mail_search_arg *args,
				enum fts_lookup_flags flags,
				struct fts_multi_result *result)
{
	struct lucene_fts_backend *backend =
		(struct lucene_fts_backend *)_backend;
	int ret;

	T_BEGIN {
		HASH_TABLE_TYPE(wguid_result) guids;

		hash_table_create(&guids, default_pool, 0, wstr_hash, wcscmp);
		ret = mailboxes_get_guids(boxes, guids, result);
		if (ret == 0) {
			ret = lucene_index_lookup_multi(backend->index,
							guids, args, flags,
							result);
		}
		hash_table_destroy(&guids);
	} T_END;
	return ret;
}

static void fts_backend_lucene_lookup_done(struct fts_backend *_backend)
{
	/* the next refresh is going to close the index anyway, so we might as
	   well do it now */
	(void)fts_backend_lucene_refresh(_backend);
}

struct fts_backend fts_backend_lucene = {
	.name = "lucene",
	.flags = FTS_BACKEND_FLAG_BUILD_FULL_WORDS |
		FTS_BACKEND_FLAG_FUZZY_SEARCH,

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
		fts_backend_lucene_lookup_multi,
		fts_backend_lucene_lookup_done
	}
};
