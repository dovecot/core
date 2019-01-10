/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "ostream.h"
#include "mkdir-parents.h"
#include "unlink-old-files.h"
#include "mailbox-list-private.h"
#include "mdbox-storage.h"
#include "mdbox-file.h"
#include "mdbox-map-private.h"

#include <dirent.h>

#define MAX_BACKWARDS_LOOKUPS 10

#define DBOX_FORCE_PURGE_MIN_BYTES (1024*1024*10)
#define DBOX_FORCE_PURGE_MIN_RATIO 0.5

#define MAP_STORAGE(map) (&(map)->storage->storage.storage)

struct mdbox_map_transaction_context {
	struct mdbox_map_atomic_context *atomic;
	struct mail_index_transaction *trans;

	bool changed:1;
	bool committed:1;
};

static int mdbox_map_generate_uid_validity(struct mdbox_map *map);

void mdbox_map_set_corrupted(struct mdbox_map *map, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	mail_storage_set_critical(MAP_STORAGE(map),
				  "mdbox map %s corrupted: %s",
				  map->index->filepath,
				  t_strdup_vprintf(format, args));
	va_end(args);

	mdbox_storage_set_corrupted(map->storage);
}

struct mdbox_map *
mdbox_map_init(struct mdbox_storage *storage, struct mailbox_list *root_list)
{
	struct mdbox_map *map;
	const char *root, *index_root;

	root = mailbox_list_get_root_forced(root_list, MAILBOX_LIST_PATH_TYPE_DIR);
	index_root = mailbox_list_get_root_forced(root_list, MAILBOX_LIST_PATH_TYPE_INDEX);

	map = i_new(struct mdbox_map, 1);
	map->storage = storage;
	map->set = storage->set;
	map->path = i_strconcat(root, "/"MDBOX_GLOBAL_DIR_NAME, NULL);
	map->index_path =
		i_strconcat(index_root, "/"MDBOX_GLOBAL_DIR_NAME, NULL);
	map->index = mail_index_alloc(storage->storage.storage.event,
				      map->index_path,
				      MDBOX_GLOBAL_INDEX_PREFIX);
	mail_index_set_fsync_mode(map->index,
		MAP_STORAGE(map)->set->parsed_fsync_mode, 0);
	mail_index_set_lock_method(map->index,
		MAP_STORAGE(map)->set->parsed_lock_method,
		mail_storage_get_lock_timeout(MAP_STORAGE(map), UINT_MAX));
	map->root_list = root_list;
	map->map_ext_id = mail_index_ext_register(map->index, "map",
				sizeof(struct mdbox_map_mail_index_header),
				sizeof(struct mdbox_map_mail_index_record),
				sizeof(uint32_t));
	map->ref_ext_id = mail_index_ext_register(map->index, "ref", 0,
				sizeof(uint16_t), sizeof(uint16_t));
	return map;
}

void mdbox_map_deinit(struct mdbox_map **_map)
{
	struct mdbox_map *map = *_map;

	*_map = NULL;

	if (map->view != NULL) {
		mail_index_view_close(&map->view);
		mail_index_close(map->index);
	}
	mail_index_free(&map->index);
	i_free(map->index_path);
	i_free(map->path);
	i_free(map);
}

static int mdbox_map_mkdir_storage(struct mdbox_map *map)
{
	if (mailbox_list_mkdir_root(map->root_list, map->path,
				    MAILBOX_LIST_PATH_TYPE_DIR) < 0) {
		mail_storage_copy_list_error(MAP_STORAGE(map), map->root_list);
		return -1;
	}

	if (strcmp(map->path, map->index_path) != 0 &&
	    mailbox_list_mkdir_root(map->root_list, map->index_path,
				    MAILBOX_LIST_PATH_TYPE_INDEX) < 0) {
		mail_storage_copy_list_error(MAP_STORAGE(map), map->root_list);
		return -1;
	}
	return 0;
}

static void mdbox_map_cleanup(struct mdbox_map *map)
{
	unsigned int interval =
		MAP_STORAGE(map)->set->mail_temp_scan_interval;
	struct stat st;

	if (stat(map->path, &st) < 0)
		return;

	/* check once in a while if there are temp files to clean up */
	if (interval == 0) {
		/* disabled */
	} else if (st.st_atime > st.st_ctime + DBOX_TMP_DELETE_SECS) {
		/* there haven't been any changes to this directory since we
		   last checked it. */
	} else if (st.st_atime < ioloop_time - (time_t)interval) {
		/* time to scan */
		(void)unlink_old_files(map->path, DBOX_TEMP_FILE_PREFIX,
				       ioloop_time - DBOX_TMP_DELETE_SECS);
	}
}

static int mdbox_map_open_internal(struct mdbox_map *map, bool create_missing)
{
	enum mail_index_open_flags open_flags;
	struct mailbox_permissions perm;
	int ret = 0;

	if (map->view != NULL) {
		/* already opened */
		return 1;
	}

	mailbox_list_get_root_permissions(map->root_list, &perm);
	mail_index_set_permissions(map->index, perm.file_create_mode,
				   perm.file_create_gid,
				   perm.file_create_gid_origin);

	open_flags = MAIL_INDEX_OPEN_FLAG_NEVER_IN_MEMORY |
		mail_storage_settings_to_index_flags(MAP_STORAGE(map)->set);
	if (create_missing) {
		if ((ret = mdbox_map_mkdir_storage(map)) < 0)
			return -1;
		if (ret > 0) {
			/* storage/ directory already existed.
			   the index should exist also. */
		} else {
			open_flags |= MAIL_INDEX_OPEN_FLAG_CREATE;
		}
	}
	ret = mail_index_open(map->index, open_flags);
	if (ret == 0 && create_missing) {
		/* storage/ already existed, but indexes didn't. we'll need to
		   take extra steps to make sure we won't overwrite any m.*
		   files that may already exist. */
		map->verify_existing_file_ids = TRUE;
		open_flags |= MAIL_INDEX_OPEN_FLAG_CREATE;
		ret = mail_index_open(map->index, open_flags);
	}
	if (ret < 0) {
		mail_storage_set_index_error(MAP_STORAGE(map), map->index);
		return -1;
	}
	if (ret == 0) {
		/* index not found - for now just return failure */
		i_assert(!create_missing);
		return 0;
	}

	map->view = mail_index_view_open(map->index);
	mdbox_map_cleanup(map);

	if (mail_index_get_header(map->view)->uid_validity == 0) {
		if (mdbox_map_generate_uid_validity(map) < 0) {
			mail_storage_set_index_error(MAP_STORAGE(map), map->index);
			mail_index_close(map->index);
			return -1;
		}
		if (mdbox_map_refresh(map) < 0) {
			mail_index_close(map->index);
			return -1;
		}
	}
	return 1;
}

int mdbox_map_open(struct mdbox_map *map)
{
	return mdbox_map_open_internal(map, FALSE);
}

int mdbox_map_open_or_create(struct mdbox_map *map)
{
	return mdbox_map_open_internal(map, TRUE) <= 0 ? -1 : 0;
}

int mdbox_map_refresh(struct mdbox_map *map)
{
	struct mail_index_view_sync_ctx *ctx;
	bool delayed_expunges, fscked;
	int ret = 0;

	/* some open files may have read partially written mails. now that
	   map syncing makes the new mails visible, we need to make sure the
	   partial data is flushed out of memory */
	mdbox_files_sync_input(map->storage);

	if (mail_index_refresh(map->view->index) < 0) {
		mail_storage_set_index_error(MAP_STORAGE(map), map->index);
		return -1;
	}
	if (mail_index_view_get_transaction_count(map->view) > 0) {
		/* can't sync when there are transactions */
		return 0;
	}

	ctx = mail_index_view_sync_begin(map->view,
				MAIL_INDEX_VIEW_SYNC_FLAG_FIX_INCONSISTENT);
	fscked = mail_index_reset_fscked(map->view->index);
	if (mail_index_view_sync_commit(&ctx, &delayed_expunges) < 0) {
		mail_storage_set_index_error(MAP_STORAGE(map), map->index);
		ret = -1;
	}
	if (fscked)
		mdbox_storage_set_corrupted(map->storage);
	return ret;
}

bool mdbox_map_is_fscked(struct mdbox_map *map)
{
	const struct mail_index_header *hdr;

	if (map->view == NULL) {
		/* map isn't opened yet. don't bother. */
		return FALSE;
	}

	hdr = mail_index_get_header(map->view);
	return (hdr->flags & MAIL_INDEX_HDR_FLAG_FSCKD) != 0;
}

static void
mdbox_map_get_ext_hdr(struct mdbox_map *map, struct mail_index_view *view,
		      struct mdbox_map_mail_index_header *hdr_r)
{
	const void *data;
	size_t data_size;

	mail_index_get_header_ext(view, map->map_ext_id, &data, &data_size);
	i_zero(hdr_r);
	memcpy(hdr_r, data, I_MIN(data_size, sizeof(*hdr_r)));
}

uint32_t mdbox_map_get_rebuild_count(struct mdbox_map *map)
{
	struct mdbox_map_mail_index_header hdr;

	mdbox_map_get_ext_hdr(map, map->view, &hdr);
	return hdr.rebuild_count;
}

static int
mdbox_map_lookup_seq(struct mdbox_map *map, uint32_t seq,
		     const struct mdbox_map_mail_index_record **rec_r)
{
	const struct mdbox_map_mail_index_record *rec;
	const void *data;
	uint32_t uid;

	mail_index_lookup_ext(map->view, seq, map->map_ext_id, &data, NULL);
	rec = data;

	if (rec == NULL || rec->file_id == 0) {
		mail_index_lookup_uid(map->view, seq, &uid);
		mdbox_map_set_corrupted(map, "file_id=0 for map_uid=%u", uid);
		return -1;
	}
	*rec_r = rec;
	return 0;
}

static int
mdbox_map_get_seq(struct mdbox_map *map, uint32_t map_uid, uint32_t *seq_r)
{
	if (!mail_index_lookup_seq(map->view, map_uid, seq_r)) {
		/* not found - try again after a refresh */
		if (mdbox_map_refresh(map) < 0)
			return -1;
		if (!mail_index_lookup_seq(map->view, map_uid, seq_r))
			return 0;
	}
	return 1;
}

int mdbox_map_lookup(struct mdbox_map *map, uint32_t map_uid,
		     uint32_t *file_id_r, uoff_t *offset_r)
{
	const struct mdbox_map_mail_index_record *rec;
	uint32_t seq;
	int ret;

	if (mdbox_map_open_or_create(map) < 0)
		return -1;

	if ((ret = mdbox_map_get_seq(map, map_uid, &seq)) <= 0)
		return ret;

	if (mdbox_map_lookup_seq(map, seq, &rec) < 0)
		return -1;
	*file_id_r = rec->file_id;
	*offset_r = rec->offset;
	return 1;
}

int mdbox_map_lookup_full(struct mdbox_map *map, uint32_t map_uid,
			  struct mdbox_map_mail_index_record *rec_r,
			  uint16_t *refcount_r)
{
	uint32_t seq;
	int ret;

	if (mdbox_map_open_or_create(map) < 0)
		return -1;

	if ((ret = mdbox_map_get_seq(map, map_uid, &seq)) <= 0)
		return ret;

	return mdbox_map_lookup_seq_full(map, seq, rec_r, refcount_r);
}

int mdbox_map_lookup_seq_full(struct mdbox_map *map, uint32_t seq,
			      struct mdbox_map_mail_index_record *rec_r,
			      uint16_t *refcount_r)
{
	const struct mdbox_map_mail_index_record *rec;
	const uint16_t *ref16_p;
	const void *data;

	if (mdbox_map_lookup_seq(map, seq, &rec) < 0)
		return -1;
	*rec_r = *rec;

	mail_index_lookup_ext(map->view, seq, map->ref_ext_id, &data, NULL);
	if (data == NULL) {
		mdbox_map_set_corrupted(map, "missing ref extension");
		return -1;
	}
	ref16_p = data;
	*refcount_r = *ref16_p;
	return 1;
}

uint32_t mdbox_map_lookup_uid(struct mdbox_map *map, uint32_t seq)
{
	uint32_t uid;

	mail_index_lookup_uid(map->view, seq, &uid);
	return uid;
}

unsigned int mdbox_map_get_messages_count(struct mdbox_map *map)
{
	return mail_index_view_get_messages_count(map->view);
}

int mdbox_map_view_lookup_rec(struct mdbox_map *map,
			      struct mail_index_view *view, uint32_t seq,
			      struct dbox_mail_lookup_rec *rec_r)
{
	const uint16_t *ref16_p;
	const void *data;

	i_zero(rec_r);
	mail_index_lookup_uid(view, seq, &rec_r->map_uid);

	mail_index_lookup_ext(view, seq, map->map_ext_id, &data, NULL);
	if (data == NULL) {
		mdbox_map_set_corrupted(map, "missing map extension");
		return -1;
	}
	memcpy(&rec_r->rec, data, sizeof(rec_r->rec));

	mail_index_lookup_ext(view, seq, map->ref_ext_id, &data, NULL);
	if (data == NULL) {
		mdbox_map_set_corrupted(map, "missing ref extension");
		return -1;
	}
	ref16_p = data;
	rec_r->refcount = *ref16_p;
	return 0;
}

int mdbox_map_get_file_msgs(struct mdbox_map *map, uint32_t file_id,
			    ARRAY_TYPE(mdbox_map_file_msg) *recs)
{
	const struct mail_index_header *hdr;
	struct dbox_mail_lookup_rec rec;
	struct mdbox_map_file_msg msg;
	uint32_t seq;

	if (mdbox_map_refresh(map) < 0)
		return -1;
	hdr = mail_index_get_header(map->view);

	i_zero(&msg);
	for (seq = 1; seq <= hdr->messages_count; seq++) {
		if (mdbox_map_view_lookup_rec(map, map->view, seq, &rec) < 0)
			return -1;

		if (rec.rec.file_id == file_id) {
			msg.map_uid = rec.map_uid;
			msg.offset = rec.rec.offset;
			msg.refcount = rec.refcount;
			array_append(recs, &msg, 1);
		}
	}
	return 0;
}

int mdbox_map_get_zero_ref_files(struct mdbox_map *map,
				 ARRAY_TYPE(seq_range) *file_ids_r)
{
	const struct mail_index_header *hdr;
	const struct mdbox_map_mail_index_record *rec;
	const uint16_t *ref16_p;
	const void *data;
	uint32_t seq;
	bool expunged;
	int ret;

	if ((ret = mdbox_map_open(map)) <= 0) {
		/* no map / internal error */
		return ret;
	}
	if (mdbox_map_refresh(map) < 0)
		return -1;

	hdr = mail_index_get_header(map->view);
	for (seq = 1; seq <= hdr->messages_count; seq++) {
		mail_index_lookup_ext(map->view, seq, map->ref_ext_id,
				      &data, &expunged);
		if (data != NULL && !expunged) {
			ref16_p = data;
			if (*ref16_p != 0)
				continue;
		}

		mail_index_lookup_ext(map->view, seq, map->map_ext_id,
				      &data, &expunged);
		if (data != NULL && !expunged) {
			rec = data;
			seq_range_array_add(file_ids_r, rec->file_id);
		}
	}
	return 0;
}

struct mdbox_map_atomic_context *mdbox_map_atomic_begin(struct mdbox_map *map)
{
	struct mdbox_map_atomic_context *atomic;

	atomic = i_new(struct mdbox_map_atomic_context, 1);
	atomic->map = map;
	return atomic;
}

static void
mdbox_map_sync_handle(struct mdbox_map *map,
		      struct mail_index_sync_ctx *sync_ctx)
{
	struct mail_index_sync_rec sync_rec;
	uint32_t seq1, seq2;
	uoff_t offset1, offset2;

	mail_index_sync_get_offsets(sync_ctx, &seq1, &offset1, &seq2, &offset2);
	if (offset1 != offset2 || seq1 != seq2) {
		/* something had crashed. need a full resync. */
		i_warning("mdbox %s: Inconsistency in map index "
			  "(%u,%"PRIuUOFF_T" != %u,%"PRIuUOFF_T")",
			  map->path, seq1, offset1, seq2, offset2);
		mdbox_storage_set_corrupted(map->storage);
	}
	while (mail_index_sync_next(sync_ctx, &sync_rec)) ;
}

int mdbox_map_atomic_lock(struct mdbox_map_atomic_context *atomic,
			  const char *reason)
{
	int ret;

	if (atomic->locked)
		return 0;

	if (mdbox_map_open_or_create(atomic->map) < 0)
		return -1;

	/* use syncing to lock the transaction log, so that we always see
	   log's head_offset = tail_offset */
	ret = mail_index_sync_begin(atomic->map->index, &atomic->sync_ctx,
				    &atomic->sync_view, &atomic->sync_trans,
				    MAIL_INDEX_SYNC_FLAG_UPDATE_TAIL_OFFSET);
	if (mail_index_reset_fscked(atomic->map->index))
		mdbox_storage_set_corrupted(atomic->map->storage);
	if (ret <= 0) {
		i_assert(ret != 0);
		mail_storage_set_index_error(MAP_STORAGE(atomic->map),
					     atomic->map->index);
		return -1;
	}
	mail_index_sync_set_reason(atomic->sync_ctx, reason);
	atomic->locked = TRUE;
	/* reset refresh state so that if it's wanted to be done locked,
	   it gets the latest changes */
	atomic->map_refreshed = FALSE;
	mdbox_map_sync_handle(atomic->map, atomic->sync_ctx);
	return 0;
}

bool mdbox_map_atomic_is_locked(struct mdbox_map_atomic_context *atomic)
{
	return atomic->locked;
}

void mdbox_map_atomic_set_failed(struct mdbox_map_atomic_context *atomic)
{
	atomic->success = FALSE;
	atomic->failed = TRUE;
}

void mdbox_map_atomic_set_success(struct mdbox_map_atomic_context *atomic)
{
	if (!atomic->failed)
		atomic->success = TRUE;
}

void mdbox_map_atomic_unset_fscked(struct mdbox_map_atomic_context *atomic)
{
	mail_index_unset_fscked(atomic->sync_trans);
}

int mdbox_map_atomic_finish(struct mdbox_map_atomic_context **_atomic)
{
	struct mdbox_map_atomic_context *atomic = *_atomic;
	int ret = 0;

	*_atomic = NULL;

	if (atomic->sync_ctx == NULL) {
		/* not locked */
		i_assert(!atomic->locked);
	} else if (atomic->success) {
		if (mail_index_sync_commit(&atomic->sync_ctx) < 0) {
			mail_storage_set_index_error(MAP_STORAGE(atomic->map),
						     atomic->map->index);
			ret = -1;
		}
	} else {
		mail_index_sync_rollback(&atomic->sync_ctx);
	}
	i_free(atomic);
	return ret;
}

struct mdbox_map_transaction_context *
mdbox_map_transaction_begin(struct mdbox_map_atomic_context *atomic,
			    bool external)
{
	struct mdbox_map_transaction_context *ctx;
	enum mail_index_transaction_flags flags =
		MAIL_INDEX_TRANSACTION_FLAG_FSYNC;
	bool success;

	if (external)
		flags |= MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL;

	ctx = i_new(struct mdbox_map_transaction_context, 1);
	ctx->atomic = atomic;
	if (atomic->locked && atomic->map_refreshed) {
		/* already refreshed within a lock, don't do it again */
		success = TRUE;
	} else {
		success = mdbox_map_open(atomic->map) > 0 &&
			mdbox_map_refresh(atomic->map) == 0;
	}

	if (success) {
		atomic->map_refreshed = TRUE;
		ctx->trans = mail_index_transaction_begin(atomic->map->view,
							  flags);
	}
	return ctx;
}

int mdbox_map_transaction_commit(struct mdbox_map_transaction_context *ctx,
				 const char *reason)
{
	i_assert(!ctx->committed);

	ctx->committed = TRUE;
	if (!ctx->changed)
		return 0;

	if (mdbox_map_atomic_lock(ctx->atomic, reason) < 0)
		return -1;

	if (mail_index_transaction_commit(&ctx->trans) < 0) {
		mail_storage_set_index_error(MAP_STORAGE(ctx->atomic->map),
					     ctx->atomic->map->index);
		return -1;
	}
	mdbox_map_atomic_set_success(ctx->atomic);
	return 0;
}

void mdbox_map_transaction_free(struct mdbox_map_transaction_context **_ctx)
{
	struct mdbox_map_transaction_context *ctx = *_ctx;

	*_ctx = NULL;

	if (ctx->trans != NULL)
		mail_index_transaction_rollback(&ctx->trans);
	i_free(ctx);
}

int mdbox_map_update_refcount(struct mdbox_map_transaction_context *ctx,
			      uint32_t map_uid, int diff)
{
	struct mdbox_map *map = ctx->atomic->map;
	const void *data;
	uint32_t seq;
	int old_diff, new_diff;

	if (unlikely(ctx->trans == NULL))
		return -1;

	if (!mail_index_lookup_seq(map->view, map_uid, &seq)) {
		/* we can't refresh map here since view has a
		   transaction open. */
		if (diff > 0) {
			/* the message was probably just purged */
			mail_storage_set_error(MAP_STORAGE(map), MAIL_ERROR_EXPUNGED,
				"Some of the requested messages no longer exist.");
		} else {
			mdbox_map_set_corrupted(map,
				"refcount update lost map_uid=%u", map_uid);
		}
		return -1;
	}
	mail_index_lookup_ext(map->view, seq, map->ref_ext_id, &data, NULL);
	old_diff = data == NULL ? 0 : *((const uint16_t *)data);
	ctx->changed = TRUE;
	new_diff = mail_index_atomic_inc_ext(ctx->trans, seq,
					     map->ref_ext_id, diff);
	if (old_diff + new_diff < 0) {
		mdbox_map_set_corrupted(map, "map_uid=%u refcount too low",
					map_uid);
		return -1;
	}
	if (old_diff + new_diff >= 32768 && new_diff > 0) {
		/* we're getting close to the 64k limit. fail early
		   to make it less likely that two processes increase
		   the refcount enough times to cross the limit */
		mail_storage_set_error(MAP_STORAGE(map), MAIL_ERROR_LIMIT,
			t_strdup_printf("Message has been copied too many times (%d + %d)",
					old_diff, new_diff));
		return -1;
	}
	return 0;
}

int mdbox_map_update_refcounts(struct mdbox_map_transaction_context *ctx,
			       const ARRAY_TYPE(uint32_t) *map_uids, int diff)
{
	const uint32_t *uidp;
	unsigned int i, count;

	if (unlikely(ctx->trans == NULL))
		return -1;

	count = array_count(map_uids);
	for (i = 0; i < count; i++) {
		uidp = array_idx(map_uids, i);
		if (mdbox_map_update_refcount(ctx, *uidp, diff) < 0)
			return -1;
	}
	return 0;
}

int mdbox_map_remove_file_id(struct mdbox_map *map, uint32_t file_id)
{
	struct mdbox_map_atomic_context *atomic;
	struct mdbox_map_transaction_context *map_trans;
	const struct mail_index_header *hdr;
	const struct mdbox_map_mail_index_record *rec;
	const void *data;
	uint32_t seq;
	int ret = 0;

	/* make sure the map is refreshed, otherwise we might be expunging
	   messages that have already been moved to other files. */

	/* we need a per-file transaction, otherwise we can't refresh the map */
	atomic = mdbox_map_atomic_begin(map);
	map_trans = mdbox_map_transaction_begin(atomic, TRUE);

	hdr = mail_index_get_header(map->view);
	for (seq = 1; seq <= hdr->messages_count; seq++) {
		mail_index_lookup_ext(map->view, seq, map->map_ext_id,
				      &data, NULL);
		if (data == NULL) {
			mdbox_map_set_corrupted(map, "missing map extension");
			ret = -1;
			break;
		}

		rec = data;
		if (rec->file_id == file_id) {
			map_trans->changed = TRUE;
			mail_index_expunge(map_trans->trans, seq);
		}
	}
	if (ret == 0)
		ret = mdbox_map_transaction_commit(map_trans, "removing file");
	mdbox_map_transaction_free(&map_trans);
	if (mdbox_map_atomic_finish(&atomic) < 0)
		ret = -1;
	return ret;
}

struct mdbox_map_append_context *
mdbox_map_append_begin(struct mdbox_map_atomic_context *atomic)
{
	struct mdbox_map_append_context *ctx;

	ctx = i_new(struct mdbox_map_append_context, 1);
	ctx->atomic = atomic;
	ctx->map = atomic->map;
	ctx->first_new_file_id = (uint32_t)-1;
	i_array_init(&ctx->file_appends, 64);
	i_array_init(&ctx->files, 64);
	i_array_init(&ctx->appends, 128);

	if (mdbox_map_open_or_create(atomic->map) < 0)
		ctx->failed = TRUE;
	else {
		/* refresh the map so we can try appending to the
		   latest files */
		if (mdbox_map_refresh(atomic->map) == 0)
			atomic->map_refreshed = TRUE;
		else
			ctx->failed = TRUE;
	}
	return ctx;
}

static time_t day_begin_stamp(unsigned int interval)
{
	struct tm tm;
	time_t stamp;
	unsigned int unit = 1;

	if (interval == 0)
		return 0;

	/* get the beginning of day/hour/minute depending on how large
	   the interval is */
	tm = *localtime(&ioloop_time);
	if (interval >= 60) {
		tm.tm_sec = 0;
		unit = 60;
		if (interval >= 3600) {
			tm.tm_min = 0;
			unit = 3600;
			if (interval >= 3600*24) {
				tm.tm_hour = 0;
				unit = 3600*24;
			}
		}
	}
	stamp = mktime(&tm);
	if (stamp == (time_t)-1)
		i_panic("mktime(today) failed");

	return stamp - (interval - unit);
}

static bool dbox_try_open(struct dbox_file *file, bool want_altpath)
{
	bool notfound;

	if (want_altpath) {
		if (dbox_file_open(file, &notfound) <= 0)
			return FALSE;
	} else {
		if (dbox_file_open_primary(file, &notfound) <= 0)
			return FALSE;
	}
	if (notfound)
		return FALSE;

	if (file->lock != NULL) {
		/* already locked, we're possibly in the middle of purging it
		   in which case we really don't want to write there. */
		return FALSE;
	}
	if (dbox_file_is_in_alt(file) != want_altpath) {
		/* different alt location than what we want, can't use it */
		return FALSE;
	}
	return TRUE;
}

static bool dbox_file_is_ok_at(struct dbox_file *file, uoff_t offset)
{
	bool last;
	int ret;

	if (dbox_file_seek(file, offset) == 0)
		return FALSE;

	while ((ret = dbox_file_seek_next(file, &offset, &last)) > 0);
	if (ret == 0 && !last)
		return FALSE;
	return TRUE;
}

static bool
mdbox_map_file_try_append(struct mdbox_map_append_context *ctx,
			  bool want_altpath,
			  const struct mdbox_map_mail_index_record *rec,
			  time_t stamp, uoff_t mail_size,
			  struct dbox_file_append_context **file_append_r,
			  struct ostream **output_r, bool *retry_later_r)
{
	struct mdbox_map *map = ctx->map;
	struct mdbox_storage *storage = map->storage;
	struct dbox_file *file;
	struct dbox_file_append_context *file_append;
	struct stat st;
	bool file_too_old = FALSE;
	int ret;

	*file_append_r = NULL;
	*output_r = NULL;
	*retry_later_r = FALSE;

	file = mdbox_file_init(storage, rec->file_id);
	if (!dbox_try_open(file, want_altpath)) {
		dbox_file_unref(&file);
		return TRUE;
	}

	if (file->create_time < stamp)
		file_too_old = TRUE;
	else if ((ret = dbox_file_try_lock(file)) <= 0) {
		/* locking failed */
		*retry_later_r = ret == 0;
	} else if (stat(file->cur_path, &st) < 0) {
		if (errno != ENOENT)
			i_error("stat(%s) failed: %m", file->cur_path);
		/* the file was unlinked between opening and locking it. */
	} else if (st.st_size != rec->offset + rec->size &&
		   /* check if there's any garbage at the end of file.
		      note that there may be valid messages added by another
		      session before we locked it (but after we refreshed
		      map index). */
		   !dbox_file_is_ok_at(file, rec->offset + rec->size)) {
		/* error message was already logged */
	} else {
		file_append = dbox_file_append_init(file);
		if (dbox_file_get_append_stream(file_append, output_r) <= 0) {
			/* couldn't append to this file */
		} else if ((*output_r)->offset + mail_size > map->set->mdbox_rotate_size) {
			/* file was too large after all */
		} else {
			/* success */
			*file_append_r = file_append;
			return TRUE;
		}
		dbox_file_append_rollback(&file_append);
	}

	/* failure */
	dbox_file_unlock(file);
	dbox_file_unref(&file);
	return !file_too_old;
}

static bool
mdbox_map_is_appending(struct mdbox_map_append_context *ctx, uint32_t file_id)
{
	struct dbox_file_append_context *const *file_appends;
	unsigned int i, count;

	/* there shouldn't be many files open, don't bother with anything
	   faster. */
	file_appends = array_get(&ctx->file_appends, &count);
	for (i = 0; i < count; i++) {
		struct mdbox_file *mfile =
			(struct mdbox_file *)file_appends[i]->file;

		if (mfile->file_id == file_id)
			return TRUE;
	}
	return FALSE;
}

static struct dbox_file_append_context *
mdbox_map_find_existing_append(struct mdbox_map_append_context *ctx,
			       uoff_t mail_size, bool want_altpath,
			       struct ostream **output_r)
{
	struct mdbox_map *map = ctx->map;
	struct dbox_file_append_context *const *file_appends, *append;
	struct mdbox_file *mfile;
	unsigned int i, count;
	uoff_t append_offset;

	/* first try to use files already used in this append */
	file_appends = array_get(&ctx->file_appends, &count);
	for (i = count; i > ctx->files_nonappendable_count; i--) {
		append = file_appends[i-1];

		if (dbox_file_is_in_alt(append->file) != want_altpath)
			continue;
		if (append->file->fd == -1) {
			/* already closed it (below). we might be able to still
			   fit some small mail there, but that's too much
			   trouble */
			continue;
		}

		append_offset = append->output->offset;
		if (append_offset + mail_size <= map->set->mdbox_rotate_size &&
		    dbox_file_get_append_stream(append, output_r) > 0)
			return append;

		/* can't append to this file anymore. if we created this file,
		   close it so we don't waste fds. if we didn't, we can't close
		   it without also losing our lock too early. */
		mfile = (struct mdbox_file *)append->file;
		if (mfile->file_id == 0 && dbox_file_append_flush(append) == 0)
			dbox_file_close(append->file);
	}
	ctx->files_nonappendable_count = count;
	return NULL;
}

static int
mdbox_map_find_primary_files(struct mdbox_map_append_context *ctx,
			     ARRAY_TYPE(seq_range) *file_ids_r)
{
	struct mdbox_storage *dstorage = ctx->map->storage;
	struct mail_storage *storage = &dstorage->storage.storage;
	DIR *dir;
	struct dirent *d;
	uint32_t file_id;
	int ret = 0;

	/* we want to quickly find the latest alt file, but we also want to
	   avoid accessing the alt storage as much as possible. typically most
	   of the older mails would be in alt storage, so we'll just put the
	   few m.* files in primary storage to checked_file_ids array. other
	   files are then known to exist in alt storage. */
	dir = opendir(dstorage->storage_dir);
	if (dir == NULL) {
		mail_storage_set_critical(storage,
			"opendir(%s) failed: %m", dstorage->storage_dir);
		return -1;
	}

	for (errno = 0; (d = readdir(dir)) != NULL; errno = 0) {
		if (strncmp(d->d_name, MDBOX_MAIL_FILE_PREFIX,
			    strlen(MDBOX_MAIL_FILE_PREFIX)) != 0)
			continue;
		if (str_to_uint32(d->d_name + strlen(MDBOX_MAIL_FILE_PREFIX),
				  &file_id) < 0)
			continue;

		seq_range_array_add(file_ids_r, file_id);
	}
	if (errno != 0) {
		mail_storage_set_critical(storage,
			"readdir(%s) failed: %m", dstorage->storage_dir);
		ret = -1;
	}
	if (closedir(dir) < 0) {
		mail_storage_set_critical(storage,
			"closedir(%s) failed: %m", dstorage->storage_dir);
		ret = -1;
	}
	return ret;
}

static int
mdbox_map_find_appendable_file(struct mdbox_map_append_context *ctx,
			       uoff_t mail_size, bool want_altpath,
			       struct dbox_file_append_context **file_append_r,
			       struct ostream **output_r)
{
	struct mdbox_map *map = ctx->map;
	ARRAY_TYPE(seq_range) checked_file_ids;
	const struct mail_index_header *hdr;
	const struct mdbox_map_mail_index_record *rec;
	unsigned int backwards_lookup_count;
	uint32_t seq, seq1, uid;
	time_t stamp;
	bool retry_later;

	if (mail_size >= map->set->mdbox_rotate_size)
		return 0;

	/* try to find an existing appendable file */
	stamp = day_begin_stamp(map->set->mdbox_rotate_interval);
	hdr = mail_index_get_header(map->view);

	backwards_lookup_count = 0;
	t_array_init(&checked_file_ids, 16);

	if (want_altpath) {
		/* we want to save to alt storage. */
		if (mdbox_map_find_primary_files(ctx, &checked_file_ids) < 0)
			return -1;
	}

	for (seq = hdr->messages_count; seq > 0; seq--) {
		if (mdbox_map_lookup_seq(map, seq, &rec) < 0)
			return -1;

		if (seq_range_exists(&checked_file_ids, rec->file_id))
			continue;
		seq_range_array_add(&checked_file_ids, rec->file_id);

		if (++backwards_lookup_count > MAX_BACKWARDS_LOOKUPS) {
			/* we've wasted enough time here */
			break;
		}

		/* first lookup: this should be enough usually, but we can't
		   be sure until after locking. also if messages were recently
		   moved, this message might not be the last one in the file. */
		if (rec->offset + rec->size + mail_size >=
		    			map->set->mdbox_rotate_size)
			continue;

		if (mdbox_map_is_appending(ctx, rec->file_id)) {
			/* already checked this */
			continue;
		}

		mail_index_lookup_uid(map->view, seq, &uid);
		if (!mdbox_map_file_try_append(ctx, want_altpath, rec,
					       stamp, mail_size, file_append_r,
					       output_r, &retry_later)) {
			/* file is too old. the rest of the files are too. */
			break;
		}
		/* NOTE: we've now refreshed map view. there are no guarantees
		   about sequences anymore. */
		if (*file_append_r != NULL)
			return 1;
		/* FIXME: use retry_later somehow */
		if (uid == 1 ||
		    !mail_index_lookup_seq_range(map->view, 1, uid-1,
						 &seq1, &seq))
			break;
		seq++;
	}
	return 0;
}

int mdbox_map_append_next(struct mdbox_map_append_context *ctx,
			  uoff_t mail_size, enum mdbox_map_append_flags flags,
			  struct dbox_file_append_context **file_append_ctx_r,
			  struct ostream **output_r)
{
	struct dbox_file *file;
	struct mdbox_map_append *append;
	struct dbox_file_append_context *file_append;
	bool existing, want_altpath;
	int ret;

	if (ctx->failed)
		return -1;

	want_altpath = (flags & DBOX_MAP_APPEND_FLAG_ALT) != 0;
	file_append = mdbox_map_find_existing_append(ctx, mail_size,
						     want_altpath, output_r);
	if (file_append != NULL) {
		ret = 1;
		existing = TRUE;
	} else {
		ret = mdbox_map_find_appendable_file(ctx, mail_size, want_altpath,
						     &file_append, output_r);
		existing = FALSE;
	}
	if (ret > 0)
		file = file_append->file;
	else if (ret < 0)
		return -1;
	else {
		/* create a new file */
		file = (flags & DBOX_MAP_APPEND_FLAG_ALT) == 0 ?
			mdbox_file_init(ctx->map->storage, 0) :
			mdbox_file_init_new_alt(ctx->map->storage);
		file_append = dbox_file_append_init(file);

		ret = dbox_file_get_append_stream(file_append, output_r);
		if (ret <= 0) {
			i_assert(ret < 0);
			dbox_file_append_rollback(&file_append);
			dbox_file_unref(&file);
			return -1;
		}
	}

	append = array_append_space(&ctx->appends);
	append->file_append = file_append;
	append->offset = (*output_r)->offset;
	append->size = (uint32_t)-1;
	if (!existing) {
		i_assert(file_append->first_append_offset == 0);
		file_append->first_append_offset = file_append->output->offset;
		array_push_back(&ctx->file_appends, &file_append);
		array_push_back(&ctx->files, &file);
	}
	*file_append_ctx_r = file_append;
	return 0;
}

static void
mdbox_map_append_close_if_unneeded(struct mdbox_map *map,
				   struct dbox_file_append_context *append_ctx)
{
	struct mdbox_file *mfile =
		(struct mdbox_file *)append_ctx->file;
	uoff_t end_offset = append_ctx->output->offset;

	/* if this file is now large enough not to fit any other
	   mails and we created it, close its fd since it's not
	   needed anymore. */
	if (end_offset > map->set->mdbox_rotate_size &&
	    mfile->file_id == 0 &&
	    dbox_file_append_flush(append_ctx) == 0)
		dbox_file_close(append_ctx->file);
}

void mdbox_map_append_finish(struct mdbox_map_append_context *ctx)
{
	struct mdbox_map_append *appends, *last;
	unsigned int count;
	uoff_t cur_offset;

	appends = array_get_modifiable(&ctx->appends, &count);
	i_assert(count > 0);
	last = &appends[count-1];
	i_assert(last->size == (uint32_t)-1);

	cur_offset = last->file_append->output->offset;
	i_assert(cur_offset >= last->offset);
	last->size = cur_offset - last->offset;
	dbox_file_append_checkpoint(last->file_append);

	mdbox_map_append_close_if_unneeded(ctx->map, last->file_append);
}

void mdbox_map_append_abort(struct mdbox_map_append_context *ctx)
{
	struct mdbox_map_append *appends;
	unsigned int count;

	appends = array_get_modifiable(&ctx->appends, &count);
	i_assert(count > 0 && appends[count-1].size == (uint32_t)-1);
	array_delete(&ctx->appends, count-1, 1);
}

static int
mdbox_find_highest_file_id(struct mdbox_map *map, uint32_t *file_id_r)
{
	const size_t prefix_len = strlen(MDBOX_MAIL_FILE_PREFIX);
	DIR *dir;
	struct dirent *d;
	unsigned int id, highest_id = 0;

	dir = opendir(map->path);
	if (dir == NULL) {
		i_error("opendir(%s) failed: %m", map->path);
		return -1;
	}
	while ((d = readdir(dir)) != NULL) {
		if (strncmp(d->d_name, MDBOX_MAIL_FILE_PREFIX, prefix_len) == 0 &&
		    str_to_uint(d->d_name + prefix_len, &id) == 0) {
			if (highest_id < id)
				highest_id = id;
		}
	}
	(void)closedir(dir);

	*file_id_r = highest_id;
	return 0;
}

static int
mdbox_map_assign_file_ids(struct mdbox_map_append_context *ctx,
			  bool separate_transaction, const char *reason)
{
	struct dbox_file_append_context *const *file_appends;
	unsigned int i, count;
	struct mdbox_map_mail_index_header hdr;
	uint32_t first_file_id, file_id, existing_id;

	/* start the syncing. we'll need it even if there are no file ids to
	   be assigned. */
	if (mdbox_map_atomic_lock(ctx->atomic, reason) < 0)
		return -1;

	mdbox_map_get_ext_hdr(ctx->map, ctx->atomic->sync_view, &hdr);
	file_id = hdr.highest_file_id + 1;

	if (ctx->map->verify_existing_file_ids) {
		/* storage/ directory had been already created but
		   without indexes. scan to see if there exists a higher
		   m.* file id than what is in header, so we won't
		   accidentally overwrite any existing files. */
		if (mdbox_find_highest_file_id(ctx->map, &existing_id) < 0)
			return -1;
		if (file_id < existing_id+1)
			file_id = existing_id+1;
	}

	/* assign file_ids for newly created files */
	first_file_id = file_id;
	file_appends = array_get(&ctx->file_appends, &count);
	for (i = 0; i < count; i++) {
		struct mdbox_file *mfile =
			(struct mdbox_file *)file_appends[i]->file;

		if (dbox_file_append_flush(file_appends[i]) < 0)
			return -1;

		if (mfile->file_id == 0) {
			if (mdbox_file_assign_file_id(mfile, file_id++) < 0)
				return -1;
		}
	}

	ctx->trans = !separate_transaction ? NULL :
		mail_index_transaction_begin(ctx->map->view,
					MAIL_INDEX_TRANSACTION_FLAG_FSYNC);

	/* update the highest used file_id */
	if (first_file_id != file_id) {
		file_id--;
		mail_index_update_header_ext(ctx->trans != NULL ? ctx->trans :
					     ctx->atomic->sync_trans,
					     ctx->map->map_ext_id,
					     0, &file_id, sizeof(file_id));
	}
	return 0;
}

int mdbox_map_append_assign_map_uids(struct mdbox_map_append_context *ctx,
				     uint32_t *first_map_uid_r,
				     uint32_t *last_map_uid_r)
{
	const struct mdbox_map_append *appends;
	const struct mail_index_header *hdr;
	struct mdbox_map_mail_index_record rec;
	unsigned int i, count;
	ARRAY_TYPE(seq_range) uids;
	const struct seq_range *range;
	uint32_t seq;
	uint16_t ref16;
	int ret = 0;

	if (array_count(&ctx->appends) == 0) {
		*first_map_uid_r = 0;
		*last_map_uid_r = 0;
		return 0;
	}

	if (mdbox_map_assign_file_ids(ctx, TRUE, "saving - assign uids") < 0)
		return -1;

	/* append map records to index */
	i_zero(&rec);
	ref16 = 1;
	appends = array_get(&ctx->appends, &count);
	for (i = 0; i < count; i++) {
		struct mdbox_file *mfile =
			(struct mdbox_file *)appends[i].file_append->file;

		i_assert(appends[i].offset <= (uint32_t)-1);
		i_assert(appends[i].size <= (uint32_t)-1);

		rec.file_id = mfile->file_id;
		rec.offset = appends[i].offset;
		rec.size = appends[i].size;

		mail_index_append(ctx->trans, 0, &seq);
		mail_index_update_ext(ctx->trans, seq, ctx->map->map_ext_id,
				      &rec, NULL);
		mail_index_update_ext(ctx->trans, seq, ctx->map->ref_ext_id,
				      &ref16, NULL);
	}

	/* assign map UIDs for appended records */
	hdr = mail_index_get_header(ctx->atomic->sync_view);
	t_array_init(&uids, 1);
	mail_index_append_finish_uids(ctx->trans, hdr->next_uid, &uids);
	range = array_first(&uids);
	i_assert(range[0].seq2 - range[0].seq1 + 1 == count);

	if (hdr->uid_validity == 0) {
		/* we don't really care about uidvalidity, but it can't be 0 */
		uint32_t uid_validity = ioloop_time;
		mail_index_update_header(ctx->trans,
			offsetof(struct mail_index_header, uid_validity),
			&uid_validity, sizeof(uid_validity), TRUE);
	}

	if (mail_index_transaction_commit(&ctx->trans) < 0) {
		mail_storage_set_index_error(MAP_STORAGE(ctx->map),
					     ctx->map->index);
		return -1;
	}

	*first_map_uid_r = range[0].seq1;
	*last_map_uid_r = range[0].seq2;
	return ret;
}

int mdbox_map_append_move(struct mdbox_map_append_context *ctx,
			  const ARRAY_TYPE(uint32_t) *map_uids,
			  const ARRAY_TYPE(seq_range) *expunge_map_uids)
{
	const struct mdbox_map_append *appends;
	struct mdbox_map_mail_index_record rec;
	struct seq_range_iter iter;
	const uint32_t *uids;
	unsigned int i, j, map_uids_count, appends_count;
	uint32_t uid, seq, next_uid;

	/* map is locked by this call */
	if (mdbox_map_assign_file_ids(ctx, FALSE, "purging - update uids") < 0)
		return -1;

	i_zero(&rec);
	appends = array_get(&ctx->appends, &appends_count);

	next_uid = mail_index_get_header(ctx->atomic->sync_view)->next_uid;
	uids = array_get(map_uids, &map_uids_count);
	for (i = j = 0; i < map_uids_count; i++) {
		struct mdbox_file *mfile =
			(struct mdbox_file *)appends[j].file_append->file;

		i_assert(j < appends_count);
		rec.file_id = mfile->file_id;
		rec.offset = appends[j].offset;
		rec.size = appends[j].size;
		j++;

		if (!mail_index_lookup_seq(ctx->atomic->sync_view,
					   uids[i], &seq)) {
			/* We wrote the email to the new m.* file, but another
			   process already expunged it and purged it. Deleting
			   the email from the new m.* file would be problematic
			   at this point, so just add the mail back to the map
			   with refcount=0 and the next purge will remove it. */
			mail_index_append(ctx->atomic->sync_trans,
					  next_uid++, &seq);
		}
		mail_index_update_ext(ctx->atomic->sync_trans, seq,
				      ctx->map->map_ext_id, &rec, NULL);
	}

	seq_range_array_iter_init(&iter, expunge_map_uids); i = 0;
	while (seq_range_array_iter_nth(&iter, i++, &uid)) {
		if (!mail_index_lookup_seq(ctx->atomic->sync_view, uid, &seq))
			i_unreached();
		mail_index_expunge(ctx->atomic->sync_trans, seq);
	}
	return 0;
}

int mdbox_map_append_flush(struct mdbox_map_append_context *ctx)
{
	struct dbox_file_append_context **file_appends;
	unsigned int i, count;

	i_assert(ctx->trans == NULL);

	file_appends = array_get_modifiable(&ctx->file_appends, &count);
	for (i = 0; i < count; i++) {
		if (dbox_file_append_flush(file_appends[i]) < 0)
			return -1;
	}
	return 0;
}

int mdbox_map_append_commit(struct mdbox_map_append_context *ctx)
{
	struct dbox_file_append_context **file_appends;
	unsigned int i, count;

	i_assert(ctx->trans == NULL);

	file_appends = array_get_modifiable(&ctx->file_appends, &count);
	for (i = 0; i < count; i++) {
		if (dbox_file_append_commit(&file_appends[i]) < 0)
			return -1;
	}
	mdbox_map_atomic_set_success(ctx->atomic);
	return 0;
}

void mdbox_map_append_free(struct mdbox_map_append_context **_ctx)
{
	struct mdbox_map_append_context *ctx = *_ctx;
	struct dbox_file_append_context **file_appends;
	struct dbox_file **files;
	unsigned int i, count;

	*_ctx = NULL;

	if (ctx->trans != NULL)
		mail_index_transaction_rollback(&ctx->trans);

	file_appends = array_get_modifiable(&ctx->file_appends, &count);
	for (i = 0; i < count; i++) {
		if (file_appends[i] != NULL)
			dbox_file_append_rollback(&file_appends[i]);
	}

	files = array_get_modifiable(&ctx->files, &count);
	for (i = 0; i < count; i++) {
		dbox_file_unlock(files[i]);
		dbox_file_unref(&files[i]);
	}

	array_free(&ctx->appends);
	array_free(&ctx->file_appends);
	array_free(&ctx->files);
	i_free(ctx);
}

static int mdbox_map_generate_uid_validity(struct mdbox_map *map)
{
	const struct mail_index_header *hdr;
	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	uint32_t uid_validity;
	int ret;

	/* do this inside syncing, so that we're locked and there are no
	   race conditions */
	ret = mail_index_sync_begin(map->index, &sync_ctx, &view, &trans, 0);
	if (ret <= 0) {
		i_assert(ret != 0);
		return -1;
	}
	mdbox_map_sync_handle(map, sync_ctx);

	hdr = mail_index_get_header(map->view);
	if (hdr->uid_validity != 0) {
		/* someone else beat us to it */
	} else {
		uid_validity = ioloop_time;
		mail_index_update_header(trans,
			offsetof(struct mail_index_header, uid_validity),
			&uid_validity, sizeof(uid_validity), TRUE);
	}
	mail_index_sync_set_reason(sync_ctx, "uidvalidity initialization");
	return mail_index_sync_commit(&sync_ctx);
}

uint32_t mdbox_map_get_uid_validity(struct mdbox_map *map)
{
	uint32_t uid_validity;

	i_assert(map->view != NULL);

	uid_validity = mail_index_get_header(map->view)->uid_validity;
	if (uid_validity == 0)
		mdbox_map_set_corrupted(map, "lost uidvalidity");
	return uid_validity;
}
