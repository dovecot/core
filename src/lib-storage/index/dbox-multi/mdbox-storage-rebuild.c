/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "istream.h"
#include "hash.h"
#include "str.h"
#include "mail-cache.h"
#include "dbox-sync-rebuild.h"
#include "mail-namespace.h"
#include "mailbox-list-private.h"
#include "mdbox-storage.h"
#include "mdbox-file.h"
#include "mdbox-map-private.h"
#include "mdbox-sync.h"
#include "mdbox-storage-rebuild.h"

#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>

struct mdbox_rebuild_msg {
	uint8_t guid_128[MAIL_GUID_128_SIZE];
	uint32_t file_id;
	uint32_t offset;
	uint32_t size;
	uint32_t map_uid;

	uint16_t refcount;
	unsigned int seen_zero_ref_in_map:1;
};

struct rebuild_msg_mailbox {
	struct mailbox *box;
	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	uint32_t next_uid;
};

struct mdbox_storage_rebuild_context {
	struct mdbox_storage *storage;
	struct mdbox_map_atomic_context *atomic;
	pool_t pool;

	struct mdbox_map_mail_index_header orig_map_hdr;
	struct hash_table *guid_hash;
	ARRAY_DEFINE(msgs, struct mdbox_rebuild_msg *);
	ARRAY_TYPE(seq_range) seen_file_ids;

	uint32_t rebuild_count;
	uint32_t highest_seen_map_uid;
	uint32_t highest_file_id;

	struct mailbox_list *default_list;

	struct rebuild_msg_mailbox prev_msg;
};

static unsigned int guid_hash(const void *p)
{
        const uint8_t *s = p;
	unsigned int i, g, h = 0;

	for (i = 0; i < MAIL_GUID_128_SIZE; i++) {
		h = (h << 4) + s[i];
		if ((g = h & 0xf0000000UL)) {
			h = h ^ (g >> 24);
			h = h ^ g;
		}
	}
	return h;
}

static int guid_cmp(const void *p1, const void *p2)
{
	return memcmp(p1, p2, MAIL_GUID_128_SIZE);
}

static struct mdbox_storage_rebuild_context *
mdbox_storage_rebuild_init(struct mdbox_storage *storage,
			   struct mdbox_map_atomic_context *atomic)
{
	struct mdbox_storage_rebuild_context *ctx;

	i_assert(!storage->rebuilding_storage);

	ctx = i_new(struct mdbox_storage_rebuild_context, 1);
	ctx->storage = storage;
	ctx->atomic = atomic;
	ctx->pool = pool_alloconly_create("dbox map rebuild", 1024*256);
	ctx->guid_hash = hash_table_create(default_pool, ctx->pool, 0,
					   guid_hash, guid_cmp);
	i_array_init(&ctx->msgs, 512);
	i_array_init(&ctx->seen_file_ids, 128);

	ctx->storage->rebuilding_storage = TRUE;
	return ctx;
}

static void
mdbox_storage_rebuild_deinit(struct mdbox_storage_rebuild_context *ctx)
{
	i_assert(ctx->storage->rebuilding_storage);

	ctx->storage->rebuilding_storage = FALSE;

	hash_table_destroy(&ctx->guid_hash);
	pool_unref(&ctx->pool);
	array_free(&ctx->seen_file_ids);
	array_free(&ctx->msgs);
	i_free(ctx);
}

static int mdbox_rebuild_msg_offset_cmp(const void *p1, const void *p2)
{
	const struct mdbox_rebuild_msg *const *m1 = p1, *const *m2 = p2;

	if ((*m1)->file_id < (*m2)->file_id)
		return -1;
	if ((*m1)->file_id > (*m2)->file_id)
		return 1;

	if ((*m1)->offset < (*m2)->offset)
		return -1;
	if ((*m1)->offset > (*m2)->offset)
		return 1;

	if ((*m1)->size < (*m2)->size)
		return -1;
	if ((*m1)->size > (*m2)->size)
		return 1;
	return 0;
}

static int mdbox_rebuild_msg_uid_cmp(struct mdbox_rebuild_msg *const *m1,
				     struct mdbox_rebuild_msg *const *m2)
{
	if ((*m1)->map_uid < (*m2)->map_uid)
		return -1;
	if ((*m1)->map_uid > (*m2)->map_uid)
		return 1;
	return 0;
}

static int rebuild_file_mails(struct mdbox_storage_rebuild_context *ctx,
			      struct dbox_file *file, uint32_t file_id)
{
	const char *guid;
	struct mdbox_rebuild_msg *rec;
	uoff_t offset, prev_offset;
	bool last, first, fixed = FALSE;
	int ret;

	dbox_file_seek_rewind(file);
	prev_offset = 0;
	while ((ret = dbox_file_seek_next(file, &offset, &last)) >= 0) {
		if (ret > 0) {
			if ((ret = dbox_file_metadata_read(file)) < 0)
				break;
		}

		if (ret == 0) {
			/* file is corrupted. fix it and retry. */
			if (fixed || last)
				break;
			first = prev_offset == 0;
			if (prev_offset == 0) {
				/* use existing file header if it was ok */
				prev_offset = offset;
			}
			if (dbox_file_fix(file, prev_offset) < 0) {
				ret = -1;
				break;
			}
			fixed = TRUE;
			if (!first) {
				/* seek to the offset where we last left off */
				ret = dbox_file_seek(file, prev_offset);
				if (ret <= 0)
					break;
			}
			continue;
		}
		prev_offset = offset;

		guid = dbox_file_metadata_get(file, DBOX_METADATA_GUID);
		if (guid == NULL || *guid == '\0') {
			dbox_file_set_corrupted(file,
						"Message is missing GUID");
			ret = 0;
			break;
		}

		rec = p_new(ctx->pool, struct mdbox_rebuild_msg, 1);
		rec->file_id = file_id;
		rec->offset = offset;
		rec->size = file->input->v_offset - offset;
		mail_generate_guid_128_hash(guid, rec->guid_128);
		i_assert(!mail_guid_128_is_empty(rec->guid_128));
		array_append(&ctx->msgs, &rec, 1);

		if (hash_table_lookup(ctx->guid_hash, rec->guid_128) != NULL) {
			/* duplicate. save this as a refcount=0 to map,
			   so it will eventually be deleted. */
			rec->seen_zero_ref_in_map = TRUE;
		} else {
			hash_table_insert(ctx->guid_hash, rec->guid_128, rec);
		}
	}
	if (ret < 0)
		return -1;
	else if (ret == 0 && !last)
		return 0;
	else
		return 1;
}

static int
rebuild_rename_file(struct mdbox_storage_rebuild_context *ctx,
		    const char *dir, const char **fname_p, uint32_t *file_id_r)
{
	const char *old_path, *new_path, *fname = *fname_p;

	old_path = t_strconcat(dir, "/", fname, NULL);
	do {
		new_path = t_strdup_printf("%s/"MDBOX_MAIL_FILE_FORMAT,
					   dir, ++ctx->highest_file_id);
		/* use link()+unlink() instead of rename() to make sure we
		   don't overwrite any files. */
		if (link(old_path, new_path) == 0) {
			if (unlink(old_path) < 0)
				i_error("unlink(%s) failed: %m", old_path);
			*fname_p = strrchr(new_path, '/') + 1;
			*file_id_r = ctx->highest_file_id;
			return 0;
		}
	} while (errno == EEXIST);

	i_error("link(%s, %s) failed: %m", old_path, new_path);
	return -1;
}

static int rebuild_add_file(struct mdbox_storage_rebuild_context *ctx,
			    const char *dir, const char *fname)
{
	struct dbox_file *file;
	uint32_t file_id;
	const char *id_str, *ext;
	bool deleted;
	int ret = 0;

	id_str = fname + strlen(MDBOX_MAIL_FILE_PREFIX);
	if (str_to_uint32(id_str, &file_id) < 0 || file_id == 0) {
		/* m.*.broken files are created by file fixing
		   m.*.lock files are created if flock() isn't available */
		ext = strrchr(id_str, '.');
		if (ext == NULL || (strcmp(ext, ".broken") != 0 &&
				    strcmp(ext, ".lock") != 0)) {
			i_warning("mdbox rebuild: "
				  "Skipping file with missing ID: %s/%s",
				  dir, fname);
		}
		return 0;
	}
	if (!seq_range_exists(&ctx->seen_file_ids, file_id)) {
		if (ctx->highest_file_id < file_id)
			ctx->highest_file_id = file_id;
	} else {
		/* duplicate file. either readdir() returned it twice
		   (unlikely) or it exists in both alt and primary storage.
		   to make sure we don't lose any mails from either of the
		   files, give this file a new ID and rename it. */
		if (rebuild_rename_file(ctx, dir, &fname, &file_id) < 0)
			return -1;
	}
	seq_range_array_add(&ctx->seen_file_ids, 0, file_id);

	file = mdbox_file_init(ctx->storage, file_id);
	if ((ret = dbox_file_open(file, &deleted)) > 0 && !deleted)
		ret = rebuild_file_mails(ctx, file, file_id);
	if (ret == 0)
		i_error("mdbox rebuild: Failed to fix file %s/%s", dir, fname);
	dbox_file_unref(&file);
	return ret < 0 ? -1 : 0;
}

static void
rebuild_add_missing_map_uids(struct mdbox_storage_rebuild_context *ctx,
			     uint32_t next_uid)
{
	struct mdbox_rebuild_msg **msgs;
	struct mdbox_map_mail_index_record rec;
	unsigned int i, count;
	uint32_t seq;

	memset(&rec, 0, sizeof(rec));
	msgs = array_get_modifiable(&ctx->msgs, &count);
	for (i = 0; i < count; i++) {
		if (msgs[i]->map_uid != 0)
			continue;

		rec.file_id = msgs[i]->file_id;
		rec.offset = msgs[i]->offset;
		rec.size = msgs[i]->size;

		msgs[i]->map_uid = next_uid++;
		mail_index_append(ctx->atomic->sync_trans,
				  msgs[i]->map_uid, &seq);
		mail_index_update_ext(ctx->atomic->sync_trans, seq,
				      ctx->storage->map->map_ext_id,
				      &rec, NULL);
	}
}

static int rebuild_apply_map(struct mdbox_storage_rebuild_context *ctx)
{
	struct mdbox_map *map = ctx->storage->map;
	const struct mail_index_header *hdr;
	struct mdbox_rebuild_msg *const *msgs, **pos;
	struct mdbox_rebuild_msg search_msg, *search_msgp = &search_msg;
	struct dbox_mail_lookup_rec rec;
	uint32_t seq;
	unsigned int count;

	array_sort(&ctx->msgs, mdbox_rebuild_msg_offset_cmp);

	msgs = array_get_modifiable(&ctx->msgs, &count);
	hdr = mail_index_get_header(ctx->atomic->sync_view);
	for (seq = 1; seq <= hdr->messages_count; seq++) {
		if (mdbox_map_view_lookup_rec(map, ctx->atomic->sync_view,
					      seq, &rec) < 0)
			return -1;

		/* look up the rebuild msg record for this message */
		search_msg.file_id = rec.rec.file_id;
		search_msg.offset = rec.rec.offset;
		search_msg.size = rec.rec.size;
		pos = bsearch(&search_msgp, msgs, count, sizeof(*msgs),
			      mdbox_rebuild_msg_offset_cmp);
		if (pos == NULL || (*pos)->map_uid != 0) {
			/* map record points to nonexistent or
			   a duplicate message. */
			mail_index_expunge(ctx->atomic->sync_trans, seq);
		} else {
			(*pos)->map_uid = rec.map_uid;
			if (rec.refcount == 0)
				(*pos)->seen_zero_ref_in_map = TRUE;
		}
	}
	rebuild_add_missing_map_uids(ctx, hdr->next_uid);

	/* afterwards we're interested in looking up map_uids.
	   re-sort the messages to make it easier. */
	array_sort(&ctx->msgs, mdbox_rebuild_msg_uid_cmp);
	return 0;
}

static struct mdbox_rebuild_msg *
rebuild_lookup_map_uid(struct mdbox_storage_rebuild_context *ctx,
		       uint32_t map_uid)
{
	struct mdbox_rebuild_msg search_msg, *search_msgp = &search_msg;
	struct mdbox_rebuild_msg **pos;

	search_msg.map_uid = map_uid;
	pos = array_bsearch(&ctx->msgs, &search_msgp,
			    mdbox_rebuild_msg_uid_cmp);
	return pos == NULL ? NULL : *pos;
}

static void
rebuild_mailbox_multi(struct mdbox_storage_rebuild_context *ctx,
		      struct dbox_sync_rebuild_context *rebuild_ctx,
		      struct mdbox_mailbox *mbox,
		      struct mail_index_view *view,
		      struct mail_index_transaction *trans)
{
	const struct mdbox_mail_index_record *dbox_rec;
	struct mdbox_mail_index_record new_dbox_rec;
	const struct mail_index_header *hdr;
	struct mdbox_rebuild_msg *rec;
	const void *data;
	bool expunged;
	uint32_t seq, uid, new_seq, map_uid;

	memset(&new_dbox_rec, 0, sizeof(new_dbox_rec));
	hdr = mail_index_get_header(view);
	for (seq = 1; seq <= hdr->messages_count; seq++) {
		mail_index_lookup_ext(view, seq, mbox->ext_id,
				      &data, &expunged);
		dbox_rec = data;
		map_uid = dbox_rec == NULL ? 0 : dbox_rec->map_uid;

		mail_index_lookup_ext(view, seq, mbox->guid_ext_id,
				      &data, &expunged);

		/* see if we can find this message based on
		   1) GUID, 2) map_uid */
		rec = data == NULL ? NULL :
			hash_table_lookup(ctx->guid_hash, data);
		if (rec == NULL) {
			if (map_uid == 0) {
				/* not a multi-dbox message, ignore. */
				continue;
			}
			/* multi-dbox message that wasn't found with GUID.
			   either it's lost or GUID has been corrupted. we can
			   still try to look it up using map_uid. */
			rec = rebuild_lookup_map_uid(ctx, map_uid);
			if (rec != NULL) {
				mail_index_update_ext(trans, seq,
						      mbox->guid_ext_id,
						      rec->guid_128, NULL);
			}
		} else if (map_uid != rec->map_uid) {
			/* map_uid is wrong, update it */
			i_assert(rec->map_uid != 0);
			new_dbox_rec.map_uid = rec->map_uid;
			mail_index_update_ext(trans, seq, mbox->ext_id,
					      &new_dbox_rec, NULL);
		} else {
			/* everything was ok */
		}

		if (rec != NULL) T_BEGIN {
			/* keep this message */
			rec->refcount++;

			mail_index_lookup_uid(view, seq, &uid);
			mail_index_append(trans, uid, &new_seq);
			dbox_sync_rebuild_index_metadata(rebuild_ctx,
							 new_seq, uid);

			new_dbox_rec.map_uid = rec->map_uid;
			mail_index_update_ext(trans, new_seq, mbox->ext_id,
					      &new_dbox_rec, NULL);
			mail_index_update_ext(trans, new_seq, mbox->guid_ext_id,
					      rec->guid_128, NULL);
		} T_END;
	}
}

static void
mdbox_rebuild_get_header(struct mail_index_view *view, uint32_t hdr_ext_id,
			 struct mdbox_index_header *hdr_r)
{
	const void *data;
	size_t data_size;

	mail_index_get_header_ext(view, hdr_ext_id, &data, &data_size);
	memset(hdr_r, 0, sizeof(*hdr_r));
	memcpy(hdr_r, data, I_MIN(data_size, sizeof(*hdr_r)));
}

static void mdbox_header_update(struct dbox_sync_rebuild_context *rebuild_ctx,
				struct mdbox_mailbox *mbox)
{
	struct mdbox_index_header hdr, backup_hdr;

	mdbox_rebuild_get_header(rebuild_ctx->view, mbox->hdr_ext_id, &hdr);
	if (rebuild_ctx->backup_view == NULL)
		memset(&backup_hdr, 0, sizeof(backup_hdr));
	else {
		mdbox_rebuild_get_header(rebuild_ctx->backup_view,
					 mbox->hdr_ext_id, &backup_hdr);
	}

	/* make sure we have valid mailbox guid */
	if (mail_guid_128_is_empty(hdr.mailbox_guid)) {
		if (!mail_guid_128_is_empty(backup_hdr.mailbox_guid)) {
			memcpy(hdr.mailbox_guid, backup_hdr.mailbox_guid,
			       sizeof(hdr.mailbox_guid));
		} else {
			mail_generate_guid_128(hdr.mailbox_guid);
		}
	}

	/* update map's uid-validity */
	hdr.map_uid_validity = mdbox_map_get_uid_validity(mbox->storage->map);

	/* and write changes */
	mail_index_update_header_ext(rebuild_ctx->trans, mbox->hdr_ext_id, 0,
				     &hdr, sizeof(hdr));
}

static int
rebuild_mailbox(struct mdbox_storage_rebuild_context *ctx,
		struct mail_namespace *ns, const char *vname)
{
	struct mailbox *box;
	struct mdbox_mailbox *mbox;
        struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	struct dbox_sync_rebuild_context *rebuild_ctx;
	enum mail_error error;
	const char *name;
	int ret;

	name = mail_namespace_get_storage_name(ns, vname);
	box = mailbox_alloc(ns->list, name, MAILBOX_FLAG_READONLY |
			    MAILBOX_FLAG_KEEP_RECENT |
			    MAILBOX_FLAG_IGNORE_ACLS);
	i_assert(box->storage == &ctx->storage->storage.storage);
	if (dbox_mailbox_open(box) < 0) {
		(void)mail_storage_get_last_error(box->storage, &error);
		mailbox_free(&box);
		if (error == MAIL_ERROR_TEMP)
			return -1;
		/* non-temporary error, ignore */
		return 0;
	}
	mbox = (struct mdbox_mailbox *)box;

	ret = mail_index_sync_begin(box->index, &sync_ctx, &view, &trans,
				    MAIL_INDEX_SYNC_FLAG_AVOID_FLAG_UPDATES);
	if (ret <= 0) {
		i_assert(ret != 0);
		mail_storage_set_index_error(box);
		mailbox_free(&box);
		return -1;
	}

	/* reset cache, just in case it contains invalid data */
	mail_cache_reset(box->cache);

	rebuild_ctx = dbox_sync_index_rebuild_init(&mbox->box, view, trans);
	mdbox_header_update(rebuild_ctx, mbox);
	rebuild_mailbox_multi(ctx, rebuild_ctx, mbox, view, trans);
	dbox_sync_index_rebuild_deinit(&rebuild_ctx);

	if (mail_index_sync_commit(&sync_ctx) < 0) {
		mail_storage_set_index_error(box);
		ret = -1;
	}

	mailbox_free(&box);
	return ret < 0 ? -1 : 0;
}

static int
rebuild_namespace_mailboxes(struct mdbox_storage_rebuild_context *ctx,
			    struct mail_namespace *ns)
{
	struct mailbox_list_iterate_context *iter;
	const struct mailbox_info *info;
	int ret = 0;

	if (ctx->default_list == NULL ||
	    (ns->flags & NAMESPACE_FLAG_INBOX_ANY) != 0)
		ctx->default_list = ns->list;

	iter = mailbox_list_iter_init(ns->list, "*",
				      MAILBOX_LIST_ITER_RAW_LIST |
				      MAILBOX_LIST_ITER_RETURN_NO_FLAGS);
	while ((info = mailbox_list_iter_next(iter)) != NULL) {
		if ((info->flags & (MAILBOX_NONEXISTENT |
				    MAILBOX_NOSELECT)) == 0) {
			T_BEGIN {
				ret = rebuild_mailbox(ctx, ns, info->name);
			} T_END;
			if (ret < 0) {
				ret = -1;
				break;
			}
		}
	}
	if (mailbox_list_iter_deinit(&iter) < 0)
		ret = -1;
	return ret;
}

static int rebuild_mailboxes(struct mdbox_storage_rebuild_context *ctx)
{
	struct mail_storage *storage = &ctx->storage->storage.storage;
	struct mail_namespace *ns;

	for (ns = storage->user->namespaces; ns != NULL; ns = ns->next) {
		if (ns->storage == storage && ns->alias_for == NULL) {
			if (rebuild_namespace_mailboxes(ctx, ns) < 0)
				return -1;
		}
	}
	if (ctx->default_list == NULL)
		i_panic("No namespace found for storage=%s", storage->name);
	return 0;
}

static int rebuild_msg_mailbox_commit(struct rebuild_msg_mailbox *msg)
{
	if (mail_index_sync_commit(&msg->sync_ctx) < 0)
		return -1;
	mailbox_free(&msg->box);
	memset(msg, 0, sizeof(*msg));
	return 0;
}

static int rebuild_restore_msg(struct mdbox_storage_rebuild_context *ctx,
			       struct mdbox_rebuild_msg *msg)
{
	struct mail_storage *storage = &ctx->storage->storage.storage;
	struct dbox_file *file;
	const struct mail_index_header *hdr;
	struct mdbox_mail_index_record dbox_rec;
	const char *mailbox = NULL;
	struct mailbox *box;
	struct mdbox_mailbox *mbox;
	enum mail_error error;
	bool deleted, created;
	int ret;
	uint32_t seq;

	/* first see if message contains the mailbox it was originally
	   saved to */
	file = mdbox_file_init(ctx->storage, msg->file_id);
	ret = dbox_file_open(file, &deleted);
	if (ret > 0 && !deleted)
		ret = dbox_file_seek(file, msg->offset);
	if (ret > 0 && !deleted && dbox_file_metadata_read(file) > 0) {
		mailbox = dbox_file_metadata_get(file,
						 DBOX_METADATA_ORIG_MAILBOX);
		mailbox = t_strdup(mailbox);
	}
	dbox_file_unref(&file);
	if (ret <= 0 || deleted) {
		if (ret < 0)
			return -1;
		/* we shouldn't get here, so apparently we couldn't fix
		   something. just ignore the mail.. */
		return 0;
	}

	if (mailbox == NULL)
		mailbox = "INBOX";

	/* we have the destination mailbox. now open it and add the message
	   there. */
	created = FALSE;
	box = ctx->prev_msg.box != NULL &&
		strcmp(mailbox, ctx->prev_msg.box->name) == 0 ?
		ctx->prev_msg.box : NULL;
	while (box == NULL) {
		box = mailbox_alloc(ctx->default_list, mailbox,
				    MAILBOX_FLAG_READONLY |
				    MAILBOX_FLAG_KEEP_RECENT |
				    MAILBOX_FLAG_IGNORE_ACLS);
		i_assert(box->storage == storage);
		if (dbox_mailbox_open(box) == 0)
			break;

		(void)mail_storage_get_last_error(box->storage, &error);
		if (error == MAIL_ERROR_NOTFOUND && !created) {
			/* mailbox doesn't exist currently? see if creating
			   it helps. */
			created = TRUE;
			(void)mailbox_create(box, NULL, FALSE);
			mailbox_free(&box);
			continue;
		}

		mailbox_free(&box);
		if (error == MAIL_ERROR_TEMP)
			return -1;

		if (strcmp(mailbox, "INBOX") != 0) {
			/* see if we can save to INBOX instead. */
			mailbox = "INBOX";
		} else {
			/* this shouldn't happen */
			return -1;
		}
	}
	mbox = (struct mdbox_mailbox *)box;

	/* switch the mailbox cache if necessary */
	if (box != ctx->prev_msg.box && ctx->prev_msg.box != NULL) {
		if (rebuild_msg_mailbox_commit(&ctx->prev_msg) < 0)
			return -1;
	}
	if (ctx->prev_msg.box == NULL) {
		ret = mail_index_sync_begin(box->index,
					    &ctx->prev_msg.sync_ctx,
					    &ctx->prev_msg.view,
					    &ctx->prev_msg.trans, 0);
		if (ret <= 0) {
			i_assert(ret != 0);
			mail_storage_set_index_error(box);
			mailbox_free(&box);
			return -1;
		}
		ctx->prev_msg.box = box;
		hdr = mail_index_get_header(ctx->prev_msg.view);
		ctx->prev_msg.next_uid = hdr->next_uid;
	}

	/* add the new message */
	memset(&dbox_rec, 0, sizeof(dbox_rec));
	dbox_rec.map_uid = msg->map_uid;
	dbox_rec.save_date = ioloop_time;
	mail_index_append(ctx->prev_msg.trans, ctx->prev_msg.next_uid++, &seq);
	mail_index_update_ext(ctx->prev_msg.trans, seq, mbox->ext_id,
			      &dbox_rec, NULL);
	mail_index_update_ext(ctx->prev_msg.trans, seq, mbox->guid_ext_id,
			      msg->guid_128, NULL);

	msg->refcount++;
	return 0;
}

static int rebuild_handle_zero_refs(struct mdbox_storage_rebuild_context *ctx)
{
	struct mdbox_rebuild_msg **msgs;
	unsigned int i, count;

	/* if we have messages at this point which have refcount=0, they're
	   either already expunged or they were somehow lost for some reason.
	   we'll need to figure out what to do about them. */
	msgs = array_get_modifiable(&ctx->msgs, &count);
	for (i = 0; i < count; i++) {
		if (msgs[i]->refcount != 0)
			continue;

		if (msgs[i]->seen_zero_ref_in_map) {
			/* we've seen the map record, trust it. */
			continue;
		}
		/* either map record was lost for this message or the message
		   was lost from its mailbox. safest way to handle this is to
		   restore the message. */
		if (rebuild_restore_msg(ctx, msgs[i]) < 0)
			return -1;
	}
	if (ctx->prev_msg.box != NULL) {
		if (rebuild_msg_mailbox_commit(&ctx->prev_msg) < 0)
			return -1;
	}
	return 0;
}

static void rebuild_update_refcounts(struct mdbox_storage_rebuild_context *ctx)
{
	const struct mail_index_header *hdr;
	const void *data;
	struct mdbox_rebuild_msg **msgs;
	const uint16_t *ref16_p;
	bool expunged;
	uint32_t seq, map_uid;
	unsigned int i, count;

	/* update refcounts for existing map records */
	msgs = array_get_modifiable(&ctx->msgs, &count);
	hdr = mail_index_get_header(ctx->atomic->sync_view);
	for (seq = 1, i = 0; seq <= hdr->messages_count && i < count; seq++) {
		mail_index_lookup_uid(ctx->atomic->sync_view, seq, &map_uid);
		if (map_uid != msgs[i]->map_uid) {
			/* we've already expunged this map record */
			i_assert(map_uid < msgs[i]->map_uid);
			continue;
		}

		mail_index_lookup_ext(ctx->atomic->sync_view, seq,
				      ctx->storage->map->ref_ext_id,
				      &data, &expunged);
		ref16_p = data;
		if (ref16_p == NULL || *ref16_p != msgs[i]->refcount) {
			mail_index_update_ext(ctx->atomic->sync_trans, seq,
					      ctx->storage->map->ref_ext_id,
					      &msgs[i]->refcount, NULL);
		}
		i++;
	}

	/* update refcounts for newly created map records */
	for (; i < count; i++, seq++) {
		mail_index_update_ext(ctx->atomic->sync_trans, seq,
				      ctx->storage->map->ref_ext_id,
				      &msgs[i]->refcount, NULL);
	}
}

static int rebuild_finish(struct mdbox_storage_rebuild_context *ctx)
{
	struct mdbox_map_mail_index_header map_hdr;

	i_assert(ctx->default_list != NULL);

	if (rebuild_handle_zero_refs(ctx) < 0)
		return -1;
	rebuild_update_refcounts(ctx);

	/* update map header */
	map_hdr = ctx->orig_map_hdr;
	map_hdr.highest_file_id = ctx->highest_file_id;
	map_hdr.rebuild_count = ++ctx->rebuild_count;

	mail_index_update_header_ext(ctx->atomic->sync_trans,
				     ctx->storage->map->map_ext_id,
				     0, &map_hdr, sizeof(map_hdr));
	return 0;
}

static int
mdbox_storage_rebuild_scan_dir(struct mdbox_storage_rebuild_context *ctx,
			       const char *storage_dir, bool alt)
{
	DIR *dir;
	struct dirent *d;
	int ret = 0;

	dir = opendir(storage_dir);
	if (dir == NULL) {
		if (alt && errno == ENOENT)
			return 0;

		mail_storage_set_critical(&ctx->storage->storage.storage,
			"opendir(%s) failed: %m", storage_dir);
		return -1;
	}
	for (errno = 0; (d = readdir(dir)) != NULL && ret == 0; errno = 0) {
		if (strncmp(d->d_name, MDBOX_MAIL_FILE_PREFIX,
			    strlen(MDBOX_MAIL_FILE_PREFIX)) == 0) T_BEGIN {
			ret = rebuild_add_file(ctx, storage_dir, d->d_name);
		} T_END;
	}
	if (ret == 0 && errno != 0) {
		mail_storage_set_critical(&ctx->storage->storage.storage,
			"readdir(%s) failed: %m", storage_dir);
		ret = -1;
	}
	if (closedir(dir) < 0) {
		mail_storage_set_critical(&ctx->storage->storage.storage,
			"closedir(%s) failed: %m", storage_dir);
		ret = -1;
	}
	return ret;
}

static int mdbox_storage_rebuild_scan(struct mdbox_storage_rebuild_context *ctx)
{
	const void *data;
	size_t data_size;

	if (mdbox_map_open_or_create(ctx->storage->map) < 0)
		return -1;

	/* begin by locking the map, so that other processes can't try to
	   rebuild at the same time. */
	if (mdbox_map_atomic_lock(ctx->atomic) < 0)
		return -1;

	/* get old map header */
	mail_index_get_header_ext(ctx->atomic->sync_view,
				  ctx->storage->map->map_ext_id,
				  &data, &data_size);
	memset(&ctx->orig_map_hdr, 0, sizeof(ctx->orig_map_hdr));
	memcpy(&ctx->orig_map_hdr, data,
	       I_MIN(data_size, sizeof(ctx->orig_map_hdr)));
	ctx->highest_file_id = ctx->orig_map_hdr.highest_file_id;

	/* get storage rebuild counter after locking */
	ctx->rebuild_count = mdbox_map_get_rebuild_count(ctx->storage->map);
	if (ctx->rebuild_count != ctx->storage->corrupted_rebuild_count &&
	    ctx->storage->corrupted) {
		/* storage was already rebuilt by someone else */
		return 0;
	}

	i_warning("mdbox %s: rebuilding indexes", ctx->storage->storage_dir);

	if (mdbox_storage_rebuild_scan_dir(ctx, ctx->storage->storage_dir,
					   FALSE) < 0)
		return -1;
	if (ctx->storage->alt_storage_dir != NULL) {
		if (mdbox_storage_rebuild_scan_dir(ctx,
				ctx->storage->alt_storage_dir, TRUE) < 0)
			return -1;
	}

	if (rebuild_apply_map(ctx) < 0 ||
	    rebuild_mailboxes(ctx) < 0 ||
	    rebuild_finish(ctx) < 0) {
		mdbox_map_atomic_set_failed(ctx->atomic);
		return -1;
	}
	return 0;
}

int mdbox_storage_rebuild_in_context(struct mdbox_storage *storage,
				     struct mdbox_map_atomic_context *atomic)
{
	struct mdbox_storage_rebuild_context *ctx;
	int ret;

	if (dbox_sync_rebuild_verify_alt_storage(storage->map->root_list) < 0) {
		mail_storage_set_critical(&storage->storage.storage,
			"mdbox rebuild: Alt storage %s not mounted, aborting",
			storage->alt_storage_dir);
		mdbox_map_atomic_set_failed(atomic);
		return -1;
	}

	ctx = mdbox_storage_rebuild_init(storage, atomic);
	ret = mdbox_storage_rebuild_scan(ctx);
	mdbox_storage_rebuild_deinit(ctx);

	if (ret == 0) {
		storage->corrupted = FALSE;
		storage->corrupted_rebuild_count = 0;
	}
	return ret;
}

int mdbox_storage_rebuild(struct mdbox_storage *storage)
{
	struct mdbox_map_atomic_context *atomic;
	int ret;

	atomic = mdbox_map_atomic_begin(storage->map);
	ret = mdbox_storage_rebuild_in_context(storage, atomic);
	mdbox_map_atomic_set_success(atomic);
	if (mdbox_map_atomic_finish(&atomic) < 0)
		ret = -1;
	return ret;
}
