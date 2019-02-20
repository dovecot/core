/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "istream.h"
#include "hash.h"
#include "str.h"
#include "mail-cache.h"
#include "index-rebuild.h"
#include "mail-namespace.h"
#include "mailbox-list-private.h"
#include "mdbox-storage.h"
#include "mdbox-file.h"
#include "mdbox-map-private.h"
#include "mdbox-sync.h"
#include "mdbox-storage-rebuild.h"

#include <dirent.h>
#include <unistd.h>

#define REBUILD_MAX_REFCOUNT 32768

struct mdbox_rebuild_msg {
	struct mdbox_rebuild_msg *guid_hash_next;

	guid_128_t guid_128;
	uint32_t file_id;
	uint32_t offset;
	uint32_t rec_size;
	uoff_t mail_size;
	uint32_t map_uid;

	uint16_t refcount;
	bool seen_zero_ref_in_map:1;
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
	HASH_TABLE(uint8_t *, struct mdbox_rebuild_msg *) guid_hash;
	ARRAY(struct mdbox_rebuild_msg *) msgs;
	ARRAY_TYPE(seq_range) seen_file_ids;

	uint32_t rebuild_count;
	uint32_t highest_file_id;

	struct mailbox_list *default_list;

	struct rebuild_msg_mailbox prev_msg;

	bool have_pop3_uidls:1;
	bool have_pop3_orders:1;
};

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
	hash_table_create(&ctx->guid_hash, ctx->pool, 0,
			  guid_128_hash, guid_128_cmp);
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

static int
mdbox_rebuild_msg_offset_cmp(struct mdbox_rebuild_msg *const *m1,
			     struct mdbox_rebuild_msg *const *m2)
{
	if ((*m1)->file_id < (*m2)->file_id)
		return -1;
	if ((*m1)->file_id > (*m2)->file_id)
		return 1;

	if ((*m1)->offset < (*m2)->offset)
		return -1;
	if ((*m1)->offset > (*m2)->offset)
		return 1;

	if ((*m1)->rec_size < (*m2)->rec_size)
		return -1;
	if ((*m1)->rec_size > (*m2)->rec_size)
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

static void rebuild_scan_metadata(struct mdbox_storage_rebuild_context *ctx,
				  struct dbox_file *file)
{
	if (dbox_file_metadata_get(file, DBOX_METADATA_POP3_UIDL) != NULL)
		ctx->have_pop3_uidls = TRUE;
	if (dbox_file_metadata_get(file, DBOX_METADATA_POP3_ORDER) != NULL)
		ctx->have_pop3_orders = TRUE;
}

static int rebuild_file_mails(struct mdbox_storage_rebuild_context *ctx,
			      struct dbox_file *file, uint32_t file_id)
{
	const char *guid;
	uint8_t *guid_p;
	struct mdbox_rebuild_msg *rec, *old_rec;
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
			if ((ret = dbox_file_fix(file, prev_offset)) < 0)
				break;
			if (ret == 0) {
				/* file was deleted */
				return 1;
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
		rebuild_scan_metadata(ctx, file);

		rec = p_new(ctx->pool, struct mdbox_rebuild_msg, 1);
		rec->file_id = file_id;
		rec->offset = offset;
		rec->rec_size = file->input->v_offset - offset;
		rec->mail_size = dbox_file_get_plaintext_size(file);
		mail_generate_guid_128_hash(guid, rec->guid_128);
		i_assert(!guid_128_is_empty(rec->guid_128));
		array_push_back(&ctx->msgs, &rec);

		guid_p = rec->guid_128;
		old_rec = hash_table_lookup(ctx->guid_hash, guid_p);
		if (old_rec == NULL)
			hash_table_insert(ctx->guid_hash, guid_p, rec);
		else if (rec->mail_size == old_rec->mail_size) {
			/* two mails' GUID and size are the same, which quite
			   likely means that their contents are the same as
			   well. we'll compare the mail sizes instead of the
			   record sizes, because the records' metadata may
			   differ.

			   save this duplicate mail with refcount=0 to the map,
			   so it will eventually be purged. */
			rec->seen_zero_ref_in_map = TRUE;
		} else {
			/* duplicate GUID, but not a duplicate message. */
			i_error("mdbox %s: Duplicate GUID %s in "
				"m.%u:%u (size=%"PRIuUOFF_T") and m.%u:%u "
				"(size=%"PRIuUOFF_T")",
				ctx->storage->storage_dir, guid,
				old_rec->file_id, old_rec->offset, old_rec->mail_size,
				rec->file_id, rec->offset, rec->mail_size);
			rec->guid_hash_next = old_rec->guid_hash_next;
			old_rec->guid_hash_next = rec;
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
			i_unlink(old_path);
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
	seq_range_array_add(&ctx->seen_file_ids, file_id);

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

	i_zero(&rec);
	msgs = array_get_modifiable(&ctx->msgs, &count);
	for (i = 0; i < count; i++) {
		if (msgs[i]->map_uid != 0)
			continue;

		rec.file_id = msgs[i]->file_id;
		rec.offset = msgs[i]->offset;
		rec.size = msgs[i]->rec_size;

		msgs[i]->map_uid = next_uid++;
		mail_index_append(ctx->atomic->sync_trans,
				  msgs[i]->map_uid, &seq);
		mail_index_update_ext(ctx->atomic->sync_trans, seq,
				      ctx->storage->map->map_ext_id,
				      &rec, NULL);
	}
}

static void rebuild_apply_map(struct mdbox_storage_rebuild_context *ctx)
{
	struct mdbox_map *map = ctx->storage->map;
	const struct mail_index_header *hdr;
	struct mdbox_rebuild_msg **pos;
	struct mdbox_rebuild_msg search_msg, *search_msgp = &search_msg;
	struct dbox_mail_lookup_rec rec;
	uint32_t seq;

	array_sort(&ctx->msgs, mdbox_rebuild_msg_offset_cmp);
	/* msgs now contains a list of all messages that exists in m.* files,
	   sorted by file_id,offset */

	hdr = mail_index_get_header(ctx->atomic->sync_view);
	for (seq = 1; seq <= hdr->messages_count; seq++) {
		if (mdbox_map_view_lookup_rec(map, ctx->atomic->sync_view,
					      seq, &rec) < 0) {
			/* map or ref extension is missing from the index.
			   Just ignore the file entirely. (Don't try to
			   continue with other records, since they'll fail
			   as well, and each failure logs the same error.) */
			i_assert(seq == 1);
			break;
		}

		/* look up the rebuild msg record for this message based on
		   the (file_id, offset, size) triplet */
		search_msg.file_id = rec.rec.file_id;
		search_msg.offset = rec.rec.offset;
		search_msg.rec_size = rec.rec.size;
		pos = array_bsearch(&ctx->msgs, &search_msgp,
				    mdbox_rebuild_msg_offset_cmp);
		if (pos == NULL || (*pos)->map_uid != 0) {
			/* map record points to nonexistent or
			   a duplicate message. */
			mail_index_expunge(ctx->atomic->sync_trans, seq);
		} else {
			/* remember this message's map_uid */
			(*pos)->map_uid = rec.map_uid;
			if (rec.refcount == 0)
				(*pos)->seen_zero_ref_in_map = TRUE;
		}
	}
	rebuild_add_missing_map_uids(ctx, hdr->next_uid);

	/* afterwards we're interested in looking up map_uids.
	   re-sort the messages to make it easier. */
	array_sort(&ctx->msgs, mdbox_rebuild_msg_uid_cmp);
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

static bool
guid_hash_have_map_uid(struct mdbox_rebuild_msg **recp, uint32_t map_uid)
{
	struct mdbox_rebuild_msg *rec;

	for (rec = *recp; rec != NULL; rec = rec->guid_hash_next) {
		if (rec->map_uid == map_uid) {
			*recp = rec;
			return TRUE;
		}
	}
	return FALSE;
}

static void
rebuild_mailbox_multi(struct mdbox_storage_rebuild_context *ctx,
		      struct index_rebuild_context *rebuild_ctx,
		      struct mdbox_mailbox *mbox,
		      struct mail_index_view *view,
		      struct mail_index_transaction *trans)
{
	struct mdbox_mail_index_record new_dbox_rec;
	const struct mail_index_header *hdr;
	struct mdbox_rebuild_msg *rec;
	const void *data;
	const uint8_t *guid_p;
	uint32_t old_seq, new_seq, uid, map_uid;

	/* Rebuild the mailbox's index. Note that index is reset at this point,
	   so although we can still access the old messages, we'll need to
	   append anything we want to keep as new messages. */
	hdr = mail_index_get_header(view);
	for (old_seq = 1; old_seq <= hdr->messages_count; old_seq++) {
		mail_index_lookup_ext(view, old_seq, mbox->ext_id,
				      &data, NULL);
		if (data == NULL) {
			i_zero(&new_dbox_rec);
			map_uid = 0;
		} else {
			memcpy(&new_dbox_rec, data, sizeof(new_dbox_rec));
			map_uid = new_dbox_rec.map_uid;
		}

		mail_index_lookup_ext(view, old_seq, mbox->guid_ext_id,
				      &data, NULL);
		guid_p = data;

		/* see if we can find this message based on
		   1) GUID, 2) map_uid */
		rec = guid_p == NULL ? NULL :
			hash_table_lookup(ctx->guid_hash, guid_p);
		if (rec == NULL) {
			/* multi-dbox message that wasn't found with GUID.
			   either it's lost or GUID has been corrupted. we can
			   still try to look it up using map_uid. */
			rec = map_uid == 0 ? NULL :
				rebuild_lookup_map_uid(ctx, map_uid);
			map_uid = rec == NULL ? 0 : rec->map_uid;
		} else if (!guid_hash_have_map_uid(&rec, map_uid)) {
			/* message's GUID and map_uid point to different
			   physical messages. assume that GUID is correct and
			   map_uid is wrong. */
			map_uid = rec->map_uid;
		} else {
			/* everything was ok. use this specific record's
			   map_uid to avoid duplicating mails in case the same
			   GUID exists multiple times */
		}

		if (rec != NULL &&
		    rec->refcount < REBUILD_MAX_REFCOUNT) T_BEGIN {
			/* keep this message. add it to mailbox index. */
			i_assert(map_uid != 0);
			rec->refcount++;

			mail_index_lookup_uid(view, old_seq, &uid);
			mail_index_append(trans, uid, &new_seq);
			index_rebuild_index_metadata(rebuild_ctx,
						     new_seq, uid);

			new_dbox_rec.map_uid = map_uid;
			mail_index_update_ext(trans, new_seq, mbox->ext_id,
					      &new_dbox_rec, NULL);
			mail_index_update_ext(trans, new_seq, mbox->guid_ext_id,
					      rec->guid_128, NULL);
		} T_END;
	}
}

static void
mdbox_rebuild_get_header(struct mail_index_view *view, uint32_t hdr_ext_id,
			 struct mdbox_index_header *hdr_r, bool *need_resize_r)
{
	const void *data;
	size_t data_size;

	mail_index_get_header_ext(view, hdr_ext_id, &data, &data_size);
	i_zero(hdr_r);
	memcpy(hdr_r, data, I_MIN(data_size, sizeof(*hdr_r)));
	*need_resize_r = data_size < sizeof(*hdr_r);
}

static void mdbox_header_update(struct mdbox_storage_rebuild_context *ctx,
				struct index_rebuild_context *rebuild_ctx,
				struct mdbox_mailbox *mbox)
{
	struct mdbox_index_header hdr, backup_hdr;
	bool need_resize, need_resize_backup;

	mdbox_rebuild_get_header(rebuild_ctx->view, mbox->hdr_ext_id,
				 &hdr, &need_resize);
	if (rebuild_ctx->backup_view == NULL) {
		i_zero(&backup_hdr);
		need_resize = TRUE;
	} else {
		mdbox_rebuild_get_header(rebuild_ctx->backup_view,
					 mbox->hdr_ext_id, &backup_hdr,
					 &need_resize_backup);
	}

	/* make sure we have valid mailbox guid */
	if (guid_128_is_empty(hdr.mailbox_guid)) {
		if (!guid_128_is_empty(backup_hdr.mailbox_guid)) {
			memcpy(hdr.mailbox_guid, backup_hdr.mailbox_guid,
			       sizeof(hdr.mailbox_guid));
		} else {
			guid_128_generate(hdr.mailbox_guid);
		}
	}

	/* update map's uid-validity */
	hdr.map_uid_validity = mdbox_map_get_uid_validity(mbox->storage->map);

	if (ctx->have_pop3_uidls)
		hdr.flags |= DBOX_INDEX_HEADER_FLAG_HAVE_POP3_UIDLS;
	if (ctx->have_pop3_orders)
		hdr.flags |= DBOX_INDEX_HEADER_FLAG_HAVE_POP3_ORDERS;

	/* and write changes */
	if (need_resize) {
		mail_index_ext_resize_hdr(rebuild_ctx->trans, mbox->hdr_ext_id,
					  sizeof(hdr));
	}
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
	struct index_rebuild_context *rebuild_ctx;
	enum mail_error error;
	int ret;

	box = mailbox_alloc(ns->list, vname, MAILBOX_FLAG_READONLY |
			    MAILBOX_FLAG_IGNORE_ACLS);
	mailbox_set_reason(box, "mdbox rebuild");
	if (box->storage != &ctx->storage->storage.storage) {
		/* the namespace has multiple storages. */
		mailbox_free(&box);
		return 0;
	}
	if (mailbox_open(box) < 0) {
		error = mailbox_get_last_mail_error(box);
		i_error("Couldn't open mailbox '%s': %s",
			vname, mailbox_get_last_internal_error(box, NULL));
		mailbox_free(&box);
		if (error == MAIL_ERROR_TEMP)
			return -1;
		/* non-temporary error, ignore */
		return 0;
	}
	mbox = MDBOX_MAILBOX(box);

	ret = mail_index_sync_begin(box->index, &sync_ctx, &view, &trans,
				    MAIL_INDEX_SYNC_FLAG_AVOID_FLAG_UPDATES);
	if (ret <= 0) {
		i_assert(ret != 0);
		mailbox_set_index_error(box);
		mailbox_free(&box);
		return -1;
	}

	rebuild_ctx = index_index_rebuild_init(&mbox->box, view, trans);
	mdbox_header_update(ctx, rebuild_ctx, mbox);
	rebuild_mailbox_multi(ctx, rebuild_ctx, mbox, view, trans);
	index_index_rebuild_deinit(&rebuild_ctx, dbox_get_uidvalidity_next);
	mail_index_unset_fscked(trans);

	mail_index_sync_set_reason(sync_ctx, "mdbox storage rebuild");
	if (mail_index_sync_commit(&sync_ctx) < 0) {
		mailbox_set_index_error(box);
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
				ret = rebuild_mailbox(ctx, ns, info->vname);
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
	mail_index_sync_set_reason(msg->sync_ctx, "mdbox storage rebuild");
	if (mail_index_sync_commit(&msg->sync_ctx) < 0)
		return -1;
	mailbox_free(&msg->box);
	i_zero(msg);
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
		if (mailbox != NULL) {
			mailbox = mailbox_list_get_vname(ctx->default_list, mailbox);
			mailbox = t_strdup(mailbox);
		}
		rebuild_scan_metadata(ctx, file);
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
		strcmp(mailbox, ctx->prev_msg.box->vname) == 0 ?
		ctx->prev_msg.box : NULL;
	while (box == NULL) {
		box = mailbox_alloc(ctx->default_list, mailbox,
				    MAILBOX_FLAG_READONLY |
				    MAILBOX_FLAG_IGNORE_ACLS);
		mailbox_set_reason(box, "mdbox rebuild restore");
		i_assert(box->storage == storage);
		if (mailbox_open(box) == 0)
			break;

		error = mailbox_get_last_mail_error(box);
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
	mbox = MDBOX_MAILBOX(box);

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
			mailbox_set_index_error(box);
			mailbox_free(&box);
			return -1;
		}
		ctx->prev_msg.box = box;
		hdr = mail_index_get_header(ctx->prev_msg.view);
		ctx->prev_msg.next_uid = hdr->next_uid;
	}

	/* add the new message */
	i_zero(&dbox_rec);
	dbox_rec.map_uid = msg->map_uid;
	dbox_rec.save_date = ioloop_time;
	mail_index_append(ctx->prev_msg.trans, ctx->prev_msg.next_uid++, &seq);
	mail_index_update_ext(ctx->prev_msg.trans, seq, mbox->ext_id,
			      &dbox_rec, NULL);
	mail_index_update_ext(ctx->prev_msg.trans, seq, mbox->guid_ext_id,
			      msg->guid_128, NULL);

	i_assert(msg->refcount == 0);
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
				      &data, NULL);
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
	if (mdbox_map_atomic_lock(ctx->atomic, "mdbox storage rebuild") < 0)
		return -1;

	/* fsck the map just in case its UIDs are broken */
	if (mail_index_fsck(ctx->storage->map->index) < 0) {
		mail_storage_set_index_error(&ctx->storage->storage.storage,
					     ctx->storage->map->index);
		return -1;
	}

	/* get old map header */
	mail_index_get_header_ext(ctx->atomic->sync_view,
				  ctx->storage->map->map_ext_id,
				  &data, &data_size);
	i_zero(&ctx->orig_map_hdr);
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

	rebuild_apply_map(ctx);
	if (rebuild_mailboxes(ctx) < 0 ||
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

	if (dbox_verify_alt_storage(storage->map->root_list) < 0) {
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
	mdbox_map_atomic_unset_fscked(atomic);
	if (mdbox_map_atomic_finish(&atomic) < 0)
		ret = -1;
	return ret;
}
