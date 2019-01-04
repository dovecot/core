/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hash.h"
#include "mail-index-modseq.h"
#include "mail-storage-private.h"
#include "dsync-mail.h"
#include "dsync-mailbox.h"
#include "dsync-transaction-log-scan.h"

struct dsync_transaction_log_scan {
	pool_t pool;
	HASH_TABLE_TYPE(dsync_uid_mail_change) changes;
	HASH_TABLE_TYPE(dsync_attr_change) attr_changes;
	struct mail_index_view *view;
	uint32_t highest_wanted_uid;

	uint32_t last_log_seq;
	uoff_t last_log_offset;

	bool returned_all_changes;
};

static bool ATTR_NOWARN_UNUSED_RESULT
export_change_get(struct dsync_transaction_log_scan *ctx, uint32_t uid,
		  enum dsync_mail_change_type type,
		  struct dsync_mail_change **change_r)
{
	struct dsync_mail_change *change;
	const char *orig_guid;

	i_assert(uid > 0);
	i_assert(type != DSYNC_MAIL_CHANGE_TYPE_SAVE);

	*change_r = NULL;

	if (uid > ctx->highest_wanted_uid)
		return FALSE;

	change = hash_table_lookup(ctx->changes, POINTER_CAST(uid));
	if (change == NULL) {
		/* first change for this UID */
		change = p_new(ctx->pool, struct dsync_mail_change, 1);
		change->uid = uid;
		change->type = type;
		hash_table_insert(ctx->changes, POINTER_CAST(uid), change);
	} else if (type == DSYNC_MAIL_CHANGE_TYPE_EXPUNGE) {
		/* expunge overrides flag changes */
		orig_guid = change->guid;
		i_zero(change);
		change->type = type;
		change->uid = uid;
		change->guid = orig_guid;
	} else if (change->type == DSYNC_MAIL_CHANGE_TYPE_EXPUNGE) {
		/* already expunged, this change doesn't matter */
		return FALSE;
	} else {
		/* another flag update */
	}
	*change_r = change;
	return TRUE;
}

static void
log_add_expunge(struct dsync_transaction_log_scan *ctx, const void *data,
		const struct mail_transaction_header *hdr)
{
	const struct mail_transaction_expunge *rec = data, *end;
	struct dsync_mail_change *change;
	uint32_t uid;

	if ((hdr->type & MAIL_TRANSACTION_EXTERNAL) == 0) {
		/* this is simply a request for expunge */
		return;
	}
	end = CONST_PTR_OFFSET(data, hdr->size);
	for (; rec != end; rec++) {
		for (uid = rec->uid1; uid <= rec->uid2; uid++) {
			export_change_get(ctx, uid,
					  DSYNC_MAIL_CHANGE_TYPE_EXPUNGE,
					  &change);
		}
	}
}

static bool
log_add_expunge_uid(struct dsync_transaction_log_scan *ctx, const void *data,
		    const struct mail_transaction_header *hdr, uint32_t uid)
{
	const struct mail_transaction_expunge *rec = data, *end;
	struct dsync_mail_change *change;

	if ((hdr->type & MAIL_TRANSACTION_EXTERNAL) == 0) {
		/* this is simply a request for expunge */
		return FALSE;
	}
	end = CONST_PTR_OFFSET(data, hdr->size);
	for (; rec != end; rec++) {
		if (uid >= rec->uid1 && uid <= rec->uid2) {
			export_change_get(ctx, uid,
					  DSYNC_MAIL_CHANGE_TYPE_EXPUNGE,
					  &change);
			return TRUE;
		}
	}
	return FALSE;
}

static void
log_add_expunge_guid(struct dsync_transaction_log_scan *ctx,
		     struct mail_index_view *view, const void *data,
		     const struct mail_transaction_header *hdr)
{
	const struct mail_transaction_expunge_guid *rec = data, *end;
	struct dsync_mail_change *change;
	uint32_t seq;
	bool external;

	external = (hdr->type & MAIL_TRANSACTION_EXTERNAL) != 0;

	end = CONST_PTR_OFFSET(data, hdr->size);
	for (; rec != end; rec++) {
		if (!external && mail_index_lookup_seq(view, rec->uid, &seq)) {
			/* expunge request that hasn't been actually done yet.
			   we check non-external ones because they might have
			   the GUID while external ones don't. */
			continue;
		}
		if (export_change_get(ctx, rec->uid,
				      DSYNC_MAIL_CHANGE_TYPE_EXPUNGE,
				      &change) &&
		    !guid_128_is_empty(rec->guid_128)) T_BEGIN {
			change->guid = p_strdup(ctx->pool,
				guid_128_to_string(rec->guid_128));
		} T_END;
	}
}

static bool
log_add_expunge_guid_uid(struct dsync_transaction_log_scan *ctx, const void *data,
			 const struct mail_transaction_header *hdr, uint32_t uid)
{
	const struct mail_transaction_expunge_guid *rec = data, *end;
	struct dsync_mail_change *change;

	/* we're assuming UID is already known to be expunged */
	end = CONST_PTR_OFFSET(data, hdr->size);
	for (; rec != end; rec++) {
		if (rec->uid != uid)
			continue;

		if (!export_change_get(ctx, rec->uid,
				       DSYNC_MAIL_CHANGE_TYPE_EXPUNGE,
				       &change))
			i_unreached();
		if (!guid_128_is_empty(rec->guid_128)) T_BEGIN {
			change->guid = p_strdup(ctx->pool,
						guid_128_to_string(rec->guid_128));
		} T_END;
		return TRUE;
	}
	return FALSE;
}

static void
log_add_flag_update(struct dsync_transaction_log_scan *ctx, const void *data,
		    const struct mail_transaction_header *hdr)
{
	const struct mail_transaction_flag_update *rec = data, *end;
	struct dsync_mail_change *change;
	uint32_t uid;

	end = CONST_PTR_OFFSET(data, hdr->size);
	for (; rec != end; rec++) {
		for (uid = rec->uid1; uid <= rec->uid2; uid++) {
			if (export_change_get(ctx, uid,
					DSYNC_MAIL_CHANGE_TYPE_FLAG_CHANGE,
					&change)) {
				change->add_flags |= rec->add_flags;
				change->remove_flags &= ~rec->add_flags;
				change->remove_flags |= rec->remove_flags;
				change->add_flags &= ~rec->remove_flags;
			}
		}
	}
}

static void
log_add_keyword_reset(struct dsync_transaction_log_scan *ctx, const void *data,
		      const struct mail_transaction_header *hdr)
{
	const struct mail_transaction_keyword_reset *rec = data, *end;
	struct dsync_mail_change *change;
	uint32_t uid;

	end = CONST_PTR_OFFSET(data, hdr->size);
	for (; rec != end; rec++) {
		for (uid = rec->uid1; uid <= rec->uid2; uid++) {
			if (!export_change_get(ctx, uid,
					DSYNC_MAIL_CHANGE_TYPE_FLAG_CHANGE,
					&change))
				continue;

			change->keywords_reset = TRUE;
			if (array_is_created(&change->keyword_changes))
				array_clear(&change->keyword_changes);
		}
	}
}

static void
keywords_change_remove(struct dsync_mail_change *change, const char *name)
{
	const char *const *changes;
	unsigned int i, count;

	changes = array_get(&change->keyword_changes, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(changes[i]+1, name) == 0) {
			array_delete(&change->keyword_changes, i, 1);
			break;
		}
	}
}

static void
log_add_keyword_update(struct dsync_transaction_log_scan *ctx, const void *data,
		       const struct mail_transaction_header *hdr)
{
	const struct mail_transaction_keyword_update *rec = data;
	struct dsync_mail_change *change;
	const char *kw_name, *change_str;
	const uint32_t *uids, *end;
	unsigned int uids_offset;
	uint32_t uid;

	uids_offset = sizeof(*rec) + rec->name_size;
	if ((uids_offset % 4) != 0)
		uids_offset += 4 - (uids_offset % 4);

	kw_name = t_strndup((const void *)(rec+1), rec->name_size);
	switch (rec->modify_type) {
	case MODIFY_ADD:
		change_str = p_strdup_printf(ctx->pool, "%c%s",
					     KEYWORD_CHANGE_ADD, kw_name);
		break;
	case MODIFY_REMOVE:
		change_str = p_strdup_printf(ctx->pool, "%c%s",
					     KEYWORD_CHANGE_REMOVE, kw_name);
		break;
	default:
		i_unreached();
	}

	uids = CONST_PTR_OFFSET(rec, uids_offset);
	end = CONST_PTR_OFFSET(rec, hdr->size);

	for (; uids < end; uids += 2) {
		for (uid = uids[0]; uid <= uids[1]; uid++) {
			if (!export_change_get(ctx, uid,
					DSYNC_MAIL_CHANGE_TYPE_FLAG_CHANGE,
					&change))
				continue;
			if (!array_is_created(&change->keyword_changes)) {
				p_array_init(&change->keyword_changes,
					     ctx->pool, 4);
			} else {
				keywords_change_remove(change, kw_name);
			}
			array_push_back(&change->keyword_changes, &change_str);
		}
	}
}

static void
log_add_modseq_update(struct dsync_transaction_log_scan *ctx, const void *data,
		      const struct mail_transaction_header *hdr, bool pvt_scan)
{
	const struct mail_transaction_modseq_update *rec = data, *end;
	struct dsync_mail_change *change;
	uint64_t modseq;

	/* update message's modseq, possibly by creating an empty flag change */
	end = CONST_PTR_OFFSET(rec, hdr->size);
	for (; rec != end; rec++) {
		if (rec->uid == 0) {
			/* highestmodseq update */
			continue;
		}

		if (!export_change_get(ctx, rec->uid,
				       DSYNC_MAIL_CHANGE_TYPE_FLAG_CHANGE,
				       &change))
			continue;

		modseq = rec->modseq_low32 |
			((uint64_t)rec->modseq_high32 << 32);
		if (!pvt_scan) {
			if (change->modseq < modseq)
				change->modseq = modseq;
		} else {
			if (change->pvt_modseq < modseq)
				change->pvt_modseq = modseq;
		}
	}
}

static void
log_add_attribute_update_key(struct dsync_transaction_log_scan *ctx,
			     const char *attr_change, uint64_t modseq)
{
	struct dsync_mailbox_attribute lookup_attr, *attr;

	i_assert(strlen(attr_change) > 2); /* checked by lib-index */

	lookup_attr.type = attr_change[1] == 'p' ?
		MAIL_ATTRIBUTE_TYPE_PRIVATE : MAIL_ATTRIBUTE_TYPE_SHARED;
	lookup_attr.key = attr_change+2;

	attr = hash_table_lookup(ctx->attr_changes, &lookup_attr);
	if (attr == NULL) {
		attr = p_new(ctx->pool, struct dsync_mailbox_attribute, 1);
		attr->type = lookup_attr.type;
		attr->key = p_strdup(ctx->pool, lookup_attr.key);
		hash_table_insert(ctx->attr_changes, attr, attr);
	}
	attr->deleted = attr_change[0] == '-';
	attr->modseq = modseq;
}

static void
log_add_attribute_update(struct dsync_transaction_log_scan *ctx,
			 const void *data,
			 const struct mail_transaction_header *hdr,
			 uint64_t modseq)
{
	const char *attr_changes = data;
	unsigned int i;

	for (i = 0; i < hdr->size && attr_changes[i] != '\0'; ) {
		log_add_attribute_update_key(ctx, attr_changes+i, modseq);
		i += strlen(attr_changes+i) + 1;
	}
}

static int
dsync_log_set(struct dsync_transaction_log_scan *ctx,
	      struct mail_index_view *view, bool pvt_scan,
	      struct mail_transaction_log_view *log_view, uint64_t modseq)
{
	uint32_t log_seq, end_seq;
	uoff_t log_offset, end_offset;
	const char *reason;
	bool reset;
	int ret;

	end_seq = view->log_file_head_seq;
	end_offset = view->log_file_head_offset;

	if (modseq != 0 &&
	    mail_index_modseq_get_next_log_offset(view, modseq,
						  &log_seq, &log_offset)) {
		/* scan the view only up to end of the current view.
		   if there are more changes, we don't care about them until
		   the next sync. */
		ret = mail_transaction_log_view_set(log_view,
						    log_seq, log_offset,
						    end_seq, end_offset,
						    &reset, &reason);
		if (ret != 0)
			return ret;
	}

	/* return everything we've got (until the end of the view) */
	if (!pvt_scan)
		ctx->returned_all_changes = TRUE;
	if (mail_transaction_log_view_set_all(log_view) < 0)
		return -1;

	mail_transaction_log_view_get_prev_pos(log_view, &log_seq, &log_offset);
	if (log_seq > end_seq ||
	    (log_seq == end_seq && log_offset > end_offset)) {
		end_seq = log_seq;
		end_offset = log_offset;
	}
	ret = mail_transaction_log_view_set(log_view,
					    log_seq, log_offset,
					    end_seq, end_offset,
					    &reset, &reason);
	if (ret == 0) {
		/* we shouldn't get here. _view_set_all() already
		   reserved all the log files, the _view_set() only
		   removed unwanted ones. */
		i_error("%s: Couldn't set transaction log view (seq %u..%u): %s",
			view->index->filepath, log_seq, end_seq, reason);
		ret = -1;
	}
	if (ret < 0)
		return -1;
	if (modseq != 0) {
		/* we didn't see all the changes that we wanted to */
		return 0;
	}
	return 1;
}

static int
dsync_log_scan(struct dsync_transaction_log_scan *ctx,
	       struct mail_index_view *view, uint64_t modseq, bool pvt_scan)
{
	struct mail_transaction_log_view *log_view;
	const struct mail_transaction_header *hdr;
	const void *data;
	uint32_t file_seq, max_seq;
	uoff_t file_offset, max_offset;
	uint64_t cur_modseq;
	int ret;

	log_view = mail_transaction_log_view_open(view->index->log);
	if ((ret = dsync_log_set(ctx, view, pvt_scan, log_view, modseq)) < 0) {
		mail_transaction_log_view_close(&log_view);
		return -1;
	}

	/* read the log only up to current position in view */
	max_seq = view->log_file_expunge_seq;
	max_offset = view->log_file_expunge_offset;

	mail_transaction_log_view_get_prev_pos(log_view, &file_seq,
					       &file_offset);

	while (mail_transaction_log_view_next(log_view, &hdr, &data) > 0) {
		mail_transaction_log_view_get_prev_pos(log_view, &file_seq,
						       &file_offset);
		if (file_offset >= max_offset && file_seq == max_seq)
			break;

		if ((hdr->type & MAIL_TRANSACTION_SYNC) != 0) {
			/* ignore changes done by dsync, unless we can get
			   expunged message's GUID from it */
			if ((hdr->type & MAIL_TRANSACTION_TYPE_MASK) !=
			    MAIL_TRANSACTION_EXPUNGE_GUID)
				continue;
		}

		switch (hdr->type & MAIL_TRANSACTION_TYPE_MASK) {
		case MAIL_TRANSACTION_EXPUNGE:
			if (!pvt_scan)
				log_add_expunge(ctx, data, hdr);
			break;
		case MAIL_TRANSACTION_EXPUNGE_GUID:
			if (!pvt_scan)
				log_add_expunge_guid(ctx, view, data, hdr);
			break;
		case MAIL_TRANSACTION_FLAG_UPDATE:
			log_add_flag_update(ctx, data, hdr);
			break;
		case MAIL_TRANSACTION_KEYWORD_RESET:
			log_add_keyword_reset(ctx, data, hdr);
			break;
		case MAIL_TRANSACTION_KEYWORD_UPDATE:
			T_BEGIN {
				log_add_keyword_update(ctx, data, hdr);
			} T_END;
			break;
		case MAIL_TRANSACTION_MODSEQ_UPDATE:
			log_add_modseq_update(ctx, data, hdr, pvt_scan);
			break;
		case MAIL_TRANSACTION_ATTRIBUTE_UPDATE:
			cur_modseq = mail_transaction_log_view_get_prev_modseq(log_view);
			log_add_attribute_update(ctx, data, hdr, cur_modseq);
			break;
		}
	}

	if (!pvt_scan) {
		ctx->last_log_seq = file_seq;
		ctx->last_log_offset = file_offset;
	}
	mail_transaction_log_view_close(&log_view);
	return ret;
}

static int
dsync_mailbox_attribute_cmp(const struct dsync_mailbox_attribute *attr1,
			    const struct dsync_mailbox_attribute *attr2)
{
	if (attr1->type < attr2->type)
		return -1;
	if (attr1->type > attr2->type)
		return 1;
	return strcmp(attr1->key, attr2->key);
}

static unsigned int
dsync_mailbox_attribute_hash(const struct dsync_mailbox_attribute *attr)
{
	return str_hash(attr->key) ^ attr->type;
}

int dsync_transaction_log_scan_init(struct mail_index_view *view,
				    struct mail_index_view *pvt_view,
				    uint32_t highest_wanted_uid,
				    uint64_t modseq, uint64_t pvt_modseq,
				    struct dsync_transaction_log_scan **scan_r,
				    bool *pvt_too_old_r)
{
	struct dsync_transaction_log_scan *ctx;
	pool_t pool;
	int ret, ret2;

	*pvt_too_old_r = FALSE;

	pool = pool_alloconly_create(MEMPOOL_GROWING"dsync transaction log scan",
				     10240);
	ctx = p_new(pool, struct dsync_transaction_log_scan, 1);
	ctx->pool = pool;
	hash_table_create_direct(&ctx->changes, pool, 0);
	hash_table_create(&ctx->attr_changes, pool, 0,
			  dsync_mailbox_attribute_hash,
			  dsync_mailbox_attribute_cmp);
	ctx->view = view;
	ctx->highest_wanted_uid = highest_wanted_uid;

	if ((ret = dsync_log_scan(ctx, view, modseq, FALSE)) < 0)
		return -1;
	if (pvt_view != NULL) {
		if ((ret2 = dsync_log_scan(ctx, pvt_view, pvt_modseq, TRUE)) < 0)
			return -1;
		if (ret2 == 0) {
			ret = 0;
			*pvt_too_old_r = TRUE;
		}
	}

	*scan_r = ctx;
	return ret;
}

HASH_TABLE_TYPE(dsync_uid_mail_change)
dsync_transaction_log_scan_get_hash(struct dsync_transaction_log_scan *scan)
{
	return scan->changes;
}

HASH_TABLE_TYPE(dsync_attr_change)
dsync_transaction_log_scan_get_attr_hash(struct dsync_transaction_log_scan *scan)
{
	return scan->attr_changes;
}

bool
dsync_transaction_log_scan_has_all_changes(struct dsync_transaction_log_scan *scan)
{
	return scan->returned_all_changes;
}

struct dsync_mail_change *
dsync_transaction_log_scan_find_new_expunge(struct dsync_transaction_log_scan *scan,
					    uint32_t uid)
{
	struct mail_transaction_log_view *log_view;
	const struct mail_transaction_header *hdr;
	const void *data;
	const char *reason;
	bool reset, found = FALSE;

	i_assert(uid > 0);

	if (scan->highest_wanted_uid < uid)
		scan->highest_wanted_uid = uid;

	log_view = mail_transaction_log_view_open(scan->view->index->log);
	if (mail_transaction_log_view_set(log_view,
					  scan->last_log_seq,
					  scan->last_log_offset,
					  (uint32_t)-1, (uoff_t)-1,
					  &reset, &reason) > 0) {
		while (!found &&
		       mail_transaction_log_view_next(log_view, &hdr, &data) > 0) {
			switch (hdr->type & MAIL_TRANSACTION_TYPE_MASK) {
			case MAIL_TRANSACTION_EXPUNGE:
				if (log_add_expunge_uid(scan, data, hdr, uid))
					found = TRUE;
				break;
			case MAIL_TRANSACTION_EXPUNGE_GUID:
				if (log_add_expunge_guid_uid(scan, data, hdr, uid))
					found = TRUE;
				break;
			}
		}
	}
	mail_transaction_log_view_close(&log_view);

	return !found ? NULL :
		hash_table_lookup(scan->changes, POINTER_CAST(uid));
}

void dsync_transaction_log_scan_deinit(struct dsync_transaction_log_scan **_scan)
{
	struct dsync_transaction_log_scan *scan = *_scan;

	*_scan = NULL;

	hash_table_destroy(&scan->changes);
	hash_table_destroy(&scan->attr_changes);
	pool_unref(&scan->pool);
}
