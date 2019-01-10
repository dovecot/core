/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "mail-cache-private.h"
#include "mail-namespace.h"
#include "mail-storage-private.h"
#include "dsync-ibc.h"
#include "dsync-mailbox-tree.h"
#include "dsync-mailbox-import.h"
#include "dsync-mailbox-export.h"
#include "dsync-transaction-log-scan.h"
#include "dsync-brain-private.h"

static int
ns_mailbox_try_alloc(struct dsync_brain *brain, struct mail_namespace *ns,
		     const guid_128_t guid, struct mailbox **box_r,
		     const char **errstr_r, enum mail_error *error_r)
{
	enum mailbox_flags flags = 0;
	struct mailbox *box;
	enum mailbox_existence existence;
	int ret;

	if (brain->backup_send) {
		/* make sure mailbox isn't modified */
		flags |= MAILBOX_FLAG_READONLY;
	}

	box = mailbox_alloc_guid(ns->list, guid, flags);
	ret = mailbox_exists(box, FALSE, &existence);
	if (ret < 0) {
		*errstr_r = mailbox_get_last_internal_error(box, error_r);
		mailbox_free(&box);
		return -1;
	}
	if (existence != MAILBOX_EXISTENCE_SELECT) {
		mailbox_free(&box);
		*errstr_r = existence == MAILBOX_EXISTENCE_NONE ?
			"Mailbox was already deleted" :
			"Mailbox is no longer selectable";
		return 0;
	}
	*box_r = box;
	return 1;
}

int dsync_brain_mailbox_alloc(struct dsync_brain *brain, const guid_128_t guid,
			      struct mailbox **box_r, const char **errstr_r,
			      enum mail_error *error_r)
{
	struct mail_namespace *ns;
	int ret;

	*box_r = NULL;

	for (ns = brain->user->namespaces; ns != NULL; ns = ns->next) {
		if (!dsync_brain_want_namespace(brain, ns))
			continue;
		if ((ret = ns_mailbox_try_alloc(brain, ns, guid, box_r,
						errstr_r, error_r)) != 0)
			return ret;
	}
	return 0;
}

static void
dsync_mailbox_cache_field_dup(ARRAY_TYPE(mailbox_cache_field) *dest,
			      const ARRAY_TYPE(mailbox_cache_field) *src,
			      pool_t pool)
{
	const struct mailbox_cache_field *src_field;
	struct mailbox_cache_field *dest_field;

	p_array_init(dest, pool, array_count(src));
	array_foreach(src, src_field) {
		dest_field = array_append_space(dest);
		dest_field->name = p_strdup(pool, src_field->name);
		dest_field->decision = src_field->decision;
		dest_field->last_used = src_field->last_used;
	}
}


static const struct dsync_mailbox_state *
dsync_mailbox_state_find(struct dsync_brain *brain,
			 const guid_128_t mailbox_guid)
{
	const uint8_t *guid_p;

	guid_p = mailbox_guid;
	return hash_table_lookup(brain->mailbox_states, guid_p);
}

static void
dsync_mailbox_state_remove(struct dsync_brain *brain,
			   const guid_128_t mailbox_guid)
{
	const uint8_t *guid_p;

	guid_p = mailbox_guid;
	if (hash_table_lookup(brain->mailbox_states, guid_p) != NULL)
		hash_table_remove(brain->mailbox_states, guid_p);
}

void dsync_brain_sync_init_box_states(struct dsync_brain *brain)
{
	if (brain->backup_send) {
		/* we have an exporter, but no importer. */
		brain->box_send_state = DSYNC_BOX_STATE_ATTRIBUTES;
		brain->box_recv_state = brain->mail_requests ?
			DSYNC_BOX_STATE_MAIL_REQUESTS :
			DSYNC_BOX_STATE_RECV_LAST_COMMON;
	} else if (brain->backup_recv) {
		/* we have an importer, but no exporter */
		brain->box_send_state = brain->mail_requests ?
			DSYNC_BOX_STATE_MAIL_REQUESTS :
			DSYNC_BOX_STATE_DONE;
		brain->box_recv_state = DSYNC_BOX_STATE_ATTRIBUTES;
	} else {
		brain->box_send_state = DSYNC_BOX_STATE_ATTRIBUTES;
		brain->box_recv_state = DSYNC_BOX_STATE_ATTRIBUTES;
	}
}

static void
dsync_brain_sync_mailbox_init(struct dsync_brain *brain,
			      struct mailbox *box,
			      struct file_lock *lock,
			      const struct dsync_mailbox *local_dsync_box,
			      bool wait_for_remote_box)
{
	const struct dsync_mailbox_state *state;

	i_assert(brain->box_importer == NULL);
	i_assert(brain->box_exporter == NULL);
	i_assert(box->synced);

	brain->box = box;
	brain->box_lock = lock;
	brain->pre_box_state = brain->state;
	if (wait_for_remote_box) {
		brain->box_send_state = DSYNC_BOX_STATE_MAILBOX;
		brain->box_recv_state = DSYNC_BOX_STATE_MAILBOX;
	} else {
		dsync_brain_sync_init_box_states(brain);
	}
	brain->local_dsync_box = *local_dsync_box;
	if (brain->dsync_box_pool != NULL)
		p_clear(brain->dsync_box_pool);
	else {
		brain->dsync_box_pool =
			pool_alloconly_create(MEMPOOL_GROWING"dsync brain box pool", 2048);
	}
	dsync_mailbox_cache_field_dup(&brain->local_dsync_box.cache_fields,
				      &local_dsync_box->cache_fields,
				      brain->dsync_box_pool);
	i_zero(&brain->remote_dsync_box);

	state = dsync_mailbox_state_find(brain, local_dsync_box->mailbox_guid);
	if (state != NULL)
		brain->mailbox_state = *state;
	else {
		i_zero(&brain->mailbox_state);
		memcpy(brain->mailbox_state.mailbox_guid,
		       local_dsync_box->mailbox_guid,
		       sizeof(brain->mailbox_state.mailbox_guid));
		brain->mailbox_state.last_uidvalidity =
			local_dsync_box->uid_validity;
	}
}

static void
dsync_brain_sync_mailbox_init_remote(struct dsync_brain *brain,
				     const struct dsync_mailbox *remote_dsync_box)
{
	enum dsync_mailbox_import_flags import_flags = 0;
	const struct dsync_mailbox_state *state;
	uint32_t last_common_uid;
	uint64_t last_common_modseq, last_common_pvt_modseq;

	i_assert(brain->box_importer == NULL);
	i_assert(brain->log_scan != NULL);

	i_assert(memcmp(brain->local_dsync_box.mailbox_guid,
			remote_dsync_box->mailbox_guid,
			sizeof(remote_dsync_box->mailbox_guid)) == 0);

	brain->remote_dsync_box = *remote_dsync_box;
	dsync_mailbox_cache_field_dup(&brain->remote_dsync_box.cache_fields,
				      &remote_dsync_box->cache_fields,
				      brain->dsync_box_pool);

	state = dsync_mailbox_state_find(brain, remote_dsync_box->mailbox_guid);
	if (state != NULL) {
		last_common_uid = state->last_common_uid;
		last_common_modseq = state->last_common_modseq;
		last_common_pvt_modseq = state->last_common_pvt_modseq;
	} else {
		last_common_uid = 0;
		last_common_modseq = 0;
		last_common_pvt_modseq = 0;
	}

	if (brain->mail_requests)
		import_flags |= DSYNC_MAILBOX_IMPORT_FLAG_WANT_MAIL_REQUESTS;
	if (brain->master_brain)
		import_flags |= DSYNC_MAILBOX_IMPORT_FLAG_MASTER_BRAIN;
	if (brain->backup_recv && !brain->no_backup_overwrite)
		import_flags |= DSYNC_MAILBOX_IMPORT_FLAG_REVERT_LOCAL_CHANGES;
	if (brain->debug)
		import_flags |= DSYNC_MAILBOX_IMPORT_FLAG_DEBUG;
	if (brain->local_dsync_box.have_save_guids &&
	    (remote_dsync_box->have_save_guids ||
	     (brain->backup_recv && remote_dsync_box->have_guids)))
		import_flags |= DSYNC_MAILBOX_IMPORT_FLAG_MAILS_HAVE_GUIDS;
	if (brain->local_dsync_box.have_only_guid128 ||
	    remote_dsync_box->have_only_guid128)
		import_flags |= DSYNC_MAILBOX_IMPORT_FLAG_MAILS_USE_GUID128;
	if (brain->no_notify)
		import_flags |= DSYNC_MAILBOX_IMPORT_FLAG_NO_NOTIFY;
	if (brain->empty_hdr_workaround)
		import_flags |= DSYNC_MAILBOX_IMPORT_FLAG_EMPTY_HDR_WORKAROUND;

	brain->box_importer = brain->backup_send ? NULL :
		dsync_mailbox_import_init(brain->box, brain->virtual_all_box,
					  brain->log_scan,
					  last_common_uid, last_common_modseq,
					  last_common_pvt_modseq,
					  remote_dsync_box->uid_next,
					  remote_dsync_box->first_recent_uid,
					  remote_dsync_box->highest_modseq,
					  remote_dsync_box->highest_pvt_modseq,
					  brain->sync_since_timestamp,
					  brain->sync_until_timestamp,
					  brain->sync_max_size,
					  brain->sync_flag,
					  brain->import_commit_msgs_interval,
					  import_flags, brain->hdr_hash_version,
					  brain->hashed_headers);
}

int dsync_brain_sync_mailbox_open(struct dsync_brain *brain,
				  const struct dsync_mailbox *remote_dsync_box)
{
	struct mailbox_status status;
	enum dsync_mailbox_exporter_flags exporter_flags = 0;
	uint32_t last_common_uid, highest_wanted_uid;
	uint64_t last_common_modseq, last_common_pvt_modseq;
	const char *desync_reason = "";
	bool pvt_too_old;
	int ret;

	i_assert(brain->log_scan == NULL);
	i_assert(brain->box_exporter == NULL);

	last_common_uid = brain->mailbox_state.last_common_uid;
	last_common_modseq = brain->mailbox_state.last_common_modseq;
	last_common_pvt_modseq = brain->mailbox_state.last_common_pvt_modseq;
	highest_wanted_uid = last_common_uid == 0 ?
		(uint32_t)-1 : last_common_uid;
	ret = dsync_transaction_log_scan_init(brain->box->view,
					      brain->box->view_pvt,
					      highest_wanted_uid,
					      last_common_modseq,
					      last_common_pvt_modseq,
					      &brain->log_scan, &pvt_too_old);
	if (ret < 0) {
		i_error("Failed to read transaction log for mailbox %s",
			mailbox_get_vname(brain->box));
		brain->failed = TRUE;
		return -1;
	}

	mailbox_get_open_status(brain->box, STATUS_UIDNEXT |
				STATUS_HIGHESTMODSEQ |
				STATUS_HIGHESTPVTMODSEQ, &status);
	if (ret == 0) {
		if (pvt_too_old) {
			desync_reason = t_strdup_printf(
				"Private modseq %"PRIu64" no longer in transaction log "
				"(highest=%"PRIu64", last_common_uid=%u, nextuid=%u)",
				last_common_pvt_modseq,
				status.highest_pvt_modseq, last_common_uid,
				status.uidnext);
		} else {
			desync_reason = t_strdup_printf(
				"Modseq %"PRIu64" no longer in transaction log "
				"(highest=%"PRIu64", last_common_uid=%u, nextuid=%u)",
				last_common_modseq,
				status.highest_modseq, last_common_uid,
				status.uidnext);
		}
	}

	if (last_common_uid != 0) {
		/* if last_common_* is higher than our current ones it means
		   that the incremental sync state is stale and we need to do
		   a full resync */
		if (status.uidnext < last_common_uid) {
			desync_reason = t_strdup_printf("uidnext %u < %u",
				status.uidnext, last_common_uid);
			ret = 0;
		} else if (status.highest_modseq < last_common_modseq) {
			desync_reason = t_strdup_printf("highest_modseq %"PRIu64" < %"PRIu64,
				status.highest_modseq, last_common_modseq);
			ret = 0;
		} else if (status.highest_pvt_modseq < last_common_pvt_modseq) {
			desync_reason = t_strdup_printf("highest_pvt_modseq %"PRIu64" < %"PRIu64,
				status.highest_pvt_modseq, last_common_pvt_modseq);
			ret = 0;
		}
	}
	if (ret == 0) {
		i_warning("Failed to do incremental sync for mailbox %s, "
			  "retry with a full sync (%s)",
			  mailbox_get_vname(brain->box), desync_reason);
		dsync_brain_set_changes_during_sync(brain, t_strdup_printf(
			"Incremental sync failed: %s", desync_reason));
		brain->require_full_resync = TRUE;
		return 0;
	}

	if (!brain->mail_requests)
		exporter_flags |= DSYNC_MAILBOX_EXPORTER_FLAG_AUTO_EXPORT_MAILS;
	if (remote_dsync_box->have_save_guids &&
	    (brain->local_dsync_box.have_save_guids ||
	     (brain->backup_send && brain->local_dsync_box.have_guids)))
		exporter_flags |= DSYNC_MAILBOX_EXPORTER_FLAG_MAILS_HAVE_GUIDS;
	if (brain->no_mail_prefetch)
		exporter_flags |= DSYNC_MAILBOX_EXPORTER_FLAG_MINIMAL_DMAIL_FILL;
	if (brain->sync_since_timestamp > 0 ||
	    brain->sync_until_timestamp > 0)
		exporter_flags |= DSYNC_MAILBOX_EXPORTER_FLAG_TIMESTAMPS;
	if (brain->sync_max_size > 0)
		exporter_flags |= DSYNC_MAILBOX_EXPORTER_FLAG_VSIZES;
	if (remote_dsync_box->messages_count == 0) {
		/* remote mailbox is empty - we don't really need to export
		   header hashes since they're not going to match anything
		   anyway. */
		exporter_flags |= DSYNC_MAILBOX_EXPORTER_FLAG_NO_HDR_HASHES;
	}

	brain->box_exporter = brain->backup_recv ? NULL :
		dsync_mailbox_export_init(brain->box, brain->log_scan,
					  last_common_uid,
					  exporter_flags,
					  brain->hdr_hash_version,
					  brain->hashed_headers);
	dsync_brain_sync_mailbox_init_remote(brain, remote_dsync_box);
	return 1;
}

void dsync_brain_sync_mailbox_deinit(struct dsync_brain *brain)
{
	enum mail_error error;

	i_assert(brain->box != NULL);

	array_push_back(&brain->remote_mailbox_states, &brain->mailbox_state);
	if (brain->box_exporter != NULL) {
		const char *errstr;

		i_assert(brain->failed || brain->require_full_resync ||
			 brain->sync_type == DSYNC_BRAIN_SYNC_TYPE_CHANGED);
		if (dsync_mailbox_export_deinit(&brain->box_exporter,
						&errstr, &error) < 0)
			i_error("Mailbox export failed: %s", errstr);
	}
	if (brain->box_importer != NULL) {
		uint32_t last_common_uid, last_messages_count;
		uint64_t last_common_modseq, last_common_pvt_modseq;
		const char *changes_during_sync;
		bool require_full_resync;

		i_assert(brain->failed);
		(void)dsync_mailbox_import_deinit(&brain->box_importer,
						  FALSE,
						  &last_common_uid,
						  &last_common_modseq,
						  &last_common_pvt_modseq,
						  &last_messages_count,
						  &changes_during_sync,
						  &require_full_resync,
						  &brain->mail_error);
		if (require_full_resync)
			brain->require_full_resync = TRUE;
	}
	if (brain->log_scan != NULL)
		dsync_transaction_log_scan_deinit(&brain->log_scan);
	file_lock_free(&brain->box_lock);
	mailbox_free(&brain->box);

	brain->state = brain->pre_box_state;
}

static int dsync_box_get(struct mailbox *box, struct dsync_mailbox *dsync_box_r,
			 enum mail_error *error_r)
{
	const enum mailbox_status_items status_items =
		STATUS_UIDVALIDITY | STATUS_UIDNEXT | STATUS_MESSAGES |
		STATUS_FIRST_RECENT_UID | STATUS_HIGHESTMODSEQ |
		STATUS_HIGHESTPVTMODSEQ;
	const enum mailbox_metadata_items metadata_items =
		MAILBOX_METADATA_CACHE_FIELDS | MAILBOX_METADATA_GUID;
	struct mailbox_status status;
	struct mailbox_metadata metadata;
	const char *errstr;
	enum mail_error error;

	/* get metadata first, since it may autocreate the mailbox */
	if (mailbox_get_metadata(box, metadata_items, &metadata) < 0 ||
	    mailbox_get_status(box, status_items, &status) < 0) {
		errstr = mailbox_get_last_internal_error(box, &error);
		if (error == MAIL_ERROR_NOTFOUND ||
		    error == MAIL_ERROR_NOTPOSSIBLE) {
			/* Mailbox isn't selectable, try the next one. We
			   should have already caught \Noselect mailboxes, but
			   check them anyway here. The NOTPOSSIBLE check is
			   mainly for invalid mbox files. */
			return 0;
		}
		i_error("Failed to access mailbox %s: %s",
			mailbox_get_vname(box), errstr);
		*error_r = error;
		return -1;
	}

	i_assert(status.uidvalidity != 0 || status.messages == 0);

	i_zero(dsync_box_r);
	memcpy(dsync_box_r->mailbox_guid, metadata.guid,
	       sizeof(dsync_box_r->mailbox_guid));
	dsync_box_r->uid_validity = status.uidvalidity;
	dsync_box_r->uid_next = status.uidnext;
	dsync_box_r->messages_count = status.messages;
	dsync_box_r->first_recent_uid = status.first_recent_uid;
	dsync_box_r->highest_modseq = status.highest_modseq;
	dsync_box_r->highest_pvt_modseq = status.highest_pvt_modseq;
	dsync_mailbox_cache_field_dup(&dsync_box_r->cache_fields,
				      metadata.cache_fields,
				      pool_datastack_create());
	dsync_box_r->have_guids = status.have_guids;
	dsync_box_r->have_save_guids = status.have_save_guids;
	dsync_box_r->have_only_guid128 = status.have_only_guid128;
	return 1;
}

static bool
dsync_brain_has_mailbox_state_changed(struct dsync_brain *brain,
				      const struct dsync_mailbox *dsync_box)
{
	const struct dsync_mailbox_state *state;

	if (brain->sync_type != DSYNC_BRAIN_SYNC_TYPE_STATE)
		return TRUE;

	state = dsync_mailbox_state_find(brain, dsync_box->mailbox_guid);
	return state == NULL ||
		state->last_uidvalidity != dsync_box->uid_validity ||
		state->last_common_uid+1 != dsync_box->uid_next ||
		state->last_common_modseq != dsync_box->highest_modseq ||
		state->last_common_pvt_modseq != dsync_box->highest_pvt_modseq ||
		state->last_messages_count != dsync_box->messages_count;
}

static int
dsync_brain_try_next_mailbox(struct dsync_brain *brain, struct mailbox **box_r,
			     struct file_lock **lock_r,
			     struct dsync_mailbox *dsync_box_r)
{
	enum mailbox_flags flags = 0;
	struct dsync_mailbox dsync_box;
	struct mailbox *box;
	struct file_lock *lock = NULL;
	struct dsync_mailbox_node *node;
	const char *vname = NULL;
	enum mail_error error;
	bool synced = FALSE;
	int ret;

	*box_r = NULL;

	while (dsync_mailbox_tree_iter_next(brain->local_tree_iter, &vname, &node)) {
		if (node->existence == DSYNC_MAILBOX_NODE_EXISTS &&
		    !guid_128_is_empty(node->mailbox_guid))
			break;
		vname = NULL;
	}
	if (vname == NULL) {
		/* no more mailboxes */
		dsync_mailbox_tree_iter_deinit(&brain->local_tree_iter);
		return -1;
	}

	if (brain->backup_send) {
		/* make sure mailbox isn't modified */
		flags |= MAILBOX_FLAG_READONLY;
	}
	box = mailbox_alloc(node->ns->list, vname, flags);
	for (;;) {
		if ((ret = dsync_box_get(box, &dsync_box, &error)) <= 0) {
			if (ret < 0) {
				brain->mail_error = error;
				brain->failed = TRUE;
			}
			mailbox_free(&box);
			file_lock_free(&lock);
			return ret;
		}

		/* if mailbox's last_common_* state equals the current state,
		   we can skip the mailbox */
		if (!dsync_brain_has_mailbox_state_changed(brain, &dsync_box)) {
			if (brain->debug) {
				i_debug("brain %c: Skipping mailbox %s with unchanged state "
					"uidvalidity=%u uidnext=%u highestmodseq=%"PRIu64" highestpvtmodseq=%"PRIu64" messages=%u",
					brain->master_brain ? 'M' : 'S',
					guid_128_to_string(dsync_box.mailbox_guid),
					dsync_box.uid_validity,
					dsync_box.uid_next,
					dsync_box.highest_modseq,
					dsync_box.highest_pvt_modseq,
					dsync_box.messages_count);
			}
			mailbox_free(&box);
			file_lock_free(&lock);
			return 0;
		}
		if (synced) {
			/* ok, the mailbox really changed */
			break;
		}

		/* mailbox appears to have changed. do a full sync here and get the
		   state again. Lock before syncing. */
		if (dsync_mailbox_lock(brain, box, &lock) < 0) {
			brain->failed = TRUE;
			mailbox_free(&box);
			return -1;
		}
		if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FULL_READ) < 0) {
			i_error("Can't sync mailbox %s: %s",
				mailbox_get_vname(box),
				mailbox_get_last_internal_error(box, &brain->mail_error));
			brain->failed = TRUE;
			mailbox_free(&box);
			file_lock_free(&lock);
			return -1;
		}
		synced = TRUE;
	}

	*box_r = box;
	*lock_r = lock;
	*dsync_box_r = dsync_box;
	return 1;
}

static bool
dsync_brain_next_mailbox(struct dsync_brain *brain, struct mailbox **box_r,
			 struct file_lock **lock_r,
			 struct dsync_mailbox *dsync_box_r)
{
	int ret;

	if (brain->no_mail_sync)
		return FALSE;

	while ((ret = dsync_brain_try_next_mailbox(brain, box_r, lock_r, dsync_box_r)) == 0)
		;
	return ret > 0;
}

void dsync_brain_master_send_mailbox(struct dsync_brain *brain)
{
	struct dsync_mailbox dsync_box;
	struct mailbox *box;
	struct file_lock *lock;

	i_assert(brain->master_brain);
	i_assert(brain->box == NULL);

	if (!dsync_brain_next_mailbox(brain, &box, &lock, &dsync_box)) {
		brain->state = DSYNC_STATE_FINISH;
		dsync_ibc_send_end_of_list(brain->ibc, DSYNC_IBC_EOL_MAILBOX);
		return;
	}

	/* start exporting this mailbox (wait for remote to start importing) */
	dsync_ibc_send_mailbox(brain->ibc, &dsync_box);
	dsync_brain_sync_mailbox_init(brain, box, lock, &dsync_box, TRUE);
	brain->state = DSYNC_STATE_SYNC_MAILS;
}

bool dsync_boxes_need_sync(struct dsync_brain *brain,
			   const struct dsync_mailbox *box1,
			   const struct dsync_mailbox *box2)
{
	if (brain->no_mail_sync)
		return FALSE;
	if (brain->sync_type != DSYNC_BRAIN_SYNC_TYPE_CHANGED)
		return TRUE;
	return box1->highest_modseq != box2->highest_modseq ||
		box1->highest_pvt_modseq != box2->highest_pvt_modseq ||
		box1->messages_count != box2->messages_count ||
		box1->uid_next != box2->uid_next ||
		box1->uid_validity != box2->uid_validity ||
		box1->first_recent_uid != box2->first_recent_uid;
}

static int
mailbox_cache_field_name_cmp(const struct mailbox_cache_field *f1,
			     const struct mailbox_cache_field *f2)
{
	return strcmp(f1->name, f2->name);
}

static void
dsync_cache_fields_update(const struct dsync_mailbox *local_box,
			  const struct dsync_mailbox *remote_box,
			  struct mailbox *box,
			  struct mailbox_update *update)
{
	ARRAY_TYPE(mailbox_cache_field) local_sorted, remote_sorted, changes;
	const struct mailbox_cache_field *local_fields, *remote_fields;
	unsigned int li, ri, local_count, remote_count;
	time_t drop_older_timestamp;
	int ret;

	if (array_count(&remote_box->cache_fields) == 0) {
		/* remote has no cached fields. there's nothing to update. */
		return;
	}

	t_array_init(&local_sorted, array_count(&local_box->cache_fields));
	t_array_init(&remote_sorted, array_count(&remote_box->cache_fields));
	array_append_array(&local_sorted, &local_box->cache_fields);
	array_append_array(&remote_sorted, &remote_box->cache_fields);
	array_sort(&local_sorted, mailbox_cache_field_name_cmp);
	array_sort(&remote_sorted, mailbox_cache_field_name_cmp);

	if (array_count(&local_sorted) == 0) {
		/* local has no cached fields. set them to same as remote. */
		array_append_zero(&remote_sorted);
		update->cache_updates = array_first(&remote_sorted);
		return;
	}

	/* figure out what to change */
	local_fields = array_get(&local_sorted, &local_count);
	remote_fields = array_get(&remote_sorted, &remote_count);
	t_array_init(&changes, local_count + remote_count);
	drop_older_timestamp = ioloop_time -
		box->index->optimization_set.cache.unaccessed_field_drop_secs;

	for (li = ri = 0; li < local_count || ri < remote_count; ) {
		ret = li == local_count ? 1 :
			ri == remote_count ? -1 :
			strcmp(local_fields[li].name, remote_fields[ri].name);
		if (ret == 0) {
			/* field exists in both local and remote */
			const struct mailbox_cache_field *lf = &local_fields[li];
			const struct mailbox_cache_field *rf = &remote_fields[ri];

			if (lf->last_used > rf->last_used ||
			    (lf->last_used == rf->last_used &&
			     lf->decision > rf->decision)) {
				/* use local decision and timestamp */
			} else {
				array_append(&changes, rf, 1);
			}
			li++; ri++;
		} else if (ret < 0) {
			/* remote field doesn't exist */
			li++;
		} else {
			/* local field doesn't exist */
			if (remote_fields[ri].last_used < drop_older_timestamp) {
				/* field hasn't be used for a long time, remote
				   will probably drop this soon as well */
			} else {
				array_append(&changes, &remote_fields[ri], 1);
			}
			ri++;
		}
	}
	i_assert(li == local_count && ri == remote_count);
	if (array_count(&changes) > 0) {
		array_append_zero(&changes);
		update->cache_updates = array_first(&changes);
	}
}

bool dsync_brain_mailbox_update_pre(struct dsync_brain *brain,
				    struct mailbox *box,
				    const struct dsync_mailbox *local_box,
				    const struct dsync_mailbox *remote_box,
				    const char **reason_r)
{
	struct mailbox_update update;
	const struct dsync_mailbox_state *state;
	bool ret = TRUE;

	*reason_r = NULL;
	i_zero(&update);

	if (local_box->uid_validity != remote_box->uid_validity) {
		/* Keep the UIDVALIDITY for the mailbox that has more
		   messages. If they equal, use the higher UIDVALIDITY. */
		if (remote_box->messages_count > local_box->messages_count ||
		    (remote_box->messages_count == local_box->messages_count &&
		     remote_box->uid_validity > local_box->uid_validity))
			update.uid_validity = remote_box->uid_validity;

		state = dsync_mailbox_state_find(brain, local_box->mailbox_guid);
		if (state != NULL && state->last_common_uid > 0) {
			/* we can't continue syncing this mailbox in this
			   session, because the other side already started
			   sending mailbox changes, but not for all mails. */
			dsync_mailbox_state_remove(brain, local_box->mailbox_guid);
			*reason_r = "UIDVALIDITY changed during a stateful sync, need to restart";
			brain->failed = TRUE;
			ret = FALSE;
		}
	}

	dsync_cache_fields_update(local_box, remote_box, box, &update);

	if (update.uid_validity == 0 &&
	    update.cache_updates == NULL) {
		/* no changes */
		return ret;
	}

	if (mailbox_update(box, &update) < 0) {
		i_error("Couldn't update mailbox %s metadata: %s",
			mailbox_get_vname(box),
			mailbox_get_last_internal_error(box, &brain->mail_error));
		brain->failed = TRUE;
	}
	return ret;
}

static void
dsync_brain_slave_send_mailbox_lost(struct dsync_brain *brain,
				    const struct dsync_mailbox *dsync_box,
				    bool ignore)
{
	struct dsync_mailbox delete_box;

	if (brain->debug) {
		i_debug("brain %c: We don't have mailbox %s",
			brain->master_brain ? 'M' : 'S',
			guid_128_to_string(dsync_box->mailbox_guid));
	}
	i_zero(&delete_box);
	memcpy(delete_box.mailbox_guid, dsync_box->mailbox_guid,
	       sizeof(delete_box.mailbox_guid));
	t_array_init(&delete_box.cache_fields, 0);
	if (ignore)
		delete_box.mailbox_ignore = TRUE;
	else
		delete_box.mailbox_lost = TRUE;
	dsync_ibc_send_mailbox(brain->ibc, &delete_box);
}

bool dsync_brain_slave_recv_mailbox(struct dsync_brain *brain)
{
	const struct dsync_mailbox *dsync_box;
	struct dsync_mailbox local_dsync_box;
	struct mailbox *box;
	struct file_lock *lock;
	const char *errstr, *resync_reason;
	enum mail_error error;
	int ret;
	bool resync;

	i_assert(!brain->master_brain);
	i_assert(brain->box == NULL);

	if ((ret = dsync_ibc_recv_mailbox(brain->ibc, &dsync_box)) == 0)
		return FALSE;
	if (ret < 0) {
		brain->state = DSYNC_STATE_FINISH;
		return TRUE;
	}

	if (dsync_brain_mailbox_alloc(brain, dsync_box->mailbox_guid,
				      &box, &errstr, &error) < 0) {
		i_error("Couldn't allocate mailbox GUID %s: %s",
			guid_128_to_string(dsync_box->mailbox_guid), errstr);
		brain->mail_error = error;
		brain->failed = TRUE;
		return TRUE;
	}
	if (box == NULL) {
		/* mailbox was probably deleted/renamed during sync */
		if (brain->backup_send && brain->no_backup_overwrite) {
			if (brain->debug) {
				i_debug("brain %c: Ignore nonexistent "
					"mailbox GUID %s with -1 sync",
					brain->master_brain ? 'M' : 'S',
					guid_128_to_string(dsync_box->mailbox_guid));
			}
			dsync_brain_slave_send_mailbox_lost(brain, dsync_box, TRUE);
			return TRUE;
		}
		//FIXME: verify this from log, and if not log an error.
		dsync_brain_set_changes_during_sync(brain, t_strdup_printf(
			"Mailbox GUID %s was lost",
			guid_128_to_string(dsync_box->mailbox_guid)));
		dsync_brain_slave_send_mailbox_lost(brain, dsync_box, FALSE);
		return TRUE;
	}
	/* Lock before syncing */
	if (dsync_mailbox_lock(brain, box, &lock) < 0) {
		mailbox_free(&box);
		brain->failed = TRUE;
		return TRUE;
	}
	if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FULL_READ) < 0) {
		i_error("Can't sync mailbox %s: %s",
			mailbox_get_vname(box),
			mailbox_get_last_internal_error(box, &brain->mail_error));
		file_lock_free(&lock);
		mailbox_free(&box);
		brain->failed = TRUE;
		return TRUE;
	}

	if ((ret = dsync_box_get(box, &local_dsync_box, &error)) <= 0) {
		file_lock_free(&lock);
		mailbox_free(&box);
		if (ret < 0) {
			brain->mail_error = error;
			brain->failed = TRUE;
			return TRUE;
		}
		/* another process just deleted this mailbox? */
		if (brain->debug) {
			i_debug("brain %c: Skipping lost mailbox %s",
				brain->master_brain ? 'M' : 'S',
				guid_128_to_string(dsync_box->mailbox_guid));
		}
		dsync_brain_slave_send_mailbox_lost(brain, dsync_box, FALSE);
		return TRUE;
	}
	i_assert(local_dsync_box.uid_validity != 0);
	i_assert(memcmp(dsync_box->mailbox_guid, local_dsync_box.mailbox_guid,
			sizeof(dsync_box->mailbox_guid)) == 0);

	resync = !dsync_brain_mailbox_update_pre(brain, box, &local_dsync_box,
						 dsync_box, &resync_reason);

	if (!dsync_boxes_need_sync(brain, &local_dsync_box, dsync_box)) {
		/* no fields appear to have changed, skip this mailbox */
		if (brain->debug) {
			i_debug("brain %c: Skipping unchanged mailbox %s",
				brain->master_brain ? 'M' : 'S',
				guid_128_to_string(dsync_box->mailbox_guid));
		}
		dsync_ibc_send_mailbox(brain->ibc, &local_dsync_box);
		file_lock_free(&lock);
		mailbox_free(&box);
		return TRUE;
	}

	/* start export/import */
	dsync_brain_sync_mailbox_init(brain, box, lock, &local_dsync_box, FALSE);
	if ((ret = dsync_brain_sync_mailbox_open(brain, dsync_box)) < 0)
		return TRUE;
	if (resync)
		dsync_brain_set_changes_during_sync(brain, resync_reason);
	if (ret == 0 || resync) {
		brain->require_full_resync = TRUE;
		dsync_brain_sync_mailbox_deinit(brain);
		dsync_brain_slave_send_mailbox_lost(brain, dsync_box, FALSE);
		return TRUE;
	}

	dsync_ibc_send_mailbox(brain->ibc, &local_dsync_box);
	brain->state = DSYNC_STATE_SYNC_MAILS;
	return TRUE;
}
