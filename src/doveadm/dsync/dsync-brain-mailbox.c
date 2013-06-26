/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

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
ns_mailbox_try_alloc(struct mail_namespace *ns, const guid_128_t guid,
		     struct mailbox **box_r)
{
	struct mailbox *box;
	enum mailbox_existence existence;
	int ret;

	box = mailbox_alloc_guid(ns->list, guid, 0);
	ret = mailbox_exists(box, FALSE, &existence);
	if (ret < 0) {
		mailbox_free(&box);
		return -1;
	}
	if (existence != MAILBOX_EXISTENCE_SELECT) {
		mailbox_free(&box);
		return 0;
	}
	*box_r = box;
	return 1;
}

int dsync_brain_mailbox_alloc(struct dsync_brain *brain, const guid_128_t guid,
			      struct mailbox **box_r)
{
	struct mail_namespace *ns;
	int ret;

	*box_r = NULL;
	if (brain->sync_ns != NULL) {
		ret = ns_mailbox_try_alloc(brain->sync_ns, guid, box_r);
		if (ret < 0)
			brain->failed = TRUE;
		return ret;
	}

	for (ns = brain->user->namespaces; ns != NULL; ns = ns->next) {
		if (!dsync_brain_want_namespace(brain, ns))
			continue;
		if ((ret = ns_mailbox_try_alloc(ns, guid, box_r)) != 0) {
			if (ret < 0)
				brain->failed = TRUE;
			return ret;
		}
	}
	return 0;
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
			      const struct dsync_mailbox *local_dsync_box,
			      bool wait_for_remote_box)
{
	const struct dsync_mailbox_state *state;

	i_assert(brain->box_importer == NULL);
	i_assert(brain->box_exporter == NULL);
	i_assert(box->synced);

	brain->box = box;
	brain->pre_box_state = brain->state;
	if (wait_for_remote_box) {
		brain->box_send_state = DSYNC_BOX_STATE_MAILBOX;
		brain->box_recv_state = DSYNC_BOX_STATE_MAILBOX;
	} else {
		dsync_brain_sync_init_box_states(brain);
	}
	brain->local_dsync_box = *local_dsync_box;
	memset(&brain->remote_dsync_box, 0, sizeof(brain->remote_dsync_box));

	state = dsync_mailbox_state_find(brain, local_dsync_box->mailbox_guid);
	if (state != NULL)
		brain->mailbox_state = *state;
	else {
		memset(&brain->mailbox_state, 0, sizeof(brain->mailbox_state));
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

	brain->box_importer = brain->backup_send ? NULL :
		dsync_mailbox_import_init(brain->box, brain->log_scan,
					  last_common_uid, last_common_modseq,
					  last_common_pvt_modseq,
					  remote_dsync_box->uid_next,
					  remote_dsync_box->first_recent_uid,
					  remote_dsync_box->highest_modseq,
					  remote_dsync_box->highest_pvt_modseq,
					  import_flags);
}

int dsync_brain_sync_mailbox_open(struct dsync_brain *brain,
				  const struct dsync_mailbox *remote_dsync_box)
{
	enum dsync_mailbox_exporter_flags exporter_flags = 0;
	uint32_t last_common_uid, highest_wanted_uid;
	uint64_t last_common_modseq, last_common_pvt_modseq;

	i_assert(brain->log_scan == NULL);
	i_assert(brain->box_exporter == NULL);

	last_common_uid = brain->mailbox_state.last_common_uid;
	last_common_modseq = brain->mailbox_state.last_common_modseq;
	last_common_pvt_modseq = brain->mailbox_state.last_common_pvt_modseq;
	highest_wanted_uid = last_common_uid == 0 ?
		(uint32_t)-1 : last_common_uid;
	if (dsync_transaction_log_scan_init(brain->box->view,
					    brain->box->view_pvt,
					    highest_wanted_uid,
					    last_common_modseq,
					    last_common_pvt_modseq,
					    &brain->log_scan) < 0) {
		i_error("Failed to read transaction log for mailbox %s",
			mailbox_get_vname(brain->box));
		brain->failed = TRUE;
		return -1;
	}

	if (!brain->mail_requests)
		exporter_flags |= DSYNC_MAILBOX_EXPORTER_FLAG_AUTO_EXPORT_MAILS;
	if (remote_dsync_box->have_save_guids &&
	    (brain->local_dsync_box.have_save_guids ||
	     (brain->backup_send && brain->local_dsync_box.have_guids)))
		exporter_flags |= DSYNC_MAILBOX_EXPORTER_FLAG_MAILS_HAVE_GUIDS;

	brain->box_exporter = brain->backup_recv ? NULL :
		dsync_mailbox_export_init(brain->box, brain->log_scan,
					  last_common_uid,
					  exporter_flags);
	dsync_brain_sync_mailbox_init_remote(brain, remote_dsync_box);
	return 0;
}

void dsync_brain_sync_mailbox_deinit(struct dsync_brain *brain)
{
	i_assert(brain->box != NULL);

	array_append(&brain->remote_mailbox_states, &brain->mailbox_state, 1);
	if (brain->box_exporter != NULL) {
		const char *error;

		i_assert(brain->failed ||
			 brain->sync_type == DSYNC_BRAIN_SYNC_TYPE_CHANGED);
		(void)dsync_mailbox_export_deinit(&brain->box_exporter, &error);
	}
	if (brain->box_importer != NULL) {
		uint32_t last_common_uid;
		uint64_t last_common_modseq, last_common_pvt_modseq;
		bool changes_during_sync;

		i_assert(brain->failed);
		(void)dsync_mailbox_import_deinit(&brain->box_importer,
						  FALSE,
						  &last_common_uid,
						  &last_common_modseq,
						  &last_common_pvt_modseq,
						  &changes_during_sync);
	}
	if (brain->log_scan != NULL)
		dsync_transaction_log_scan_deinit(&brain->log_scan);
	mailbox_free(&brain->box);

	brain->state = brain->pre_box_state;
}

static int dsync_box_get(struct mailbox *box, struct dsync_mailbox *dsync_box_r)
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
		errstr = mailbox_get_last_error(box, &error);
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
		return -1;
	}

	i_assert(status.uidvalidity != 0 || status.messages == 0);

	memset(dsync_box_r, 0, sizeof(*dsync_box_r));
	memcpy(dsync_box_r->mailbox_guid, metadata.guid,
	       sizeof(dsync_box_r->mailbox_guid));
	dsync_box_r->uid_validity = status.uidvalidity;
	dsync_box_r->uid_next = status.uidnext;
	dsync_box_r->messages_count = status.messages;
	dsync_box_r->first_recent_uid = status.first_recent_uid;
	dsync_box_r->highest_modseq = status.highest_modseq;
	dsync_box_r->highest_pvt_modseq = status.highest_pvt_modseq;
	dsync_box_r->cache_fields = *metadata.cache_fields;
	dsync_box_r->have_guids = status.have_guids;
	dsync_box_r->have_save_guids = status.have_save_guids;
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
		state->last_common_pvt_modseq != dsync_box->highest_pvt_modseq;
}

static int
dsync_brain_try_next_mailbox(struct dsync_brain *brain, struct mailbox **box_r,
			     struct dsync_mailbox *dsync_box_r)
{
	enum mailbox_flags flags = 0;
	struct dsync_mailbox dsync_box;
	struct mailbox *box;
	struct dsync_mailbox_node *node;
	const char *vname = NULL;
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
		if ((ret = dsync_box_get(box, &dsync_box)) <= 0) {
			if (ret < 0)
				brain->failed = TRUE;
			mailbox_free(&box);
			return ret;
		}

		/* if mailbox's last_common_* state equals the current state,
		   we can skip the mailbox */
		if (!dsync_brain_has_mailbox_state_changed(brain, &dsync_box)) {
			mailbox_free(&box);
			return 0;
		}
		if (synced) {
			/* ok, the mailbox really changed */
			break;
		}

		/* mailbox appears to have changed. do a full sync here and get the
		   state again */
		if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FULL_READ) < 0) {
			i_error("Can't sync mailbox %s: %s",
				mailbox_get_vname(box),
				mailbox_get_last_error(box, NULL));
			brain->failed = TRUE;
			mailbox_free(&box);
			return -1;
		}
		synced = TRUE;
	}

	*box_r = box;
	*dsync_box_r = dsync_box;
	return 1;
}

static bool
dsync_brain_next_mailbox(struct dsync_brain *brain, struct mailbox **box_r,
			 struct dsync_mailbox *dsync_box_r)
{
	int ret;

	if (brain->no_mail_sync)
		return FALSE;

	while ((ret = dsync_brain_try_next_mailbox(brain, box_r, dsync_box_r)) == 0)
		;
	return ret > 0;
}

void dsync_brain_master_send_mailbox(struct dsync_brain *brain)
{
	struct dsync_mailbox dsync_box;
	struct mailbox *box;

	i_assert(brain->master_brain);
	i_assert(brain->box == NULL);

	if (!dsync_brain_next_mailbox(brain, &box, &dsync_box)) {
		brain->state = DSYNC_STATE_DONE;
		dsync_ibc_send_end_of_list(brain->ibc, DSYNC_IBC_EOL_MAILBOX);
		return;
	}

	/* start exporting this mailbox (wait for remote to start importing) */
	dsync_ibc_send_mailbox(brain->ibc, &dsync_box);
	dsync_brain_sync_mailbox_init(brain, box, &dsync_box, TRUE);
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
		update->cache_updates = array_idx(&remote_sorted, 0);
		return;
	}

	/* figure out what to change */
	local_fields = array_get(&local_sorted, &local_count);
	remote_fields = array_get(&remote_sorted, &remote_count);
	t_array_init(&changes, local_count + remote_count);
	drop_older_timestamp = ioloop_time - MAIL_CACHE_FIELD_DROP_SECS;

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
		update->cache_updates = array_idx(&changes, 0);
	}
}

void dsync_brain_mailbox_update_pre(struct dsync_brain *brain,
				    struct mailbox *box,
				    const struct dsync_mailbox *local_box,
				    const struct dsync_mailbox *remote_box)
{
	struct mailbox_update update;
	const struct dsync_mailbox_state *state;

	memset(&update, 0, sizeof(update));

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
			// FIXME: handle this properly
		}
	}

	dsync_cache_fields_update(local_box, remote_box, &update);

	if (update.uid_validity == 0 &&
	    update.cache_updates == NULL) {
		/* no changes */
		return;
	}

	if (mailbox_update(box, &update) < 0) {
		i_error("Couldn't update mailbox %s metadata: %s",
			mailbox_get_vname(box),
			mailbox_get_last_error(box, NULL));
		brain->failed = TRUE;
	}
}

static void
dsync_brain_slave_send_mailbox_lost(struct dsync_brain *brain,
				    const struct dsync_mailbox *dsync_box)
{
	struct dsync_mailbox delete_box;

	if (brain->debug) {
		i_debug("brain %c: We don't have mailbox %s",
			brain->master_brain ? 'M' : 'S',
			guid_128_to_string(dsync_box->mailbox_guid));
	}
	memset(&delete_box, 0, sizeof(delete_box));
	memcpy(delete_box.mailbox_guid, dsync_box->mailbox_guid,
	       sizeof(delete_box.mailbox_guid));
	t_array_init(&delete_box.cache_fields, 0);
	delete_box.mailbox_lost = TRUE;
	dsync_ibc_send_mailbox(brain->ibc, &delete_box);
}

bool dsync_brain_slave_recv_mailbox(struct dsync_brain *brain)
{
	const struct dsync_mailbox *dsync_box;
	struct dsync_mailbox local_dsync_box;
	struct mailbox *box;
	int ret;

	i_assert(!brain->master_brain);
	i_assert(brain->box == NULL);

	if ((ret = dsync_ibc_recv_mailbox(brain->ibc, &dsync_box)) == 0)
		return FALSE;
	if (ret < 0) {
		brain->state = DSYNC_STATE_DONE;
		return TRUE;
	}

	if (dsync_brain_mailbox_alloc(brain, dsync_box->mailbox_guid, &box) < 0) {
		i_assert(brain->failed);
		return TRUE;
	}
	if (box == NULL) {
		/* mailbox was probably deleted/renamed during sync */
		//FIXME: verify this from log, and if not log an error.
		brain->changes_during_sync = TRUE;
		dsync_brain_slave_send_mailbox_lost(brain, dsync_box);
		return TRUE;
	}
	if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FULL_READ) < 0) {
		i_error("Can't sync mailbox %s: %s",
			mailbox_get_vname(box),
			mailbox_get_last_error(box, NULL));
		mailbox_free(&box);
		brain->failed = TRUE;
		return TRUE;
	}

	if ((ret = dsync_box_get(box, &local_dsync_box)) <= 0) {
		mailbox_free(&box);
		if (ret < 0) {
			brain->failed = TRUE;
			return TRUE;
		}
		/* another process just deleted this mailbox? */
		dsync_brain_slave_send_mailbox_lost(brain, dsync_box);
		return TRUE;
	}
	i_assert(local_dsync_box.uid_validity != 0);
	i_assert(memcmp(dsync_box->mailbox_guid, local_dsync_box.mailbox_guid,
			sizeof(dsync_box->mailbox_guid)) == 0);
	dsync_ibc_send_mailbox(brain->ibc, &local_dsync_box);

	dsync_brain_mailbox_update_pre(brain, box, &local_dsync_box, dsync_box);

	if (!dsync_boxes_need_sync(brain, &local_dsync_box, dsync_box)) {
		/* no fields appear to have changed, skip this mailbox */
		mailbox_free(&box);
		return TRUE;
	}

	/* start export/import */
	dsync_brain_sync_mailbox_init(brain, box, &local_dsync_box, FALSE);
	if (dsync_brain_sync_mailbox_open(brain, dsync_box) < 0)
		return TRUE;

	brain->state = DSYNC_STATE_SYNC_MAILS;
	return TRUE;
}
