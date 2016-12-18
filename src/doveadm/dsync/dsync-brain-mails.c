/* Copyright (c) 2013-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "dsync-ibc.h"
#include "dsync-mail.h"
#include "dsync-mailbox-import.h"
#include "dsync-mailbox-export.h"
#include "dsync-brain-private.h"

const char *dsync_box_state_names[DSYNC_BOX_STATE_DONE+1] = {
	"mailbox",
	"changes",
	"attributes",
	"mail_requests",
	"mails",
	"recv_last_common",
	"done"
};

static bool dsync_brain_master_sync_recv_mailbox(struct dsync_brain *brain)
{
	const struct dsync_mailbox *dsync_box;
	const char *resync_reason;
	enum dsync_ibc_recv_ret ret;
	bool resync;

	i_assert(brain->master_brain);

	if ((ret = dsync_ibc_recv_mailbox(brain->ibc, &dsync_box)) == 0)
		return FALSE;
	if (ret == DSYNC_IBC_RECV_RET_FINISHED) {
		i_error("Remote sent end-of-list instead of a mailbox");
		brain->failed = TRUE;
		return TRUE;
	}
	if (memcmp(dsync_box->mailbox_guid, brain->local_dsync_box.mailbox_guid,
		   sizeof(dsync_box->mailbox_guid)) != 0) {
		i_error("Remote sent mailbox with a wrong GUID");
		brain->failed = TRUE;
		return TRUE;
	}

	if (dsync_box->mailbox_lost) {
		/* remote lost the mailbox. it's probably already deleted, but
		   verify it on next sync just to be sure */
		dsync_brain_set_changes_during_sync(brain, t_strdup_printf(
			"Remote lost mailbox GUID %s (maybe it was just deleted?)",
			guid_128_to_string(dsync_box->mailbox_guid)));
		brain->require_full_resync = TRUE;
		dsync_brain_sync_mailbox_deinit(brain);
		return TRUE;
	}
	resync = !dsync_brain_mailbox_update_pre(brain, brain->box,
						 &brain->local_dsync_box,
						 dsync_box, &resync_reason);

	if (!dsync_boxes_need_sync(brain, &brain->local_dsync_box, dsync_box)) {
		/* no fields appear to have changed, skip this mailbox */
		dsync_brain_sync_mailbox_deinit(brain);
		return TRUE;
	}
	if ((ret = dsync_brain_sync_mailbox_open(brain, dsync_box)) < 0)
		return TRUE;
	if (resync)
		dsync_brain_set_changes_during_sync(brain, resync_reason);
	if (ret == 0 || resync) {
		brain->require_full_resync = TRUE;
		brain->failed = TRUE;
		dsync_brain_sync_mailbox_deinit(brain);
		return TRUE;
	}
	dsync_brain_sync_init_box_states(brain);
	return TRUE;
}

static bool dsync_brain_recv_mailbox_attribute(struct dsync_brain *brain)
{
	const struct dsync_mailbox_attribute *attr;
	struct istream *input;
	enum dsync_ibc_recv_ret ret;

	if ((ret = dsync_ibc_recv_mailbox_attribute(brain->ibc, &attr)) == 0)
		return FALSE;
	if (ret == DSYNC_IBC_RECV_RET_FINISHED) {
		brain->box_recv_state = DSYNC_BOX_STATE_CHANGES;
		return TRUE;
	}
	if (dsync_mailbox_import_attribute(brain->box_importer, attr) < 0)
		brain->failed = TRUE;
	input = attr->value_stream;
	if (input != NULL)
		i_stream_unref(&input);
	return TRUE;
}

static void dsync_brain_send_end_of_list(struct dsync_brain *brain,
					 enum dsync_ibc_eol_type type)
{
	i_assert(!brain->failed);
	dsync_ibc_send_end_of_list(brain->ibc, type);
}

static int dsync_brain_export_deinit(struct dsync_brain *brain)
{
	const char *errstr;
	enum mail_error error;

	if (dsync_mailbox_export_deinit(&brain->box_exporter,
					&errstr, &error) < 0) {
		i_error("Exporting mailbox %s failed: %s",
			mailbox_get_vname(brain->box), errstr);
		brain->mail_error = error;
		brain->failed = TRUE;
		return -1;
	}
	return 0;
}

static void dsync_brain_send_mailbox_attribute(struct dsync_brain *brain)
{
	const struct dsync_mailbox_attribute *attr;
	int ret;

	while ((ret = dsync_mailbox_export_next_attr(brain->box_exporter, &attr)) > 0) {
		if (dsync_ibc_send_mailbox_attribute(brain->ibc, attr) == 0)
			return;
	}
	if (ret < 0) {
		if (dsync_brain_export_deinit(brain) == 0)
			i_unreached();
		return;
	}
	dsync_brain_send_end_of_list(brain, DSYNC_IBC_EOL_MAILBOX_ATTRIBUTE);
	brain->box_send_state = DSYNC_BOX_STATE_CHANGES;
}

static bool dsync_brain_recv_mail_change(struct dsync_brain *brain)
{
	const struct dsync_mail_change *change;
	enum dsync_ibc_recv_ret ret;

	if ((ret = dsync_ibc_recv_change(brain->ibc, &change)) == 0)
		return FALSE;
	if (ret == DSYNC_IBC_RECV_RET_FINISHED) {
		if (dsync_mailbox_import_changes_finish(brain->box_importer) < 0)
			brain->failed = TRUE;
		if (brain->mail_requests && brain->box_exporter != NULL)
			brain->box_recv_state = DSYNC_BOX_STATE_MAIL_REQUESTS;
		else
			brain->box_recv_state = DSYNC_BOX_STATE_MAILS;
		return TRUE;
	}
	if (dsync_mailbox_import_change(brain->box_importer, change) < 0)
		brain->failed = TRUE;
	return TRUE;
}

static void dsync_brain_send_mail_change(struct dsync_brain *brain)
{
	const struct dsync_mail_change *change;
	int ret;

	while ((ret = dsync_mailbox_export_next(brain->box_exporter, &change)) > 0) {
		if (dsync_ibc_send_change(brain->ibc, change) == 0)
			return;
	}
	if (ret < 0) {
		if (dsync_brain_export_deinit(brain) == 0)
			i_unreached();
		return;
	}
	dsync_brain_send_end_of_list(brain, DSYNC_IBC_EOL_MAIL_CHANGES);
	if (brain->mail_requests && brain->box_importer != NULL)
		brain->box_send_state = DSYNC_BOX_STATE_MAIL_REQUESTS;
	else
		brain->box_send_state = DSYNC_BOX_STATE_MAILS;
}

static bool dsync_brain_recv_mail_request(struct dsync_brain *brain)
{
	const struct dsync_mail_request *request;
	enum dsync_ibc_recv_ret ret;

	i_assert(brain->mail_requests);
	i_assert(brain->box_exporter != NULL);

	if ((ret = dsync_ibc_recv_mail_request(brain->ibc, &request)) == 0)
		return FALSE;
	if (ret == DSYNC_IBC_RECV_RET_FINISHED) {
		brain->box_recv_state = brain->box_importer != NULL ?
			DSYNC_BOX_STATE_MAILS :
			DSYNC_BOX_STATE_RECV_LAST_COMMON;
		return TRUE;
	}
	dsync_mailbox_export_want_mail(brain->box_exporter, request);
	return TRUE;
}

static bool dsync_brain_send_mail_request(struct dsync_brain *brain)
{
	const struct dsync_mail_request *request;

	i_assert(brain->mail_requests);

	while ((request = dsync_mailbox_import_next_request(brain->box_importer)) != NULL) {
		if (dsync_ibc_send_mail_request(brain->ibc, request) == 0)
			return TRUE;
	}
	if (brain->box_recv_state < DSYNC_BOX_STATE_MAIL_REQUESTS)
		return FALSE;

	dsync_brain_send_end_of_list(brain, DSYNC_IBC_EOL_MAIL_REQUESTS);
	if (brain->box_exporter != NULL)
		brain->box_send_state = DSYNC_BOX_STATE_MAILS;
	else {
		i_assert(brain->box_recv_state != DSYNC_BOX_STATE_DONE);
		brain->box_send_state = DSYNC_BOX_STATE_DONE;
	}
	return TRUE;
}

static void dsync_brain_sync_half_finished(struct dsync_brain *brain)
{
	struct dsync_mailbox_state state;
	const char *changes_during_sync;
	bool require_full_resync;

	if (brain->box_recv_state < DSYNC_BOX_STATE_RECV_LAST_COMMON ||
	    brain->box_send_state < DSYNC_BOX_STATE_RECV_LAST_COMMON)
		return;

	/* finished with this mailbox */
	i_zero(&state);
	memcpy(state.mailbox_guid, brain->local_dsync_box.mailbox_guid,
	       sizeof(state.mailbox_guid));
	state.last_uidvalidity = brain->local_dsync_box.uid_validity;
	if (brain->box_importer == NULL) {
		/* this mailbox didn't exist on remote */
		state.last_common_uid = brain->local_dsync_box.uid_next-1;
		state.last_common_modseq =
			brain->local_dsync_box.highest_modseq;
		state.last_common_pvt_modseq =
			brain->local_dsync_box.highest_pvt_modseq;
		state.last_messages_count =
			brain->local_dsync_box.messages_count;
	} else {
		if (dsync_mailbox_import_deinit(&brain->box_importer,
						!brain->failed,
						&state.last_common_uid,
						&state.last_common_modseq,
						&state.last_common_pvt_modseq,
						&state.last_messages_count,
						&changes_during_sync,
						&require_full_resync,
						&brain->mail_error) < 0) {
			if (require_full_resync) {
				/* don't treat this as brain failure or the
				   state won't be sent to the other brain.
				   this also means we'll continue syncing the
				   following mailboxes. */
				brain->require_full_resync = TRUE;
			} else {
				brain->failed = TRUE;
			}
		}
		if (changes_during_sync != NULL) {
			state.changes_during_sync = TRUE;
			dsync_brain_set_changes_during_sync(brain, changes_during_sync);
		}
	}
	if (brain->require_full_resync) {
		state.last_uidvalidity = 0;
		state.changes_during_sync = TRUE;
	}
	brain->mailbox_state = state;
	dsync_ibc_send_mailbox_state(brain->ibc, &state);
}

static bool dsync_brain_recv_mail(struct dsync_brain *brain)
{
	struct dsync_mail *mail;
	enum dsync_ibc_recv_ret ret;

	if ((ret = dsync_ibc_recv_mail(brain->ibc, &mail)) == 0)
		return FALSE;
	if (ret == DSYNC_IBC_RECV_RET_FINISHED) {
		brain->box_recv_state = DSYNC_BOX_STATE_RECV_LAST_COMMON;
		if (brain->box_exporter != NULL &&
		    brain->box_send_state >= DSYNC_BOX_STATE_RECV_LAST_COMMON) {
			if (dsync_brain_export_deinit(brain) < 0)
				return TRUE;
		}
		dsync_brain_sync_half_finished(brain);
		return TRUE;
	}
	if (brain->debug) {
		i_debug("brain %c: import mail uid %u guid %s",
			brain->master_brain ? 'M' : 'S', mail->uid, mail->guid);
	}
	if (dsync_mailbox_import_mail(brain->box_importer, mail) < 0)
		brain->failed = TRUE;
	if (mail->input != NULL)
		i_stream_unref(&mail->input);
	return TRUE;
}

static bool dsync_brain_send_mail(struct dsync_brain *brain)
{
	const struct dsync_mail *mail;

	if (brain->mail_requests &&
	    brain->box_recv_state < DSYNC_BOX_STATE_MAILS) {
		/* wait for mail requests to finish. we could already start
		   exporting, but then we're going to do quite a lot of
		   separate searches. especially with pipe backend we'd do
		   a separate search for each mail. */
		return FALSE;
	}

	while (dsync_mailbox_export_next_mail(brain->box_exporter, &mail) > 0) {
		if (dsync_ibc_send_mail(brain->ibc, mail) == 0)
			return TRUE;
	}

	if (dsync_brain_export_deinit(brain) < 0)
		return TRUE;

	brain->box_send_state = DSYNC_BOX_STATE_DONE;
	dsync_brain_send_end_of_list(brain, DSYNC_IBC_EOL_MAILS);

	dsync_brain_sync_half_finished(brain);
	return TRUE;
}

static bool dsync_brain_recv_last_common(struct dsync_brain *brain)
{
	enum dsync_ibc_recv_ret ret;
	struct dsync_mailbox_state state;

	if ((ret = dsync_ibc_recv_mailbox_state(brain->ibc, &state)) == 0)
		return FALSE;
	if (ret == DSYNC_IBC_RECV_RET_FINISHED) {
		i_error("Remote sent end-of-list instead of a mailbox state");
		brain->failed = TRUE;
		return TRUE;
	}
	i_assert(brain->box_send_state == DSYNC_BOX_STATE_DONE);
	i_assert(memcmp(state.mailbox_guid, brain->local_dsync_box.mailbox_guid,
			sizeof(state.mailbox_guid)) == 0);

	/* normally the last_common_* values should be the same in local and
	   remote, but during unexpected changes they may differ. use the
	   values that are lower as the final state. */
	if (brain->mailbox_state.last_common_uid > state.last_common_uid)
		brain->mailbox_state.last_common_uid = state.last_common_uid;
	if (brain->mailbox_state.last_common_modseq > state.last_common_modseq)
		brain->mailbox_state.last_common_modseq = state.last_common_modseq;
	if (brain->mailbox_state.last_common_pvt_modseq > state.last_common_pvt_modseq)
		brain->mailbox_state.last_common_pvt_modseq = state.last_common_pvt_modseq;
	if (state.changes_during_sync)
		brain->changes_during_remote_sync = TRUE;

	dsync_brain_sync_mailbox_deinit(brain);
	return TRUE;
}

bool dsync_brain_sync_mails(struct dsync_brain *brain)
{
	bool changed = FALSE;

	i_assert(brain->box != NULL);

	switch (brain->box_recv_state) {
	case DSYNC_BOX_STATE_MAILBOX:
		changed = dsync_brain_master_sync_recv_mailbox(brain);
		break;
	case DSYNC_BOX_STATE_ATTRIBUTES:
		changed = dsync_brain_recv_mailbox_attribute(brain);
		break;
	case DSYNC_BOX_STATE_CHANGES:
		changed = dsync_brain_recv_mail_change(brain);
		break;
	case DSYNC_BOX_STATE_MAIL_REQUESTS:
		changed = dsync_brain_recv_mail_request(brain);
		break;
	case DSYNC_BOX_STATE_MAILS:
		changed = dsync_brain_recv_mail(brain);
		break;
	case DSYNC_BOX_STATE_RECV_LAST_COMMON:
		changed = dsync_brain_recv_last_common(brain);
		break;
	case DSYNC_BOX_STATE_DONE:
		break;
	}

	if (!dsync_ibc_is_send_queue_full(brain->ibc) && !brain->failed) {
		switch (brain->box_send_state) {
		case DSYNC_BOX_STATE_MAILBOX:
			/* wait for mailbox to be received first */
			break;
		case DSYNC_BOX_STATE_ATTRIBUTES:
			dsync_brain_send_mailbox_attribute(brain);
			changed = TRUE;
			break;
		case DSYNC_BOX_STATE_CHANGES:
			dsync_brain_send_mail_change(brain);
			changed = TRUE;
			break;
		case DSYNC_BOX_STATE_MAIL_REQUESTS:
			if (dsync_brain_send_mail_request(brain))
				changed = TRUE;
			break;
		case DSYNC_BOX_STATE_MAILS:
			if (dsync_brain_send_mail(brain))
				changed = TRUE;
			break;
		case DSYNC_BOX_STATE_RECV_LAST_COMMON:
			i_unreached();
		case DSYNC_BOX_STATE_DONE:
			break;
		}
	}
	return changed;
}
