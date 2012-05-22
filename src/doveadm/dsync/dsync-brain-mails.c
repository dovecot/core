/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "dsync-slave.h"
#include "dsync-mail.h"
#include "dsync-mailbox-import.h"
#include "dsync-mailbox-export.h"
#include "dsync-brain-private.h"

static bool dsync_brain_master_sync_recv_mailbox(struct dsync_brain *brain)
{
	const struct dsync_mailbox *dsync_box;
	enum dsync_slave_recv_ret ret;

	i_assert(brain->master_brain);

	if ((ret = dsync_slave_recv_mailbox(brain->slave, &dsync_box)) == 0)
		return FALSE;
	if (ret == DSYNC_SLAVE_RECV_RET_FINISHED) {
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
		dsync_brain_sync_mailbox_deinit(brain);
		return TRUE;
	}
	dsync_brain_mailbox_update_pre(brain, brain->box,
				       &brain->local_dsync_box, dsync_box);

	if (brain->sync_type == DSYNC_BRAIN_SYNC_TYPE_CHANGED &&
	    !dsync_boxes_need_sync(&brain->local_dsync_box, dsync_box)) {
		/* no fields appear to have changed, skip this mailbox */
		dsync_brain_sync_mailbox_deinit(brain);
		return TRUE;
	}
	dsync_brain_sync_mailbox_init_remote(brain, dsync_box);
	brain->box_recv_state = DSYNC_BOX_STATE_CHANGES;
	brain->box_send_state = DSYNC_BOX_STATE_CHANGES;

	i_assert(brain->box_importer != NULL);
	return TRUE;
}

static bool dsync_brain_recv_mail_change(struct dsync_brain *brain)
{
	const struct dsync_mail_change *change;
	enum dsync_slave_recv_ret ret;

	if ((ret = dsync_slave_recv_change(brain->slave, &change)) == 0)
		return FALSE;
	if (ret == DSYNC_SLAVE_RECV_RET_FINISHED) {
		dsync_mailbox_import_changes_finish(brain->box_importer);
		brain->box_recv_state = brain->guid_requests ?
			DSYNC_BOX_STATE_MAIL_REQUESTS : DSYNC_BOX_STATE_MAILS;
		return TRUE;
	}
	dsync_mailbox_import_change(brain->box_importer, change);
	return TRUE;
}

static void dsync_brain_send_mail_change(struct dsync_brain *brain)
{
	const struct dsync_mail_change *change;

	while ((change = dsync_mailbox_export_next(brain->box_exporter)) != NULL) {
		if (dsync_slave_send_change(brain->slave, change) == 0)
			return;
	}
	dsync_slave_send_end_of_list(brain->slave);
	brain->box_send_state = brain->guid_requests ?
		DSYNC_BOX_STATE_MAIL_REQUESTS : DSYNC_BOX_STATE_MAILS;
}

static bool dsync_brain_recv_mail_request(struct dsync_brain *brain)
{
	const struct dsync_mail_request *request;
	enum dsync_slave_recv_ret ret;

	i_assert(brain->guid_requests);

	if ((ret = dsync_slave_recv_mail_request(brain->slave, &request)) == 0)
		return FALSE;
	if (ret == DSYNC_SLAVE_RECV_RET_FINISHED) {
		brain->box_recv_state = DSYNC_BOX_STATE_MAILS;
		return TRUE;
	}
	dsync_mailbox_export_want_mail(brain->box_exporter, request);
	return TRUE;
}

static void dsync_brain_send_mail_request(struct dsync_brain *brain)
{
	const struct dsync_mail_request *request;

	i_assert(brain->guid_requests);

	while ((request = dsync_mailbox_import_next_request(brain->box_importer)) != NULL) {
		if (dsync_slave_send_mail_request(brain->slave, request) == 0)
			return;
	}
	if (brain->box_recv_state > DSYNC_BOX_STATE_CHANGES) {
		dsync_slave_send_end_of_list(brain->slave);
		brain->box_send_state = DSYNC_BOX_STATE_MAILS;
	}
}

static void dsync_brain_sync_half_finished(struct dsync_brain *brain)
{
	struct dsync_mailbox_state state;
	bool changes_during_sync;
	const char *error;

	if (brain->box_recv_state < DSYNC_BOX_STATE_RECV_LAST_COMMON ||
	    brain->box_send_state < DSYNC_BOX_STATE_RECV_LAST_COMMON)
		return;

	/* finished with this mailbox */
	if (dsync_mailbox_export_deinit(&brain->box_exporter, &error) < 0) {
		i_error("Exporting mailbox %s failed: %s",
			mailbox_get_vname(brain->box), error);
		brain->failed = TRUE;
		return;
	}

	memset(&state, 0, sizeof(state));
	memcpy(state.mailbox_guid, brain->local_dsync_box.mailbox_guid,
	       sizeof(state.mailbox_guid));
	state.last_uidvalidity = brain->local_dsync_box.uid_validity;
	if (brain->box_importer == NULL) {
		/* this mailbox didn't exist on remote */
		state.last_common_uid = brain->local_dsync_box.uid_next-1;
		state.last_common_modseq =
			brain->local_dsync_box.highest_modseq;
	} else {
		if (dsync_mailbox_import_deinit(&brain->box_importer,
						&state.last_common_uid,
						&state.last_common_modseq,
						&changes_during_sync) < 0) {
			i_error("Importing mailbox %s failed",
				mailbox_get_vname(brain->box));
			brain->failed = TRUE;
			return;
		}
		if (changes_during_sync)
			brain->changes_during_sync = TRUE;
	}
	dsync_slave_send_mailbox_state(brain->slave, &state);
}

static bool dsync_brain_recv_mail(struct dsync_brain *brain)
{
	struct dsync_mail *mail;
	enum dsync_slave_recv_ret ret;

	if ((ret = dsync_slave_recv_mail(brain->slave, &mail)) == 0)
		return FALSE;
	if (ret == DSYNC_SLAVE_RECV_RET_FINISHED) {
		brain->box_recv_state = DSYNC_BOX_STATE_RECV_LAST_COMMON;
		dsync_brain_sync_half_finished(brain);
		return TRUE;
	}
	dsync_mailbox_import_mail(brain->box_importer, mail);
	if (mail->input != NULL)
		i_stream_unref(&mail->input);
	return TRUE;
}

static bool dsync_brain_send_mail(struct dsync_brain *brain)
{
	const struct dsync_mail *mail;
	bool changed = FALSE;

	while ((mail = dsync_mailbox_export_next_mail(brain->box_exporter)) != NULL) {
		changed = TRUE;
		if (dsync_slave_send_mail(brain->slave, mail) == 0)
			return TRUE;
	}
	if (brain->guid_requests &&
	    brain->box_recv_state < DSYNC_BOX_STATE_MAILS) {
		/* wait for mail requests to finish */
		return changed;
	}

	brain->box_send_state = DSYNC_BOX_STATE_DONE;
	dsync_slave_send_end_of_list(brain->slave);

	dsync_brain_sync_half_finished(brain);
	return TRUE;
}

static bool dsync_brain_recv_last_common(struct dsync_brain *brain)
{
	enum dsync_slave_recv_ret ret;
	struct dsync_mailbox_state state;

	if ((ret = dsync_slave_recv_mailbox_state(brain->slave, &state)) == 0)
		return FALSE;
	if (ret == DSYNC_SLAVE_RECV_RET_FINISHED) {
		i_error("Remote sent end-of-list instead of a mailbox state");
		brain->failed = TRUE;
		return TRUE;
	}
	i_assert(brain->box_send_state == DSYNC_BOX_STATE_DONE);
	brain->mailbox_state = state;

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

	if (brain->failed)
		return TRUE;

	switch (brain->box_send_state) {
	case DSYNC_BOX_STATE_MAILBOX:
		/* wait for mailbox to be received first */
		break;
	case DSYNC_BOX_STATE_CHANGES:
		dsync_brain_send_mail_change(brain);
		changed = TRUE;
		break;
	case DSYNC_BOX_STATE_MAIL_REQUESTS:
		dsync_brain_send_mail_request(brain);
		changed = TRUE;
		break;
	case DSYNC_BOX_STATE_MAILS:
		if (!dsync_slave_is_send_queue_full(brain->slave)) {
			if (dsync_brain_send_mail(brain))
				changed = TRUE;
		}
		break;
	case DSYNC_BOX_STATE_RECV_LAST_COMMON:
		i_unreached();
	case DSYNC_BOX_STATE_DONE:
		break;
	}
	return changed;
}
