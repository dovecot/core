/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "index-storage.h"
#include "index-mail.h"
#include "index-pop3-uidl.h"

void index_pop3_uidl_set_max_uid(struct mailbox *box,
				 struct mail_index_transaction *trans,
				 uint32_t uid)
{
	struct mailbox_index_pop3_uidl uidl;

	i_zero(&uidl);
	uidl.max_uid_with_pop3_uidl = uid;

	mail_index_update_header_ext(trans, box->pop3_uidl_hdr_ext_id,
				     0, &uidl, sizeof(uidl));
}

bool index_pop3_uidl_can_exist(struct mail *mail)
{
	struct mailbox_index_pop3_uidl uidl;
	const void *data;
	size_t size;

	/* We'll assume that if the header exists, it's up-to-date. normally
	   UIDLs are set only during migration, so this value never changes.
	   Also even if it does, it becomes out-of-date only when the mailbox
	   is modified with old Dovecot versions. To fix that we'd have to
	   add and keep updating "max tracked uid" in this header for every
	   saved mail, which isn't worth it. */
	mail_index_get_header_ext(mail->transaction->view,
				  mail->box->pop3_uidl_hdr_ext_id,
				  &data, &size);
	if (size < sizeof(uidl)) {
		/* this header isn't set yet */
		return TRUE;
	}
	memcpy(&uidl, data, sizeof(uidl));
	return mail->uid <= uidl.max_uid_with_pop3_uidl;
}

void index_pop3_uidl_update_exists(struct mail *mail, bool exists)
{
	struct mailbox_transaction_context *trans = mail->transaction;

	if (exists) {
		if (trans->highest_pop3_uidl_uid < mail->uid) {
			trans->highest_pop3_uidl_uid = mail->uid;
			trans->prev_pop3_uidl_tracking_seq = mail->seq;
		}
	} else if (mail->seq == trans->prev_pop3_uidl_tracking_seq+1) {
		trans->prev_pop3_uidl_tracking_seq++;
	} else {
		/* skipping mails. we don't know the state. */
	}
}

void index_pop3_uidl_update_exists_finish(struct mailbox_transaction_context *trans)
{
	struct mail_index_view *view;
	struct mailbox_index_pop3_uidl uidl;
	const void *data;
	size_t size;
	bool seen_all_msgs;

	mail_index_get_header_ext(trans->view, trans->box->pop3_uidl_hdr_ext_id,
				  &data, &size);

	if (trans->highest_pop3_uidl_uid == 0 && size >= sizeof(uidl)) {
		/* header already set and nothing to change */
		return;
	}

	/* First check that we actually looked at UIDL for all messages.
	   Otherwise we can't say for sure if the newest messages had UIDLs. */
	if (trans->prev_pop3_uidl_tracking_seq !=
	    mail_index_view_get_messages_count(trans->view))
		return;

	/* Just to be sure: Refresh the index and check again. POP3 keeps
	   transactions open for duration of the entire session. Maybe another
	   process already added new mails (and already updated this header).
	   This check is racy, but normally UIDLs aren't added after migration
	   so it's a bit questionable if it's even worth having this check in
	   there. */
	view = mail_index_view_open(trans->box->index);
	seen_all_msgs = mail_index_refresh(trans->box->index) == 0 &&
		trans->prev_pop3_uidl_tracking_seq ==
		mail_index_view_get_messages_count(view);
	mail_index_view_close(&view);
	if (!seen_all_msgs)
		return;

	/* check if we have already the same header */
	if (size >= sizeof(uidl)) {
		memcpy(&uidl, data, sizeof(uidl));
		if (trans->highest_pop3_uidl_uid == uidl.max_uid_with_pop3_uidl)
			return;
	}
	index_pop3_uidl_set_max_uid(trans->box, trans->itrans,
				    trans->highest_pop3_uidl_uid);
}
