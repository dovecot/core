/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "imap-arg.h"
#include "imap-util.h"
#include "imapc-client.h"
#include "imapc-mail.h"
#include "imapc-msgmap.h"
#include "imapc-sync.h"
#include "imapc-storage.h"

#define NOTIFY_DELAY_MSECS 500

static void imapc_mailbox_set_corrupted(struct imapc_mailbox *mbox,
					const char *reason, ...)
{
	va_list va;

	va_start(va, reason);
	i_error("imapc: Mailbox '%s' state corrupted: %s",
		mbox->box.name, t_strdup_vprintf(reason, va));
	va_end(va);

	sleep(3600);

	mail_index_mark_corrupted(mbox->box.index);
	imapc_client_mailbox_disconnect(mbox->client_box);
}

static struct mail_index_view *
imapc_mailbox_get_sync_view(struct imapc_mailbox *mbox)
{
	if (mbox->sync_view == NULL)
		mbox->sync_view = mail_index_view_open(mbox->box.index);
	return mbox->sync_view;
}

static void imapc_mailbox_init_delayed_trans(struct imapc_mailbox *mbox)
{
	if (mbox->delayed_sync_trans != NULL)
		return;

	mbox->delayed_sync_trans =
		mail_index_transaction_begin(imapc_mailbox_get_sync_view(mbox),
					MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	mbox->delayed_sync_view =
		mail_index_transaction_open_updated_view(mbox->delayed_sync_trans);
}

int imapc_mailbox_commit_delayed_trans(struct imapc_mailbox *mbox,
				       bool *changes_r)
{
	int ret = 0;

	*changes_r = FALSE;

	if (mbox->delayed_sync_view != NULL)
		mail_index_view_close(&mbox->delayed_sync_view);
	if (mbox->delayed_sync_trans != NULL) {
		if (mail_index_transaction_commit(&mbox->delayed_sync_trans) < 0) {
			mail_storage_set_index_error(&mbox->box);
			ret = -1;
		}
		*changes_r = TRUE;
	}
	if (mbox->sync_view != NULL)
		mail_index_view_close(&mbox->sync_view);
	return ret;
}

static void imapc_untagged_exists(const struct imapc_untagged_reply *reply,
				  struct imapc_mailbox *mbox)
{
	struct mail_index_view *view = mbox->delayed_sync_view;
	uint32_t rcount = reply->num;
	const struct mail_index_header *hdr;

	if (mbox == NULL)
		return;

	if (view == NULL)
		view = imapc_mailbox_get_sync_view(mbox);

	if (mbox->opening) {
		/* We don't know the latest flags, refresh them. */
		mbox->sync_fetch_first_uid = 1;
	} else if (mbox->sync_fetch_first_uid != 1) {
		hdr = mail_index_get_header(view);
		mbox->sync_fetch_first_uid = hdr->next_uid;
	}
}

static void imapc_mailbox_idle_timeout(struct imapc_mailbox *mbox)
{
	timeout_remove(&mbox->to_idle_delay);
	if (mbox->box.notify_callback != NULL)
		mbox->box.notify_callback(&mbox->box, mbox->box.notify_context);
}

static void imapc_mailbox_idle_notify(struct imapc_mailbox *mbox)
{
	if (mbox->box.notify_callback != NULL &&
	    mbox->to_idle_delay == NULL) {
		mbox->to_idle_delay =
			timeout_add(NOTIFY_DELAY_MSECS,
				    imapc_mailbox_idle_timeout, mbox);
	}
}

static bool keywords_are_equal(struct mail_keywords *kw,
			       const ARRAY_TYPE(keyword_indexes) *kw_arr)
{
	const unsigned int *kw_idx;
	unsigned int i, j, count;

	kw_idx = array_get(kw_arr, &count);
	if (count != kw->count)
		return FALSE;

	/* there are normally only a few keywords, so O(n^2) is fine */
	for (i = 0; i < count; i++) {
		for (j = 0; j < count; j++) {
			if (kw->idx[i] == kw_idx[j])
				break;
		}
		if (j == count)
			return FALSE;
	}
	return TRUE;
}

static void imapc_untagged_fetch(const struct imapc_untagged_reply *reply,
				 struct imapc_mailbox *mbox)
{
	uint32_t lseq, rseq = reply->num;
	struct imapc_mail *const *mailp;
	const struct imap_arg *list, *flags_list;
	const char *atom;
	const struct mail_index_record *rec = NULL;
	struct imapc_msgmap *msgmap;
	enum mail_flags flags;
	uint32_t fetch_uid, uid, msg_count;
	unsigned int i, j;
	ARRAY_TYPE(const_string) keywords = ARRAY_INIT;
	bool seen_flags = FALSE;

	if (mbox == NULL || rseq == 0 || !imap_arg_get_list(reply->args, &list))
		return;

	fetch_uid = 0; flags = 0;
	for (i = 0; list[i].type != IMAP_ARG_EOL; i += 2) {
		if (!imap_arg_get_atom(&list[i], &atom))
			return;

		if (strcasecmp(atom, "UID") == 0) {
			if (!imap_arg_get_atom(&list[i+1], &atom) ||
			    str_to_uint32(atom, &fetch_uid) < 0)
				return;
		} else if (strcasecmp(atom, "FLAGS") == 0) {
			if (!imap_arg_get_list(&list[i+1], &flags_list))
				return;

			t_array_init(&keywords, 8);
			seen_flags = TRUE;
			for (j = 0; flags_list[j].type != IMAP_ARG_EOL; j++) {
				if (!imap_arg_get_atom(&flags_list[j], &atom))
					return;
				if (atom[0] == '\\')
					flags |= imap_parse_system_flag(atom);
				else {
					/* keyword */
					array_append(&keywords, &atom, 1);
				}
			}
		}
	}
	/* FIXME: need to do something about recent flags */
	flags &= ~MAIL_RECENT;

	imapc_mailbox_init_delayed_trans(mbox);

	msgmap = imapc_client_mailbox_get_msgmap(mbox->client_box);
	msg_count = imapc_msgmap_count(msgmap);
	if (rseq > msg_count) {
		/* newly seen message */
		if (fetch_uid == 0 || rseq != msg_count+1) {
			/* can't handle this one now. we should get another
			   FETCH reply for it. */
			return;
		}
		uid = fetch_uid;

		if (uid < imapc_msgmap_uidnext(msgmap)) {
			imapc_mailbox_set_corrupted(mbox,
				"Expunged message reappeared "
				"(uid=%u < next_uid=%u)",
				uid, imapc_msgmap_uidnext(msgmap));
			return;
		}

		imapc_msgmap_append(msgmap, rseq, uid);
		if (uid < mbox->min_append_uid) {
			/* message is already added to index */
			lseq = 0;
		} else if (mbox->syncing) {
			mail_index_append(mbox->delayed_sync_trans, uid, &lseq);
			mbox->min_append_uid = uid + 1;
		}
	} else {
		uid = imapc_msgmap_rseq_to_uid(msgmap, rseq);
		if (uid != fetch_uid && fetch_uid != 0) {
			imapc_mailbox_set_corrupted(mbox,
				"FETCH UID mismatch (%u != %u)",
				fetch_uid, uid);
			return;
		}
		lseq = 0;
	}
	/* if this is a reply to some FETCH request, update the mail's fields */
	array_foreach(&mbox->fetch_mails, mailp) {
		struct imapc_mail *mail = *mailp;

		if (mail->imail.mail.mail.uid == uid)
			imapc_mail_fetch_update(mail, reply, list);
	}

	if (lseq == 0) {
		if (!mail_index_lookup_seq(mbox->delayed_sync_view,
					   uid, &lseq)) {
			/* already expunged by another session */
			return;
		}
		rec = mail_index_lookup(mbox->delayed_sync_view, lseq);
	}

	if (rseq == mbox->sync_next_rseq) {
		/* we're doing the initial full sync of mails. expunge any
		   mails that no longer exist. */
		i_assert(mbox->syncing);

		while (mbox->sync_next_lseq < lseq) {
			mail_index_expunge(mbox->delayed_sync_trans,
					   mbox->sync_next_lseq);
			mbox->sync_next_lseq++;
		}
		i_assert(lseq == mbox->sync_next_lseq);
		mbox->sync_next_rseq++;
		mbox->sync_next_lseq++;
	}

	if (seen_flags && (rec == NULL || rec->flags != flags)) {
		mail_index_update_flags(mbox->delayed_sync_trans, lseq,
					MODIFY_REPLACE, flags);
	}
	if (seen_flags) T_BEGIN {
		ARRAY_TYPE(keyword_indexes) old_kws;
		struct mail_keywords *kw;

		t_array_init(&old_kws, 8);
		mail_index_lookup_keywords(mbox->delayed_sync_view, lseq,
					   &old_kws);

		(void)array_append_space(&keywords);
		kw = mail_index_keywords_create(mbox->box.index,
						array_idx(&keywords, 0));
		if (!keywords_are_equal(kw, &old_kws)) {
			mail_index_update_keywords(mbox->delayed_sync_trans,
						   lseq, MODIFY_REPLACE, kw);
		}
		mail_index_keywords_unref(&kw);
	} T_END;
	imapc_mailbox_idle_notify(mbox);
}

static void imapc_untagged_expunge(const struct imapc_untagged_reply *reply,
				   struct imapc_mailbox *mbox)
{
	struct imapc_msgmap *msgmap;
	uint32_t lseq, uid, rseq = reply->num;
	
	if (mbox == NULL || rseq == 0)
		return;

	msgmap = imapc_client_mailbox_get_msgmap(mbox->client_box);
	if (rseq > imapc_msgmap_count(msgmap)) {
		/* we haven't even seen this message yet */
		return;
	}
	uid = imapc_msgmap_rseq_to_uid(msgmap, rseq);
	imapc_msgmap_expunge(msgmap, rseq);

	imapc_mailbox_init_delayed_trans(mbox);
	if (!mail_index_lookup_seq(mbox->delayed_sync_view, uid, &lseq)) {
		/* already expunged by another session */
	} else {
		mail_index_expunge(mbox->delayed_sync_trans, lseq);
	}
	imapc_mailbox_idle_notify(mbox);
}

static void
imapc_resp_text_uidvalidity(const struct imapc_untagged_reply *reply,
			    struct imapc_mailbox *mbox)
{
	uint32_t uid_validity;

	if (mbox == NULL || reply->resp_text_value == NULL ||
	    str_to_uint32(reply->resp_text_value, &uid_validity) < 0)
		return;

	mbox->sync_uid_validity = uid_validity;
}

static void
imapc_resp_text_uidnext(const struct imapc_untagged_reply *reply,
			struct imapc_mailbox *mbox)
{
	uint32_t uid_next;

	if (mbox == NULL || reply->resp_text_value == NULL ||
	    str_to_uint32(reply->resp_text_value, &uid_next) < 0)
		return;

	mbox->sync_uid_next = uid_next;
}

void imapc_mailbox_register_untagged(struct imapc_mailbox *mbox,
				     const char *key,
				     imapc_mailbox_callback_t *callback)
{
	struct imapc_mailbox_event_callback *cb;

	cb = array_append_space(&mbox->untagged_callbacks);
	cb->name = p_strdup(mbox->box.pool, key);
	cb->callback = callback;
}

void imapc_mailbox_register_resp_text(struct imapc_mailbox *mbox,
				      const char *key,
				      imapc_mailbox_callback_t *callback)
{
	struct imapc_mailbox_event_callback *cb;

	cb = array_append_space(&mbox->resp_text_callbacks);
	cb->name = p_strdup(mbox->box.pool, key);
	cb->callback = callback;
}

void imapc_mailbox_register_callbacks(struct imapc_mailbox *mbox)
{
	imapc_mailbox_register_untagged(mbox, "EXISTS",
					imapc_untagged_exists);
	imapc_mailbox_register_untagged(mbox, "FETCH",
					imapc_untagged_fetch);
	imapc_mailbox_register_untagged(mbox, "EXPUNGE",
					imapc_untagged_expunge);
	imapc_mailbox_register_resp_text(mbox, "UIDVALIDITY",
					 imapc_resp_text_uidvalidity);
	imapc_mailbox_register_resp_text(mbox, "UIDNEXT",
					 imapc_resp_text_uidnext);
}
