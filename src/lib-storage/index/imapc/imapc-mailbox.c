/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

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

void imapc_mailbox_set_corrupted(struct imapc_mailbox *mbox,
				 const char *reason, ...)
{
	va_list va;

	va_start(va, reason);
	i_error("imapc: Mailbox '%s' state corrupted: %s",
		mbox->box.name, t_strdup_vprintf(reason, va));
	va_end(va);

	if (!mbox->initial_sync_done) {
		/* we failed during initial sync. need to rebuild indexes if
		   we want to get this fixed */
		mail_index_mark_corrupted(mbox->box.index);
	} else {
		/* maybe the remote server is buggy and has become confused.
		   try reconnecting. */
	}
	imapc_client_mailbox_reconnect(mbox->client_box);
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

static int imapc_mailbox_commit_delayed_expunges(struct imapc_mailbox *mbox)
{
	struct mail_index_view *view = imapc_mailbox_get_sync_view(mbox);
	struct mail_index_transaction *trans;
	const uint32_t *uidp;
	uint32_t lseq;
	int ret;

	trans = mail_index_transaction_begin(view,
			MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	array_foreach(&mbox->delayed_expunged_uids, uidp) {
		if (mail_index_lookup_seq(view, *uidp, &lseq))
			mail_index_expunge(trans, lseq);
	}
	array_clear(&mbox->delayed_expunged_uids);
	ret = mail_index_transaction_commit(&trans);
	if (ret < 0)
		mailbox_set_index_error(&mbox->box);
	return ret;
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
			mailbox_set_index_error(&mbox->box);
			ret = -1;
		}
		*changes_r = TRUE;
	}
	if (mbox->sync_view != NULL)
		mail_index_view_close(&mbox->sync_view);

	if (array_count(&mbox->delayed_expunged_uids) > 0) {
		/* delayed expunges - commit them now in a separate
		   transaction */
		if (imapc_mailbox_commit_delayed_expunges(mbox) < 0)
			ret = -1;
	}
	return ret;
}

static void imapc_mailbox_idle_timeout(struct imapc_mailbox *mbox)
{
	timeout_remove(&mbox->to_idle_delay);
	if (mbox->box.notify_callback != NULL)
		mbox->box.notify_callback(&mbox->box, mbox->box.notify_context);
}

static void imapc_mailbox_idle_notify(struct imapc_mailbox *mbox)
{
	struct ioloop *old_ioloop = current_ioloop;

	if (mbox->box.notify_callback != NULL &&
	    mbox->to_idle_delay == NULL) {
		io_loop_set_current(mbox->storage->root_ioloop);
		mbox->to_idle_delay =
			timeout_add_short(NOTIFY_DELAY_MSECS,
					  imapc_mailbox_idle_timeout, mbox);
		io_loop_set_current(old_ioloop);
	}
}

static void
imapc_untagged_exists(const struct imapc_untagged_reply *reply,
		      struct imapc_mailbox *mbox)
{
	struct mail_index_view *view = mbox->delayed_sync_view;
	uint32_t exists_count = reply->num;
	const struct mail_index_header *hdr;

	if (mbox == NULL)
		return;

	if (view == NULL)
		view = imapc_mailbox_get_sync_view(mbox);

	if (mbox->selecting) {
		/* We don't know the latest flags, refresh them. */
		mbox->sync_fetch_first_uid = 1;
	} else if (mbox->sync_fetch_first_uid != 1) {
		hdr = mail_index_get_header(view);
		mbox->sync_fetch_first_uid = hdr->next_uid;
	}
	mbox->exists_count = exists_count;
	mbox->exists_received = TRUE;
	imapc_mailbox_idle_notify(mbox);
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

static int
imapc_mailbox_msgmap_update(struct imapc_mailbox *mbox,
			    uint32_t rseq, uint32_t fetch_uid,
			    uint32_t *lseq_r, uint32_t *uid_r)
{
	struct imapc_msgmap *msgmap;
	uint32_t uid, msg_count, rseq2;

	*lseq_r = 0;
	*uid_r = uid = fetch_uid;

	if (rseq > mbox->exists_count) {
		/* Receiving a FETCH for a message that EXISTS hasn't
		   announced yet. MS Exchange has a bug where our UID FETCH
		   request sometimes sends replies where sequences are above
		   EXISTS value, but their UIDs are for existing messages.
		   We'll just ignore these replies. */
		return 0;
	}
	if (rseq < mbox->prev_skipped_rseq &&
	    fetch_uid > mbox->prev_skipped_uid) {
		/* This was the initial attempt at catching the above
		   MS Exchange bug, but the above one appears to catch all
		   these cases. But keep it here just in case. */
		imapc_mailbox_set_corrupted(mbox,
			"FETCH sequence/UID order is mixed "
			"(seq=%u,%u vs uid=%u,%u)",
			mbox->prev_skipped_rseq, rseq,
			mbox->prev_skipped_uid, fetch_uid);
		return -1;
	}

	msgmap = imapc_client_mailbox_get_msgmap(mbox->client_box);
	msg_count = imapc_msgmap_count(msgmap);
	if (rseq <= msg_count) {
		uid = imapc_msgmap_rseq_to_uid(msgmap, rseq);
		if (uid != fetch_uid && fetch_uid != 0) {
			imapc_mailbox_set_corrupted(mbox,
				"FETCH UID mismatch (%u != %u)",
				fetch_uid, uid);
			return -1;
		}
		*uid_r = uid;
	} else if (fetch_uid == 0 || rseq != msg_count+1) {
		/* probably a flag update for a message we haven't yet
		   received our initial UID FETCH for. we should get
		   another one. */
		if (fetch_uid == 0)
			return 0;

		if (imapc_msgmap_uid_to_rseq(msgmap, fetch_uid, &rseq2)) {
			imapc_mailbox_set_corrupted(mbox,
				"FETCH returned wrong sequence for UID %u "
				"(%u != %u)", fetch_uid, rseq, rseq2);
			return -1;
		}
		mbox->prev_skipped_rseq = rseq;
		mbox->prev_skipped_uid = fetch_uid;
	} else if (fetch_uid < imapc_msgmap_uidnext(msgmap)) {
		imapc_mailbox_set_corrupted(mbox,
			"Expunged message reappeared in session "
			"(uid=%u < next_uid=%u)",
			fetch_uid, imapc_msgmap_uidnext(msgmap));
		return -1;
	} else {
		/* newly seen message */
		imapc_msgmap_append(msgmap, rseq, uid);
		if (uid < mbox->min_append_uid) {
			/* message is already added to index */
		} else if (mbox->syncing) {
			mail_index_append(mbox->delayed_sync_trans,
					  uid, lseq_r);
			mbox->min_append_uid = uid + 1;
		}
	}
	return 0;
}

static void imapc_untagged_fetch(const struct imapc_untagged_reply *reply,
				 struct imapc_mailbox *mbox)
{
	uint32_t lseq, rseq = reply->num;
	struct imapc_mail *const *mailp;
	const struct imap_arg *list, *flags_list;
	const char *atom;
	const struct mail_index_record *rec = NULL;
	enum mail_flags flags;
	uint32_t fetch_uid, uid;
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
	if (imapc_mailbox_msgmap_update(mbox, rseq, fetch_uid,
					&lseq, &uid) < 0 || uid == 0)
		return;

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
			if (rseq == mbox->sync_next_rseq)
				mbox->sync_next_rseq++;
			return;
		}
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

	rec = mail_index_lookup(mbox->delayed_sync_view, lseq);
	if (seen_flags && rec->flags != flags) {
		mail_index_update_flags(mbox->delayed_sync_trans, lseq,
					MODIFY_REPLACE, flags);
	}
	if (seen_flags) {
		ARRAY_TYPE(keyword_indexes) old_kws;
		struct mail_keywords *kw;

		t_array_init(&old_kws, 8);
		mail_index_lookup_keywords(mbox->delayed_sync_view, lseq,
					   &old_kws);

		array_append_zero(&keywords);
		kw = mail_index_keywords_create(mbox->box.index,
						array_idx(&keywords, 0));
		if (!keywords_are_equal(kw, &old_kws)) {
			mail_index_update_keywords(mbox->delayed_sync_trans,
						   lseq, MODIFY_REPLACE, kw);
		}
		mail_index_keywords_unref(&kw);
	}
	imapc_mailbox_idle_notify(mbox);
}

static void imapc_untagged_expunge(const struct imapc_untagged_reply *reply,
				   struct imapc_mailbox *mbox)
{
	struct imapc_msgmap *msgmap;
	uint32_t lseq, uid, rseq = reply->num;
	
	if (mbox == NULL || rseq == 0)
		return;

	mbox->prev_skipped_rseq = 0;
	mbox->prev_skipped_uid = 0;

	if (mbox->exists_count == 0) {
		imapc_mailbox_set_corrupted(mbox,
			"EXPUNGE received for empty mailbox");
		return;
	}
	mbox->exists_count--;

	msgmap = imapc_client_mailbox_get_msgmap(mbox->client_box);
	if (rseq > imapc_msgmap_count(msgmap)) {
		/* we haven't even seen this message yet */
		return;
	}
	uid = imapc_msgmap_rseq_to_uid(msgmap, rseq);
	imapc_msgmap_expunge(msgmap, rseq);

	imapc_mailbox_init_delayed_trans(mbox);
	if (mail_index_lookup_seq(mbox->sync_view, uid, &lseq))
		mail_index_expunge(mbox->delayed_sync_trans, lseq);
	else if (mail_index_lookup_seq(mbox->delayed_sync_view, uid, &lseq)) {
		/* this message exists only in this transaction. lib-index
		   can't currently handle expunging anything except the last
		   appended message in a transaction, and fixing it would be
		   quite a lot of trouble. so instead we'll just delay doing
		   this expunge until after the current transaction has been
		   committed. */
		array_append(&mbox->delayed_expunged_uids, &uid, 1);
	} else {
		/* already expunged by another session */
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

	if (mbox->sync_uid_validity != uid_validity) {
		mbox->sync_uid_validity = uid_validity;
		imapc_mail_cache_free(&mbox->prev_mail_cache);
	}
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

static void
imapc_resp_text_permanentflags(const struct imapc_untagged_reply *reply,
			       struct imapc_mailbox *mbox)
{
	const struct imap_arg *flags_args, *arg;
	const char *flag;
	unsigned int idx;

	i_assert(reply->args[0].type == IMAP_ARG_ATOM);

	if (mbox == NULL || !imap_arg_get_list(&reply->args[1], &flags_args))
		return;

	mbox->permanent_flags = 0;
	mbox->box.disallow_new_keywords = TRUE;

	for (arg = flags_args; arg->type != IMAP_ARG_EOL; arg++) {
		if (!imap_arg_get_atom(arg, &flag))
			continue;

		if (strcmp(flag, "\\*") == 0)
			mbox->box.disallow_new_keywords = FALSE;
		else if (*flag == '\\')
			mbox->permanent_flags |= imap_parse_system_flag(flag);
		else {
			/* we'll simply make sure that it exists in the index */
			mail_index_keyword_lookup_or_create(mbox->box.index,
							    flag, &idx);
		}
	}
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
	imapc_mailbox_register_resp_text(mbox, "PERMANENTFLAGS",
					 imapc_resp_text_permanentflags);
}
