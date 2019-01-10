/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "mail-index-modseq.h"
#include "imap-arg.h"
#include "imap-seqset.h"
#include "imap-util.h"
#include "imapc-mail.h"
#include "imapc-msgmap.h"
#include "imapc-list.h"
#include "imapc-search.h"
#include "imapc-sync.h"
#include "imapc-storage.h"

#define NOTIFY_DELAY_MSECS 500

void imapc_mailbox_set_corrupted(struct imapc_mailbox *mbox,
				 const char *reason, ...)
{
	const char *errmsg;
	va_list va;

	va_start(va, reason);
	errmsg = t_strdup_printf("Mailbox '%s' state corrupted: %s",
		mbox->box.name, t_strdup_vprintf(reason, va));
	va_end(va);

	mail_storage_set_internal_error(&mbox->storage->storage);

	if (!mbox->initial_sync_done) {
		/* we failed during initial sync. need to rebuild indexes if
		   we want to get this fixed */
		mail_index_mark_corrupted(mbox->box.index);
	} else {
		/* maybe the remote server is buggy and has become confused.
		   try reconnecting. */
	}
	imapc_client_mailbox_reconnect(mbox->client_box, errmsg);
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

	i_assert(mbox->delayed_sync_cache_view == NULL);
	i_assert(mbox->delayed_sync_cache_trans == NULL);

	mbox->delayed_sync_trans =
		mail_index_transaction_begin(imapc_mailbox_get_sync_view(mbox),
					MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	mbox->delayed_sync_view =
		mail_index_transaction_open_updated_view(mbox->delayed_sync_trans);

	mbox->delayed_sync_cache_view =
		mail_cache_view_open(mbox->box.cache, mbox->delayed_sync_view);
	mbox->delayed_sync_cache_trans =
		mail_cache_get_transaction(mbox->delayed_sync_cache_view,
					   mbox->delayed_sync_trans);
}

static int imapc_mailbox_commit_delayed_expunges(struct imapc_mailbox *mbox)
{
	struct mail_index_view *view = imapc_mailbox_get_sync_view(mbox);
	struct mail_index_transaction *trans;
	struct seq_range_iter iter;
	unsigned int n;
	uint32_t lseq, uid;
	int ret;

	trans = mail_index_transaction_begin(view,
			MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);

	seq_range_array_iter_init(&iter, &mbox->delayed_expunged_uids); n = 0;
	while (seq_range_array_iter_nth(&iter, n++, &uid)) {
		if (mail_index_lookup_seq(view, uid, &lseq))
			mail_index_expunge(trans, lseq);
	}
	array_clear(&mbox->delayed_expunged_uids);
	ret = mail_index_transaction_commit(&trans);
	if (ret < 0)
		mailbox_set_index_error(&mbox->box);
	return ret;
}

int imapc_mailbox_commit_delayed_trans(struct imapc_mailbox *mbox,
				       bool force, bool *changes_r)
{
	int ret = 0;

	*changes_r = FALSE;

	if (mbox->delayed_sync_view != NULL)
		mail_index_view_close(&mbox->delayed_sync_view);
	if (mbox->delayed_sync_trans == NULL)
		;
	else if (!mbox->selected && !force) {
		/* ignore any changes done during SELECT */
		mail_index_transaction_rollback(&mbox->delayed_sync_trans);
	} else {
		if (mail_index_transaction_commit(&mbox->delayed_sync_trans) < 0) {
			mailbox_set_index_error(&mbox->box);
			ret = -1;
		}
		*changes_r = TRUE;
	}
	mbox->delayed_sync_cache_trans = NULL;
	if (mbox->delayed_sync_cache_view != NULL)
		mail_cache_view_close(&mbox->delayed_sync_cache_view);

	if (array_count(&mbox->delayed_expunged_uids) > 0) {
		/* delayed expunges - commit them now in a separate
		   transaction. Reopen mbox->sync_view to see changes
		   committed in delayed_sync_trans. */
		if (mbox->sync_view != NULL)
			mail_index_view_close(&mbox->sync_view);
		if (imapc_mailbox_commit_delayed_expunges(mbox) < 0)
			ret = -1;
	}

	if (mbox->sync_view != NULL)
		mail_index_view_close(&mbox->sync_view);
	i_assert(mbox->delayed_sync_trans == NULL);
	i_assert(mbox->delayed_sync_view == NULL);
	i_assert(mbox->delayed_sync_cache_trans == NULL);
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
imapc_mailbox_index_expunge(struct imapc_mailbox *mbox, uint32_t uid)
{
	uint32_t lseq;

	if (mail_index_lookup_seq(mbox->sync_view, uid, &lseq))
		mail_index_expunge(mbox->delayed_sync_trans, lseq);
	else if (mail_index_lookup_seq(mbox->delayed_sync_view, uid, &lseq)) {
		/* this message exists only in this transaction. lib-index
		   can't currently handle expunging anything except the last
		   appended message in a transaction, and fixing it would be
		   quite a lot of trouble. so instead we'll just delay doing
		   this expunge until after the current transaction has been
		   committed. */
		seq_range_array_add(&mbox->delayed_expunged_uids, uid);
	} else {
		/* already expunged by another session */
	}
}

static void
imapc_mailbox_fetch_state_finish(struct imapc_mailbox *mbox)
{
	uint32_t lseq, uid, msg_count;

	if (mbox->sync_next_lseq == 0) {
		/* FETCH n:*, not 1:* */
		i_assert(mbox->state_fetched_success ||
			 (mbox->box.flags & MAILBOX_FLAG_SAVEONLY) != 0);
		return;
	}

	/* if we haven't seen FETCH reply for some messages at the end of
	   mailbox they've been externally expunged. */
	msg_count = mail_index_view_get_messages_count(mbox->delayed_sync_view);
	for (lseq = mbox->sync_next_lseq; lseq <= msg_count; lseq++) {
		mail_index_lookup_uid(mbox->delayed_sync_view, lseq, &uid);
		if (uid >= mbox->sync_uid_next) {
			/* another process already added new messages to index
			   that our IMAP connection hasn't seen yet */
			break;
		}
		imapc_mailbox_index_expunge(mbox, uid);
	}

	mbox->sync_next_lseq = 0;
	mbox->sync_next_rseq = 0;
	mbox->state_fetched_success = TRUE;
}

static void
imapc_mailbox_fetch_state_callback(const struct imapc_command_reply *reply,
				   void *context)
{
	struct imapc_mailbox *mbox = context;

	mbox->state_fetching_uid1 = FALSE;
	imapc_client_stop(mbox->storage->client->client);

	switch (reply->state) {
	case IMAPC_COMMAND_STATE_OK:
		imapc_mailbox_fetch_state_finish(mbox);
		break;
	case IMAPC_COMMAND_STATE_NO:
		imapc_copy_error_from_reply(mbox->storage, MAIL_ERROR_PARAMS, reply);
		break;
	case IMAPC_COMMAND_STATE_DISCONNECTED:
		mail_storage_set_internal_error(mbox->box.storage);

		break;
	default:
		mail_storage_set_critical(mbox->box.storage,
			"imapc: state FETCH failed: %s", reply->text_full);
		break;
	}
}

static void
imapc_mailbox_fetch_state(struct imapc_mailbox *mbox, uint32_t first_uid)
{
	struct imapc_command *cmd;

	if (mbox->exists_count == 0) {
		/* empty mailbox - no point in fetching anything.
		   just make sure everything is expunged in local index. */
		mbox->sync_next_lseq = 1;
		imapc_mailbox_init_delayed_trans(mbox);
		imapc_mailbox_fetch_state_finish(mbox);
		return;
	}
	if (mbox->state_fetching_uid1) {
		/* retrying after reconnection - don't send duplicate */
		return;
	}

	string_t *str = t_str_new(64);
	str_printfa(str, "UID FETCH %u:* (FLAGS", first_uid);
	if (imapc_mailbox_has_modseqs(mbox)) {
		str_append(str, " MODSEQ");
		mail_index_modseq_enable(mbox->box.index);
	}
	if (IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_GMAIL_MIGRATION)) {
		enum mailbox_info_flags flags;

		if (!mail_index_is_in_memory(mbox->box.index)) {
			/* these can be efficiently fetched among flags and
			   stored into cache */
			str_append(str, " X-GM-MSGID");
		}
		/* do this only for the \All mailbox */
		if (imapc_list_get_mailbox_flags(mbox->box.list,
						 mbox->box.name, &flags) == 0 &&
		    (flags & MAILBOX_SPECIALUSE_ALL) != 0)
			str_append(str, " X-GM-LABELS");

	}
	str_append_c(str, ')');

	cmd = imapc_client_mailbox_cmd(mbox->client_box,
		imapc_mailbox_fetch_state_callback, mbox);
	if (first_uid == 1) {
		mbox->sync_next_lseq = 1;
		mbox->sync_next_rseq = 1;
		mbox->state_fetched_success = FALSE;
		/* only the FETCH 1:* is retriable - others will be retried
		   by the 1:* after the reconnection */
		imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_RETRIABLE);
	}
	mbox->state_fetching_uid1 = first_uid == 1;
	imapc_command_send(cmd, str_c(str));
}

static void
imapc_untagged_exists(const struct imapc_untagged_reply *reply,
		      struct imapc_mailbox *mbox)
{
	struct mail_index_view *view;
	uint32_t exists_count = reply->num;
	const struct mail_index_header *hdr;

	if (mbox == NULL)
		return;
	if (mbox->exists_received &&
	    IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_NO_MSN_UPDATES)) {
		/* ignore all except the first EXISTS reply (returned by
		   SELECT) */
		return;
	}

	mbox->exists_count = exists_count;
	mbox->exists_received = TRUE;

	view = mbox->delayed_sync_view;
	if (view == NULL)
		view = imapc_mailbox_get_sync_view(mbox);

	if (mbox->selecting) {
		/* We don't know the latest flags, refresh them. */
		imapc_mailbox_fetch_state(mbox, 1);
	} else if (mbox->sync_fetch_first_uid != 1) {
		hdr = mail_index_get_header(view);
		mbox->sync_fetch_first_uid = hdr->next_uid;
		imapc_mailbox_fetch_state(mbox, hdr->next_uid);
	}
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
	if (fetch_uid != 0 && mbox->state_fetched_success &&
	    (IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_FETCH_MSN_WORKAROUNDS) ||
	     IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_NO_MSN_UPDATES))) {
		/* if we know the UID, use own own generated rseq instead of
		   the potentially broken rseq that the server sent.
		   Skip this during the initial FETCH 1:* (UID ..) handling,
		   or we can't detect duplicate UIDs and will instead
		   assert-crash later on. */
		uint32_t fixed_rseq;

		if (imapc_msgmap_uid_to_rseq(msgmap, fetch_uid, &fixed_rseq))
			rseq = fixed_rseq;
		else if (fetch_uid >= imapc_msgmap_uidnext(msgmap) &&
			 rseq <= msg_count) {
			/* The current rseq is wrong. Lets hope that the
			   correct rseq is the next new one. This happens
			   especially with no-msn-updates when mails have been
			   expunged and new mails arrive in the same session. */
			rseq = msg_count+1;
		}
	}

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
		if (uid < mbox->min_append_uid ||
		    uid < mail_index_get_header(mbox->delayed_sync_view)->next_uid) {
			/* message is already added to index */
		} else {
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
	struct imapc_fetch_request *const *fetch_requestp;
	struct imapc_mail *const *mailp;
	const struct imap_arg *list, *flags_list, *modseq_list;
	const char *atom, *guid = NULL;
	const struct mail_index_record *rec = NULL;
	enum mail_flags flags;
	uint32_t fetch_uid, uid;
	uint64_t modseq = 0;
	unsigned int i, j;
	ARRAY_TYPE(const_string) keywords = ARRAY_INIT;
	bool seen_flags = FALSE, have_labels = FALSE;

	if (mbox == NULL || rseq == 0 || !imap_arg_get_list(reply->args, &list))
		return;

	fetch_uid = 0; flags = 0;
	for (i = 0; list[i].type != IMAP_ARG_EOL; i += 2) {
		if (!imap_arg_get_atom(&list[i], &atom) ||
		    list[i+1].type == IMAP_ARG_EOL)
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
		} else if (strcasecmp(atom, "MODSEQ") == 0 &&
			   imapc_mailbox_has_modseqs(mbox)) {
			/* (modseq-number) */
			if (!imap_arg_get_list(&list[i+1], &modseq_list))
				return;
			if (!imap_arg_get_atom(&modseq_list[0], &atom) ||
			    str_to_uint64(atom, &modseq) < 0 ||
			    modseq_list[1].type != IMAP_ARG_EOL)
				return;
		} else if (strcasecmp(atom, "X-GM-MSGID") == 0 &&
			   !mbox->initial_sync_done) {
			if (imap_arg_get_atom(&list[i+1], &atom))
				guid = atom;
		} else if (strcasecmp(atom, "X-GM-LABELS") == 0 &&
			   IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_GMAIL_MIGRATION)) {
			if (!imap_arg_get_list(&list[i+1], &flags_list))
				return;
			for (j = 0; flags_list[j].type != IMAP_ARG_EOL; j++) {
				if (!imap_arg_get_astring(&flags_list[j], &atom))
					return;
				if (strcasecmp(atom, "\\Muted") != 0)
					have_labels = TRUE;
			}
		}
	}
	if (fetch_uid == 0 &&
	    IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_NO_MSN_UPDATES)) {
		/* UID missing and we're not tracking MSNs */
		return;
	}

	imapc_mailbox_init_delayed_trans(mbox);
	if (imapc_mailbox_msgmap_update(mbox, rseq, fetch_uid,
					&lseq, &uid) < 0 || uid == 0)
		return;

	if ((flags & MAIL_RECENT) == 0 && mbox->highest_nonrecent_uid < uid) {
		/* remember for STATUS_FIRST_RECENT_UID */
		mbox->highest_nonrecent_uid = uid;
	}
	/* FIXME: we should ideally also pass these through so they show up
	   to clients. */
	flags &= ~MAIL_RECENT;

	/* if this is a reply to some FETCH request, update the mail's fields */
	array_foreach(&mbox->fetch_requests, fetch_requestp) {
		array_foreach(&(*fetch_requestp)->mails, mailp) {
			struct imapc_mail *mail = *mailp;

			if (mail->imail.mail.mail.uid == uid)
				imapc_mail_fetch_update(mail, reply, list);
		}
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
		while (mbox->sync_next_lseq < lseq) {
			mail_index_lookup_uid(mbox->delayed_sync_view,
					      mbox->sync_next_lseq, &uid);
			imapc_mailbox_index_expunge(mbox, uid);
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

		if (have_labels) {
			/* add keyword for mails that have GMail labels.
			   this can be used for "All Mail" mailbox migrations
			   with dsync */
			atom = "$GMailHaveLabels";
			array_append(&keywords, &atom, 1);
		}

		array_append_zero(&keywords);
		kw = mail_index_keywords_create(mbox->box.index,
						array_first(&keywords));
		if (!keywords_are_equal(kw, &old_kws)) {
			mail_index_update_keywords(mbox->delayed_sync_trans,
						   lseq, MODIFY_REPLACE, kw);
		}
		mail_index_keywords_unref(&kw);
	}
	if (modseq != 0) {
		if (mail_index_modseq_lookup(mbox->delayed_sync_view, lseq) < modseq)
			mail_index_update_modseq(mbox->delayed_sync_trans, lseq, modseq);
		array_idx_set(&mbox->rseq_modseqs, rseq-1, &modseq);
	}
	if (guid != NULL) {
		struct index_mailbox_context *ibox = INDEX_STORAGE_CONTEXT(&mbox->box);
		const enum index_cache_field guid_cache_idx =
			ibox->cache_fields[MAIL_CACHE_GUID].idx;

		if (mail_cache_field_can_add(mbox->delayed_sync_cache_trans,
					     lseq, guid_cache_idx)) {
			mail_cache_add(mbox->delayed_sync_cache_trans, lseq,
				       guid_cache_idx, guid, strlen(guid)+1);
		}
	}
	imapc_mailbox_idle_notify(mbox);
}

static void imapc_untagged_expunge(const struct imapc_untagged_reply *reply,
				   struct imapc_mailbox *mbox)
{
	struct imapc_msgmap *msgmap;
	uint32_t uid, rseq = reply->num;
	
	if (mbox == NULL || rseq == 0 ||
	    IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_NO_MSN_UPDATES))
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
	if (array_is_created(&mbox->rseq_modseqs))
		array_delete(&mbox->rseq_modseqs, rseq-1, 1);

	imapc_mailbox_init_delayed_trans(mbox);
	imapc_mailbox_index_expunge(mbox, uid);
	imapc_mailbox_idle_notify(mbox);
}

static void
imapc_untagged_esearch_gmail_pop3(const struct imap_arg *args,
				  struct imapc_mailbox *mbox)
{
	struct imapc_msgmap *msgmap;
	const char *atom;
	struct seq_range_iter iter;
	ARRAY_TYPE(seq_range) rseqs;
	unsigned int n;
	uint32_t rseq, lseq, uid;
	ARRAY_TYPE(keyword_indexes) keywords;
	struct mail_keywords *kw;
	unsigned int pop3_deleted_kw_idx;

	i_free_and_null(mbox->sync_gmail_pop3_search_tag);

	/* It should contain ALL <seqset> or nonexistent if nothing matched */
	if (args[0].type == IMAP_ARG_EOL)
		return;
	t_array_init(&rseqs, 64);
	if (!imap_arg_atom_equals(&args[0], "ALL") ||
	    !imap_arg_get_atom(&args[1], &atom) ||
	    imap_seq_set_nostar_parse(atom, &rseqs) < 0) {
		i_error("Invalid gmail-pop3 ESEARCH reply");
		return;
	}

	mail_index_keyword_lookup_or_create(mbox->box.index,
		mbox->storage->set->pop3_deleted_flag, &pop3_deleted_kw_idx);

	t_array_init(&keywords, 1);
	array_append(&keywords, &pop3_deleted_kw_idx, 1);
	kw = mail_index_keywords_create_from_indexes(mbox->box.index, &keywords);

	msgmap = imapc_client_mailbox_get_msgmap(mbox->client_box);
	seq_range_array_iter_init(&iter, &rseqs); n = 0;
	while (seq_range_array_iter_nth(&iter, n++, &rseq)) {
		if (rseq > imapc_msgmap_count(msgmap)) {
			/* we haven't even seen this message yet */
			break;
		}
		uid = imapc_msgmap_rseq_to_uid(msgmap, rseq);
		if (!mail_index_lookup_seq(mbox->delayed_sync_view,
					   uid, &lseq))
			continue;

		/* add the pop3_deleted_flag */
		mail_index_update_keywords(mbox->delayed_sync_trans,
					   lseq, MODIFY_ADD, kw);
	}
	mail_index_keywords_unref(&kw);
}

static void imapc_untagged_search(const struct imapc_untagged_reply *reply,
				  struct imapc_mailbox *mbox)
{
	if (mbox != NULL)
		imapc_search_reply_search(reply->args, mbox);
}

static void imapc_untagged_esearch(const struct imapc_untagged_reply *reply,
				   struct imapc_mailbox *mbox)
{
	const struct imap_arg *tag_list;
	const char *str;

	if (mbox == NULL || !imap_arg_get_list(reply->args, &tag_list))
		return;

	/* ESEARCH begins with (TAG <tag>) */
	if (!imap_arg_atom_equals(&tag_list[0], "TAG") ||
	    !imap_arg_get_string(&tag_list[1], &str) ||
	    tag_list[2].type != IMAP_ARG_EOL)
		return;

	/* for now the only ESEARCH reply that we have is for getting GMail's
	   list of hidden POP3 messages. */
	if (mbox->sync_gmail_pop3_search_tag != NULL &&
	    strcmp(mbox->sync_gmail_pop3_search_tag, str) == 0)
		imapc_untagged_esearch_gmail_pop3(reply->args+1, mbox);
	else
		imapc_search_reply_esearch(reply->args+1, mbox);
}

static void imapc_sync_uid_validity(struct imapc_mailbox *mbox)
{
	const struct mail_index_header *hdr;

	imapc_mailbox_init_delayed_trans(mbox);
	hdr = mail_index_get_header(mbox->delayed_sync_view);
	if (hdr->uid_validity != mbox->sync_uid_validity &&
	    mbox->sync_uid_validity != 0) {
		if (hdr->uid_validity != 0) {
			/* uidvalidity changed, reset the entire mailbox */
			mail_index_reset(mbox->delayed_sync_trans);
			mbox->sync_fetch_first_uid = 1;
			/* The reset needs to be committed before FETCH 1:*
			   results are received. */
			bool changes;
			if (imapc_mailbox_commit_delayed_trans(mbox, TRUE, &changes) < 0)
				mail_index_mark_corrupted(mbox->box.index);
			imapc_mailbox_init_delayed_trans(mbox);
		}
		mail_index_update_header(mbox->delayed_sync_trans,
			offsetof(struct mail_index_header, uid_validity),
			&mbox->sync_uid_validity,
			sizeof(mbox->sync_uid_validity), TRUE);
	}
}

static void
imapc_resp_text_uidvalidity(const struct imapc_untagged_reply *reply,
			    struct imapc_mailbox *mbox)
{
	uint32_t uid_validity;

	if (mbox == NULL ||
	    str_to_uint32(reply->resp_text_value, &uid_validity) < 0 ||
	    uid_validity == 0)
		return;

	if (mbox->sync_uid_validity != uid_validity) {
		mbox->sync_uid_validity = uid_validity;
		imapc_mail_cache_free(&mbox->prev_mail_cache);
		imapc_sync_uid_validity(mbox);
	}
}

static void
imapc_resp_text_uidnext(const struct imapc_untagged_reply *reply,
			struct imapc_mailbox *mbox)
{
	uint32_t uid_next;

	if (mbox == NULL ||
	    str_to_uint32(reply->resp_text_value, &uid_next) < 0)
		return;

	mbox->sync_uid_next = uid_next;
}

static void
imapc_resp_text_highestmodseq(const struct imapc_untagged_reply *reply,
			      struct imapc_mailbox *mbox)
{
	uint64_t highestmodseq;

	if (mbox == NULL ||
	    str_to_uint64(reply->resp_text_value, &highestmodseq) < 0)
		return;

	mbox->sync_highestmodseq = highestmodseq;
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
	imapc_mailbox_register_untagged(mbox, "SEARCH",
					imapc_untagged_search);
	imapc_mailbox_register_untagged(mbox, "ESEARCH",
					imapc_untagged_esearch);
	imapc_mailbox_register_resp_text(mbox, "UIDVALIDITY",
					 imapc_resp_text_uidvalidity);
	imapc_mailbox_register_resp_text(mbox, "UIDNEXT",
					 imapc_resp_text_uidnext);
	imapc_mailbox_register_resp_text(mbox, "HIGHESTMODSEQ",
					 imapc_resp_text_highestmodseq);
	imapc_mailbox_register_resp_text(mbox, "PERMANENTFLAGS",
					 imapc_resp_text_permanentflags);
}
