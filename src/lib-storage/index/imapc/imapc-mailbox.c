/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "imap-arg.h"
#include "imap-util.h"
#include "imapc-client.h"
#include "imapc-seqmap.h"
#include "imapc-storage.h"

#define NOTIFY_DELAY_MSECS 500

static void imapc_mailbox_init_delayed_trans(struct imapc_mailbox *mbox)
{
	if (mbox->delayed_sync_trans != NULL)
		return;

	mbox->delayed_sync_trans =
		mail_index_transaction_begin(mbox->box.view,
					MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	mbox->delayed_sync_view =
		mail_index_transaction_open_updated_view(mbox->delayed_sync_trans);
}

static void
imapc_newmsgs_callback(const struct imapc_command_reply *reply,
		       void *context)
{
	struct imapc_mailbox *mbox = context;

	if (reply->state == IMAPC_COMMAND_STATE_OK)
		;
	else if (reply->state == IMAPC_COMMAND_STATE_NO) {
		imapc_copy_error_from_reply(mbox->storage, MAIL_ERROR_PARAMS,
					    reply);
	} else {
		mail_storage_set_critical(&mbox->storage->storage,
			"imapc: Command failed: %s", reply->text_full);
	}
	if (mbox->opening)
		imapc_client_stop(mbox->storage->client);
}

static void imapc_untagged_exists(const struct imapc_untagged_reply *reply,
				  struct imapc_mailbox *mbox)
{
	uint32_t rcount = reply->num;
	const struct mail_index_header *hdr;
	struct imapc_seqmap *seqmap;
	uint32_t next_lseq, next_rseq;

	if (mbox == NULL)
		return;

	seqmap = imapc_client_mailbox_get_seqmap(mbox->client_box);
	next_lseq = mail_index_view_get_messages_count(mbox->box.view) + 1;
	next_rseq = imapc_seqmap_lseq_to_rseq(seqmap, next_lseq);
	if (next_rseq > rcount)
		return;

	hdr = mail_index_get_header(mbox->box.view);

	mbox->new_msgs = TRUE;
	imapc_client_mailbox_cmdf(mbox->client_box, imapc_newmsgs_callback,
				  mbox, "UID FETCH %u:* FLAGS", hdr->next_uid);
}

static void imapc_mailbox_idle_timeout(struct imapc_mailbox *mbox)
{
	timeout_remove(&mbox->to_idle);
	if (mbox->box.notify_callback != NULL)
		mbox->box.notify_callback(&mbox->box, mbox->box.notify_context);
}

static void imapc_mailbox_idle_notify(struct imapc_mailbox *mbox)
{
	if (mbox->box.notify_callback != NULL && mbox->to_idle == NULL) {
		mbox->to_idle =
			timeout_add(NOTIFY_DELAY_MSECS,
				    imapc_mailbox_idle_timeout, mbox);
	}
}

static void imapc_untagged_fetch(const struct imapc_untagged_reply *reply,
				 struct imapc_mailbox *mbox)
{
	uint32_t seq = reply->num;
	struct imapc_seqmap *seqmap;
	const struct imap_arg *list, *flags_list;
	const char *atom;
	const struct mail_index_record *rec;
	enum mail_flags flags;
	uint32_t uid, old_count;
	unsigned int i, j;
	ARRAY_TYPE(const_string) keywords = ARRAY_INIT;
	bool seen_flags = FALSE;

	if (mbox == NULL || seq == 0 || !imap_arg_get_list(reply->args, &list))
		return;

	uid = 0; flags = 0;
	for (i = 0; list[i].type != IMAP_ARG_EOL; i += 2) {
		if (!imap_arg_get_atom(&list[i], &atom))
			return;

		if (strcasecmp(atom, "UID") == 0) {
			if (!imap_arg_get_atom(&list[i+1], &atom) ||
			    str_to_uint32(atom, &uid) < 0)
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

	seqmap = imapc_client_mailbox_get_seqmap(mbox->client_box);
	seq = imapc_seqmap_rseq_to_lseq(seqmap, seq);

	if (mbox->cur_fetch_mail != NULL && mbox->cur_fetch_mail->seq == seq) {
		i_assert(uid == 0 || mbox->cur_fetch_mail->uid == uid);
		imapc_fetch_mail_update(mbox->cur_fetch_mail, list);
	}

	imapc_mailbox_init_delayed_trans(mbox);
	old_count = mail_index_view_get_messages_count(mbox->delayed_sync_view);
	if (seq > old_count) {
		if (uid == 0)
			return;
		i_assert(seq == old_count + 1);
		mail_index_append(mbox->delayed_sync_trans, uid, &seq);
	}
	rec = mail_index_lookup(mbox->delayed_sync_view, seq);
	if (seen_flags && rec->flags != flags) {
		mail_index_update_flags(mbox->delayed_sync_trans, seq,
					MODIFY_REPLACE, flags);
	}
	if (seen_flags) {
		struct mail_keywords *kw;

		(void)array_append_space(&keywords);
		kw = mail_index_keywords_create(mbox->box.index,
						array_idx(&keywords, 0));
		mail_index_update_keywords(mbox->delayed_sync_trans, seq,
					   MODIFY_REPLACE, kw);
		mail_index_keywords_unref(&kw);
	}
	imapc_mailbox_idle_notify(mbox);
}

static void imapc_untagged_expunge(const struct imapc_untagged_reply *reply,
				   struct imapc_mailbox *mbox)
{
	struct imapc_seqmap *seqmap;
	uint32_t lseq, rseq = reply->num;

	if (mbox == NULL || rseq == 0)
		return;

	seqmap = imapc_client_mailbox_get_seqmap(mbox->client_box);
	lseq = imapc_seqmap_rseq_to_lseq(seqmap, rseq);
	imapc_seqmap_expunge(seqmap, rseq);

	imapc_mailbox_init_delayed_trans(mbox);
	mail_index_expunge(mbox->delayed_sync_trans, lseq);

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

	imapc_mailbox_init_delayed_trans(mbox);
	mail_index_update_header(mbox->delayed_sync_trans,
		offsetof(struct mail_index_header, uid_validity),
		&uid_validity, sizeof(uid_validity), TRUE);
}

static void
imapc_resp_text_uidnext(const struct imapc_untagged_reply *reply,
			struct imapc_mailbox *mbox)
{
	uint32_t uid_next;

	if (mbox == NULL || reply->resp_text_value == NULL ||
	    str_to_uint32(reply->resp_text_value, &uid_next) < 0)
		return;

	imapc_mailbox_init_delayed_trans(mbox);
	mail_index_update_header(mbox->delayed_sync_trans,
				 offsetof(struct mail_index_header, next_uid),
				 &uid_next, sizeof(uid_next), FALSE);
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
