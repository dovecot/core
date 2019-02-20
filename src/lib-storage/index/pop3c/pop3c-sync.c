/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "bsearch-insert-pos.h"
#include "str.h"
#include "sort.h"
#include "strnum.h"
#include "index-mail.h"
#include "pop3c-client.h"
#include "pop3c-storage.h"
#include "pop3c-sync.h"
#include "mailbox-recent-flags.h"

struct pop3c_sync_msg {
	uint32_t seq;
	const char *uidl;
};
ARRAY_DEFINE_TYPE(pop3c_sync_msg, struct pop3c_sync_msg);

int pop3c_sync_get_uidls(struct pop3c_mailbox *mbox)
{
	ARRAY_TYPE(const_string) uidls;
	struct istream *input;
	const char *error, *cline;
	char *line, *p;
	unsigned int seq, line_seq;

	if (mbox->msg_uidls != NULL)
		return 0;
	if ((pop3c_client_get_capabilities(mbox->client) &
	     POP3C_CAPABILITY_UIDL) == 0) {
		mail_storage_set_error(mbox->box.storage,
				       MAIL_ERROR_NOTPOSSIBLE,
				       "UIDLs not supported by server");
		return -1;
	}

	if (pop3c_client_cmd_stream(mbox->client, "UIDL\r\n",
				    &input, &error) < 0) {
		mailbox_set_critical(&mbox->box, "UIDL failed: %s", error);
		return -1;
	}

	mbox->uidl_pool = pool_alloconly_create("POP3 UIDLs", 1024*32);
	p_array_init(&uidls, mbox->uidl_pool, 64); seq = 0;
	while ((line = i_stream_read_next_line(input)) != NULL) {
		seq++;
		p = strchr(line, ' ');
		if (p == NULL) {
			mailbox_set_critical(&mbox->box,
				"Invalid UIDL line: %s", line);
			break;
		}
		*p++ = '\0';
		if (str_to_uint(line, &line_seq) < 0 || line_seq != seq) {
			mailbox_set_critical(&mbox->box,
				"Unexpected UIDL seq: %s != %u", line, seq);
			break;
		}

		cline = p_strdup(mbox->uidl_pool, p);
		array_push_back(&uidls, &cline);
	}
	i_stream_destroy(&input);
	if (line != NULL) {
		pool_unref(&mbox->uidl_pool);
		return -1;
	}
	if (seq == 0) {
		/* make msg_uidls non-NULL */
		array_append_zero(&uidls);
	}
	mbox->msg_uidls = array_front(&uidls);
	mbox->msg_count = seq;
	return 0;
}

int pop3c_sync_get_sizes(struct pop3c_mailbox *mbox)
{
	struct istream *input;
	const char *error;
	char *line, *p;
	unsigned int seq, line_seq;

	i_assert(mbox->msg_sizes == NULL);

	if (mbox->msg_uidls == NULL) {
		if (pop3c_sync_get_uidls(mbox) < 0)
			return -1;
	}
	if (mbox->msg_count == 0) {
		mbox->msg_sizes = i_new(uoff_t, 1);
		return 0;
	}

	if (pop3c_client_cmd_stream(mbox->client, "LIST\r\n",
				    &input, &error) < 0) {
		mailbox_set_critical(&mbox->box, "LIST failed: %s", error);
		return -1;
	}

	mbox->msg_sizes = i_new(uoff_t, mbox->msg_count); seq = 0;
	while ((line = i_stream_read_next_line(input)) != NULL) {
		if (++seq > mbox->msg_count) {
			mailbox_set_critical(&mbox->box,
				"Too much data in LIST: %s", line);
			break;
		}
		p = strchr(line, ' ');
		if (p == NULL) {
			mailbox_set_critical(&mbox->box,
				"Invalid LIST line: %s", line);
			break;
		}
		*p++ = '\0';
		if (str_to_uint(line, &line_seq) < 0 || line_seq != seq) {
			mailbox_set_critical(&mbox->box,
				"Unexpected LIST seq: %s != %u", line, seq);
			break;
		}
		if (str_to_uoff(p, &mbox->msg_sizes[seq-1]) < 0) {
			mailbox_set_critical(&mbox->box,
				"Invalid LIST size: %s", p);
			break;
		}
	}
	i_stream_destroy(&input);
	if (line != NULL) {
		i_free_and_null(mbox->msg_sizes);
		return -1;
	}
	return 0;
}

static void
pop3c_get_local_msgs(pool_t pool, ARRAY_TYPE(pop3c_sync_msg) *local_msgs,
		     uint32_t messages_count,
		     struct mail_cache_view *cache_view,
		     unsigned int cache_idx)
{
	string_t *str = t_str_new(128);
	struct pop3c_sync_msg msg;
	uint32_t seq;

	i_zero(&msg);
	for (seq = 1; seq <= messages_count; seq++) {
		str_truncate(str, 0);
		if (mail_cache_lookup_field(cache_view, str, seq,
					    cache_idx) > 0)
			msg.uidl = p_strdup(pool, str_c(str));
		msg.seq = seq;
		array_idx_set(local_msgs, seq-1, &msg);
	}
}

static void
pop3c_get_remote_msgs(ARRAY_TYPE(pop3c_sync_msg) *remote_msgs,
		      struct pop3c_mailbox *mbox)
{
	struct pop3c_sync_msg *msg;
	uint32_t seq;

	for (seq = 1; seq <= mbox->msg_count; seq++) {
		msg = array_append_space(remote_msgs);
		msg->seq = seq;
		msg->uidl = mbox->msg_uidls[seq-1];
	}
}

static int pop3c_sync_msg_uidl_cmp(const struct pop3c_sync_msg *msg1,
				   const struct pop3c_sync_msg *msg2)
{
	return null_strcmp(msg1->uidl, msg2->uidl);
}

static void
pop3c_sync_messages(struct pop3c_mailbox *mbox,
		    struct mail_index_view *sync_view,
		    struct mail_index_transaction *sync_trans,
		    struct mail_cache_view *cache_view)
{
	struct index_mailbox_context *ibox =
		INDEX_STORAGE_CONTEXT(&mbox->box);
	const struct mail_index_header *hdr;
	struct mail_cache_transaction_ctx *cache_trans;
	ARRAY_TYPE(pop3c_sync_msg) local_msgs, remote_msgs;
	const struct pop3c_sync_msg *lmsg, *rmsg;
	uint32_t seq1, seq2, next_uid;
	unsigned int lidx, ridx, lcount, rcount;
	unsigned int cache_idx = ibox->cache_fields[MAIL_CACHE_POP3_UIDL].idx;
	pool_t pool;

	i_assert(mbox->msg_uids == NULL);

	/* set our uidvalidity */
	hdr = mail_index_get_header(sync_view);
	if (hdr->uid_validity == 0) {
		uint32_t uid_validity = ioloop_time;
		mail_index_update_header(sync_trans,
			offsetof(struct mail_index_header, uid_validity),
			&uid_validity, sizeof(uid_validity), TRUE);
	}

	pool = pool_alloconly_create(MEMPOOL_GROWING"pop3c sync", 10240);
	p_array_init(&local_msgs, pool, hdr->messages_count);
	pop3c_get_local_msgs(pool, &local_msgs, hdr->messages_count,
			     cache_view, cache_idx);
	p_array_init(&remote_msgs, pool, mbox->msg_count);
	pop3c_get_remote_msgs(&remote_msgs, mbox);

	/* sort the messages by UIDLs, because some servers reorder messages */
	array_sort(&local_msgs, pop3c_sync_msg_uidl_cmp);
	array_sort(&remote_msgs, pop3c_sync_msg_uidl_cmp);

	/* skip over existing messages with matching UIDLs and expunge the ones
	   that no longer exist in remote. */
	mbox->msg_uids = mbox->msg_count == 0 ?
		i_new(uint32_t, 1) : /* avoid malloc(0) assert */
		i_new(uint32_t, mbox->msg_count);
	cache_trans = mail_cache_get_transaction(cache_view, sync_trans);

	lmsg = array_get(&local_msgs, &lcount);
	rmsg = array_get(&remote_msgs, &rcount);
	next_uid = hdr->next_uid;
	lidx = ridx = 0;
	while (lidx < lcount || ridx < rcount) {
		uint32_t lseq = lidx < lcount ? lmsg[lidx].seq : 0;
		uint32_t rseq = ridx < rcount ? rmsg[ridx].seq : 0;
		int ret;

		if (lidx >= lcount)
			ret = 1;
		else if (ridx >= rcount || lmsg[lidx].uidl == NULL)
			ret = -1;
		else
			ret = strcmp(lmsg[lidx].uidl, rmsg[ridx].uidl);
		if (ret < 0) {
			/* message expunged in remote, or we didn't have a
			   local message's UIDL in cache. */
			mail_index_expunge(sync_trans, lseq);
			lidx++;
		} else if (ret > 0) {
			/* new message in remote */
			i_assert(mbox->msg_uids[rseq-1] == 0);
			mbox->msg_uids[rseq-1] = next_uid;
			mail_index_append(sync_trans, next_uid++, &lseq);
			mail_cache_add(cache_trans, lseq, cache_idx,
				       rmsg[ridx].uidl,
				       strlen(rmsg[ridx].uidl));
			ridx++;
		} else {
			/* UIDL matched */
			i_assert(mbox->msg_uids[rseq-1] == 0);
			mail_index_lookup_uid(sync_view, lseq,
					      &mbox->msg_uids[rseq-1]);
			lidx++;
			ridx++;
		}
	}

	/* mark the newly seen messages as recent */
	if (mail_index_lookup_seq_range(sync_view, hdr->first_recent_uid,
					hdr->next_uid, &seq1, &seq2))
		mailbox_recent_flags_set_seqs(&mbox->box, sync_view, seq1, seq2);
	pool_unref(&pool);
}

int pop3c_sync(struct pop3c_mailbox *mbox)
{
        struct mail_index_sync_ctx *index_sync_ctx;
	struct mail_index_view *sync_view, *trans_view;
	struct mail_index_transaction *sync_trans;
	struct mail_index_sync_rec sync_rec;
	struct mail_cache_view *cache_view = NULL;
	enum mail_index_sync_flags sync_flags;
	unsigned int idx;
	string_t *str;
	const char *reply;
	int ret;
	bool deletions = FALSE;

	if (pop3c_sync_get_uidls(mbox) < 0)
		return -1;

	sync_flags = index_storage_get_sync_flags(&mbox->box) |
		MAIL_INDEX_SYNC_FLAG_FLUSH_DIRTY;

	ret = mail_index_sync_begin(mbox->box.index, &index_sync_ctx,
				    &sync_view, &sync_trans, sync_flags);
	if (ret <= 0) {
		if (ret < 0)
			mailbox_set_index_error(&mbox->box);
		return ret;
	}

	if (mbox->msg_uids == NULL) {
		trans_view = mail_index_transaction_open_updated_view(sync_trans);
		cache_view = mail_cache_view_open(mbox->box.cache, trans_view);
		pop3c_sync_messages(mbox, sync_view, sync_trans, cache_view);
	}

	/* mark expunges messages as deleted in this pop3 session,
	   if those exist */
	str = t_str_new(32);
	while (mail_index_sync_next(index_sync_ctx, &sync_rec)) {
		if (sync_rec.type != MAIL_INDEX_SYNC_TYPE_EXPUNGE)
			continue;

		if (!bsearch_insert_pos(&sync_rec.uid1, mbox->msg_uids,
					mbox->msg_count, sizeof(uint32_t),
					uint32_cmp, &idx)) {
			/* no such messages in this session */
			continue;
		}
		for (; idx < mbox->msg_count; idx++) {
			i_assert(mbox->msg_uids[idx] >= sync_rec.uid1);
			if (mbox->msg_uids[idx] > sync_rec.uid2)
				break;

			str_truncate(str, 0);
			str_printfa(str, "DELE %u\r\n", idx+1);
			pop3c_client_cmd_line_async_nocb(mbox->client, str_c(str));
			deletions = TRUE;
		}
	}

	if (mail_index_sync_commit(&index_sync_ctx) < 0) {
		mailbox_set_index_error(&mbox->box);
		return -1;
	}
	if (cache_view != NULL) {
		mail_cache_view_close(&cache_view);
		mail_index_view_close(&trans_view);
	}
	if (deletions) {
		if (pop3c_client_cmd_line(mbox->client, "QUIT\r\n",
					  &reply) < 0) {
			mail_storage_set_error(mbox->box.storage,
					       MAIL_ERROR_TEMP, reply);
			return -1;
		}
	}
	return 0;
}

struct mailbox_sync_context *
pop3c_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct pop3c_mailbox *mbox = POP3C_MAILBOX(box);
	int ret = 0;

	if ((flags & MAILBOX_SYNC_FLAG_FULL_READ) != 0 &&
	    mbox->msg_uidls == NULL) {
		/* FIXME: reconnect */
	}

	ret = pop3c_sync(mbox);
	return index_mailbox_sync_init(box, flags, ret < 0);
}
