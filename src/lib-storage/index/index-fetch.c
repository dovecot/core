/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-index-modseq.h"
#include "index-storage.h"
#include "index-mail.h"

void index_storage_get_seq_range(struct mailbox *box,
				 uint32_t uid1, uint32_t uid2,
				 uint32_t *seq1_r, uint32_t *seq2_r)
{
	mail_index_lookup_seq_range(box->view, uid1, uid2, seq1_r, seq2_r);
}

void index_storage_get_uid_range(struct mailbox *box,
				 const ARRAY_TYPE(seq_range) *seqs,
				 ARRAY_TYPE(seq_range) *uids)
{
	const struct seq_range *range;
	unsigned int i, count;
	uint32_t seq, uid;

	range = array_get(seqs, &count);
	for (i = 0; i < count; i++) {
		if (range[i].seq2 == (uint32_t)-1) {
			i_assert(count == i-1);
			mail_index_lookup_uid(box->view, range[i].seq1, &uid);
			seq_range_array_add_range(uids, uid, (uint32_t)-1);
			break;
		}
		for (seq = range[i].seq1; seq <= range[i].seq2; seq++) {
			mail_index_lookup_uid(box->view, seq, &uid);
			seq_range_array_add(uids, 0, uid);
		}
	}
}

static void
add_expunges(ARRAY_TYPE(seq_range) *expunged_uids, uint32_t min_uid,
	     const struct mail_transaction_expunge *src, size_t src_size)
{
	const struct mail_transaction_expunge *end;

	end = src + src_size / sizeof(*src);
	for (; src != end; src++) {
		if (src->uid2 >= min_uid) {
			seq_range_array_add_range(expunged_uids,
						  src->uid1, src->uid2);
		}
	}
}

static void
add_guid_expunges(ARRAY_TYPE(seq_range) *expunged_uids, uint32_t min_uid,
		  const struct mail_transaction_expunge_guid *src,
		  size_t src_size)
{
	const struct mail_transaction_expunge_guid *end;

	end = src + src_size / sizeof(*src);
	for (; src != end; src++) {
		if (src->uid >= min_uid)
			seq_range_array_add(expunged_uids, 0, src->uid);
	}
}

static int
index_storage_get_expunges_init(struct mailbox *box, uint64_t prev_modseq,
				struct mail_transaction_log_view **log_view_r,
				uint32_t *tail_seq_r)
{
	struct mail_transaction_log_view *log_view;
	uint32_t log_seq, tail_seq = 0;
	uoff_t log_offset;
	bool reset;
	int ret;

	if (!mail_index_modseq_get_next_log_offset(box->view, prev_modseq,
						   &log_seq, &log_offset)) {
		log_seq = 1;
		log_offset = 0;
	}
	if (log_seq > box->view->log_file_head_seq ||
	    (log_seq == box->view->log_file_head_seq &&
	     log_offset >= box->view->log_file_head_offset)) {
		/* we haven't seen this high expunges at all */
		return 1;
	}

	log_view = mail_transaction_log_view_open(box->index->log);
	ret = mail_transaction_log_view_set(log_view, log_seq, log_offset,
					    box->view->log_file_head_seq,
					    box->view->log_file_head_offset,
					    &reset);
	if (ret == 0) {
		mail_transaction_log_get_tail(box->index->log, &tail_seq);
		i_assert(tail_seq > log_seq);
		ret = mail_transaction_log_view_set(log_view, tail_seq, 0,
					box->view->log_file_head_seq,
					box->view->log_file_head_offset,
					&reset);
		i_assert(ret != 0);
	}
	if (ret <= 0) {
		mail_transaction_log_view_close(&log_view);
		return -1;
	}

	*log_view_r = log_view;
	*tail_seq_r = tail_seq;
	return 0;
}

static void
index_storage_get_expunged_guids(struct mail_transaction_log_view *log_view,
				 ARRAY_TYPE(seq_range) *expunged_uids,
				 ARRAY_TYPE(mailbox_expunge_rec) *expunges)
{
	const struct mail_transaction_header *thdr;
	const void *tdata;
	const struct mail_transaction_expunge_guid *rec, *end;
	struct mailbox_expunge_rec *expunge;
	struct seq_range_iter iter;
	unsigned int n;
	uint32_t uid;

	while (mail_transaction_log_view_next(log_view, &thdr, &tdata) > 0) {
		if ((thdr->type & MAIL_TRANSACTION_TYPE_MASK) !=
		    MAIL_TRANSACTION_EXPUNGE_GUID)
			continue;

		rec = tdata;
		end = rec + thdr->size / sizeof(*rec);
		for (; rec != end; rec++) {
			if (!seq_range_exists(expunged_uids, rec->uid))
				continue;
			seq_range_array_remove(expunged_uids, rec->uid);

			expunge = array_append_space(expunges);
			expunge->uid = rec->uid;
			memcpy(expunge->guid_128, rec->guid_128,
			       sizeof(expunge->guid_128));
		}
	}

	/* everything left in expunged_uids didn't get a GUID */
	seq_range_array_iter_init(&iter, expunged_uids); n = 0;
	while (seq_range_array_iter_nth(&iter, n++, &uid)) {
		expunge = array_append_space(expunges);
		expunge->uid = uid;
	}
}

bool index_storage_get_expunges(struct mailbox *box, uint64_t prev_modseq,
				const ARRAY_TYPE(seq_range) *uids_filter,
				ARRAY_TYPE(seq_range) *expunged_uids,
				ARRAY_TYPE(mailbox_expunge_rec) *expunges)
{
	struct mail_transaction_log_view *log_view;
	ARRAY_TYPE(seq_range) tmp_expunged_uids = ARRAY_INIT;
	const struct mail_transaction_header *thdr;
	const struct seq_range *range;
	const void *tdata;
	uint32_t min_uid, tail_seq;
	int ret;

	i_assert(array_count(uids_filter) > 0);
	i_assert(expunged_uids == NULL || expunges == NULL);

	ret = index_storage_get_expunges_init(box, prev_modseq,
					      &log_view, &tail_seq);
	if (ret != 0)
		return ret > 0;

	range = array_idx(uids_filter, 0);
	min_uid = range->seq1;

	/* first get UIDs of all actual expunges */
	if (expunged_uids == NULL) {
		i_array_init(&tmp_expunged_uids, 64);
		expunged_uids = &tmp_expunged_uids;
	}
	mail_transaction_log_view_mark(log_view);
	while ((ret = mail_transaction_log_view_next(log_view,
						     &thdr, &tdata)) > 0) {
		if ((thdr->type & MAIL_TRANSACTION_EXTERNAL) == 0) {
			/* skip expunge requests */
			continue;
		}
		switch (thdr->type & MAIL_TRANSACTION_TYPE_MASK) {
		case MAIL_TRANSACTION_EXPUNGE:
			add_expunges(expunged_uids, min_uid, tdata, thdr->size);
			break;
		case MAIL_TRANSACTION_EXPUNGE_GUID:
			add_guid_expunges(expunged_uids, min_uid,
					  tdata, thdr->size);
			break;
		}
	}
	mail_transaction_log_view_rewind(log_view);

	/* drop UIDs that don't match the filter */
	seq_range_array_intersect(expunged_uids, uids_filter);

	if (expunges != NULL) {
		index_storage_get_expunged_guids(log_view, expunged_uids,
						 expunges);
		array_free(&tmp_expunged_uids);
	}

	mail_transaction_log_view_close(&log_view);
	return ret < 0 || tail_seq != 0 ? FALSE : TRUE;
}
