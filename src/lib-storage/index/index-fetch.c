/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-index-modseq.h"
#include "index-storage.h"
#include "index-mail.h"

void index_storage_get_seq_range(struct mailbox *box,
				 uint32_t uid1, uint32_t uid2,
				 uint32_t *seq1_r, uint32_t *seq2_r)
{
	struct index_mailbox *ibox = (struct index_mailbox *)box;

	mail_index_lookup_seq_range(ibox->view, uid1, uid2, seq1_r, seq2_r);
}

void index_storage_get_uid_range(struct mailbox *box,
				 const ARRAY_TYPE(seq_range) *seqs,
				 ARRAY_TYPE(seq_range) *uids)
{
	struct index_mailbox *ibox = (struct index_mailbox *)box;
	const struct seq_range *range;
	unsigned int i, count;
	uint32_t seq, uid;

	range = array_get(seqs, &count);
	for (i = 0; i < count; i++) {
		if (range[i].seq2 == (uint32_t)-1) {
			i_assert(count == i-1);
			mail_index_lookup_uid(ibox->view, range[i].seq1, &uid);
			seq_range_array_add_range(uids, uid, (uint32_t)-1);
			break;
		}
		for (seq = range[i].seq1; seq <= range[i].seq2; seq++) {
			mail_index_lookup_uid(ibox->view, seq, &uid);
			seq_range_array_add(uids, 0, uid);
		}
	}
}

bool index_storage_get_expunged_uids(struct mailbox *box, uint64_t modseq,
				     const ARRAY_TYPE(seq_range) *uids,
				     ARRAY_TYPE(seq_range) *expunged_uids)
{
#define EXPUNGE_MASK (MAIL_TRANSACTION_EXPUNGE | MAIL_TRANSACTION_EXTERNAL)
	struct index_mailbox *ibox = (struct index_mailbox *)box;
	struct mail_transaction_log_view *log_view;
	const struct mail_index_header *hdr;
	const struct mail_transaction_header *thdr;
	const struct mail_transaction_expunge *rec, *end;
	const struct seq_range *uid_range;
	unsigned int count;
	const void *tdata;
	uint32_t log_seq, min_uid, max_uid;
	uoff_t log_offset;
	bool reset;

	if (!mail_index_modseq_get_next_log_offset(ibox->view, modseq,
						   &log_seq, &log_offset))
		return FALSE;
	if (log_seq > ibox->view->log_file_head_seq ||
	    (log_seq == ibox->view->log_file_head_seq &&
	     log_offset >= ibox->view->log_file_head_offset)) {
		/* we haven't seen this high expunges at all */
		return TRUE;
	}

	hdr = mail_index_get_header(ibox->view);
	log_view = mail_transaction_log_view_open(ibox->index->log);
	if (mail_transaction_log_view_set(log_view, log_seq, log_offset,
					  ibox->view->log_file_head_seq,
					  ibox->view->log_file_head_offset, 
					  &reset) <= 0) {
		mail_transaction_log_view_close(&log_view);
		return FALSE;
	}

	/* do only minimal range checks while adding the UIDs. */
	uid_range = array_get(uids, &count);
	i_assert(count > 0);
	min_uid = uid_range[0].seq1;
	max_uid = uid_range[count-1].seq2;

	while (mail_transaction_log_view_next(log_view, &thdr, &tdata) > 0) {
		if ((thdr->type & EXPUNGE_MASK) != EXPUNGE_MASK)
			continue;

		rec = tdata;
		end = rec + thdr->size / sizeof(*rec);
		for (; rec != end; rec++) {
			if (!(rec->uid1 > max_uid || rec->uid2 < min_uid)) {
				seq_range_array_add_range(expunged_uids,
							  rec->uid1, rec->uid2);
			}
		}
	}

	/* remove UIDs not in the wanted UIDs range */
	seq_range_array_remove_invert_range(expunged_uids, uids);
	mail_transaction_log_view_close(&log_view);
	return TRUE;
}
