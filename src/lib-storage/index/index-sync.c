/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "index-storage.h"

void index_mailbox_set_recent(struct index_mailbox *ibox, uint32_t seq)
{
	unsigned char *p;
	static char flag;

	if (ibox->recent_flags_start_seq == 0) {
		ibox->recent_flags =
			buffer_create_dynamic(default_pool, 128, (size_t)-1);
		ibox->recent_flags_start_seq = seq;
	} else if (seq < ibox->recent_flags_start_seq) {
		buffer_copy(ibox->recent_flags,
			    ibox->recent_flags_start_seq - seq,
			    ibox->recent_flags, 0, (size_t)-1);
		ibox->recent_flags_start_seq = seq;
	}

	flag = TRUE;
	p = buffer_get_space_unsafe(ibox->recent_flags,
				    seq - ibox->recent_flags_start_seq, 1);
	if (*p == 0) {
		ibox->recent_flags_count++;
		*p = 1;
	}
}

int index_mailbox_is_recent(struct index_mailbox *ibox, uint32_t seq)
{
	const unsigned char *data;
	size_t size;
	uint32_t idx;

	if (seq < ibox->recent_flags_start_seq ||
	    ibox->recent_flags_start_seq == 0)
		return FALSE;

	idx = seq - ibox->recent_flags_start_seq;
	data = buffer_get_data(ibox->recent_flags, &size);
	return idx < size ? data[idx] : FALSE;
}

static void index_mailbox_expunge_recent(struct index_mailbox *ibox,
					 uint32_t seq1, uint32_t seq2)
{
	const unsigned char *data;
	size_t size;
	uint32_t i, idx, count;

	if (seq2 < ibox->recent_flags_start_seq ||
	    ibox->recent_flags_start_seq == 0)
		return;

	if (seq1 < ibox->recent_flags_start_seq)
		seq1 = ibox->recent_flags_start_seq;

	idx = seq1 - ibox->recent_flags_start_seq;
	count = seq2 - seq1 + 1;

	data = buffer_get_data(ibox->recent_flags, &size);
	if (idx > size)
		return;
	if (idx + count > size)
		count = size - idx;

	for (i = 0; i < count; i++) {
		if (data[idx+i])
			ibox->recent_flags_count--;
	}

	buffer_copy(ibox->recent_flags, idx,
		    ibox->recent_flags, idx + count, (size_t)-1);
	buffer_set_used_size(ibox->recent_flags, size - count);

}

static int index_mailbox_update_recent(struct index_mailbox *ibox,
				       uint32_t seq1, uint32_t seq2)
{
	const struct mail_index_record *rec;

	for (; seq1 <= seq2; seq1++) {
		if (mail_index_lookup(ibox->view, seq1, &rec) < 0) {
			mail_storage_set_index_error(ibox);
			return -1;
		}

		if ((rec->flags & MAIL_RECENT) != 0 ||
		    ibox->is_recent(ibox, rec->uid))
                        index_mailbox_set_recent(ibox, seq1);
	}

	return 0;
}

int index_storage_sync(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct index_mailbox *ibox = (struct index_mailbox *)box;
	struct mail_index_view_sync_ctx *ctx;
        struct mail_full_flags full_flags;
	const struct mail_index_record *rec;
	struct mail_index_sync_rec sync;
	struct mail_storage_callbacks *sc;
	const uint32_t *expunges;
	size_t i, expunges_count;
	void *sc_context;
	enum mail_index_sync_type sync_mask;
	uint32_t seq, seq1, seq2;
	uint32_t messages_count, last_messages_count;
	int ret;

	sync_mask = MAIL_INDEX_SYNC_MASK_ALL;
	if ((flags & MAILBOX_SYNC_FLAG_NO_EXPUNGES) != 0)
		sync_mask &= ~MAIL_INDEX_SYNC_TYPE_EXPUNGE;

	if (mail_index_view_sync_begin(ibox->view, sync_mask, &ctx) < 0) {
                mail_storage_set_index_error(ibox);
		return -1;
	}

	last_messages_count = mail_index_view_get_message_count(ibox->view);

	if (!ibox->recent_flags_synced) {
		ibox->recent_flags_synced = TRUE;
                index_mailbox_update_recent(ibox, 1, last_messages_count);
	}

	if ((flags & MAILBOX_SYNC_FLAG_NO_EXPUNGES) != 0) {
		expunges_count = 0;
		expunges = NULL;
	} else {
		expunges =
			mail_index_view_sync_get_expunges(ctx, &expunges_count);
	}

	sc = ibox->storage->callbacks;
	sc_context = ibox->storage->callback_context;

	memset(&full_flags, 0, sizeof(full_flags));
	while ((ret = mail_index_view_sync_next(ctx, &sync)) > 0) {
		switch (sync.type) {
		case MAIL_INDEX_SYNC_TYPE_APPEND:
			break;
		case MAIL_INDEX_SYNC_TYPE_EXPUNGE:
			/* later */
			break;
		case MAIL_INDEX_SYNC_TYPE_FLAGS:
			if (sc->update_flags == NULL)
				break;

			/* FIXME: hide the flag updates for expunged messages */

			if (mail_index_lookup_uid_range(ibox->view,
							sync.uid1, sync.uid2,
							&seq1, &seq2) < 0) {
				ret = -1;
				break;
			}

			if (seq1 == 0)
				break;

			for (seq = seq1; seq <= seq2; seq++) {
				if (mail_index_lookup(ibox->view,
						      seq, &rec) < 0) {
					ret = -1;
					break;
				}
				full_flags.flags = rec->flags; // FIXME
				if (index_mailbox_is_recent(ibox, seq))
					full_flags.flags |= MAIL_RECENT;
				sc->update_flags(&ibox->box, seq,
						 &full_flags, sc_context);
			}
			break;
		}
	}

	if (ret < 0)
		mail_storage_set_index_error(ibox);

	if (sc->expunge != NULL) {
		/* expunges[] is a sorted array of sequences. it's easiest for
		   us to print them from end to beginning. */
		messages_count = mail_index_view_get_message_count(ibox->view);
		for (i = expunges_count*2; i > 0; i -= 2) {
			seq = expunges[i-1];
			index_mailbox_expunge_recent(ibox, expunges[i-2], seq);
			if (seq > messages_count)
				seq = messages_count;
			for (; seq >= expunges[i-2]; seq--) {
				sc->expunge(&ibox->box, seq, sc_context);
				last_messages_count--;
			}
		}
	}

	mail_index_view_sync_end(ctx);

	messages_count = mail_index_view_get_message_count(ibox->view);
	if (messages_count != last_messages_count) {
		index_mailbox_update_recent(ibox, last_messages_count+1,
					    messages_count);
		sc->message_count_changed(&ibox->box, messages_count,
					  sc_context);
	}

	if (ibox->recent_flags_count != ibox->synced_recent_count) {
                ibox->synced_recent_count = ibox->recent_flags_count;
		sc->recent_count_changed(&ibox->box, ibox->synced_recent_count,
					 sc_context);
	}

	mail_index_view_unlock(ibox->view);
	return ret;
}
