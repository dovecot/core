/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "index-storage.h"

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
	uint32_t messages_count, last_messages_count, recent_count;
	int ret;

	sync_mask = MAIL_INDEX_SYNC_MASK_ALL;
	if ((flags & MAILBOX_SYNC_FLAG_NO_EXPUNGES) != 0)
		sync_mask &= ~MAIL_INDEX_SYNC_TYPE_EXPUNGE;

	if (mail_index_view_sync_begin(ibox->view, sync_mask, &ctx) < 0) {
                mail_storage_set_index_error(ibox);
		return -1;
	}

	if (!ibox->last_recent_count_initialized) {
                ibox->last_recent_count_initialized = TRUE;
		ibox->last_recent_count = ibox->get_recent_count(ibox);
	}
	last_messages_count = mail_index_view_get_message_count(ibox->view);

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
		sc->message_count_changed(&ibox->box, messages_count,
					  sc_context);
		recent_count = ibox->get_recent_count(ibox);
	} else if (expunges_count != 0)
		recent_count = ibox->get_recent_count(ibox);
	else
		recent_count = ibox->last_recent_count;

	if (recent_count != ibox->last_recent_count) {
		ibox->last_recent_count = recent_count;
		sc->recent_count_changed(&ibox->box, recent_count, sc_context);
	}

	mail_index_view_unlock(ibox->view);
	return ret;
}
