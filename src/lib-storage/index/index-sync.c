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
	uint32_t seq, messages_count, recent_count;
	int ret, appends;

	sync_mask = MAIL_INDEX_SYNC_MASK_ALL;
	if ((flags & MAILBOX_SYNC_FLAG_NO_EXPUNGES) != 0)
		sync_mask &= ~MAIL_INDEX_SYNC_TYPE_EXPUNGE;

	if (mail_index_view_sync_begin(ibox->view, sync_mask, &ctx) < 0) {
                mail_storage_set_index_error(ibox);
		return -1;
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
	appends = FALSE;

	messages_count = mail_index_view_get_message_count(ibox->view);

	memset(&full_flags, 0, sizeof(full_flags));
	while ((ret = mail_index_view_sync_next(ctx, &sync)) > 0) {
		switch (sync.type) {
		case MAIL_INDEX_SYNC_TYPE_APPEND:
			appends = TRUE;
			break;
		case MAIL_INDEX_SYNC_TYPE_EXPUNGE:
			/* later */
			break;
		case MAIL_INDEX_SYNC_TYPE_FLAGS:
			if (sc->update_flags == NULL)
				break;

			if (sync.seq2 > messages_count)
				sync.seq2 = messages_count;

			/* FIXME: hide the flag updates for expunged messages */
			for (seq = sync.seq1; seq <= sync.seq2; seq++) {
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
		for (i = expunges_count*2; i > 0; i -= 2) {
			seq = expunges[i-1];
			if (seq > messages_count)
				seq = messages_count;
			for (; seq >= expunges[i-2]; seq--)
				sc->expunge(&ibox->box, seq, sc_context);
		}
	}

	mail_index_view_sync_end(ctx);

	if (appends) {
		messages_count = mail_index_view_get_message_count(ibox->view);
		recent_count = ibox->get_recent_count(ibox);
		sc->new_messages(&ibox->box, messages_count, recent_count,
				 sc_context);
	}

	mail_index_view_unlock(ibox->view);
	return ret;
}
