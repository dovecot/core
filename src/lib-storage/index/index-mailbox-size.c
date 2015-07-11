/* Copyright (c) 2002-2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-search-build.h"
#include "index-storage.h"

static int
virtual_size_add_new(struct mailbox *box,
		     struct mailbox_index_vsize *vsize_hdr)
{
	const struct mail_index_header *hdr;
	struct mailbox_transaction_context *trans;
	struct mail_search_context *search_ctx;
	struct mail_search_args *search_args;
	struct mail *mail;
	uint32_t seq1, seq2;
	uoff_t vsize;
	int ret = 0;

	hdr = mail_index_get_header(box->view);
	if (vsize_hdr->highest_uid == 0)
		seq2 = 0;
	else if (!mail_index_lookup_seq_range(box->view, 1,
					      vsize_hdr->highest_uid,
					      &seq1, &seq2))
		seq2 = 0;

	if (vsize_hdr->message_count != seq2) {
		if (vsize_hdr->message_count < seq2) {
			mail_storage_set_critical(box->storage,
				"vsize-hdr has invalid message-count (%u < %u)",
				vsize_hdr->message_count, seq2);
		} else {
			/* some messages have been expunged, rescan */
		}
		memset(vsize_hdr, 0, sizeof(*vsize_hdr));
		seq2 = 0;
	}

	search_args = mail_search_build_init();
	mail_search_build_add_seqset(search_args, seq2 + 1,
				     hdr->messages_count);

	trans = mailbox_transaction_begin(box, 0);
	search_ctx = mailbox_search_init(trans, search_args, NULL,
					 MAIL_FETCH_VIRTUAL_SIZE, NULL);
	while (mailbox_search_next(search_ctx, &mail)) {
		if (mail_get_virtual_size(mail, &vsize) < 0) {
			if (mail->expunged)
				continue;
			ret = -1;
			break;
		}
		vsize_hdr->vsize += vsize;
		vsize_hdr->highest_uid = mail->uid;
		vsize_hdr->message_count++;
	}
	if (mailbox_search_deinit(&search_ctx) < 0)
		ret = -1;
	mail_search_args_unref(&search_args);

	if (ret == 0) {
		/* success, cache all */
		vsize_hdr->highest_uid = hdr->next_uid - 1;
	} else {
		/* search failed, cache only up to highest seen uid */
	}
	mail_index_update_header_ext(trans->itrans, box->vsize_hdr_ext_id,
				     0, vsize_hdr, sizeof(*vsize_hdr));
	(void)mailbox_transaction_commit(&trans);
	return ret;
}

int index_mailbox_get_virtual_size(struct mailbox *box,
				   struct mailbox_metadata *metadata_r)
{
	struct mailbox_index_vsize vsize_hdr;
	struct mailbox_status status;
	const void *data;
	size_t size;
	int ret;

	mailbox_get_open_status(box, STATUS_MESSAGES | STATUS_UIDNEXT, &status);
	mail_index_get_header_ext(box->view, box->vsize_hdr_ext_id,
				  &data, &size);
	if (size == sizeof(vsize_hdr))
		memcpy(&vsize_hdr, data, sizeof(vsize_hdr));
	else {
		if (size != 0) {
			mail_storage_set_critical(box->storage,
				"vsize-hdr has invalid size: %"PRIuSIZE_T,
				size);
		}
		memset(&vsize_hdr, 0, sizeof(vsize_hdr));
	}

	if (vsize_hdr.highest_uid + 1 == status.uidnext &&
	    vsize_hdr.message_count == status.messages) {
		/* up to date */
		metadata_r->virtual_size = vsize_hdr.vsize;
		return 0;
	}
	if (vsize_hdr.highest_uid >= status.uidnext) {
		mail_storage_set_critical(box->storage,
			"vsize-hdr has invalid highest-uid (%u >= %u)",
			vsize_hdr.highest_uid, status.uidnext);
		memset(&vsize_hdr, 0, sizeof(vsize_hdr));
	}
	ret = virtual_size_add_new(box, &vsize_hdr);
	metadata_r->virtual_size = vsize_hdr.vsize;
	return ret;
}
