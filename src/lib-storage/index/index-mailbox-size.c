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

int index_mailbox_get_physical_size(struct mailbox *box,
				    struct mailbox_metadata *metadata_r)
{
	struct mailbox_transaction_context *trans;
	struct mail_search_context *ctx;
	struct mail *mail;
	struct mail_search_args *search_args;
	uoff_t size;
	int ret = 0;

	/* if physical size = virtual size always for the storage, we can
	   use the optimized vsize code for this */
	if (box->mail_vfuncs->get_physical_size ==
	    box->mail_vfuncs->get_virtual_size) {
		if (index_mailbox_get_virtual_size(box, metadata_r) < 0)
			return -1;
		metadata_r->physical_size = metadata_r->virtual_size;
		return 0;
	}
	/* do it the slow way (we could implement similar logic as for vsize,
	   but for now it's not really needed) */
	if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FULL_READ) < 0)
		return -1;

	trans = mailbox_transaction_begin(box, 0);

	search_args = mail_search_build_init();
	mail_search_build_add_all(search_args);
	ctx = mailbox_search_init(trans, search_args, NULL,
				  MAIL_FETCH_PHYSICAL_SIZE, NULL);
	mail_search_args_unref(&search_args);

	metadata_r->physical_size = 0;
	while (mailbox_search_next(ctx, &mail)) {
		if (mail_get_physical_size(mail, &size) == 0)
			metadata_r->physical_size += size;
		else {
			const char *errstr;
			enum mail_error error;

			errstr = mailbox_get_last_error(box, &error);
			if (error != MAIL_ERROR_EXPUNGED) {
				i_error("Couldn't get size of mail UID %u in %s: %s",
					mail->uid, box->vname, errstr);
				ret = -1;
				break;
			}
		}
	}
	if (mailbox_search_deinit(&ctx) < 0) {
		i_error("Listing mails in %s failed: %s",
			box->vname, mailbox_get_last_error(box, NULL));
		ret = -1;
	}
	(void)mailbox_transaction_commit(&trans);
	return ret;
}
