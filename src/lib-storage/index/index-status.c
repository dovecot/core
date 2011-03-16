/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-cache.h"
#include "mail-search-build.h"
#include "index-storage.h"
#include "mail-index-modseq.h"

static void
index_storage_get_status_cache_fields(struct mailbox *box,
				      struct mailbox_status *status_r)
{
	const struct mail_cache_field *fields;
	enum mail_cache_decision_type dec;
	ARRAY_TYPE(const_string) *cache_fields;
	unsigned int i, count;

	fields = mail_cache_register_get_list(box->cache,
					      pool_datastack_create(), &count);

	cache_fields = t_new(ARRAY_TYPE(const_string), 1);
	t_array_init(cache_fields, count);
	for (i = 0; i < count; i++) {
		dec = fields[i].decision & ~MAIL_CACHE_DECISION_FORCED;
		if (dec != MAIL_CACHE_DECISION_NO)
			array_append(cache_fields, &fields[i].name, 1);
	}
	status_r->cache_fields = cache_fields;
}

static void
index_storage_virtual_size_add_new(struct mailbox *box,
				   struct index_vsize_header *vsize_hdr)
{
	struct index_mailbox_context *ibox = INDEX_STORAGE_CONTEXT(box);
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
	search_ctx = mailbox_search_init(trans, search_args, NULL);
	mail = mail_alloc(trans, MAIL_FETCH_VIRTUAL_SIZE, NULL);
	while (mailbox_search_next(search_ctx, mail)) {
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
	mail_free(&mail);
	if (mailbox_search_deinit(&search_ctx) < 0)
		ret = -1;

	if (ret == 0) {
		/* success, cache all */
		vsize_hdr->highest_uid = hdr->next_uid - 1;
	} else {
		/* search failed, cache only up to highest seen uid */
	}
	mail_index_update_header_ext(trans->itrans, ibox->vsize_hdr_ext_id,
				     0, vsize_hdr, sizeof(*vsize_hdr));
	(void)mailbox_transaction_commit(&trans);

}

static void
index_storage_get_status_virtual_size(struct mailbox *box,
				      struct mailbox_status *status_r)
{
	struct index_mailbox_context *ibox = INDEX_STORAGE_CONTEXT(box);
	struct index_vsize_header vsize_hdr;
	const void *data;
	size_t size;

	mail_index_get_header_ext(box->view, ibox->vsize_hdr_ext_id,
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

	if (vsize_hdr.highest_uid + 1 == status_r->uidnext &&
	    vsize_hdr.message_count == status_r->messages) {
		/* up to date */
		status_r->virtual_size = vsize_hdr.vsize;
		return;
	}
	if (vsize_hdr.highest_uid >= status_r->uidnext) {
		mail_storage_set_critical(box->storage,
			"vsize-hdr has invalid highest-uid (%u >= %u)",
			vsize_hdr.highest_uid, status_r->uidnext);
		memset(&vsize_hdr, 0, sizeof(vsize_hdr));
	}
	index_storage_virtual_size_add_new(box, &vsize_hdr);
	status_r->virtual_size = vsize_hdr.vsize;
}

void index_storage_get_status(struct mailbox *box,
			      enum mailbox_status_items items,
			      struct mailbox_status *status_r)
{
	const struct mail_index_header *hdr;

	i_assert(box->opened);

	memset(status_r, 0, sizeof(struct mailbox_status));

	/* we can get most of the status items without any trouble */
	hdr = mail_index_get_header(box->view);
	status_r->messages = hdr->messages_count;
	if ((items & STATUS_RECENT) != 0) {
		status_r->recent = index_mailbox_get_recent_count(box);
		i_assert(status_r->recent <= status_r->messages);
	}
	status_r->unseen = hdr->messages_count - hdr->seen_messages_count;
	status_r->uidvalidity = hdr->uid_validity;
	status_r->first_recent_uid = hdr->first_recent_uid;
	status_r->uidnext = hdr->next_uid;
	status_r->nonpermanent_modseqs = mail_index_is_in_memory(box->index);
	if ((items & STATUS_HIGHESTMODSEQ) != 0) {
		status_r->highest_modseq =
			mail_index_modseq_get_highest(box->view);
		if (status_r->highest_modseq == 0) {
			/* modseqs not enabled yet, but we can't return 0 */
			status_r->highest_modseq = 1;
		}
	}

	if ((items & STATUS_FIRST_UNSEEN_SEQ) != 0) {
		mail_index_lookup_first(box->view, 0, MAIL_SEEN,
					&status_r->first_unseen_seq);
	}

	if ((items & STATUS_KEYWORDS) != 0)
		status_r->keywords = mail_index_get_keywords(box->index);
	if ((items & STATUS_CACHE_FIELDS) != 0)
		index_storage_get_status_cache_fields(box, status_r);
	if ((items & STATUS_VIRTUAL_SIZE) != 0)
		index_storage_get_status_virtual_size(box, status_r);
}
