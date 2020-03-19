/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-cache.h"
#include "mail-index-modseq.h"
#include "mailbox-recent-flags.h"
#include "index-storage.h"

static void
get_last_cached_seq(struct mailbox *box, uint32_t *last_cached_seq_r)
{
	const struct mail_index_header *hdr;
	struct mail_cache_view *cache_view;
	uint32_t seq;

	*last_cached_seq_r = 0;
	if (!mail_cache_exists(box->cache))
		return;

	cache_view = mail_cache_view_open(box->cache, box->view);
	hdr = mail_index_get_header(box->view);
	for (seq = hdr->messages_count; seq > 0; seq--) {
		if (mail_cache_field_exists_any(cache_view, seq)) {
			*last_cached_seq_r = seq;
			break;
		}
	}
	mail_cache_view_close(&cache_view);
}

int index_storage_get_status(struct mailbox *box,
			     enum mailbox_status_items items,
			     struct mailbox_status *status_r)
{
	if (items == 0) {
		/* caller could have wanted only e.g. mailbox_status.have_*
		   flags */
		return 0;
	}

	if (!box->opened) {
		if (mailbox_open(box) < 0)
			return -1;
		if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FAST) < 0)
			return -1;
	}
	index_storage_get_open_status(box, items, status_r);
	return 0;
}

static unsigned int index_storage_count_pvt_unseen(struct mailbox *box)
{
	const struct mail_index_record *pvt_rec;
	uint32_t shared_seq, pvt_seq, shared_count, pvt_count;
	uint32_t shared_uid;
	unsigned int unseen_count = 0;

	/* we can't trust private index to be up to date. we'll need to go
	   through the shared index and for each existing mail lookup its
	   private flags. if a mail doesn't exist in private index then its
	   flags are 0. */
	shared_count = mail_index_view_get_messages_count(box->view);
	pvt_count = mail_index_view_get_messages_count(box->view_pvt);
	shared_seq = pvt_seq = 1;
	while (shared_seq <= shared_count && pvt_seq <= pvt_count) {
		mail_index_lookup_uid(box->view, shared_seq, &shared_uid);
		pvt_rec = mail_index_lookup(box->view_pvt, pvt_seq);

		if (shared_uid == pvt_rec->uid) {
			if ((pvt_rec->flags & MAIL_SEEN) == 0)
				unseen_count++;
			shared_seq++; pvt_seq++;
		} else if (shared_uid < pvt_rec->uid) {
			shared_seq++;
		} else {
			pvt_seq++;
		}
	}
	unseen_count += (shared_count+1) - shared_seq;
	return unseen_count;
}

static uint32_t index_storage_find_first_pvt_unseen_seq(struct mailbox *box)
{
	const struct mail_index_header *pvt_hdr;
	const struct mail_index_record *pvt_rec;
	uint32_t pvt_seq, pvt_count, shared_seq, seq2;

	pvt_count = mail_index_view_get_messages_count(box->view_pvt);
	mail_index_lookup_first(box->view_pvt, 0, MAIL_SEEN, &pvt_seq);
	if (pvt_seq == 0)
		pvt_seq = pvt_count+1;
	for (; pvt_seq <= pvt_count; pvt_seq++) {
		pvt_rec = mail_index_lookup(box->view_pvt, pvt_seq);
		if ((pvt_rec->flags & MAIL_SEEN) == 0 &&
		    mail_index_lookup_seq(box->view, pvt_rec->uid, &shared_seq))
			return shared_seq;
	}
	/* if shared index has any messages that don't exist in private index,
	   the first of them is the first unseen message */
	pvt_hdr = mail_index_get_header(box->view_pvt);
	if (mail_index_lookup_seq_range(box->view,
					pvt_hdr->next_uid, (uint32_t)-1,
					&shared_seq, &seq2))
		return shared_seq;
	return 0;
}

void index_storage_get_open_status(struct mailbox *box,
				   enum mailbox_status_items items,
				   struct mailbox_status *status_r)
{
	const struct mail_index_header *hdr;

	/* we can get most of the status items without any trouble */
	hdr = mail_index_get_header(box->view);
	status_r->messages = hdr->messages_count;
	if ((items & STATUS_RECENT) != 0) {
		if ((box->flags & MAILBOX_FLAG_DROP_RECENT) != 0) {
			/* recent flags are set and dropped by the previous
			   sync while index was locked. if we updated the
			   recent flags here we'd have a race condition. */
			i_assert(box->synced);
		} else {
			/* make sure recent count is set, in case we haven't
			   synced yet */
			index_sync_update_recent_count(box);
		}
		status_r->recent = mailbox_recent_flags_count(box);
		i_assert(status_r->recent <= status_r->messages);
	}
	if ((items & STATUS_UNSEEN) != 0) {
		if (box->view_pvt == NULL ||
		    (mailbox_get_private_flags_mask(box) & MAIL_SEEN) == 0) {
			status_r->unseen = hdr->messages_count -
				hdr->seen_messages_count;
		} else {
			status_r->unseen = index_storage_count_pvt_unseen(box);
		}
	}
	status_r->uidvalidity = hdr->uid_validity;
	status_r->uidnext = hdr->next_uid;
	status_r->first_recent_uid = hdr->first_recent_uid;
	if ((items & STATUS_HIGHESTMODSEQ) != 0) {
		status_r->nonpermanent_modseqs =
			mail_index_is_in_memory(box->index);
		status_r->no_modseq_tracking =
			!mail_index_have_modseq_tracking(box->index);
		status_r->highest_modseq =
			mail_index_modseq_get_highest(box->view);
		if (status_r->highest_modseq == 0) {
			/* modseqs not enabled yet, but we can't return 0 */
			status_r->highest_modseq = 1;
		}
	}
	if ((items & STATUS_HIGHESTPVTMODSEQ) != 0 && box->view_pvt != NULL) {
		status_r->highest_pvt_modseq =
			mail_index_modseq_get_highest(box->view_pvt);
		if (status_r->highest_pvt_modseq == 0) {
			/* modseqs not enabled yet, but we can't return 0 */
			status_r->highest_pvt_modseq = 1;
		}
	}

	if ((items & STATUS_FIRST_UNSEEN_SEQ) != 0) {
		if (box->view_pvt == NULL ||
		    (mailbox_get_private_flags_mask(box) & MAIL_SEEN) == 0) {
			mail_index_lookup_first(box->view, 0, MAIL_SEEN,
						&status_r->first_unseen_seq);
		} else {
			status_r->first_unseen_seq =
				index_storage_find_first_pvt_unseen_seq(box);
		}
	}
	if ((items & STATUS_LAST_CACHED_SEQ) != 0)
		get_last_cached_seq(box, &status_r->last_cached_seq);

	if ((items & STATUS_KEYWORDS) != 0)
		status_r->keywords = mail_index_get_keywords(box->index);
	if ((items & STATUS_PERMANENT_FLAGS) != 0) {
		if (!mailbox_is_readonly(box)) {
			status_r->permanent_flags = MAIL_FLAGS_NONRECENT;
			status_r->permanent_keywords = TRUE;
			status_r->allow_new_keywords =
				!box->disallow_new_keywords;
		}
		status_r->flags = MAIL_FLAGS_NONRECENT;
	}
}

static void
get_metadata_cache_fields(struct mailbox *box,
			  struct mailbox_metadata *metadata_r)
{
	const struct mail_cache_field *fields;
	enum mail_cache_decision_type dec;
	ARRAY_TYPE(mailbox_cache_field) *cache_fields;
	struct mailbox_cache_field *cf;
	unsigned int i, count;

	fields = mail_cache_register_get_list(box->cache,
					      pool_datastack_create(), &count);

	cache_fields = t_new(ARRAY_TYPE(mailbox_cache_field), 1);
	t_array_init(cache_fields, count);
	for (i = 0; i < count; i++) {
		dec = fields[i].decision & ~MAIL_CACHE_DECISION_FORCED;
		if (dec != MAIL_CACHE_DECISION_NO) {
			cf = array_append_space(cache_fields);
			cf->name = fields[i].name;
			cf->decision = fields[i].decision;
			cf->last_used = fields[i].last_used;
		}
	}
	metadata_r->cache_fields = cache_fields;
}

static void get_metadata_precache_fields(struct mailbox *box,
					 struct mailbox_metadata *metadata_r)
{
	const struct mail_cache_field *fields;
	unsigned int i, count;
	enum mail_fetch_field cache = 0;

	fields = mail_cache_register_get_list(box->cache,
					      pool_datastack_create(), &count);
	for (i = 0; i < count; i++) {
		const char *name = fields[i].name;

		if (str_begins(name, "hdr.") ||
		    strcmp(name, "date.sent") == 0 ||
		    strcmp(name, "imap.envelope") == 0)
			cache |= MAIL_FETCH_STREAM_HEADER;
		else if (strcmp(name, "mime.parts") == 0 ||
			 strcmp(name, "binary.parts") == 0 ||
			 strcmp(name, "imap.body") == 0 ||
			 strcmp(name, "imap.bodystructure") == 0 ||
			 strcmp(name, "body.snippet") == 0)
			cache |= MAIL_FETCH_STREAM_BODY;
		else if (strcmp(name, "date.received") == 0)
			cache |= MAIL_FETCH_RECEIVED_DATE;
		else if (strcmp(name, "date.save") == 0)
			cache |= MAIL_FETCH_SAVE_DATE;
		else if (strcmp(name, "size.virtual") == 0)
			cache |= MAIL_FETCH_VIRTUAL_SIZE;
		else if (strcmp(name, "size.physical") == 0)
			cache |= MAIL_FETCH_PHYSICAL_SIZE;
		else if (strcmp(name, "pop3.uidl") == 0)
			cache |= MAIL_FETCH_UIDL_BACKEND;
		else if (strcmp(name, "pop3.order") == 0)
			cache |= MAIL_FETCH_POP3_ORDER;
		else if (strcmp(name, "guid") == 0)
			cache |= MAIL_FETCH_GUID;
		else if (strcmp(name, "flags") == 0) {
			/* just ignore for now at least.. */
		} else
			e_debug(box->event,
				"Ignoring unknown cache field: %s", name);
	}
	metadata_r->precache_fields = cache;
}

static int
index_mailbox_get_first_save_date(struct mailbox *box,
				  struct mailbox_metadata *metadata_r)
{
	const struct mail_index_header *hdr;
	struct mailbox_transaction_context *t;
	struct mail *mail;
	uint32_t seq;
	int ret = -1;

	hdr = mail_index_get_header(box->view);
	if (hdr->messages_count == 0) {
		metadata_r->first_save_date = (time_t)-1;
		return 0;
	}

	t = mailbox_transaction_begin(box, 0, __func__);
	mail = mail_alloc(t, 0, NULL);
	for (seq = 1; seq <= hdr->messages_count; seq++) {
		mail_set_seq(mail, seq);
		if (mail_get_save_date(mail, &metadata_r->first_save_date) >= 0) {
			ret = 0;
			break;
		}
		if (mailbox_get_last_mail_error(box) != MAIL_ERROR_EXPUNGED) {
			/* failed */
			break;
		}
	}
	mail_free(&mail);
	(void)mailbox_transaction_commit(&t);
	if (seq > hdr->messages_count) {
		/* all messages were expunged after all */
		metadata_r->first_save_date = (time_t)-1;
		return 0;
	}
	return ret;
}

int index_mailbox_get_metadata(struct mailbox *box,
			       enum mailbox_metadata_items items,
			       struct mailbox_metadata *metadata_r)
{
	/* handle items that don't require opening the mailbox */
	if ((items & MAILBOX_METADATA_BACKEND_NAMESPACE) != 0) {
		metadata_r->backend_ns_prefix = "";
		metadata_r->backend_ns_type =
			mailbox_list_get_namespace(box->list)->type;
		items &= ~MAILBOX_METADATA_BACKEND_NAMESPACE;
	}
	if (items == 0)
		return 0;

	/* handle items that require opening the mailbox */
	if (!box->opened) {
		if (mailbox_open(box) < 0)
			return -1;
	}
	if (!box->synced && (items & MAILBOX_METADATA_SYNC_ITEMS) != 0) {
		if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FAST) < 0)
			return -1;
	}

	if ((items & MAILBOX_METADATA_VIRTUAL_SIZE) != 0) {
		if (index_mailbox_get_virtual_size(box, metadata_r) < 0)
			return -1;
	}
	if ((items & MAILBOX_METADATA_PHYSICAL_SIZE) != 0) {
		if (index_mailbox_get_physical_size(box, metadata_r) < 0)
			return -1;
	}
	if ((items & MAILBOX_METADATA_FIRST_SAVE_DATE) != 0) {
		if (index_mailbox_get_first_save_date(box, metadata_r) < 0)
			return -1;
	}
	if ((items & MAILBOX_METADATA_CACHE_FIELDS) != 0)
		get_metadata_cache_fields(box, metadata_r);
	if ((items & MAILBOX_METADATA_PRECACHE_FIELDS) != 0)
		get_metadata_precache_fields(box, metadata_r);
	return 0;
}
