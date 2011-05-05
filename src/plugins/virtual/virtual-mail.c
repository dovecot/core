/* Copyright (c) 2008-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "index-mail.h"
#include "virtual-storage.h"
#include "virtual-transaction.h"

struct virtual_mail {
	struct index_mail imail;

	enum mail_fetch_field wanted_fields;
	struct mailbox_header_lookup_ctx *wanted_headers;

	/* currently active mail */
	struct mail *backend_mail;
	/* all allocated mails */
	ARRAY_DEFINE(backend_mails, struct mail *);

	/* mail is lost if backend_mail doesn't point to correct mail */
	unsigned int lost:1;
};

struct mail *
virtual_mail_alloc(struct mailbox_transaction_context *t,
		   enum mail_fetch_field wanted_fields,
		   struct mailbox_header_lookup_ctx *wanted_headers)
{
	struct virtual_mailbox *mbox = (struct virtual_mailbox *)t->box;
	struct virtual_mail *vmail;
	pool_t pool;

	pool = pool_alloconly_create("vmail", 1024);
	vmail = p_new(pool, struct virtual_mail, 1);
	vmail->imail.mail.pool = pool;
	vmail->imail.mail.v = virtual_mail_vfuncs;
	vmail->imail.mail.mail.box = t->box;
	vmail->imail.mail.mail.transaction = t;
	array_create(&vmail->imail.mail.module_contexts, pool,
		     sizeof(void *), 5);

	vmail->imail.data_pool =
		pool_alloconly_create("virtual index_mail", 512);
	vmail->imail.ibox = INDEX_STORAGE_CONTEXT(t->box);
	vmail->imail.trans = (struct index_transaction_context *)t;

	vmail->wanted_fields = wanted_fields;
	if (wanted_headers != NULL) {
		vmail->wanted_headers = wanted_headers;
		mailbox_header_lookup_ref(wanted_headers);
	}

	i_array_init(&vmail->backend_mails, array_count(&mbox->backend_boxes));
	return &vmail->imail.mail.mail;
}

static void virtual_mail_free(struct mail *mail)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mail **mails;
	unsigned int i, count;

	mails = array_get_modifiable(&vmail->backend_mails, &count);
	for (i = 0; i < count; i++)
		mail_free(&mails[i]);
	array_free(&vmail->backend_mails);

	if (vmail->wanted_headers != NULL)
		mailbox_header_lookup_unref(&vmail->wanted_headers);

	pool_unref(&vmail->imail.data_pool);
	pool_unref(&vmail->imail.mail.pool);
}

static struct mail *
backend_mail_find(struct virtual_mail *vmail, struct mailbox *box)
{
	struct mail *const *mails;
	unsigned int i, count;

	mails = array_get(&vmail->backend_mails, &count);
	for (i = 0; i < count; i++) {
		if (mails[i]->box == box)
			return mails[i];
	}
	return NULL;
}

struct mail *
virtual_mail_set_backend_mail(struct mail *mail,
			      struct virtual_backend_box *bbox)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mailbox_transaction_context *backend_trans;
	struct mailbox_header_lookup_ctx *backend_headers;

	backend_trans = virtual_transaction_get(mail->transaction, bbox->box);

	backend_headers = vmail->wanted_headers == NULL ? NULL :
		mailbox_header_lookup_init(bbox->box,
					   vmail->wanted_headers->headers);
	vmail->backend_mail = mail_alloc(backend_trans, vmail->wanted_fields,
					 backend_headers);
	if (backend_headers != NULL)
		mailbox_header_lookup_unref(&backend_headers);
	array_append(&vmail->backend_mails, &vmail->backend_mail, 1);
	return vmail->backend_mail;
}

static void virtual_mail_set_seq(struct mail *mail, uint32_t seq)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct virtual_mailbox *mbox = (struct virtual_mailbox *)mail->box;
	struct virtual_backend_box *bbox;
	const struct virtual_mail_index_record *vrec;
	const void *data;
	bool expunged;

	mail_index_lookup_ext(mail->box->view, seq, mbox->virtual_ext_id,
			      &data, &expunged);
	vrec = data;

	bbox = virtual_backend_box_lookup(mbox, vrec->mailbox_id);
	vmail->backend_mail = backend_mail_find(vmail, bbox->box);
	if (vmail->backend_mail == NULL)
		virtual_mail_set_backend_mail(mail, bbox);
	vmail->lost = !mail_set_uid(vmail->backend_mail, vrec->real_uid);
	memset(&vmail->imail.data, 0, sizeof(vmail->imail.data));
	p_clear(vmail->imail.data_pool);

	vmail->imail.data.seq = seq;
	mail->seq = seq;
	mail_index_lookup_uid(mail->box->view, seq, &mail->uid);

	if (!vmail->lost) {
		mail->expunged = vmail->backend_mail->expunged;
		mail->has_nuls = vmail->backend_mail->has_nuls;
		mail->has_no_nuls = vmail->backend_mail->has_no_nuls;
	} else {
		mail->expunged = TRUE;
		mail->has_nuls = FALSE;
		mail->has_no_nuls = FALSE;
	}
}

static bool virtual_mail_set_uid(struct mail *mail, uint32_t uid)
{
	uint32_t seq;

	if (!mail_index_lookup_seq(mail->box->view, uid, &seq))
		return FALSE;

	virtual_mail_set_seq(mail, seq);
	return TRUE;
}

static void virtual_mail_set_uid_cache_updates(struct mail *mail, bool set)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mail_private *p = (struct mail_private *)vmail->backend_mail;

	p->v.set_uid_cache_updates(vmail->backend_mail, set);
}

static int virtual_mail_handle_lost(struct virtual_mail *vmail)
{
	if (!vmail->lost)
		return 0;

	mail_set_expunged(&vmail->imail.mail.mail);
	return -1;
}

static int
virtual_mail_get_parts(struct mail *mail, struct message_part **parts_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;

	if (virtual_mail_handle_lost(vmail) < 0)
		return -1;
	if (mail_get_parts(vmail->backend_mail, parts_r) < 0) {
		virtual_box_copy_error(mail->box, vmail->backend_mail->box);
		return -1;
	}
	return 0;
}

static int
virtual_mail_get_date(struct mail *mail, time_t *date_r, int *timezone_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	int tz;

	if (timezone_r == NULL)
		timezone_r = &tz;

	if (virtual_mail_handle_lost(vmail) < 0)
		return -1;
	if (mail_get_date(vmail->backend_mail, date_r, timezone_r) < 0) {
		virtual_box_copy_error(mail->box, vmail->backend_mail->box);
		return -1;
	}
	return 0;
}

static int virtual_mail_get_received_date(struct mail *mail, time_t *date_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;

	if (virtual_mail_handle_lost(vmail) < 0)
		return -1;
	if (mail_get_received_date(vmail->backend_mail, date_r) < 0) {
		virtual_box_copy_error(mail->box, vmail->backend_mail->box);
		return -1;
	}
	return 0;
}

static int virtual_mail_get_save_date(struct mail *mail, time_t *date_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;

	if (virtual_mail_handle_lost(vmail) < 0)
		return -1;
	if (mail_get_save_date(vmail->backend_mail, date_r) < 0) {
		virtual_box_copy_error(mail->box, vmail->backend_mail->box);
		return -1;
	}
	return 0;
}

static int virtual_mail_get_virtual_mail_size(struct mail *mail, uoff_t *size_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;

	if (virtual_mail_handle_lost(vmail) < 0)
		return -1;
	if (mail_get_virtual_size(vmail->backend_mail, size_r) < 0) {
		virtual_box_copy_error(mail->box, vmail->backend_mail->box);
		return -1;
	}
	return 0;
}

static int virtual_mail_get_physical_size(struct mail *mail, uoff_t *size_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;

	if (virtual_mail_handle_lost(vmail) < 0)
		return -1;
	if (mail_get_physical_size(vmail->backend_mail, size_r) < 0) {
		virtual_box_copy_error(mail->box, vmail->backend_mail->box);
		return -1;
	}
	return 0;
}

static int
virtual_mail_get_first_header(struct mail *mail, const char *field,
			      bool decode_to_utf8, const char **value_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mail_private *p = (struct mail_private *)vmail->backend_mail;

	if (virtual_mail_handle_lost(vmail) < 0)
		return -1;
	if (p->v.get_first_header(vmail->backend_mail, field,
				  decode_to_utf8, value_r) < 0) {
		virtual_box_copy_error(mail->box, vmail->backend_mail->box);
		return -1;
	}
	return 0;
}

static int
virtual_mail_get_headers(struct mail *mail, const char *field,
			 bool decode_to_utf8, const char *const **value_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mail_private *p = (struct mail_private *)vmail->backend_mail;

	if (virtual_mail_handle_lost(vmail) < 0)
		return -1;
	if (p->v.get_headers(vmail->backend_mail, field,
			     decode_to_utf8, value_r) < 0) {
		virtual_box_copy_error(mail->box, vmail->backend_mail->box);
		return -1;
	}
	return 0;
}

static int
virtual_mail_get_header_stream(struct mail *mail,
			       struct mailbox_header_lookup_ctx *headers,
			       struct istream **stream_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mailbox_header_lookup_ctx *backend_headers;
	int ret;

	if (virtual_mail_handle_lost(vmail) < 0)
		return -1;

	backend_headers = mailbox_header_lookup_init(vmail->backend_mail->box,
						     headers->headers);
	ret = mail_get_header_stream(vmail->backend_mail, backend_headers,
				     stream_r);
	mailbox_header_lookup_unref(&backend_headers);
	if (ret < 0) {
		virtual_box_copy_error(mail->box, vmail->backend_mail->box);
		return -1;
	}
	return 0;
}

static int
virtual_mail_get_stream(struct mail *mail, struct message_size *hdr_size,
			struct message_size *body_size,
			struct istream **stream_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;

	if (virtual_mail_handle_lost(vmail) < 0)
		return -1;
	if (mail_get_stream(vmail->backend_mail, hdr_size, body_size,
			    stream_r) < 0) {
		virtual_box_copy_error(mail->box, vmail->backend_mail->box);
		return -1;
	}
	return 0;
}

static int
virtual_mail_get_special(struct mail *mail, enum mail_fetch_field field,
			 const char **value_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mailbox *box = vmail->backend_mail->box;

	if (virtual_mail_handle_lost(vmail) < 0)
		return -1;
	if (mail_get_special(vmail->backend_mail, field, value_r) < 0) {
		virtual_box_copy_error(mail->box, box);
		return -1;
	}
	return 0;
}

static struct mail *virtual_mail_get_real_mail(struct mail *mail)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;

	return mail_get_real_mail(vmail->backend_mail);
}

static void virtual_mail_update_pop3_uidl(struct mail *mail, const char *uidl)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;

	mail_update_pop3_uidl(vmail->backend_mail, uidl);
}

static void virtual_mail_expunge(struct mail *mail)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;

	if (virtual_mail_handle_lost(vmail) < 0)
		return;
	mail_expunge(vmail->backend_mail);
}

static void virtual_mail_parse(struct mail *mail, bool parse_body)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;

	if (virtual_mail_handle_lost(vmail) < 0)
		return;
	mail_parse(vmail->backend_mail, parse_body);
}

static void
virtual_mail_set_cache_corrupted(struct mail *mail, enum mail_fetch_field field)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;

	if (virtual_mail_handle_lost(vmail) < 0)
		return;
	mail_set_cache_corrupted(vmail->backend_mail, field);
}

struct mail_vfuncs virtual_mail_vfuncs = {
	NULL,
	virtual_mail_free,
	virtual_mail_set_seq,
	virtual_mail_set_uid,
	virtual_mail_set_uid_cache_updates,

	index_mail_get_flags,
	index_mail_get_keywords,
	index_mail_get_keyword_indexes,
	index_mail_get_modseq,
	virtual_mail_get_parts,
	virtual_mail_get_date,
	virtual_mail_get_received_date,
	virtual_mail_get_save_date,
	virtual_mail_get_virtual_mail_size,
	virtual_mail_get_physical_size,
	virtual_mail_get_first_header,
	virtual_mail_get_headers,
	virtual_mail_get_header_stream,
	virtual_mail_get_stream,
	virtual_mail_get_special,
	virtual_mail_get_real_mail,
	index_mail_update_flags,
	index_mail_update_keywords,
	index_mail_update_modseq,
	virtual_mail_update_pop3_uidl,
	virtual_mail_expunge,
	virtual_mail_parse,
	virtual_mail_set_cache_corrupted,
	NULL
};
