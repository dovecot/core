/* Copyright (c) 2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "index-mail.h"
#include "virtual-storage.h"

struct virtual_mail {
	struct index_mail imail;

	enum mail_fetch_field wanted_fields;
	struct mailbox_header_lookup_ctx *wanted_headers;

	/* currently active mail */
	struct mail *backend_mail;
	/* all allocated mails */
	ARRAY_DEFINE(backend_mails, struct mail *);
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
	vmail->imail.ibox = &mbox->ibox;
	vmail->imail.trans = (struct index_transaction_context *)t;

	vmail->wanted_fields = wanted_fields;
	vmail->wanted_headers = wanted_headers;
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

static void virtual_mail_set_seq(struct mail *mail, uint32_t seq)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct virtual_mailbox *mbox = (struct virtual_mailbox *)mail->box;
	struct virtual_backend_box *bbox;
	struct mailbox_transaction_context *backend_trans;
	const struct virtual_mail_index_record *vrec;
	const struct mail_index_record *rec;
	const void *data;
	bool expunged;

	mail_index_lookup_ext(mbox->ibox.view, seq, mbox->virtual_ext_id,
			      &data, &expunged);
	vrec = data;

	bbox = virtual_backend_box_lookup(mbox, vrec->mailbox_id);
	vmail->backend_mail = backend_mail_find(vmail, bbox->box);
	if (vmail->backend_mail == NULL) {
		backend_trans =
			virtual_transaction_get(mail->transaction, bbox->box);
		vmail->backend_mail = mail_alloc(backend_trans,
						 vmail->wanted_fields,
						 vmail->wanted_headers);
		array_append(&vmail->backend_mails, &vmail->backend_mail, 1);
	}
	mail_set_uid(vmail->backend_mail, vrec->real_uid);
	memset(&vmail->imail.data, 0, sizeof(vmail->imail.data));
	p_clear(vmail->imail.data_pool);

	rec = mail_index_lookup(mbox->ibox.view, seq);
	vmail->imail.data.seq = seq;
	vmail->imail.data.flags = rec->flags & MAIL_FLAGS_NONRECENT;

	mail->seq = seq;
	mail->uid = rec->uid;

	mail->expunged = vmail->backend_mail->expunged;
	mail->has_nuls = vmail->backend_mail->has_nuls;
	mail->has_no_nuls = vmail->backend_mail->has_no_nuls;
}

static bool virtual_mail_set_uid(struct mail *mail, uint32_t uid)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct virtual_mailbox *mbox = (struct virtual_mailbox *)mail->box;
	uint32_t seq;

	if (!mail_index_lookup_seq(mbox->ibox.view, uid, &seq))
		return FALSE;

	virtual_mail_set_seq(vmail->backend_mail, seq);
	return TRUE;
}

static int
virtual_mail_get_parts(struct mail *mail, const struct message_part **parts_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;

	return mail_get_parts(vmail->backend_mail, parts_r);
}

static int
virtual_mail_get_date(struct mail *mail, time_t *date_r, int *timezone_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	int tz;

	if (timezone_r == NULL)
		timezone_r = &tz;

	return mail_get_date(vmail->backend_mail, date_r, timezone_r);
}

static int virtual_mail_get_received_date(struct mail *mail, time_t *date_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;

	return mail_get_received_date(vmail->backend_mail, date_r);
}

static int virtual_mail_get_save_date(struct mail *mail, time_t *date_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;

	return mail_get_save_date(vmail->backend_mail, date_r);
}

static int virtual_mail_get_virtual_mail_size(struct mail *mail, uoff_t *size_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;

	return mail_get_virtual_size(vmail->backend_mail, size_r);
}

static int virtual_mail_get_physical_size(struct mail *mail, uoff_t *size_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;

	return mail_get_physical_size(vmail->backend_mail, size_r);
}

static int
virtual_mail_get_first_header(struct mail *mail, const char *field,
			      bool decode_to_utf8, const char **value_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mail_private *p = (struct mail_private *)vmail->backend_mail;

	return p->v.get_first_header(vmail->backend_mail, field,
				     decode_to_utf8, value_r);
}

static int
virtual_mail_get_headers(struct mail *mail, const char *field,
			 bool decode_to_utf8, const char *const **value_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mail_private *p = (struct mail_private *)vmail->backend_mail;

	return p->v.get_headers(vmail->backend_mail, field,
				decode_to_utf8, value_r);
}

static int
virtual_mail_get_header_stream(struct mail *mail,
			       struct mailbox_header_lookup_ctx *headers,
			       struct istream **stream_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;

	return mail_get_header_stream(vmail->backend_mail, headers, stream_r);
}

static int
virtual_mail_get_stream(struct mail *mail, struct message_size *hdr_size,
			struct message_size *body_size,
			struct istream **stream_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;

	return mail_get_stream(vmail->backend_mail, hdr_size, body_size, stream_r);
}

static int
virtual_mail_get_special(struct mail *mail, enum mail_fetch_field field,
			 const char **value_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;

	return mail_get_special(vmail->backend_mail, field, value_r);
}

static void virtual_mail_expunge(struct mail *mail)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;

	mail_expunge(vmail->backend_mail);
}

static void
virtual_mail_set_cache_corrupted(struct mail *mail, enum mail_fetch_field field)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;

	mail_set_cache_corrupted(vmail->backend_mail, field);
}

static struct index_mail *virtual_mail_get_index_mail(struct mail *mail)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;

	return (struct index_mail *)vmail->backend_mail;
}

struct mail_vfuncs virtual_mail_vfuncs = {
	NULL,
	virtual_mail_free,
	virtual_mail_set_seq,
	virtual_mail_set_uid,

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
	index_mail_update_flags,
	index_mail_update_keywords,
	virtual_mail_expunge,
	virtual_mail_set_cache_corrupted,
	virtual_mail_get_index_mail
};
