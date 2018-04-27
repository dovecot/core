/* Copyright (c) 2008-2018 Dovecot authors, see the included COPYING file */

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
	struct mail *cur_backend_mail;
	struct virtual_mail_index_record cur_vrec;

	/* all allocated mails */
	ARRAY(struct mail *) backend_mails;

	/* mail is lost if backend_mail doesn't point to correct mail */
	bool cur_lost:1;
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
	vmail->imail.mail.data_pool =
		pool_alloconly_create("virtual index_mail", 512);
	vmail->imail.mail.v = virtual_mail_vfuncs;
	vmail->imail.mail.mail.box = t->box;
	vmail->imail.mail.mail.transaction = t;
	array_create(&vmail->imail.mail.module_contexts, pool,
		     sizeof(void *), 5);

	vmail->imail.ibox = INDEX_STORAGE_CONTEXT(t->box);

	vmail->wanted_fields = wanted_fields;
	if (wanted_headers != NULL) {
		vmail->wanted_headers = wanted_headers;
		mailbox_header_lookup_ref(wanted_headers);
	}

	i_array_init(&vmail->backend_mails, array_count(&mbox->backend_boxes));
	return &vmail->imail.mail.mail;
}

static void virtual_mail_close(struct mail *mail)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mail **mails;
	unsigned int i, count;

	mails = array_get_modifiable(&vmail->backend_mails, &count);
	for (i = 0; i < count; i++) {
		struct mail_private *p = (struct mail_private *)mails[i];

		p->v.close(mails[i]);
	}
	index_mail_close(mail);
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

	mailbox_header_lookup_unref(&vmail->wanted_headers);

	pool_unref(&vmail->imail.mail.data_pool);
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

static int backend_mail_get(struct virtual_mail *vmail,
			    struct mail **backend_mail_r)
{
	struct mail *mail = &vmail->imail.mail.mail;
	struct virtual_mailbox *mbox = (struct virtual_mailbox *)mail->box;
	struct virtual_backend_box *bbox;

	*backend_mail_r = NULL;

	if (vmail->cur_backend_mail != NULL) {
		if (vmail->cur_lost) {
			mail_set_expunged(&vmail->imail.mail.mail);
			return -1;
		}
		*backend_mail_r = vmail->cur_backend_mail;
		return 0;
	}

	bbox = virtual_backend_box_lookup(mbox, vmail->cur_vrec.mailbox_id);
	i_assert(bbox != NULL);

	vmail->cur_backend_mail = backend_mail_find(vmail, bbox->box);
	if (vmail->cur_backend_mail == NULL) {
		if (!bbox->box->opened &&
		    virtual_backend_box_open(mbox, bbox) < 0) {
			virtual_box_copy_error(mail->box, bbox->box);
			return -1;
		}
		(void)virtual_mail_set_backend_mail(mail, bbox);
		i_assert(vmail->cur_backend_mail != NULL);
	}
	virtual_backend_box_accessed(mbox, bbox);
	vmail->cur_lost = !mail_set_uid(vmail->cur_backend_mail,
					vmail->cur_vrec.real_uid);
	mail->expunged = vmail->cur_lost || vmail->cur_backend_mail->expunged;
	if (vmail->cur_lost) {
		mail_set_expunged(&vmail->imail.mail.mail);
		return -1;
	}
	*backend_mail_r = vmail->cur_backend_mail;
	return 0;
}

struct mail *
virtual_mail_set_backend_mail(struct mail *mail,
			      struct virtual_backend_box *bbox)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mail_private *backend_pmail;
	struct mailbox_transaction_context *backend_trans;
	struct mailbox_header_lookup_ctx *backend_headers;

	i_assert(bbox->box->opened);

	backend_trans = virtual_transaction_get(mail->transaction, bbox->box);

	backend_headers = vmail->wanted_headers == NULL ? NULL :
		mailbox_header_lookup_init(bbox->box,
					   vmail->wanted_headers->name);
	vmail->cur_backend_mail =
		mail_alloc(backend_trans, vmail->wanted_fields, backend_headers);
	mailbox_header_lookup_unref(&backend_headers);

	backend_pmail = (struct mail_private *)vmail->cur_backend_mail;
	backend_pmail->vmail = mail;
	array_push_back(&vmail->backend_mails, &vmail->cur_backend_mail);
	return vmail->cur_backend_mail;
}

void virtual_mail_set_unattached_backend_mail(struct mail *mail,
					      struct mail *backend_mail)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mail_private *backend_pmail;

	vmail->cur_backend_mail = backend_mail;

	backend_pmail = (struct mail_private *)backend_mail;
	backend_pmail->vmail = mail;
}

static void virtual_mail_set_seq(struct mail *mail, uint32_t seq, bool saving)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct virtual_mailbox *mbox = (struct virtual_mailbox *)mail->box;
	const void *data;

	i_assert(!saving);

	mail_index_lookup_ext(mail->transaction->view, seq,
			      mbox->virtual_ext_id, &data, NULL);
	memcpy(&vmail->cur_vrec, data, sizeof(vmail->cur_vrec));

	i_zero(&vmail->imail.data);
	p_clear(vmail->imail.mail.data_pool);

	vmail->imail.data.seq = seq;
	mail->seq = seq;
	mail_index_lookup_uid(mail->transaction->view, seq, &mail->uid);

	vmail->cur_backend_mail = NULL;
}

static bool virtual_mail_set_uid(struct mail *mail, uint32_t uid)
{
	uint32_t seq;

	if (!mail_index_lookup_seq(mail->transaction->view, uid, &seq))
		return FALSE;

	virtual_mail_set_seq(mail, seq, FALSE);
	return TRUE;
}

static void virtual_mail_set_uid_cache_updates(struct mail *mail, bool set)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mail *backend_mail;
	struct mail_private *p;

	if (backend_mail_get(vmail, &backend_mail) < 0)
		return;
	p = (struct mail_private *)backend_mail;
	p->v.set_uid_cache_updates(backend_mail, set);
}

static bool virtual_mail_prefetch(struct mail *mail)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mail *backend_mail;
	struct mail_private *p;

	if (backend_mail_get(vmail, &backend_mail) < 0)
		return TRUE;
	p = (struct mail_private *)backend_mail;
	return p->v.prefetch(backend_mail);
}

static void virtual_mail_precache(struct mail *mail)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mail *backend_mail;
	struct mail_private *p;

	if (backend_mail_get(vmail, &backend_mail) < 0)
		return;
	p = (struct mail_private *)backend_mail;
	p->v.precache(backend_mail);
}

static void
virtual_mail_add_temp_wanted_fields(struct mail *mail,
				    enum mail_fetch_field fields,
				    struct mailbox_header_lookup_ctx *headers)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mail *backend_mail;
	struct mailbox_header_lookup_ctx *backend_headers;

	if (backend_mail_get(vmail, &backend_mail) < 0)
		return;
	/* convert header indexes to backend mailbox's header indexes */
	backend_headers = headers == NULL ? NULL :
		mailbox_header_lookup_init(backend_mail->box, headers->name);
	mail_add_temp_wanted_fields(backend_mail, fields, backend_headers);
	mailbox_header_lookup_unref(&backend_headers);
}

static int
virtual_mail_get_parts(struct mail *mail, struct message_part **parts_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mail *backend_mail;

	if (backend_mail_get(vmail, &backend_mail) < 0)
		return -1;
	if (mail_get_parts(backend_mail, parts_r) < 0) {
		virtual_box_copy_error(mail->box, backend_mail->box);
		return -1;
	}
	return 0;
}

static int
virtual_mail_get_date(struct mail *mail, time_t *date_r, int *timezone_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mail *backend_mail;
	int tz;

	if (timezone_r == NULL)
		timezone_r = &tz;

	if (backend_mail_get(vmail, &backend_mail) < 0)
		return -1;
	if (mail_get_date(backend_mail, date_r, timezone_r) < 0) {
		virtual_box_copy_error(mail->box, backend_mail->box);
		return -1;
	}
	return 0;
}

static int virtual_mail_get_received_date(struct mail *mail, time_t *date_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mail *backend_mail;

	if (backend_mail_get(vmail, &backend_mail) < 0)
		return -1;
	if (mail_get_received_date(backend_mail, date_r) < 0) {
		virtual_box_copy_error(mail->box, backend_mail->box);
		return -1;
	}
	return 0;
}

static int virtual_mail_get_save_date(struct mail *mail, time_t *date_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mail *backend_mail;

	if (backend_mail_get(vmail, &backend_mail) < 0)
		return -1;
	if (mail_get_save_date(backend_mail, date_r) < 0) {
		virtual_box_copy_error(mail->box, backend_mail->box);
		return -1;
	}
	return 0;
}

static int virtual_mail_get_virtual_mail_size(struct mail *mail, uoff_t *size_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mail *backend_mail;

	if (backend_mail_get(vmail, &backend_mail) < 0)
		return -1;
	if (mail_get_virtual_size(backend_mail, size_r) < 0) {
		virtual_box_copy_error(mail->box, backend_mail->box);
		return -1;
	}
	return 0;
}

static int virtual_mail_get_physical_size(struct mail *mail, uoff_t *size_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mail *backend_mail;

	if (backend_mail_get(vmail, &backend_mail) < 0)
		return -1;
	if (mail_get_physical_size(backend_mail, size_r) < 0) {
		virtual_box_copy_error(mail->box, backend_mail->box);
		return -1;
	}
	return 0;
}

static int
virtual_mail_get_first_header(struct mail *mail, const char *field,
			      bool decode_to_utf8, const char **value_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mail *backend_mail;
	struct mail_private *p;
	int ret;

	if (backend_mail_get(vmail, &backend_mail) < 0)
		return -1;
	p = (struct mail_private *)backend_mail;
	ret = p->v.get_first_header(backend_mail, field,
				    decode_to_utf8, value_r);
	if (ret < 0) {
		virtual_box_copy_error(mail->box, backend_mail->box);
		return -1;
	}
	return ret;
}

static int
virtual_mail_get_headers(struct mail *mail, const char *field,
			 bool decode_to_utf8, const char *const **value_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mail *backend_mail;
	struct mail_private *p;

	if (backend_mail_get(vmail, &backend_mail) < 0)
		return -1;
	p = (struct mail_private *)backend_mail;
	if (p->v.get_headers(backend_mail, field, decode_to_utf8, value_r) < 0) {
		virtual_box_copy_error(mail->box, backend_mail->box);
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
	struct mail *backend_mail;
	struct mailbox_header_lookup_ctx *backend_headers;
	int ret;

	if (backend_mail_get(vmail, &backend_mail) < 0)
		return -1;

	backend_headers = mailbox_header_lookup_init(backend_mail->box,
						     headers->name);
	ret = mail_get_header_stream(backend_mail, backend_headers, stream_r);
	mailbox_header_lookup_unref(&backend_headers);
	if (ret < 0) {
		virtual_box_copy_error(mail->box, backend_mail->box);
		return -1;
	}
	return 0;
}

static int
virtual_mail_get_stream(struct mail *mail, bool get_body,
			struct message_size *hdr_size,
			struct message_size *body_size,
			struct istream **stream_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mail_private *vp = (struct mail_private *)mail;
	struct mail *backend_mail;
	const char *reason = t_strdup_printf("virtual mailbox %s: Opened mail UID=%u: %s",
					     mailbox_get_vname(mail->box), mail->uid, vp->get_stream_reason);
	int ret;

	if (backend_mail_get(vmail, &backend_mail) < 0)
		return -1;

	if (get_body) {
		ret = mail_get_stream_because(backend_mail, hdr_size, body_size,
					      reason, stream_r);
	} else {
		ret = mail_get_hdr_stream_because(backend_mail, hdr_size,
						  reason, stream_r);
	}

	if (ret < 0) {
		virtual_box_copy_error(mail->box, backend_mail->box);
		return -1;
	}
	return 0;
}

static int
virtual_mail_get_binary_stream(struct mail *mail,
			       const struct message_part *part,
			       bool include_hdr, uoff_t *size_r,
			       unsigned int *lines_r, bool *binary_r,
			       struct istream **stream_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mail *backend_mail;

	if (backend_mail_get(vmail, &backend_mail) < 0)
		return -1;

	struct mail_private *p = (struct mail_private *)backend_mail;
	if (p->v.get_binary_stream(backend_mail, part, include_hdr,
				   size_r, lines_r, binary_r, stream_r) < 0) {
		virtual_box_copy_error(mail->box, backend_mail->box);
		return -1;
	}
	return 0;
}

static int
virtual_mail_get_special(struct mail *mail, enum mail_fetch_field field,
			 const char **value_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mail *backend_mail;

	if (backend_mail_get(vmail, &backend_mail) < 0)
		return -1;
	if (mail_get_special(backend_mail, field, value_r) < 0) {
		virtual_box_copy_error(mail->box, backend_mail->box);
		return -1;
	}
	return 0;
}

static int virtual_mail_get_backend_mail(struct mail *mail,
					 struct mail **real_mail_r)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mail *backend_mail;

	if (backend_mail_get(vmail, &backend_mail) < 0)
		return -1;

	if (mail_get_backend_mail(backend_mail, real_mail_r) < 0)
		return -1;
	return 0;
}

static void virtual_mail_update_pop3_uidl(struct mail *mail, const char *uidl)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mail *backend_mail;

	if (backend_mail_get(vmail, &backend_mail) < 0)
		return;
	mail_update_pop3_uidl(backend_mail, uidl);
}

static void virtual_mail_expunge(struct mail *mail)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mail *backend_mail;

	if (backend_mail_get(vmail, &backend_mail) < 0)
		return;
	mail_expunge(backend_mail);
}

static void
virtual_mail_set_cache_corrupted(struct mail *mail,
				 enum mail_fetch_field field,
				 const char *reason)
{
	struct virtual_mail *vmail = (struct virtual_mail *)mail;
	struct mail *backend_mail;

	if (backend_mail_get(vmail, &backend_mail) < 0)
		return;
	mail_set_cache_corrupted(backend_mail, field, reason);
}

struct mail_vfuncs virtual_mail_vfuncs = {
	virtual_mail_close,
	virtual_mail_free,
	virtual_mail_set_seq,
	virtual_mail_set_uid,
	virtual_mail_set_uid_cache_updates,
	virtual_mail_prefetch,
	virtual_mail_precache,
	virtual_mail_add_temp_wanted_fields,

	index_mail_get_flags,
	index_mail_get_keywords,
	index_mail_get_keyword_indexes,
	index_mail_get_modseq,
	index_mail_get_pvt_modseq,
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
	virtual_mail_get_binary_stream,
	virtual_mail_get_special,
	virtual_mail_get_backend_mail,
	index_mail_update_flags,
	index_mail_update_keywords,
	index_mail_update_modseq,
	index_mail_update_pvt_modseq,
	virtual_mail_update_pop3_uidl,
	virtual_mail_expunge,
	virtual_mail_set_cache_corrupted,
	NULL,
};
