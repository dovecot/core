/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "istream.h"
#include "message-parser.h"
#include "mail-storage.h"
#include "mail-namespace.h"
#include "imap-url.h"
#include "imap-msgpart.h"
#include "imap-msgpart-url.h"

struct imap_msgpart_url {
	char *mailbox;
	uint32_t uidvalidity;
	uint32_t uid;
	char *section;
	uoff_t partial_offset, partial_size;

	struct imap_msgpart *part;

	struct mail_user *user;
	struct mailbox *selected_box;
	struct mailbox *box;
	struct mailbox_transaction_context *trans;
	struct mail *mail;
	
	struct imap_msgpart_open_result result;

	bool decode_cte_to_binary:1;
};

int imap_msgpart_url_create(struct mail_user *user, const struct imap_url *url,
			    struct imap_msgpart_url **mpurl_r,
			    const char **client_error_r)
{
	const char *section = url->section == NULL ? "" : url->section;
	struct imap_msgpart_url *mpurl;
	struct imap_msgpart *msgpart;

	if (url->mailbox == NULL || url->uid == 0 ||
	    url->search_program != NULL) {
		*client_error_r = "Invalid messagepart IMAP URL";
		return -1;
	}
	if (imap_msgpart_parse(section, &msgpart) < 0) {
		*client_error_r = "Invalid section";
		return -1;
	}

	mpurl = i_new(struct imap_msgpart_url, 1);
	mpurl->part = msgpart;
	mpurl->user = user;
	mpurl->mailbox = i_strdup(url->mailbox);
	mpurl->uidvalidity = url->uidvalidity;
	mpurl->uid = url->uid;
	if (url->section != NULL)
		mpurl->section = i_strdup(url->section);
	mpurl->partial_offset = url->partial_offset;
	mpurl->partial_size = url->partial_size;

	imap_msgpart_set_partial(msgpart, url->partial_offset,
				 url->partial_size == 0 ?
				 (uoff_t)-1 : url->partial_size);

	*mpurl_r = mpurl;
	return 0;
}

int imap_msgpart_url_parse(struct mail_user *user, struct mailbox *selected_box,
			   const char *urlstr, struct imap_msgpart_url **mpurl_r,
			   const char **client_error_r)
{
	struct mailbox_status box_status;
	struct imap_url base_url, *url;
	const char  *error;

	/* build base url */
	i_zero(&base_url);
	if (selected_box != NULL) {
		mailbox_get_open_status(selected_box, STATUS_UIDVALIDITY,
					&box_status);
		base_url.mailbox = mailbox_get_vname(selected_box);
		base_url.uidvalidity = box_status.uidvalidity;
	}

	/* parse url */
	if (imap_url_parse(urlstr, &base_url,
			   IMAP_URL_PARSE_REQUIRE_RELATIVE, &url, &error) < 0) {
		*client_error_r = t_strconcat("Invalid IMAP URL: ", error, NULL);
		return 0;
	}
	if (url->mailbox == NULL) {
		*client_error_r = "Mailbox-relative IMAP URL, but no mailbox selected";
		return 0;
	}
	if (imap_msgpart_url_create(user, url, mpurl_r, client_error_r) < 0)
		return -1;
	(*mpurl_r)->selected_box = selected_box;
	return 1;
}

struct mailbox *imap_msgpart_url_get_mailbox(struct imap_msgpart_url *mpurl)
{
	return mpurl->box;
}

int imap_msgpart_url_open_mailbox(struct imap_msgpart_url *mpurl,
				  struct mailbox **box_r, enum mail_error *error_code_r,
				  const char **client_error_r)
{
	struct mailbox_status box_status;
	enum mailbox_flags flags = MAILBOX_FLAG_READONLY;
	struct mail_namespace *ns;
	struct mailbox *box;

	if (mpurl->box != NULL) {
		*box_r = mpurl->box;
		*error_code_r = MAIL_ERROR_NONE;
		return 1;
	}

	/* find mailbox namespace */
	ns = mail_namespace_find(mpurl->user->namespaces, mpurl->mailbox);

	/* open mailbox */
	if (mpurl->selected_box != NULL &&
	    mailbox_equals(mpurl->selected_box, ns, mpurl->mailbox))
		box = mpurl->selected_box;
	else {
		box = mailbox_alloc(ns->list, mpurl->mailbox, flags);
		mailbox_set_reason(box, "Read IMAP URL");
	}
	if (mailbox_open(box) < 0) {
		*client_error_r = mail_storage_get_last_error(mailbox_get_storage(box),
							      error_code_r);
		if (box != mpurl->selected_box)
			mailbox_free(&box);
		return *error_code_r == MAIL_ERROR_TEMP ? -1 : 0;
	}

	/* verify UIDVALIDITY */
	mailbox_get_open_status(box, STATUS_UIDVALIDITY, &box_status);
	if (mpurl->uidvalidity > 0 &&
	    box_status.uidvalidity != mpurl->uidvalidity) {
		*client_error_r = "Invalid UIDVALIDITY";
		*error_code_r = MAIL_ERROR_EXPUNGED;
		if (box != mpurl->selected_box)
			mailbox_free(&box);
		return 0;
	}
	mpurl->box = box;
	*box_r = box;
	return 1;
}

int imap_msgpart_url_open_mail(struct imap_msgpart_url *mpurl,
			       struct mail **mail_r,
			       const char **client_error_r)
{
	struct mailbox_transaction_context *t;
	struct mailbox *box;
	enum mail_error error_code;
	struct mail *mail;
	int ret;

	if (mpurl->mail != NULL) {
		*mail_r = mpurl->mail;
		return 1;
	}

	/* open mailbox if it is not yet open */
	if ((ret = imap_msgpart_url_open_mailbox(mpurl, &box, &error_code,
						 client_error_r)) <= 0)
		return ret;

	/* start transaction */
	t = mailbox_transaction_begin(box, 0, __func__);
	mail = mail_alloc(t, MAIL_FETCH_MESSAGE_PARTS |
			  MAIL_FETCH_IMAP_BODYSTRUCTURE, NULL);

	/* find the message */
	if (!mail_set_uid(mail, mpurl->uid)) {
		*client_error_r = "Message not found";
		mail_free(&mail);
		mailbox_transaction_rollback(&t);	
		return 0;
	}

	mpurl->trans = t;
	mpurl->mail = mail;
	*mail_r = mail;
	return 1;
}

struct imap_msgpart *
imap_msgpart_url_get_part(struct imap_msgpart_url *mpurl)
{
	return mpurl->part;
}

void imap_msgpart_url_set_decode_to_binary(struct imap_msgpart_url *mpurl)
{
	imap_msgpart_set_decode_to_binary(mpurl->part);
}

int imap_msgpart_url_read_part(struct imap_msgpart_url *mpurl,
			       struct imap_msgpart_open_result *result_r,
			       const char **client_error_r)
{
	struct mail *mail;
	int ret;

	if (mpurl->result.input != NULL) {
		i_stream_seek(mpurl->result.input, 0);
		*result_r = mpurl->result;
		return 1;
	}

	/* open mail if it is not yet open */
	ret = imap_msgpart_url_open_mail(mpurl, &mail, client_error_r);
	if (ret <= 0)
		return ret;

	/* open the referenced part as a stream */
	ret = imap_msgpart_open(mail, mpurl->part, result_r);
	if (ret < 0) {
		*client_error_r = mailbox_get_last_error(mpurl->box, NULL);
		return ret;
	}

	mpurl->result = *result_r;
	return 1;
}

int imap_msgpart_url_verify(struct imap_msgpart_url *mpurl,
			    const char **client_error_r)
{
	struct mail *mail;
	int ret;

	if (mpurl->result.input != NULL)
		return 1;

	/* open mail if it is not yet open */
	ret = imap_msgpart_url_open_mail(mpurl, &mail, client_error_r);
	return ret;
}

int imap_msgpart_url_get_bodypartstructure(struct imap_msgpart_url *mpurl,
					   const char **bpstruct_r,
					   const char **client_error_r)
{
	struct mail *mail;
	int ret;

	/* open mail if it is not yet open */
	ret = imap_msgpart_url_open_mail(mpurl, &mail, client_error_r);
	if (ret <= 0)
		return ret;

	ret = imap_msgpart_bodypartstructure(mail, mpurl->part, bpstruct_r);
	if (ret < 0)
		*client_error_r = mailbox_get_last_error(mpurl->box, NULL);
	else if (ret == 0)
		*client_error_r = "Message part not found";
	return ret;
}

void imap_msgpart_url_free(struct imap_msgpart_url **_mpurl)
{
	struct imap_msgpart_url *mpurl = *_mpurl;

	*_mpurl = NULL;

	i_stream_unref(&mpurl->result.input);
	if (mpurl->part != NULL)
		imap_msgpart_free(&mpurl->part);
	if (mpurl->mail != NULL)
		mail_free(&mpurl->mail);
	if (mpurl->trans != NULL)
		mailbox_transaction_rollback(&mpurl->trans);
	if (mpurl->box != NULL && mpurl->box != mpurl->selected_box)
		mailbox_free(&mpurl->box);	
	if (mpurl->section != NULL)
		i_free(mpurl->section);
	i_free(mpurl->mailbox);
	i_free(mpurl);
}
