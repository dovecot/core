/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "network.h"
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

	struct mail_user *user;
	struct mailbox *box;
	struct mailbox_transaction_context *trans;
	struct mail *mail;
	
	struct istream *input;
	uoff_t part_size;
};

struct imap_msgpart_url *
imap_msgpart_url_create(struct mail_user *user, const struct imap_url *url)
{
	struct imap_msgpart_url *mpurl;

	i_assert(url->mailbox != NULL && url->uid != 0 &&
		 url->search_program == NULL);

	mpurl = i_new(struct imap_msgpart_url, 1);
	mpurl->user = user;
	mpurl->mailbox = i_strdup(url->mailbox);
	mpurl->uidvalidity = url->uidvalidity;
	mpurl->uid = url->uid;
	if (url->section != NULL)
		mpurl->section = i_strdup(url->section);
	mpurl->partial_offset = url->partial_offset;
	mpurl->partial_size = url->partial_size;
	return mpurl;
}

int imap_msgpart_url_parse(struct mail_user *user, struct mailbox *selected_box,
			   const char *urlstr, struct imap_msgpart_url **url_r,
			   const char **error_r)
{
	struct mailbox_status box_status;
	struct imap_url base_url, *url;
	const char  *error;

	/* build base url */
	memset(&base_url, 0, sizeof(base_url));
	if (selected_box != NULL) {
		mailbox_get_open_status(selected_box, STATUS_UIDVALIDITY,
					&box_status);
		base_url.mailbox = mailbox_get_vname(selected_box);
		base_url.uidvalidity = box_status.uidvalidity;
	}

	/* parse url */
	if (imap_url_parse(urlstr, &base_url,
			   IMAP_URL_PARSE_REQUIRE_RELATIVE, &url, &error) < 0) {
		*error_r = t_strconcat("Invalid IMAP URL: ", error, NULL);
		return 0;
	}
	if (url->mailbox == NULL) {
		*error_r = "Mailbox-relative IMAP URL, but no mailbox selected";
		return 0;
	}
	if (url->uid == 0 || url->search_program != NULL) {
		*error_r = "Invalid messagepart IMAP URL";
		return 0;
	}
	*url_r = imap_msgpart_url_create(user, url);
	return 1;
}

struct mailbox *imap_msgpart_url_get_mailbox(struct imap_msgpart_url *mpurl)
{
	return mpurl->box;
}

int imap_msgpart_url_open_mailbox(struct imap_msgpart_url *mpurl,
				  struct mailbox **box_r, const char **error_r)
{
	struct mailbox_status box_status;
	enum mail_error error_code;
	enum mailbox_flags flags = MAILBOX_FLAG_READONLY;
	struct mail_namespace *ns;
	struct mailbox *box;

	if (mpurl->box != NULL) {
		*box_r = mpurl->box;
		return 1;
	}

	/* find mailbox namespace */
	ns = mail_namespace_find(mpurl->user->namespaces, mpurl->mailbox);
	if (ns == NULL) {
		*error_r = "Nonexistent mailbox namespace";
		return 0;
	}

	/* open mailbox */
	box = mailbox_alloc(ns->list, mpurl->mailbox, flags);
	if (mailbox_open(box) < 0) {
		*error_r = mail_storage_get_last_error(mailbox_get_storage(box),
						       &error_code);
		mailbox_free(&box);
		return error_code == MAIL_ERROR_TEMP ? -1 : 0;
	}

	/* verify UIDVALIDITY */
	mailbox_get_open_status(box, STATUS_UIDVALIDITY, &box_status);
	if (mpurl->uidvalidity > 0 &&
	    box_status.uidvalidity != mpurl->uidvalidity) {
		*error_r = "Invalid UIDVALIDITY";
		mailbox_free(&box);
		return 0;
	}
	mpurl->box = box;
	*box_r = box;
	return 1;
}

int imap_msgpart_url_open_mail(struct imap_msgpart_url *mpurl,
			       struct mail **mail_r, const char **error_r)
{
	struct mailbox_transaction_context *t;
	struct mailbox *box;
	struct mail *mail;
	int ret;

	if (mpurl->mail != NULL) {
		*mail_r = mpurl->mail;
		return 1;
	}

	/* open mailbox if it is not yet open */
	if ((ret = imap_msgpart_url_open_mailbox(mpurl, &box, error_r)) <= 0)
		return ret;

	/* start transaction */
	t = mailbox_transaction_begin(box, 0);
	mail = mail_alloc(t, 0, NULL);

	/* find the message */
	if (!mail_set_uid(mail, mpurl->uid)) {
		*error_r = "Message not found";
		mail_free(&mail);
		mailbox_transaction_rollback(&t);	
		return 0;
	}

	mpurl->trans = t;
	mpurl->mail = mail;
	*mail_r = mail;
	return 1;
}

static int
imap_msgpart_url_open_part(struct imap_msgpart_url *mpurl, struct mail **mail_r,
			   struct imap_msgpart **msgpart_r, const char **error_r)
{
	const char *section = mpurl->section == NULL ? "" : mpurl->section;
	int ret;

	if ((ret = imap_msgpart_url_open_mail(mpurl, mail_r, error_r)) <= 0)
		return ret;

	if (imap_msgpart_parse((*mail_r)->box, section, msgpart_r) < 0) {
		*error_r = "Invalid section";
		return 0;
	}
	imap_msgpart_set_partial(*msgpart_r, mpurl->partial_offset,
				 mpurl->partial_size == 0 ? (uoff_t)-1 :
				 mpurl->partial_size);
	return 1;
}

int imap_msgpart_url_read_part(struct imap_msgpart_url *mpurl,
			       struct istream **stream_r, uoff_t *size_r,
			       const char **error_r)
{
	struct mail *mail;
	struct imap_msgpart *msgpart;
	struct imap_msgpart_open_result result;
	int ret;

	if (mpurl->input != NULL) {
		i_stream_seek(mpurl->input, 0);
		*stream_r = mpurl->input;
		*size_r = mpurl->part_size;
		return 1;
	}

	/* open mail if it is not yet open */
	ret = imap_msgpart_url_open_part(mpurl, &mail, &msgpart, error_r);
	if (ret <= 0)
		return ret;

	/* open the referenced part as a stream */
	ret = imap_msgpart_open(mail, msgpart, &result);
	imap_msgpart_free(&msgpart);
	if (ret < 0) {
		*error_r = mailbox_get_last_error(mail->box, NULL);
		return ret;
	}

	*stream_r = mpurl->input = result.input;
	*size_r = mpurl->part_size = result.size;
	return 1;
}

int imap_msgpart_url_verify(struct imap_msgpart_url *mpurl,
			    const char **error_r)
{
	struct mail *mail;
	struct imap_msgpart *msgpart;
	int ret;

	if (mpurl->input != NULL)
		return 1;

	/* open mail if it is not yet open */
	ret = imap_msgpart_url_open_part(mpurl, &mail, &msgpart, error_r);
	if (ret > 0)
		imap_msgpart_free(&msgpart);
	return ret;
}

void imap_msgpart_url_free(struct imap_msgpart_url **_mpurl)
{
	struct imap_msgpart_url *mpurl = *_mpurl;

	*_mpurl = NULL;

	if (mpurl->input != NULL)
		i_stream_unref(&mpurl->input);
	if (mpurl->mail != NULL)
		mail_free(&mpurl->mail);
	if (mpurl->trans != NULL)
		mailbox_transaction_rollback(&mpurl->trans);
	if (mpurl->box != NULL)
		mailbox_free(&mpurl->box);	
	if (mpurl->section != NULL)
		i_free(mpurl->section);
	i_free(mpurl->mailbox);
	i_free(mpurl);
}
