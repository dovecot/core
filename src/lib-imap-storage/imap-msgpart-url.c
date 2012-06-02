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

struct imap_msgpart_url *
imap_msgpart_url_parse(struct mail_user *user, struct mailbox *selected_box,
		       const char *urlstr, const char **error_r)
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
	url = imap_url_parse(urlstr, NULL, &base_url,
			     IMAP_URL_PARSE_REQUIRE_RELATIVE, &error);
	if (url == NULL) {
		*error_r = t_strconcat("Invalid IMAP URL: ", error, NULL);
		return NULL;
	}
	if (url->mailbox == NULL) {
		*error_r = "Mailbox-relative IMAP URL, but no mailbox selected";
		return NULL;
	}
	if (url->uid == 0 || url->search_program != NULL) {
		*error_r = "Invalid messagepart IMAP URL";
		return NULL;
	}
	return imap_msgpart_url_create(user, url);
}

struct mailbox *imap_msgpart_url_get_mailbox(struct imap_msgpart_url *mpurl)
{
	return mpurl->box;
}

struct mailbox *
imap_msgpart_url_open_mailbox(struct imap_msgpart_url *mpurl,
			      const char **error_r)
{
	struct mailbox_status box_status;
	enum mail_error error_code;
	enum mailbox_flags flags = MAILBOX_FLAG_READONLY;
	struct mail_namespace *ns;
	struct mailbox *box;

	if (mpurl->box != NULL)
		return mpurl->box;

	/* find mailbox namespace */
	ns = mail_namespace_find(mpurl->user->namespaces, mpurl->mailbox);
	if (ns == NULL) {
		*error_r = "Nonexistent mailbox namespace";
		return NULL;
	}

	/* open mailbox */
	box = mailbox_alloc(ns->list, mpurl->mailbox, flags);
	if (mailbox_open(box) < 0) {
		*error_r = mail_storage_get_last_error(mailbox_get_storage(box),
						       &error_code);
		mailbox_free(&box);
		return NULL;
	}

	/* verify UIDVALIDITY */
	mailbox_get_open_status(box, STATUS_UIDVALIDITY, &box_status);
	if (mpurl->uidvalidity > 0 &&
	    box_status.uidvalidity != mpurl->uidvalidity) {
		*error_r = "Invalid UIDVALIDITY";
		mailbox_free(&box);
		return NULL;
	}
	mpurl->box = box;
	return box;
}

struct mail *
imap_msgpart_url_open_mail(struct imap_msgpart_url *mpurl, const char **error_r)
{
	struct mailbox_transaction_context *t;
	struct mail *mail;

	if (mpurl->mail != NULL)
		return mpurl->mail;

	/* open mailbox if it is not yet open */
	if (mpurl->box == NULL) {
		if (imap_msgpart_url_open_mailbox(mpurl, error_r) == NULL)
			return NULL;
	}

	/* start transaction */
	t = mailbox_transaction_begin(mpurl->box, 0);
	mail = mail_alloc(t, 0, NULL);

	/* find the message */
	if (!mail_set_uid(mail, mpurl->uid)) {
		*error_r = "Message not found";
		mail_free(&mail);
		mailbox_transaction_rollback(&t);	
		return NULL;
	}

	mpurl->trans = t;
	mpurl->mail = mail;
	return mail;
}

bool imap_msgpart_url_read_part(struct imap_msgpart_url *mpurl,
				struct istream **stream_r, uoff_t *size_r,
				const char **error_r)
{
	struct istream *input;
	uoff_t part_size;

	if (mpurl->input != NULL) {
		i_stream_seek(mpurl->input, 0);
		*stream_r = mpurl->input;
		*size_r = mpurl->part_size;
		return TRUE;
	}

	/* open mailbox if it is not yet open */
	if (mpurl->mail == NULL) {
		if (imap_msgpart_url_open_mail(mpurl, error_r) == NULL)
			return FALSE;
	}

	/* open the referenced part as a stream */
	if (!imap_msgpart_open(mpurl->mail, mpurl->section,
			       mpurl->partial_offset, mpurl->partial_size,
			       &input, &part_size, error_r))
		return FALSE;

	mpurl->input = input;
	mpurl->part_size = part_size;

	*stream_r = input;
	*size_r = part_size;
	return TRUE;
}

bool imap_msgpart_url_verify(struct imap_msgpart_url *mpurl,
			     const char **error_r)
{
	if (mpurl->input != NULL)
		return TRUE;

	/* open mailbox if it is not yet open */
	if (mpurl->mail == NULL) {
		if (imap_msgpart_url_open_mail(mpurl, error_r) == NULL)
			return FALSE;
	}

	/* open the referenced part as a stream */
	if (!imap_msgpart_verify(mpurl->mail, mpurl->section, error_r))
		return FALSE;
	return TRUE;
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
