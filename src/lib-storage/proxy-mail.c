/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "proxy-mail.h"

static enum mail_flags _get_flags(struct mail *mail)
{
	struct proxy_mail *p = (struct proxy_mail *) mail;

	return p->mail->get_flags(p->mail);
}

static const char *const *_get_keywords(struct mail *mail)
{
	struct proxy_mail *p = (struct proxy_mail *) mail;

	return p->mail->get_keywords(p->mail);
}

static const struct message_part *_get_parts(struct mail *mail)
{
	struct proxy_mail *p = (struct proxy_mail *) mail;

	return p->mail->get_parts(p->mail);
}

static time_t _get_received_date(struct mail *mail)
{
	struct proxy_mail *p = (struct proxy_mail *) mail;

	return p->mail->get_received_date(p->mail);
}

static time_t _get_date(struct mail *mail, int *timezone)
{
	struct proxy_mail *p = (struct proxy_mail *) mail;

	return p->mail->get_date(p->mail, timezone);
}

static uoff_t _get_virtual_size(struct mail *mail)
{
	struct proxy_mail *p = (struct proxy_mail *) mail;

	return p->mail->get_virtual_size(p->mail);
}

static uoff_t _get_physical_size(struct mail *mail)
{
	struct proxy_mail *p = (struct proxy_mail *) mail;

	return p->mail->get_physical_size(p->mail);
}

static const char *_get_header(struct mail *mail, const char *field)
{
	struct proxy_mail *p = (struct proxy_mail *) mail;

	return p->mail->get_header(p->mail, field);
}

static struct istream *
_get_headers(struct mail *mail, struct mailbox_header_lookup_ctx *headers)
{
	struct proxy_mail *p = (struct proxy_mail *) mail;

	return p->mail->get_headers(p->mail, headers);
}

static struct istream *_get_stream(struct mail *mail,
				   struct message_size *hdr_size,
				   struct message_size *body_size)
{
	struct proxy_mail *p = (struct proxy_mail *) mail;

	return p->mail->get_stream(p->mail, hdr_size, body_size);
}

static const char *_get_special(struct mail *mail, enum mail_fetch_field field)
{
	struct proxy_mail *p = (struct proxy_mail *) mail;

	return p->mail->get_special(p->mail, field);
}

static int _update_flags(struct mail *mail, enum modify_type modify_type,
			 enum mail_flags flags)
{
	struct proxy_mail *p = (struct proxy_mail *) mail;

	return p->mail->update_flags(p->mail, modify_type, flags);
}

static int _update_keywords(struct mail *mail, enum modify_type modify_type,
			    struct mail_keywords *keywords)
{
	struct proxy_mail *p = (struct proxy_mail *) mail;

	return p->mail->update_keywords(p->mail, modify_type, keywords);
}

static int _expunge(struct mail *mail)
{
	struct proxy_mail *p = (struct proxy_mail *) mail;

	return p->mail->expunge(p->mail);
}

void proxy_mail_init(struct proxy_mail *proxy, struct mail *mail)
{
	struct mail *pm = &proxy->proxy_mail;

	proxy->mail = mail;

	pm->box = mail->box;

	pm->get_flags = _get_flags;
	pm->get_keywords = _get_keywords;
	pm->get_parts = _get_parts;
	pm->get_received_date = _get_received_date;
	pm->get_date = _get_date;
	pm->get_virtual_size = _get_virtual_size;
	pm->get_physical_size = _get_physical_size;
	pm->get_header = _get_header;
	pm->get_headers = _get_headers;
	pm->get_stream = _get_stream;
	pm->get_special = _get_special;
	pm->update_flags = _update_flags;
	pm->update_keywords = _update_keywords;
	pm->expunge = _expunge;
}

void proxy_mail_next(struct proxy_mail *proxy)
{
	proxy->proxy_mail.seq = proxy->mail->seq;
	proxy->proxy_mail.uid = proxy->mail->uid;

	proxy->proxy_mail.has_nuls = proxy->mail->has_nuls;
	proxy->proxy_mail.has_no_nuls = proxy->mail->has_no_nuls;
}
