/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hex-binary.h"
#include "md5.h"
#include "istream.h"
#include "istream-crlf.h"
#include "message-header-hash.h"
#include "message-size.h"
#include "mail-storage.h"
#include "dsync-mail.h"

struct mailbox_header_lookup_ctx *
dsync_mail_get_hash_headers(struct mailbox *box, const char *const *hashed_headers)
{
	return mailbox_header_lookup_init(box, hashed_headers);
}

int dsync_mail_get_hdr_hash(struct mail *mail, unsigned int version,
			    const char *const *hashed_headers, const char **hdr_hash_r)
{
	struct istream *hdr_input, *input;
	struct mailbox_header_lookup_ctx *hdr_ctx;
	struct message_header_hash_context hash_ctx;
	struct md5_context md5_ctx;
	unsigned char md5_result[MD5_RESULTLEN];
	const unsigned char *data;
	size_t size;
	ssize_t sret;
	int ret = 0;

	hdr_ctx = mailbox_header_lookup_init(mail->box, hashed_headers);
	ret = mail_get_header_stream(mail, hdr_ctx, &hdr_input);
	mailbox_header_lookup_unref(&hdr_ctx);
	if (ret < 0)
		return -1;

	input = i_stream_create_lf(hdr_input);

	md5_init(&md5_ctx);
	i_zero(&hash_ctx);
	while ((sret = i_stream_read_more(input, &data, &size)) > 0) {
		message_header_hash_more(&hash_ctx, &hash_method_md5, &md5_ctx,
					 version, data, size);
		i_stream_skip(input, size);
	}
	i_assert(sret == -1);
	if (input->stream_errno != 0)
		ret = -1;
	i_stream_unref(&input);

	md5_final(&md5_ctx, md5_result);
	*hdr_hash_r = binary_to_hex(md5_result, sizeof(md5_result));
	return ret;
}

int dsync_mail_fill(struct mail *mail, bool minimal_fill,
		    struct dsync_mail *dmail_r, const char **error_field_r)
{
	const char *guid;

	i_zero(dmail_r);

	if (mail_get_special(mail, MAIL_FETCH_GUID, &guid) < 0) {
		*error_field_r = "GUID";
		return -1;
	}
	dmail_r->guid = guid;
	dmail_r->uid = mail->uid;

	dmail_r->input_mail = mail;
	dmail_r->input_mail_uid = mail->uid;

	if (mail_get_save_date(mail, &dmail_r->saved_date) < 0) {
		*error_field_r = "saved-date";
		return -1;
	}
	if (!minimal_fill)
		return dsync_mail_fill_nonminimal(mail, dmail_r, error_field_r);
	dmail_r->minimal_fields = TRUE;
	return 0;
}

int dsync_mail_fill_nonminimal(struct mail *mail, struct dsync_mail *dmail_r,
			       const char **error_field_r)
{
	const char *str;

	if (mail_get_stream(mail, NULL, NULL, &dmail_r->input) < 0) {
		*error_field_r = "body";
		return -1;
	}

	if (mail_get_special(mail, MAIL_FETCH_UIDL_BACKEND, &dmail_r->pop3_uidl) < 0) {
		*error_field_r = "pop3-uidl";
		return -1;
	}
	if (mail_get_special(mail, MAIL_FETCH_POP3_ORDER, &str) < 0) {
		*error_field_r = "pop3-order";
		return -1;
	}
	if (*str != '\0') {
		if (str_to_uint32(str, &dmail_r->pop3_order) < 0)
			i_unreached();
	}
	if (mail_get_received_date(mail, &dmail_r->received_date) < 0) {
		*error_field_r = "received-date";
		return -1;
	}
	return 0;
}

static void
const_string_array_dup(pool_t pool, const ARRAY_TYPE(const_string) *src,
		       ARRAY_TYPE(const_string) *dest)
{
	const char *const *strings, *str;
	unsigned int i, count;

	if (!array_is_created(src))
		return;

	strings = array_get(src, &count);
	if (count == 0)
		return;

	p_array_init(dest, pool, count);
	for (i = 0; i < count; i++) {
		str = p_strdup(pool, strings[i]);
		array_push_back(dest, &str);
	}
}

void dsync_mail_change_dup(pool_t pool, const struct dsync_mail_change *src,
			   struct dsync_mail_change *dest_r)
{
	dest_r->type = src->type;
	dest_r->uid = src->uid;
	if (src->guid != NULL) {
		dest_r->guid = *src->guid == '\0' ? "" :
			p_strdup(pool, src->guid);
	}
	dest_r->hdr_hash = p_strdup(pool, src->hdr_hash);
	dest_r->modseq = src->modseq;
	dest_r->pvt_modseq = src->pvt_modseq;

	dest_r->add_flags = src->add_flags;
	dest_r->remove_flags = src->remove_flags;
	dest_r->final_flags = src->final_flags;
	dest_r->keywords_reset = src->keywords_reset;
	const_string_array_dup(pool, &src->keyword_changes,
			       &dest_r->keyword_changes);
	dest_r->received_timestamp = src->received_timestamp;
	dest_r->virtual_size = src->virtual_size;
}
