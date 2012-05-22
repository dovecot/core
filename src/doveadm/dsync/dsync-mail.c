/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hex-binary.h"
#include "md5.h"
#include "istream.h"
#include "message-size.h"
#include "mail-storage.h"
#include "dsync-mail.h"

int dsync_mail_get_hdr_hash(struct mail *mail, const char **hdr_hash_r)
{
	struct message_size hdr_size;
	struct istream *input, *hdr_input;
	struct md5_context md5_ctx;
	unsigned char md5_result[MD5_RESULTLEN];
	const unsigned char *data;
	size_t size;
	int ret = 0;
	
	if (mail_get_hdr_stream(mail, &hdr_size, &input) < 0)
		return -1;

	md5_init(&md5_ctx);
	hdr_input = i_stream_create_limit(input, hdr_size.physical_size);
	while (!i_stream_is_eof(hdr_input)) {
		if (i_stream_read_data(hdr_input, &data, &size, 0) == -1)
			break;
		if (size == 0)
			break;
		md5_update(&md5_ctx, data, size);
		i_stream_skip(hdr_input, size);
	}
	if (hdr_input->stream_errno != 0)
		ret = -1;
	i_stream_unref(&hdr_input);

	md5_final(&md5_ctx, md5_result);
	*hdr_hash_r = binary_to_hex(md5_result, sizeof(md5_result));
	return ret;
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
		array_append(dest, &str, 1);
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
	dest_r->save_timestamp = src->save_timestamp;

	dest_r->add_flags = src->add_flags;
	dest_r->remove_flags = src->remove_flags;
	dest_r->final_flags = src->final_flags;
	dest_r->keywords_reset = src->keywords_reset;
	const_string_array_dup(pool, &src->keyword_changes,
			       &dest_r->keyword_changes);
}
