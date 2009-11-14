/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "hex-binary.h"
#include "sha1.h"
#include "dsync-data.h"

struct dsync_mailbox *
dsync_mailbox_dup(pool_t pool, const struct dsync_mailbox *box)
{
	struct dsync_mailbox *dest;

	dest = p_new(pool, struct dsync_mailbox, 1);
	*dest = *box;
	dest->name = p_strdup(pool, box->name);
	return dest;
}

struct dsync_message *
dsync_message_dup(pool_t pool, const struct dsync_message *msg)
{
	struct dsync_message *dest;
	const char **keywords;
	unsigned int i, count;

	dest = p_new(pool, struct dsync_message, 1);
	*dest = *msg;
	dest->guid = p_strdup(pool, msg->guid);
	if (msg->keywords != NULL) {
		count = str_array_length(msg->keywords);
		keywords = p_new(pool, const char *, count+1);
		for (i = 0; i < count; i++)
			keywords[i] = p_strdup(pool, msg->keywords[i]);
		dest->keywords = keywords;
	}
	return dest;
}

int dsync_mailbox_guid_cmp(const struct dsync_mailbox *box1,
			   const struct dsync_mailbox *box2)
{
	return memcmp(box1->mailbox_guid.guid, box2->mailbox_guid.guid,
		      sizeof(box1->mailbox_guid.guid));
}

int dsync_mailbox_p_guid_cmp(struct dsync_mailbox *const *box1,
			     struct dsync_mailbox *const *box2)
{
	return dsync_mailbox_guid_cmp(*box1, *box2);
}

int dsync_mailbox_dir_guid_cmp(const struct dsync_mailbox *box1,
			       const struct dsync_mailbox *box2)
{
	return memcmp(box1->dir_guid.guid, box2->dir_guid.guid,
		      sizeof(box1->dir_guid.guid));
}

int dsync_mailbox_p_dir_guid_cmp(struct dsync_mailbox *const *box1,
				 struct dsync_mailbox *const *box2)
{
	return dsync_mailbox_dir_guid_cmp(*box1, *box2);
}

bool dsync_keyword_list_equals(const char *const *k1, const char *const *k2)
{
	unsigned int i;

	if (k1 == NULL)
		return k2 == NULL || k2[0] == NULL;
	if (k2 == NULL)
		return k1[0] == NULL;

	for (i = 0;; i++) {
		if (k1[i] == NULL)
			return k2[i] == NULL;
		if (k2[i] == NULL)
			return FALSE;

		if (strcasecmp(k1[i], k2[i]) != 0)
			return FALSE;
	}
}

bool dsync_guid_equals(const mailbox_guid_t *guid1,
		       const mailbox_guid_t *guid2)
{
	return memcmp(guid1->guid, guid2->guid, sizeof(guid1->guid)) == 0;
}

int dsync_guid_cmp(const mailbox_guid_t *guid1, const mailbox_guid_t *guid2)
{
	return memcmp(guid1->guid, guid2->guid, sizeof(guid1->guid));
}

const char *dsync_guid_to_str(const mailbox_guid_t *guid)
{
	return binary_to_hex(guid->guid, sizeof(guid->guid));
}

const char *dsync_get_guid_128_str(const char *guid, unsigned char *dest,
				   unsigned int dest_len)
{
	uint8_t guid_128[MAIL_GUID_128_SIZE];
	buffer_t guid_128_buf;

	i_assert(dest_len >= MAIL_GUID_128_SIZE * 2 + 1);
	buffer_create_data(&guid_128_buf, dest, dest_len);
	mail_generate_guid_128_hash(guid, guid_128);
	if (mail_guid_128_is_empty(guid_128))
		return "";
	binary_to_hex_append(&guid_128_buf, guid_128, sizeof(guid_128));
	buffer_append_c(&guid_128_buf, '\0');
	return guid_128_buf.data;
}

void dsync_str_sha_to_guid(const char *str, mailbox_guid_t *guid)
{
	unsigned char sha[SHA1_RESULTLEN];

	sha1_get_digest(str, strlen(str), sha);
	memcpy(guid->guid, sha, I_MIN(sizeof(guid->guid), sizeof(sha)));
}
